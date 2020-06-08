#define pr_fmt(fmt) "KHP: " fmt

#include <linux/kernel.h>
#include <linux/khp.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/slub_def.h>
#include <linux/atomic.h>
#include <linux/siphash.h>
#include <asm/cacheflush.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/pgtable_types.h>
#include <asm/pgalloc.h>
#include "../slab.h"
#include "../internal.h"
#include "internal.h"

#define KHP_META_PER_LINE (L1_CACHE_BYTES / sizeof(struct khp_meta))

static DEFINE_SPINLOCK(khp_alloc_lock);
struct khp_meta *khp_region_start __ro_after_init;
static u16 khp_cookie_depleted_low __ro_after_init;
static siphash_key_t khp_cookie_key __ro_after_init;

struct khp_region khp_orig_region;
struct khp_region khp_fallback_region;

#define KHP_COOKIE_LOW_MASK  0x000fU
#define KHP_COOKIE_HIGH_MASK 0xfff0U

struct khp_global_state {
	/* NOTE: only the low KHP_SEQ_MASK bits are used outside debugging */
	unsigned long new_seq;
	atomic_t num_checkin_cpus;
	atomic_t num_sync_cpus;
	u32 global_delay_head;
	atomic_long_t global_pending_count; /* approximate */
	#define KHP_G_GC_SCHEDULED 1UL
	unsigned long flags; /* atomic flags */
};
static struct khp_global_state khp_global = {
	.global_delay_head = KHP_LIST_END
};

/*
 * ACTIVE is only toggled by the owning CPU.
 * CHECKIN_REQUESTED and SYNC_REQUESTED may be set by other CPUs, but only if
 * ACTIVE is set.
 * Updates are synchronized via cmpxchg.
 *
 * Do *NOT* use percpu atomics on this! We do remote writes, which percpu
 * atomics are not designed for.
 */
static DEFINE_PER_CPU(unsigned long, khp_cpu_flags);
/* Exclusively modified by the owning CPU. */
#define KHP_CPU_ACTIVE 0x1UL
/*
 * Request to confirm that we've ensured `new_seq` was used since the last
 * schedule-in.
 * Set from anywhere (only if ACTIVE), clear locally.
 */
#define KHP_CPU_CHECKIN_REQUESTED 0x2UL

static u32 khp_idx_by_raw(void *raw_ptr)
{
	struct page *page = virt_to_head_page(raw_ptr);
	struct kmem_cache *s;

	BUG_ON(!PageSlab(page)); /* TODO big allocations */
	s = page->slab_cache;
	BUG_ON((s->flags & SLAB_KHP) == 0);
	return page->khp_base_idx + (raw_ptr-page_address(page)) / s->size;
}

void khp_refcount_inc(struct khp_meta *meta)
{
	u16 old = READ_ONCE(meta->lar.khp_refcount);
	u16 tmp;

	while (1) {
		/* do nothing if saturated */
		if (unlikely(old == 0xffff))
			return;

		tmp = cmpxchg(&meta->lar.khp_refcount, old, old + 1);
		if (likely(tmp == old)) {
			/* warn if newly saturated */
			if (unlikely(old == 0xfffe))
				pr_warn("khp: saturated refcount\n");
			return;
		}
		old = tmp;
	}
}

u16 khp_depletion_cookie(struct khp_meta *meta)
{
	u32 idx = khp_meta_idx(meta);
	u16 hash = siphash_1u64(idx, &khp_cookie_key);

	return (hash & KHP_COOKIE_HIGH_MASK) | khp_cookie_depleted_low;
}

/*
 * Helper to change structure layout when switching type from one of
 *     KHP_ETT_ALLOC / KHP_ETT_ALLOC_FB
 * to
 *     KHP_ETT_QUEUED / KHP_ETT_FLOATING
 * .
 * Leaves new->khp_next uninitialized. */
static void khp_layout_to_free(struct khp_meta *new, const struct khp_meta *old,
			       bool queueing)
{
	unsigned long raw_phys = __pa(old->khp_raw_ptr) >> ilog2(ARCH_SLAB_MINALIGN);

	BUG_ON((raw_phys >> 48) != 0);
	new->khp_raw_phys_low32 = raw_phys & 0xffffffffUL;
	new->khp_raw_phys_high16 = (raw_phys >> 32) & 0xffffUL;
	new->khp_cookie = old->khp_cookie;
	new->khp_extag = queueing ? KHP_ETT_QUEUED : KHP_ETT_FLOATING;
	new->lar.etac.khp_cpu_mask_inv = old->lar.etac.khp_cpu_mask_inv;
	new->lar.khp_refcount = old->lar.khp_refcount;
}

static DEFINE_PER_CPU(u32, khp_local_delay_head) = KHP_LIST_END;

/*
 * Insert the list @added_head..@added_tail into @list.
 * @added_head..@added_tail must already be set up with ->khp_next links.
 */
static void khp_list_push(u32 *list, struct khp_meta *added_head,
			  struct khp_meta *added_tail)
{
	u32 added_head_idx;
	u32 old;
	u32 cur;

	if (added_head == NULL)
		return;

	added_head_idx = khp_meta_idx(added_head);
	old = READ_ONCE(*list);
	do {
		added_tail->khp_next = old;
		cur = old;
		old = cmpxchg(list, old, added_head_idx);
	} while (old != cur);
}

/*
 * Add @meta to the local percpu delaylist.
 * We can get away with doing this using percpu operations, since the freelists
 * are cpu-local - except that there is no non-atomic cmpxchg. Oh well.
 * Note that we can migrate in the middle of this (when coming from kfree())!
 */
static void khp_norefs_enqueue(struct khp_meta *meta)
{
	u32 new = khp_meta_idx(meta);
	u32 old = this_cpu_read(khp_local_delay_head);
	u32 prev;

	do {
		prev = old;
		meta->khp_next = prev;
		old = this_cpu_cmpxchg(khp_local_delay_head, prev, new);
	} while (unlikely(old != prev));
}

static bool khp_is_newly_depleted(struct khp_meta *m)
{
	/* fast check: do we have a potential depletion event? */
	if (likely((m->khp_cookie & KHP_COOKIE_LOW_MASK) !=
		   khp_cookie_depleted_low))
		return false;

	/* precise slow check (using siphash) */
	return m->khp_cookie == khp_depletion_cookie(m);
}

/* Release an allocation back to the slab allocator. */
static void khp_actually_free(struct khp_meta *meta)
{
	unsigned long raw_phys = meta->khp_raw_phys_low32 |
			(((unsigned long)meta->khp_raw_phys_high16) << 32);
	void *raw_ptr = __va(raw_phys << ilog2(ARCH_SLAB_MINALIGN));
	struct page *page = virt_to_head_page(raw_ptr);
	struct khp_meta *orig_meta;

	if (khp_meta_idx(meta) < KHP_IDENTIFIERS_PER_REGION) {
		/* original allocation: remember that we have no fallback */
		meta->fb_idx = KHP_LIST_END;
	} else {
		/* fallback allocation: disassociate if depleted */
		if (khp_is_newly_depleted(meta)) {
			//pr_warn("KHP: one fallback depleted\n");
			orig_meta = khp_meta_by_idx(khp_idx_by_raw(raw_ptr));
			orig_meta->fb_idx = KHP_LIST_END;
			/* TODO: mark meta as depleted for extag feature? */
		}
	}

	/* for debugging: permit distinguishing queued and unused identifiers */
	BUG_ON((meta->khp_extag & KHP_ETT_MASK) != KHP_ETT_QUEUED);
	WRITE_ONCE(meta->khp_extag, meta->khp_extag | KHP_EXTAG_RELEASED);

	if (unlikely(!PageSlab(page))) {
		// TODO vmalloc and kmalloc-large support
		BUG();
	}

	/*
	 * We're passing 0 as the caller address. This makes the freeing part of
	 * SLAB_STORE_USER useless for now - however, that's fixable;
	 * we'd have to adjust things so that SLUB stores a freeing trace before
	 * the object is put into the delayed-freeing machinery.
	 */
	___cache_free(page->slab_cache, raw_ptr, 0);
}

void khp_mark_migrated_global(struct khp_meta *meta)
{
	WRITE_ONCE(meta->lar.etac.khp_cpu_mask_inv, KHP_CPU_MASK_INV_GLOBAL);
	/* order with subsequent refcount modification */
	smp_mb__before_atomic();
}

static void khp_extag_queued_refresh(u8 *extag_)
{
	u8 extag = *extag_;
	u8 obj_cycle, cur_cycle, next_cycle, last_cycle;

	BUG_ON((extag & KHP_ETT_MASK) != KHP_ETT_QUEUED);

	/* no need to update the extag if we're locally queued */
	if ((extag & KHP_EXTAG_GLOBAL_QUEUE) == 0)
		return;

	obj_cycle = extag & KHP_SEQ_MASK;
	/*
	 * Note that the READ_ONCE() must be stable against new_seq
	 * advancing under us by more than one.
	 */
	cur_cycle = READ_ONCE(khp_global.new_seq) & KHP_SEQ_MASK;
	next_cycle = (cur_cycle + 1) & KHP_SEQ_MASK;
	last_cycle = (cur_cycle - 1) & KHP_SEQ_MASK;

	/*
	 * No need to update the extag if the object's tag is at least as recent
	 * as our cpu's - and specifically, the object shouldn't go backwards.
	 */
	if (obj_cycle == cur_cycle || obj_cycle == next_cycle)
		return;

	BUG_ON(obj_cycle != last_cycle);

	extag &= ~KHP_SEQ_MASK;
	extag |= cur_cycle;
	*extag_ = extag;
}

static inline void khp_extag_set_global(u8 *extag_, u8 cur_cycle)
{
	u8 extag = *extag_;

	BUG_ON((extag & KHP_ETT_MASK) == KHP_ETT_QUEUED &&
	       (extag & KHP_EXTAG_GLOBAL_QUEUE) != 0);

	*extag_ = KHP_ETT_QUEUED | KHP_EXTAG_GLOBAL_QUEUE | cur_cycle;
}

/*
 * Atomically update *the second half* of @p, replacing @old with @changed.
 * Return whether the update was successful.
 * On failure, @old is updated.
 */
static inline bool khp_update(struct khp_meta *p, struct khp_meta *old,
			      struct khp_meta *changed)
{
	unsigned long old_half = old->halves[1];
	unsigned long new_half;

	new_half = cmpxchg(&p->halves[1], old_half, changed->halves[1]);
	if (new_half == old_half)
		return true;

	old->halves[1] = new_half;
	return false;
}

static inline bool khp_update_full(struct khp_meta *p, struct khp_meta *old,
				   struct khp_meta *changed)
{
	if (cmpxchg_double(&p->halves[0], &p->halves[1],
			   old->halves[0], old->halves[1],
			   changed->halves[0], changed->halves[1]))
		return true;
	BUG_ON(old->halves[0] != READ_ONCE(p->halves[0]));
	old->halves[1] = READ_ONCE(p->halves[1]);
	return false;
}

/*
 * Drop a reference on @meta. If @freeing, also mark it as free, and use
 * @expected_cookie for double-free detection.
 */
void khp_refcount_dec(struct khp_meta *meta, bool freeing, u16 expected_cookie)
{
	struct khp_meta old, new;
	old.halves[1] = READ_ONCE(meta->halves[1]);

	/* For now, use this to ensure that timestamps are stable. */
	if (!freeing)
		lockdep_assert_irqs_disabled();

	while (1) {
		u8 type = old.khp_extag & KHP_ETT_MASK;
		bool last_ref = old.lar.khp_refcount == 1;
		bool saturated = old.lar.khp_refcount == 0xffff;

		/* detect double-free after reallocation */
		BUG_ON(freeing && old.khp_cookie != expected_cookie);

		/* underflows should be impossible */
		BUG_ON(old.lar.khp_refcount == 0);

		if (unlikely(freeing || (last_ref && type != KHP_ETT_QUEUED))) {
			/*
			 * Slowpath in case we can't simply decrement the
			 * refcount and potentially bump the clock; in this
			 * case, we need to also do stuff with the first half of
			 * the metadata struct.
			 *
			 * This can happen for two reasons:
			 *  - We tried to drop from refcount 1 without being
			 *    queued, so we need to queue.
			 *  - We are freeing the object and need to change the
			 *    layout.
			 */

			/* The layout *shouldn't* change to free under us, but
			 * it can if the caller has a double-free.
			 * Use READ_ONCE() because we expect correctness even if
			 * the caller is buggy.
			 * (We could hoist this load out of the loop, but then
			 * we'd have to perform this load on the fastpath.)
			 */
			old.halves[0] = READ_ONCE(meta->halves[0]);
			if (freeing) {
				/* detect double-free before reallocation */
				BUG_ON(type == KHP_ETT_FLOATING || type == KHP_ETT_QUEUED);
				khp_layout_to_free(&new, &old, last_ref);
				new.khp_cookie++;
			} else {
				if (type != KHP_ETT_FLOATING) {
					pr_err("KHP error: type=0x%x, meta=%px, freeing=%d\n", (unsigned)type, meta, (int)freeing);
				}
				BUG_ON(type != KHP_ETT_FLOATING);
				new = old;
				new.khp_extag = KHP_ETT_QUEUED;
			}
			/*
			 * If the refcount is saturated, don't decrement it, but
			 * *do* mark the allocation as free anyway; we don't
			 * want a double-free to go undetected just because its
			 * refcount is saturated.
			 */
			if (likely(!saturated))
				new.lar.khp_refcount--;

			/*
			 * No need to touch the timestamp; if we're queueing the
			 * object, we're putting it on the local queue at first.
			 */

			if (!khp_update_full(meta, &old, &new))
				continue; /* retry */

			if (last_ref) {
				/*
				 * Success! The object is now in QUEUED
				 * state, but not actually on any queue
				 * yet, so we own its state.
				 * Atomically enqueue it, giving the
				 * queue ownership of its state.
				 */
				khp_norefs_enqueue(meta);
			}
		} else {
			if (unlikely(saturated))
				return;

			new.halves[1] = old.halves[1];
			new.lar.khp_refcount--;

			/*
			 * If we're dropping the refcount to zero while the
			 * object might already be on the global freelist,
			 * we have to refresh its global cycle tracking number
			 * so that it will be skipped on the next global scan if
			 * appropriate.
			 * Note that while we also do this if the object is on
			 * the local queue, it has no effect there.
			 */
			if (last_ref) {
				BUG_ON(freeing);
				BUG_ON(type != KHP_ETT_QUEUED);
				khp_extag_queued_refresh(&new.khp_extag);
			}

			if (!khp_update(meta, &old, &new))
				continue; /* retry */
		}
		return;
	}
}

void khp_migrate(struct task_struct *t) {
	set_bit(KHP_MIGRATED_BIT, &t->khp_flags);
}

/*
 * Make sure that the top-level entries of the swapper_pg_dir are set up before
 * we start cloning the mm. Otherwise we'd have to worry about random page
 * faults from any place that can decode a KHP pointer, including NMI context
 * and whatever, and then we'd have to copy the top-level page table entries
 * over... not pretty.
 *
 * We write both the PGD entry and the P4D entry because the PGD entry doesn't
 * actually exist with 4-level paging. :/
 * We assume that KHP is contained in a single level-4 entry.
 */
static void __init khp_populate_toplevel(void)
{
	pgd_t *pgd = pgd_offset(&init_mm, (unsigned long)khp_region_start);
	p4d_t *p4d;
	pud_t *pud;
	unsigned long region_end = ((unsigned long)khp_region_start) + 2*KHP_REGION_SIZE - 1;

	BUG_ON(pgd != pgd_offset(&init_mm, region_end));

	if (pgd_none(READ_ONCE(*pgd))) {
		p4d = (p4d_t *)get_zeroed_page(GFP_KERNEL);
		if (p4d == NULL)
			panic("khp high-level page table allocation failed");
		smp_wmb(); /* See comment in __pte_alloc */
		pgd_populate(&init_mm, pgd, p4d);
	}
	p4d = p4d_offset(pgd, (unsigned long)khp_region_start);
	BUG_ON(p4d != p4d_offset(pgd, region_end));

	pud = (pud_t *)get_zeroed_page(GFP_KERNEL);
	BUG_ON(!p4d_none(READ_ONCE(*p4d)));
	if (pud == NULL)
		panic("khp high-level page table allocation failed");
	smp_wmb(); /* See comment in __pte_alloc */
	p4d_populate(&init_mm, p4d, pud);
}

void __init khp_init(void)
{
	/* TODO randomize */
	unsigned long khp_region_addr = KHP_BASE_ADDR + 0x1000UL;

	/* TODO using arch random from generic code */
	khp_cookie_depleted_low =
		kaslr_get_random_long("KHP cookie base") & KHP_COOKIE_LOW_MASK;
	khp_cookie_key.key[0] = kaslr_get_random_long("KHP cookie key 1");
	khp_cookie_key.key[1] = kaslr_get_random_long("KHP cookie key 2");

	khp_region_start = (void*)khp_region_addr;

	khp_orig_region.start = khp_orig_region.used_end =
		khp_orig_region.alloc_end = khp_region_start;
	khp_orig_region.start_idx = 0;
	khp_fallback_region.start = khp_fallback_region.used_end =
		khp_fallback_region.alloc_end =
		khp_region_start + KHP_IDENTIFIERS_PER_REGION;
	khp_fallback_region.start_idx = KHP_IDENTIFIERS_PER_REGION;
	khp_populate_toplevel();

	arch_khp_init();

	pr_warn("KHP initialized\n");

	BUILD_BUG_ON(sizeof(struct khp_meta) != 16);
}

/*
 * Map @page at @addr_ if we have sufficient pagetables; otherwise, use the
 * provided page as a pagetable, and let the caller try again.
 * See __handle_mm_fault for the general pagetable allocation pattern.
 */
static pte_t *khp_get_ptep(void *addr_, struct page *page)
{
	unsigned long address = (unsigned long)addr_;
	pgd_t *pgd = pgd_offset(&init_mm, address);
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	/* ensure that nobody sees uninitialized page tables */
	smp_wmb();

	if (pgd_none(READ_ONCE(*pgd))) { // __pud_alloc
		//pr_warn("using pfn 0x%lx as level 4 table\n", page_to_pfn(page));
		p4d = (p4d_t *)page_to_virt(page);
		pgd_populate(&init_mm, pgd, p4d);
		return NULL;
	}
	p4d = p4d_offset(pgd, address);

	if (p4d_none(READ_ONCE(*p4d))) {
		//pr_warn("using pfn 0x%lx as level 3 table\n", page_to_pfn(page));
		pud = (pud_t *)page_to_virt(page);
		p4d_populate(&init_mm, p4d, pud);
		return NULL;
	}
	pud = pud_offset(p4d, address);

	if (pud_none(READ_ONCE(*pud))) {
		//pr_warn("using pfn 0x%lx as level 2 table\n", page_to_pfn(page));
		pmd = (pmd_t *)page_to_virt(page);
		pud_populate(&init_mm, pud, pmd);
		return NULL;
	}
	pmd = pmd_offset(pud, address);

	// __pte_alloc, pte_offset_map
	/* TODO x86-64-specific */
	if (pmd_none(READ_ONCE(*pmd))) {
		//pr_warn("using pfn 0x%lx as level 1 table\n", page_to_pfn(page));
		pte = (pte_t *)page_to_virt(page);
		pmd_populate(&init_mm, pmd, page);
		return NULL;
	}
	//pr_warn("using pfn 0x%lx as data page\n", page_to_pfn(page));
	pte = pte_offset_kernel(pmd, address);

	return pte;
}

/*
 * If the required page tables exist, initialize @page as a KHP metadata page
 * and install it at @addr; otherwise, install @page as a pagetable and let the
 * caller try again.
 */
static bool khp_set_pte(void *addr, struct page *page)
{
	pte_t *pte = khp_get_ptep(addr, page);
	pte_t pte_val = mk_pte(page, PAGE_KERNEL);
	struct khp_meta *meta_page = addr; /* not mapped! */
	struct khp_meta *linear_meta_page = page_address(page);
	int i;

	if (!pte)
		return false;

	/*
	 * Initialize KHP metadata through linear mapping.
	 * This matters especially when we permit speculative decoding of bogus
	 * pointers: As soon as we install the metadata page into the KHP
	 * metadata mapping, its entries can have their refcounts modified and
	 * so on.
	 */
	for (i=0; i<PAGE_SIZE/sizeof(struct khp_meta); i++) {
		struct khp_meta *m = &linear_meta_page[i];
		m->khp_extag = KHP_ETT_QUEUED | KHP_EXTAG_RELEASED;
		m->khp_cookie = khp_depletion_cookie(&meta_page[i]) + 1;
#ifdef CONFIG_KHP_DEBUG_DEPLETE_FASTER
		m->khp_cookie += 0xff00;
#endif
		m->fb_idx = KHP_LIST_END;
	}

	/* ensure that nobody sees uninitialized KHP meta structs */
	smp_wmb();
	set_pte_at(&init_mm, (unsigned long)addr, pte, pte_val);

	return true;
}

/*
 * Allocate a virtually contiguous set of weak pointers corresponding to a slab
 * page.
 *
 * Returns index into the khp_region(), or negative error number on failure.
 */
static s64 khp_alloc_meta_area(unsigned int num_req, int gfp_flags,
			       struct khp_region *region)
{
	unsigned long flags;
	s64 ret;
	int meta_gfp_flags = (gfp_flags & GFP_RECLAIM_MASK) | __GFP_ZERO;
	struct page *page;

	//pr_warn("khp_alloc_meta_area(%u)\n", num_req);

	/*
	 * You can't use khp_alloc_meta_area() before KHP has finished
	 * initializing.
	 */
	BUG_ON(READ_ONCE(region->used_end) == 0);

	num_req = round_up(num_req, KHP_META_PER_LINE);

	spin_lock_irqsave(&khp_alloc_lock, flags);
	do {
		if (likely(num_req <= region->alloc_end - region->used_end))
			break;
		BUG_ON((region->alloc_end - khp_region_start) %
		       KHP_META_PER_LINE != 0);
		if (unlikely(region->alloc_end - region->start + num_req >
			     KHP_END_PER_TYPE)) {
			WARN_ONCE(1, "KHP out of identifiers!");
			return -ENOMEM;
		}
		spin_unlock_irqrestore(&khp_alloc_lock, flags);

		/*
		 * Allocate a page that may be used either for storing KHP
		 * metadata or as a page table.
		 */
		//pr_warn("kama: allocate page\n");
		page = alloc_page(meta_gfp_flags);
		if (unlikely(!page))
			return -ENOMEM;
		/*
		 * We could try to give the KHP metadata area a little bit of
		 * extra protection by setting the direct mapping to
		 * not-present; however, set_memory_np() requires that we're
		 * sleepable, but we can get here with GFP_ATOMIC.
		 * Plus, we have to keep our pagetables writable anyway.
		 * Let's just not worry about it; you'd already need unmitigated
		 * memory corruption to make use of that anyway.
		 */

		//if (region == &khp_fallback_region) pr_warn("attempting to allocate fallback region page at %px\n", READ_ONCE(region->alloc_end));
		spin_lock_irqsave(&khp_alloc_lock, flags);
		/* recheck whether out of identifiers */
		if (unlikely(region->alloc_end - region->start + num_req >
			     KHP_END_PER_TYPE)) {
			__free_page(page);
			continue;
		}

		//pr_warn("kama: set pte?\n");
		if (khp_set_pte(region->alloc_end, page)) {
			region->alloc_end = (void*)region->alloc_end +
					    PAGE_SIZE;
		}
	} while (1);

	ret = (region->used_end - khp_region_start);
	smp_store_release(&region->used_end, region->used_end + num_req);

	spin_unlock_irqrestore(&khp_alloc_lock, flags);
	//pr_warn("allocated meta area: 0x%08x\n", (unsigned int)ret);
	//pr_warn("khp_alloc_meta_area(%u) = %lld\n", num_req, ret);
	//if (region == &khp_fallback_region) pr_warn("allocated fallback region element idx=0x%llx\n", (u64)ret);
	return ret;
}

s64 khp_alloc_normal_area(unsigned int num_req, int gfp_flags)
{
	return khp_alloc_meta_area(num_req, gfp_flags, &khp_orig_region);
}

/*
 * Do *NOT* use percpu atomics on this! We do remote writes, which percpu
 * atomics are not designed for.
 */
struct khp_pcpu_fb {
	unsigned long head; /* actually u32 */
	unsigned long seq; /* synchronizes popping (NOT pushing) */
} __aligned(2 * sizeof(unsigned long));
static DEFINE_PER_CPU(struct khp_pcpu_fb, khp_pcpu_fb) = {
	.head = KHP_LIST_END
};

static void khp_dealloc_fb(int cpu, struct khp_meta *m)
{
	struct khp_pcpu_fb *pcpu = per_cpu_ptr(&khp_pcpu_fb, cpu);
	u32 old = READ_ONCE(pcpu->head);
	u32 cur;

	do {
		m->khp_next = old;
		cur = old;
		old = cmpxchg(&pcpu->head, old, khp_meta_idx(m));
	} while (unlikely(old != cur));
}

static s64 khp_alloc_fb(int cpu, int gfp_flags)
{
	struct khp_pcpu_fb *pcpu = per_cpu_ptr(&khp_pcpu_fb, cpu);
	s64 new_area;
	int i;

	while (1) {
		unsigned long seq = smp_load_acquire(&pcpu->seq);
		unsigned long head = READ_ONCE(pcpu->head);
		struct khp_meta *m;
		unsigned long next;

		if (head == KHP_LIST_END)
			break;

		m = khp_meta_by_idx(head);
		/* note: "next" may be garbage until we have cmpxchg success */
		next = READ_ONCE(m->khp_next);

		if (likely(cmpxchg_double(&pcpu->head, &pcpu->seq, head, seq,
					  next, seq+1))) {
			return head;
		}
		/* retry */
	}

	/* slowpath: allocate more */
	//pr_warn("khp: allocating fallback identifier block\n");
	new_area = khp_alloc_meta_area(KHP_META_PER_LINE, gfp_flags,
				       &khp_fallback_region);
	if (new_area < 0)
		return new_area;
	for (i = 1; i < KHP_META_PER_LINE; i++) {
		/* special case: the very last fallback element is unusable */
		if (new_area + i == KHP_LIST_END)
			continue;
		khp_dealloc_fb(cpu, khp_meta_by_idx(new_area + i));
	}
	//pr_warn("khp_alloc_fb(cpu=%d) = 0x%lx [fresh]\n", cpu, (unsigned long)new_area);
	return new_area;
}

void *khp_init_alloc(int cpu, unsigned int obj_idx, void *raw_ptr,
		     int gfp_flags) {
	struct khp_meta *m = khp_region_start + obj_idx;
	unsigned long fat_pointer;

	BUG_ON(cpu >= nr_cpumask_bits || !cpu_possible(cpu));

	/*
	 * If the object has a fallback but that fallback is likely to have
	 * false sharing with other CPUs, deallocate the fallback and try to
	 * grab a new one.
	 */
	if (m->fb_idx != KHP_LIST_END && unlikely(m->alloc_cpu != cpu)) {
		BUG_ON(m->alloc_cpu >= nr_cpumask_bits || !cpu_possible(m->alloc_cpu));
		khp_dealloc_fb(m->alloc_cpu, khp_meta_by_idx(m->fb_idx));
		m->fb_idx = KHP_LIST_END;
	}

	if (m->fb_idx == KHP_LIST_END && khp_is_newly_depleted(m)) {
		u64 new_fb;

		/*
		 * The object is depleted but doesn't currently have a fallback.
		 * Allocate one.
		 */
		new_fb = khp_alloc_fb(cpu, gfp_flags);

		if (unlikely(new_fb < 0))
			return NULL;

		m->fb_idx = new_fb;
		m->alloc_cpu = cpu;
	}

	if (m->fb_idx != KHP_LIST_END) {
		obj_idx = m->fb_idx;
		m = khp_meta_by_idx(obj_idx);
	}

	fat_pointer = (1UL<<62) + ((unsigned long)obj_idx << 32);
	fat_pointer |= (unsigned long)m->khp_cookie << 16;

	WRITE_ONCE(m->khp_raw_ptr, raw_ptr);
	WRITE_ONCE(m->lar.etac.khp_cpu_mask_inv, ~raw_cpu_fixedhamming_id());
	/*
	 * This normally lifts the refcount from 0 to 1, except that there may
	 * be extra references from (speculative) decodes of free pointers; so
	 * we need to do an atomic increment here.
	 */
	khp_refcount_inc(m);
	WRITE_ONCE(m->khp_extag, fat_pointer >> 56);

	return (void*)fat_pointer;
}

/*
 * For slab allocators, when detaching physical memory from a range of KHP
 * indices (iow, when freeing physical pages):
 * Push [@obj_idx..@obj_idx+@nr) onto an external freelist at @head.
 * @obj_idx must be an object in state free-orig/depleted.
 * @head must be externally locked, and initialized to KHP_LIST_END.
 *
 * You should avoid mixing elements of different sizes; but if you do it anyway,
 * we can deal with it (inefficiently). (SLUB can end up doing this when it
 * mixes high-order allocations and low-order allocations due to varying
 * fragmentation.)
 */
void khp_push_external_freelist(unsigned int obj_idx, unsigned int nr,
				unsigned int *head)
{
	struct khp_meta *m;
	unsigned int i;

	WARN_ON_ONCE(nr == 0 || nr >= U16_MAX);

	/*
	 * All fallback elements are released, both to avoid hogging ID space
	 * and to make space in the khp_meta struct.
	 */
	for (i = 0; i < nr; i++) {
		m = khp_meta_by_idx(obj_idx + i);

		if (m->fb_idx != KHP_LIST_END) {
			khp_dealloc_fb(m->alloc_cpu, khp_meta_by_idx(m->fb_idx));
			m->fb_idx = KHP_LIST_END;
		}
	}

	m = khp_meta_by_idx(obj_idx);

	/* Save the size of the range, we'll match this on pop. */
	m->extern_free_size = nr;

	/* Actual list push. */
	m->extern_free_next = *head;
	*head = obj_idx;
}

/*
 * For slab allocators:
 * Pop a range of @nr contiguous object indices from an external freelist at
 * @head.
 * @head must be externally locked.
 */
unsigned int khp_pop_external_freelist(unsigned int *head, unsigned int nr)
{
	unsigned int idx = *head;
	struct khp_meta *m;

	while (idx != KHP_LIST_END) {
		m = khp_meta_by_idx(idx);

		if (m->extern_free_size == nr) {
			/* update head */
			*head = m->extern_free_next;
			m->fb_idx = KHP_LIST_END;

			return idx;
		}

		/*
		 * We're not removing the first element; so if we do remove
		 * something, we'll have to update the element pointing to it,
		 * not the list head.
		 */
		head = &m->extern_free_next;
		idx = m->extern_free_next;
	}
	return KHP_LIST_END;
}

/*
 * WARNING: Double-free detection only happens at the end of this function, via
 * khp_refcount_dec(). Don't assume that the allocation still belongs to us
 * within this function.
 */
__attribute__((no_sanitize("kernel")))
void khp_mark_free(struct kmem_cache *s, void *ptr) {
	unsigned long fat_pointer = (unsigned long)ptr;
	u32 obj_idx;
	u16 obj_off;
	u16 cookie;
	struct khp_meta *m;
	u8 cpu_fhid_inv, cpu_fhid;
	struct khp_region *region;

	if ((s->flags & SLAB_KHP) == 0) {
		BUG_ON((fat_pointer >> 56) != 0xff);
		return;
	}

	//pr_warn("decoding fat pointer for free: 0x%016lx\n", fat_pointer);

	obj_idx = (fat_pointer >> 32) - 0x40000000UL;
	cookie = (fat_pointer >> 16) & 0xffffUL;
	obj_off = fat_pointer & 0xffffUL;

	/* expected KHP identifier, but didn't get one? */
	BUG_ON(obj_idx >= 2*KHP_IDENTIFIERS_PER_REGION);

	/* misaligned kfree()? */
	BUG_ON(obj_off != 0);

	/* sanity check */
	region = (obj_idx >= KHP_IDENTIFIERS_PER_REGION) ?
		&khp_fallback_region : &khp_orig_region;
	BUG_ON(obj_idx - region->start_idx >
	       READ_ONCE(region->used_end) - region->start);

	/* be careful about using @m in case this is a double-free! */
	m = khp_region_start + obj_idx;

	cpu_fhid_inv = READ_ONCE(m->lar.etac.khp_cpu_mask_inv);
	if (cpu_fhid_inv == 0) {
		atomic_long_inc(&khp_stat_global_frees);
		atomic_long_inc(&s->khp_stat_global_frees);
	} else {
		cpu_fhid = ~cpu_fhid_inv;
		BUG_ON(hweight8(cpu_fhid) != 4);
		atomic_long_inc(&khp_stat_local_frees);
		atomic_long_inc(&s->khp_stat_local_frees);
	}

	khp_refcount_dec(m, true, cookie);
}

/*
 * Tell @cpu to go perform work specified by @flag, except that if the CPU isn't
 * currently running, we consider it to have completed the work instantly.
 *
 * Returns whether the CPU was active (and therefore whether the flag was set).
 */
static bool khp_set_flag_if_active(int cpu, unsigned long added_flag)
{
	unsigned long *flags_ptr = per_cpu_ptr(&khp_cpu_flags, cpu);
	unsigned long flags = READ_ONCE(*flags_ptr);
	unsigned long old_flags, new_flags;

	while (1) {
		if ((flags & KHP_CPU_ACTIVE) == 0)
			return false;
		new_flags = flags | added_flag;
		old_flags = cmpxchg(flags_ptr, flags, new_flags);
		if (old_flags == flags)
			return true;
		flags = old_flags;
	}
}

/*
 * Batch-process a freelist (either a local one or the global one), sorting its
 * items into three categories:
 *  - dequeue
 *  - requeue onto global list
 *  - free immediately
 */
static void khp_batch_process(u32 free_head, bool is_global_list)
{
	unsigned long requeued = 0;
	struct khp_meta *requeue_head = NULL;
	struct khp_meta *requeue_tail = NULL;
	u8 cur_cycle = khp_global.new_seq & KHP_SEQ_MASK;
	u8 last_cycle = (cur_cycle - 1) & KHP_SEQ_MASK;

	while (free_head != KHP_LIST_END) {
		struct khp_meta *meta = khp_meta_by_idx(free_head);
		struct khp_meta meta_old, meta_new;

		free_head = meta->khp_next;

		/* stable: only contains next-pointer and raw-phys-addr */
		meta_old.halves[0] = meta->halves[0];
		meta_old.halves[1] = READ_ONCE(meta->halves[1]);
		do {
			if (meta_old.lar.khp_refcount != 0) {
				/*
				 * The object is still referenced; kick it off
				 * the freelist so that if a sleeping task is
				 * referencing it, we don't uselessly look at it
				 * over and over again.
				 */
				meta_new.halves[1] = meta_old.halves[1];
				meta_new.khp_extag = KHP_ETT_FLOATING;
				if (!khp_update(meta, &meta_old, &meta_new))
					continue; /* retry */
			} else if (!is_global_list && meta_old.lar.etac.khp_cpu_mask_inv == KHP_CPU_MASK_INV_GLOBAL) {
				/*
				 * The object was touched by a different CPU at
				 * some point. We have to shove it to the global
				 * queue (from where it can be picked up once
				 * all CPUs have confirmed that it is no longer
				 * in use).
				 */
				meta_new.halves[1] = meta_old.halves[1];
				khp_extag_set_global(&meta_new.khp_extag, cur_cycle);
				if (!khp_update(meta, &meta_old, &meta_new))
					continue; /* retry */

				if (requeue_head)
					meta->khp_next = khp_meta_idx(requeue_head);
				else
					requeue_tail = meta;
				requeue_head = meta;
				requeued++;
			} else if (is_global_list && (meta_old.khp_extag & KHP_SEQ_MASK) != last_cycle) {
				BUG_ON((meta_old.khp_extag & KHP_SEQ_MASK) != cur_cycle);

				/*
				 * The object has been touched recently; it may
				 * currently be active on some CPU.
				 * Requeue onto the global list (which doesn't
				 * require any modifications to the second half
				 * of the object).
				 */
				if (requeue_head)
					meta->khp_next = khp_meta_idx(requeue_head);
				else
					requeue_tail = meta;
				requeue_head = meta;
				requeued++;
			} else {
				/*
				 * The object can definitely not be referenced
				 * anymore, so we can free it directly!
				 *
				 * Note: If the SLUB allocator's freeing path
				 * can end up in kfree(), that means we can
				 * trigger nested khp_refcount_dec() from here.
				 */
				khp_actually_free(meta);
			}
			break;
		} while (1);
	}

	/* Shove things onto the global queue in bulk. */
	if (requeued) {
		khp_list_push(&khp_global.global_delay_head, requeue_head,
			      requeue_tail);
		atomic_long_add(requeued, &khp_global.global_pending_count);
	}
}

/*
 * When this is called, we know that all CPUs have at least once moved all their
 * stack-based pins into refcounted mode once.
 * This means that any object on the global freelist that is currently
 * referenced from a stack-based pin has either `refcount > 0` or the current
 * sequence number.
 */
static void khp_run_gc(void)
{
	u32 global_head;

	atomic_long_set(&khp_global.global_pending_count, 0);
	global_head = xchg(&khp_global.global_delay_head, KHP_LIST_END);

	/*
	 * We need a stable KHP sequence count for this, but luckily here we
	 * have it guaranteed by KHP_G_GC_SCHEDULED, even if our CPU is not
	 * tracked as active.
	 */
	khp_batch_process(global_head, true);

	clear_bit(KHP_G_GC_SCHEDULED, &khp_global.flags);
}

/*
 * If we haven't already scheduled global freelist processing, schedule it now.
 * Note that at this point, we don't mark the current CPU as ready yet.
 */
static void khp_try_schedule_gc(void)
{
	int cpu;
	int inactive = 0;

	if (test_bit(KHP_G_GC_SCHEDULED, &khp_global.flags))
		return;
	if (test_and_set_bit(KHP_G_GC_SCHEDULED, &khp_global.flags))
		return;
	/* We're in control of the next GC run now. */

	WRITE_ONCE(khp_global.new_seq, khp_global.new_seq + 1);

	atomic_set(&khp_global.num_checkin_cpus, num_possible_cpus());
	for_each_possible_cpu(cpu) {
		if (!khp_set_flag_if_active(cpu, KHP_CPU_CHECKIN_REQUESTED))
			inactive++;
	}
	/* can't drop to zero, current CPU hasn't checked in yet */
	BUG_ON(atomic_sub_and_test(inactive, &khp_global.num_checkin_cpus));
}

/*
 * Entering KHP kernel context.
 * Something like:
 *  - processor comes online
 *  - processor exits idle state
 *  - processor enters the kernel from userspace
 */
void khp_kernel_entry(void)
{
	unsigned long *my_cpu_flags = this_cpu_ptr(&khp_cpu_flags);
	BUG_ON(READ_ONCE(*my_cpu_flags) != 0);
	WRITE_ONCE(*my_cpu_flags, KHP_CPU_ACTIVE);
}

void khp_kernel_exit(void)
{
	u32 local_head;
	u32 cpu_flags;
	unsigned long *my_cpu_flags = this_cpu_ptr(&khp_cpu_flags);

	lockdep_assert_irqs_disabled();

retry:
	/*
	 * Grab the current local_delay_head, and shove the elements elsewhere
	 * depending on their state.
	 */
	local_head = __this_cpu_xchg(khp_local_delay_head, KHP_LIST_END);
	if (local_head != KHP_LIST_END) {
		/* avoid calling into SLUB freeing path with RCU off */
		rcu_irq_enter();
		khp_batch_process(local_head, false);
		rcu_irq_exit();
	}
	/*
	 * We need a stable KHP sequence count while processing items in
	 * khp_batch_process() and adding them to the global queue, so up to
	 * here, we need to keep the KHP_CPU_ACTIVE flag.
	 */

	/* Maybe schedule a new KHP GC run? */
	if (atomic_long_read(&khp_global.global_pending_count) > 100)
		khp_try_schedule_gc(); /* requires us to be KHP_CPU_ACTIVE */

	cpu_flags = xchg(my_cpu_flags, 0);
	BUG_ON((cpu_flags & KHP_CPU_ACTIVE) == 0);

	if (cpu_flags & KHP_CPU_CHECKIN_REQUESTED) {
		if (atomic_dec_and_test(&khp_global.num_checkin_cpus)) {
			/*
			 * We might call into the SLUB freeing path; we
			 * shouldn't do that with KHP off.
			 * Turn KHP back on and retry after we're done with the
			 * global processing.
			 * NOTE: This assumes that the kfree path won't trigger
			 * so many memory-freeing operations in KHP slabs on
			 * each invocation that we loop endlessly through the
			 * retry path. It shouldn't be doing that, though, since
			 * we're in interrupts-off context, where memory
			 * allocation ought to be rare.
			 */
			khp_kernel_entry();
			/* Avoid calling into SLUB freeing path with RCU off. */
			rcu_irq_enter();
			khp_run_gc();
			rcu_irq_exit();
			goto retry;
		}
	}
}

void khp_assert_active(void)
{
	unsigned long *my_cpu_flags = this_cpu_ptr(&khp_cpu_flags);

	BUG_ON((READ_ONCE(*my_cpu_flags) & KHP_CPU_ACTIVE) == 0);
}

#if 0
void khp_free_meta_area(unsigned int start, unsigned int num_entries)
{

}
#endif

/* bit of a hack, but it works for now */
__attribute__((preserve_most)) __attribute__((const))
extern void* __khp_decode_ptr(const void* ptr, void **stack_slot);
EXPORT_SYMBOL(__khp_decode_ptr);

/* Is the pointer the decoded form of a KHP-encoded pointer? */
__attribute__((no_sanitize("kernel")))
bool ptr_is_khp_alias(void *ptr) {
	struct page *page;

	if (is_khp_tagged_ptr((unsigned long)ptr) || !virt_addr_valid(ptr))
		return false;

	page = virt_to_head_page(ptr);

	if (PageSlab(page)) {
		return (page->slab_cache->flags & SLAB_KHP) != 0;
	} else {
		return false;
	}
}

/*
 * This is a dangerous API that should not be used outside core memory
 * management and such.
 * It assumes that @raw_ptr is currently valid, and reconstructs the
 * corresponding fat pointer.
 */
__attribute__((no_sanitize("kernel")))
void *khp_unsafe_rewrap(void *raw_ptr)
{
	unsigned long fat_pointer;
	u32 obj_idx;
	struct khp_meta *meta;
	unsigned long offset;
	u8 extag;

	if (is_khp_tagged_ptr((unsigned long)raw_ptr))
		return raw_ptr;

	obj_idx = khp_idx_by_raw(raw_ptr);
	meta = khp_meta_by_idx(obj_idx);

	/* Figure out whether this is a fallback allocation or a normal one. */
	extag = meta->khp_extag;
	if ((extag & KHP_ETT_MASK) == KHP_ETT_QUEUED) {
		/* must be using a fallback */
		BUG_ON((extag & KHP_EXTAG_RELEASED) == 0);
		BUG_ON(meta->alloc_cpu >= nr_cpumask_bits);
		obj_idx = meta->fb_idx;
		meta = khp_meta_by_idx(obj_idx);
	} else {
		BUG_ON((extag & KHP_ETT_MASK) != KHP_ETT_ALLOC);
	}

	offset = (unsigned long)raw_ptr - (unsigned long)meta->khp_raw_ptr;
	BUG_ON(offset > 0xffff);

	fat_pointer = (unsigned long)(obj_idx + 0x40000000UL) << 32;
	fat_pointer |= (unsigned long)READ_ONCE(meta->khp_cookie) << 16;
	//fat_pointer |= ((unsigned long)raw_ptr) & 0xffff;
	fat_pointer |= offset;
	//pr_warn("khp_unsafe_rewrap(0x%lx) = 0x%lx\n", (unsigned long)raw_ptr, fat_pointer);
	return (void*)fat_pointer;
}
