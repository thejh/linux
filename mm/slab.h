/* SPDX-License-Identifier: GPL-2.0 */
#ifndef MM_SLAB_H
#define MM_SLAB_H

#include <linux/reciprocal_div.h>
#include <linux/list_lru.h>
#include <linux/local_lock.h>
#include <linux/random.h>
#include <linux/kobject.h>
#include <linux/sched/mm.h>
#include <linux/memcontrol.h>
#include <linux/kfence.h>
#include <linux/kasan.h>
#include <linux/bug.h>
#include <linux/slab.h>

/*
 * Internal slab definitions
 */

/* slab's alloc_flags definitions */
#define SLAB_ALLOC_DEFAULT	0x00 /* no flags */
#define SLAB_ALLOC_NOLOCK	0x01 /* a kmalloc_nolock() allocation */
#define SLAB_ALLOC_NEW_SLAB	0x02 /* a flag for alloc_slab_obj_exts() */
#define SLAB_ALLOC_NO_RECURSE	0x04 /* prevent kmalloc() recursion */
#define SLAB_ALLOC_NO_OBJ_EXT	0x08 /* prevent obj_exts array allocation */

static inline bool alloc_flags_allow_spinning(const unsigned int alloc_flags)
{
	return !(alloc_flags & SLAB_ALLOC_NOLOCK);
}

void *__kmalloc_flags_noprof(DECL_TOKEN_PARAMS(size, token), gfp_t flags,
				  unsigned int alloc_flags, int node)
				  __assume_kmalloc_alignment __alloc_size(1);

static __always_inline __alloc_size(1) void *_kmalloc_flags_noprof(size_t size,
		gfp_t flags, unsigned int alloc_flags, int node, kmalloc_token_t token)
{
	return __kmalloc_flags_noprof(PASS_TOKEN_PARAMS(size, token), flags, alloc_flags, node);
}
#define kmalloc_flags_noprof(...)	_kmalloc_flags_noprof(__VA_ARGS__, __kmalloc_token(__VA_ARGS__))
#define kmalloc_flags(...)		alloc_hooks(kmalloc_flags_noprof(__VA_ARGS__))

#ifdef CONFIG_64BIT
# ifdef system_has_cmpxchg128
# define system_has_freelist_aba()	system_has_cmpxchg128()
# define try_cmpxchg_freelist		try_cmpxchg128
# endif
typedef u128 freelist_full_t;
#else /* CONFIG_64BIT */
# ifdef system_has_cmpxchg64
# define system_has_freelist_aba()	system_has_cmpxchg64()
# define try_cmpxchg_freelist		try_cmpxchg64
# endif
typedef u64 freelist_full_t;
#endif /* CONFIG_64BIT */

#if defined(system_has_freelist_aba) && !defined(CONFIG_HAVE_ALIGNED_STRUCT_PAGE)
#undef system_has_freelist_aba
#endif

/*
 * Freelist pointer and counter to cmpxchg together, avoids the typical ABA
 * problems with cmpxchg of just a pointer.
 */
struct freelist_counters {
	union {
		struct {
			void *freelist;
			union {
				unsigned long counters;
				struct {
					unsigned inuse:16;
					unsigned objects:15;
					/*
					 * If slab debugging is enabled then the
					 * frozen bit can be reused to indicate
					 * that the slab was corrupted
					 */
					unsigned frozen:1;
#ifdef CONFIG_64BIT
					/*
					 * Some optimizations use free bits in 'counters' field
					 * to save memory. In case ->stride field is not available,
					 * such optimizations are disabled.
					 */
					unsigned int stride;
#endif
				};
			};
		};
#ifdef system_has_freelist_aba
		freelist_full_t freelist_counters;
#endif
	};
};

/*
 * Word size structure that can be atomically updated or read and that
 * contains both the order and the number of objects that a slab of the
 * given order would contain.
 */
struct kmem_cache_order_objects {
	unsigned int x;
};

#define OO_SHIFT	16
#define OO_MASK		((1 << OO_SHIFT) - 1)

static inline unsigned int oo_order(struct kmem_cache_order_objects x)
{
	return x.x >> OO_SHIFT;
}

static inline unsigned int oo_objects(struct kmem_cache_order_objects x)
{
	return x.x & OO_MASK;
}

/* Reuses the bits in struct page */
struct slab {
	memdesc_flags_t flags;

#ifdef CONFIG_SLAB_VIRTUAL
	/*
	 * Used by virt_to_slab to find the actual struct slab for a slab that
	 * spans multiple pages.
	 */
	struct slab *compound_slab_head;

	/*
	 * Pointer to the folio that the objects are allocated from, or NULL if
	 * the slab is currently unused and no physical memory is allocated to
	 * it. Protected by slub_kworker_lock.
	 */
	struct folio *backing_folio;

	struct kmem_cache_order_objects oo;

	struct list_head flush_list_elem;

	/* Replaces the page lock */
	spinlock_t slab_lock;
#endif

	struct kmem_cache *slab_cache;
	union {
		struct {
			struct list_head slab_list;
			/* Double-word boundary */
			struct freelist_counters;
		};
		struct rcu_head rcu_head;
	};

#ifndef CONFIG_SLAB_VIRTUAL
	unsigned int __page_type;
	atomic_t __page_refcount;
#endif
#ifdef CONFIG_SLAB_OBJ_EXT
	unsigned long obj_exts;
#endif
};

#ifndef CONFIG_SLAB_VIRTUAL
#define SLAB_MATCH(pg, sl)						\
	static_assert(offsetof(struct page, pg) == offsetof(struct slab, sl))
SLAB_MATCH(flags, flags);
SLAB_MATCH(compound_info, slab_cache);	/* Ensure bit 0 is clear */
SLAB_MATCH(_refcount, __page_refcount);
#ifdef CONFIG_MEMCG
SLAB_MATCH(memcg_data, obj_exts);
#elif defined(CONFIG_SLAB_OBJ_EXT)
SLAB_MATCH(_unused_slab_obj_exts, obj_exts);
#endif
#undef SLAB_MATCH
static_assert(sizeof(struct slab) <= sizeof(struct page));
#if defined(system_has_freelist_aba)
static_assert(IS_ALIGNED(offsetof(struct slab, freelist), sizeof(struct freelist_counters)));
#endif
#else /* CONFIG_SLAB_VIRTUAL */
static_assert(sizeof(struct slab) <= STRUCT_SLAB_SIZE);
#endif /* CONFIG_SLAB_VIRTUAL */

/**
 * slab_folio - The folio allocated for a slab
 * @s: The slab.
 *
 * Slabs are allocated as folios that contain the individual objects and are
 * using some fields in the first struct page of the folio - those fields are
 * now accessed by struct slab. It is occasionally necessary to convert back to
 * a folio in order to communicate with the rest of the mm.  Please use this
 * helper function instead of casting yourself, as the implementation may change
 * in the future.
 */
#ifndef CONFIG_SLAB_VIRTUAL
#define slab_folio(s)		(_Generic((s),				\
	const struct slab *:	(const struct folio *)s,		\
	struct slab *:		(struct folio *)s))
#else
#define slab_folio(s) ((s)->backing_folio)
#define folio_slab(folio) NULL
static inline void *slab_to_virt(const struct slab *s);
#endif /* CONFIG_SLAB_VIRTUAL */

/**
 * page_slab - Converts from struct page to its slab.
 * @page: A page which may or may not belong to a slab.
 *
 * Return: The slab which contains this page or NULL if the page does
 * not belong to a slab.  This includes pages returned from large kmalloc.
 */
static inline struct slab *page_slab(const struct page *page)
{
	page = compound_head(page);
	if (data_race(page->page_type >> 24) != PGTY_slab)
		page = NULL;

	return (struct slab *)page;
}

/**
 * slab_page - The first struct page allocated for a slab
 * @s: The slab.
 *
 * A convenience wrapper for converting slab to the first struct page of the
 * underlying folio, to communicate with code not yet converted to folio or
 * struct slab.
 */
#define slab_page(s) folio_page(slab_folio(s), 0)

/**
 * is_slab_page - Checks if a page is really a slab page
 * @s: The slab
 *
 * Checks if s points to a slab page.
 *
 * Return: true if s points to a slab and false otherwise.
 */
#ifndef CONFIG_SLAB_VIRTUAL
#define is_slab_page(s) folio_test_slab(slab_folio(s))
#else
#define is_slab_page(s) is_slab_meta(s)
#endif /* CONFIG_SLAB_VIRTUAL */

static inline void *slab_address(const struct slab *slab)
{
#ifdef CONFIG_SLAB_VIRTUAL
	return slab_to_virt(slab);
#else
	return folio_address(slab_folio(slab));
#endif
}

static inline int slab_nid(const struct slab *slab)
{
#ifdef CONFIG_SLAB_VIRTUAL
	return folio_nid(slab_folio(slab));
#else
	return memdesc_nid(slab->flags);
#endif
}

static inline pg_data_t *slab_pgdat(const struct slab *slab)
{
	return NODE_DATA(slab_nid(slab));
}

#ifdef CONFIG_SLAB_VIRTUAL
/*
 * Internal helper. Returns the address of the struct slab corresponding to
 * the virtual memory page containing kaddr. This does a simple arithmetic
 * mapping and does *not* return the struct slab of the head page!
 */
static inline unsigned long virt_to_slab_raw(unsigned long addr)
{
	VM_WARN_ON(!is_slab_addr(addr));
	return SLAB_BASE_ADDR +
		((addr - SLAB_DATA_BASE_ADDR) / PAGE_SIZE * sizeof(struct slab));
}

static inline struct slab *virt_to_slab(const void *addr)
{
	struct slab *slab, *slab_head;

	if (!is_slab_addr(addr))
		return NULL;

	slab = (struct slab *)virt_to_slab_raw((unsigned long)addr);
	slab_head = slab->compound_slab_head;

	if (CHECK_DATA_CORRUPTION(!is_slab_meta(slab_head), slab_head,
		"compound slab head out of meta range: %p", slab_head))
		return NULL;

	return slab_head;
}

static inline void *slab_to_virt(const struct slab *s)
{
	unsigned long slab_idx;
	bool unaligned_slab =
		((unsigned long)s - SLAB_BASE_ADDR) % sizeof(*s) != 0;

	if (CHECK_DATA_CORRUPTION(!is_slab_meta(s), (void *)s, "slab not in meta range") ||
	    CHECK_DATA_CORRUPTION(unaligned_slab, (void *)s, "unaligned slab pointer") ||
	    CHECK_DATA_CORRUPTION(s->compound_slab_head != s, (void *)s,
			"%s called on non-head slab", __func__))
		return NULL;

	slab_idx = ((unsigned long)s - SLAB_BASE_ADDR) / sizeof(*s);
	return (void *)(SLAB_DATA_BASE_ADDR + PAGE_SIZE * slab_idx);
}
#else
static inline struct slab *virt_to_slab(const void *addr)
{
	return page_slab(virt_to_page(addr));
}
#endif /* CONFIG_SLAB_VIRTUAL */

static inline int slab_order(const struct slab *slab)
{
	return folio_order(slab_folio(slab));
}

static inline size_t slab_size(const struct slab *slab)
{
	return PAGE_SIZE << slab_order(slab);
}

struct kmem_cache_per_node_ptrs {
	struct node_barn *barn;
	struct kmem_cache_node *node;
};

/*
 * Slab cache management.
 */
struct kmem_cache_virtual {
#ifdef CONFIG_SLAB_VIRTUAL
	/* Protects freed_slabs, freed_slabs_min, and nr_freed_pages */
	spinlock_t freed_slabs_lock;
	/*
	 * Slabs on this list have virtual memory of size oo allocated to them
	 * but no physical memory
	 */
	struct list_head freed_slabs;
	/* Same as freed_slabs but with memory of size min */
	struct list_head freed_slabs_min;
	/* Number of slab pages which got freed */
	unsigned long nr_freed_pages;
#endif
};

struct kmem_cache {
	struct slub_percpu_sheaves __percpu *cpu_sheaves;
	/* Used for retrieving partial slabs, etc. */
	slab_flags_t flags;
	unsigned long min_partial;
	unsigned int size;		/* Object size including metadata */
	unsigned int object_size;	/* Object size without metadata */
	struct reciprocal_value reciprocal_size;
	unsigned int offset;		/* Free pointer offset */
	unsigned int sheaf_capacity;
	struct kmem_cache_order_objects oo;

	/* Allocation and freeing of slabs */
	struct kmem_cache_order_objects min;
	struct kmem_cache_virtual virtual;
	gfp_t allocflags;		/* gfp flags to use on each alloc */
	int refcount;			/* Refcount for slab cache destroy */
	void (*ctor)(void *object);	/* Object constructor */
	unsigned int inuse;		/* Offset to metadata */
	unsigned int align;		/* Alignment */
	unsigned int red_left_pad;	/* Left redzone padding size */
	const char *name;		/* Name (only for display!) */
	struct list_head list;		/* List of slab caches */
#ifdef CONFIG_SYSFS
	struct kobject kobj;		/* For sysfs */
#endif
#ifdef CONFIG_SLAB_FREELIST_HARDENED
	unsigned long random;
#endif

#ifdef CONFIG_NUMA
	/*
	 * Defragmentation by allocating from a remote node.
	 */
	unsigned int remote_node_defrag_ratio;
#endif

#ifdef CONFIG_SLAB_FREELIST_RANDOM
	unsigned int *random_seq;
#endif

#ifdef CONFIG_KASAN_GENERIC
	struct kasan_cache kasan_info;
#endif

#ifdef CONFIG_HARDENED_USERCOPY
	unsigned int useroffset;	/* Usercopy region offset */
	unsigned int usersize;		/* Usercopy region size */
#endif

#ifdef CONFIG_SLUB_STATS
	struct kmem_cache_stats __percpu *cpu_stats;
#endif

	struct kmem_cache_per_node_ptrs per_node[MAX_NUMNODES];
};

/*
 * Every cache has !NULL s->cpu_sheaves but they may point to the
 * bootstrap_sheaf temporarily during init, or permanently for the boot caches
 * and caches with debugging enabled, or all caches with CONFIG_SLUB_TINY. This
 * helper distinguishes whether cache has real non-bootstrap sheaves.
 */
static inline bool cache_has_sheaves(struct kmem_cache *s)
{
	/* Test CONFIG_SLUB_TINY for code elimination purposes */
	return !IS_ENABLED(CONFIG_SLUB_TINY) && s->sheaf_capacity;
}

#if defined(CONFIG_SYSFS) && !defined(CONFIG_SLUB_TINY)
#define SLAB_SUPPORTS_SYSFS 1
void sysfs_slab_unlink(struct kmem_cache *s);
void sysfs_slab_release(struct kmem_cache *s);
int sysfs_slab_alias(struct kmem_cache *s, const char *name);
#else
static inline void sysfs_slab_unlink(struct kmem_cache *s) { }
static inline void sysfs_slab_release(struct kmem_cache *s) { }
static inline int sysfs_slab_alias(struct kmem_cache *s, const char *name)
							{ return 0; }
#endif

void *fixup_red_left(struct kmem_cache *s, void *p);

static inline void *nearest_obj(struct kmem_cache *cache,
				const struct slab *slab, void *x)
{
	void *object = x - (x - slab_address(slab)) % cache->size;
	void *last_object = slab_address(slab) +
		(slab->objects - 1) * cache->size;
	void *result = (unlikely(object > last_object)) ? last_object : object;

	result = fixup_red_left(cache, result);
	return result;
}

/* Determine object index from a given position */
static inline unsigned int __obj_to_index(const struct kmem_cache *cache,
					  void *addr, const void *obj)
{
	return reciprocal_divide(kasan_reset_tag(obj) - addr,
				 cache->reciprocal_size);
}

static inline unsigned int obj_to_index(const struct kmem_cache *cache,
					const struct slab *slab, const void *obj)
{
	if (is_kfence_address(obj))
		return 0;
	return __obj_to_index(cache, slab_address(slab), obj);
}

static inline int objs_per_slab(const struct kmem_cache *cache,
				const struct slab *slab)
{
	return slab->objects;
}

/*
 * State of the slab allocator.
 *
 * This is used to describe the states of the allocator during bootup.
 * Allocators use this to gradually bootstrap themselves. Most allocators
 * have the problem that the structures used for managing slab caches are
 * allocated from slab caches themselves.
 */
enum slab_state {
	DOWN,			/* No slab functionality yet */
	PARTIAL,		/* SLUB: kmem_cache_node available */
	UP,			/* Slab caches usable but not all extras yet */
	FULL			/* Everything is working */
};

extern enum slab_state slab_state;

/* The slab cache mutex protects the management structures during changes */
extern struct mutex slab_mutex;

/* The list of all slab caches on the system */
extern struct list_head slab_caches;

/* The slab cache that manages slab cache information */
extern struct kmem_cache *kmem_cache;

/* A table of kmalloc cache names and sizes */
extern const struct kmalloc_info_struct {
	const char *name[NR_KMALLOC_TYPES];
	unsigned int size;
} kmalloc_info[];

/* Kmalloc array related functions */
void setup_kmalloc_cache_index_table(void);
void create_kmalloc_caches(void);

extern u8 kmalloc_size_index[24];

static inline unsigned int size_index_elem(unsigned int bytes)
{
	return (bytes - 1) / 8;
}

/*
 * Find the kmem_cache structure that serves a given size of
 * allocation
 *
 * This assumes size is larger than zero and not larger than
 * KMALLOC_MAX_CACHE_SIZE and the caller must check that.
 */
static inline struct kmem_cache *
kmalloc_slab(size_t size, kmem_buckets *b, gfp_t flags, kmalloc_token_t token,
	     unsigned int alloc_flags)
{
	unsigned int index;
	enum kmalloc_cache_type type = kmalloc_type(flags, token);

	if (alloc_flags & SLAB_ALLOC_NO_OBJ_EXT)
		type = KMALLOC_NO_OBJ_EXT;

	if (!b)
		b = &kmalloc_caches[type];
	if (size <= 192)
		index = kmalloc_size_index[size_index_elem(size)];
	else
		index = fls(size - 1);

	return (*b)[index];
}

gfp_t kmalloc_fix_flags(gfp_t flags);

/* Functions provided by the slab allocators */
int do_kmem_cache_create(struct kmem_cache *s, const char *name,
			 unsigned int size, struct kmem_cache_args *args,
			 slab_flags_t flags);

void __init kmem_cache_init(void);
extern void create_boot_cache(struct kmem_cache *, const char *name,
			unsigned int size, slab_flags_t flags,
			unsigned int useroffset, unsigned int usersize);

int slab_unmergeable(struct kmem_cache *s);
bool slab_args_unmergeable(struct kmem_cache_args *args, slab_flags_t flags);

slab_flags_t kmem_cache_flags(slab_flags_t flags, const char *name);

static inline bool is_kmalloc_cache(struct kmem_cache *s)
{
	return (s->flags & SLAB_KMALLOC);
}

static inline bool is_kmalloc_normal(struct kmem_cache *s)
{
	if (!is_kmalloc_cache(s))
		return false;

	return !(s->flags & (SLAB_CACHE_DMA|SLAB_ACCOUNT|SLAB_RECLAIM_ACCOUNT|SLAB_NO_OBJ_EXT));
}

bool __kfree_rcu_sheaf(struct kmem_cache *s, void *obj);
void flush_all_rcu_sheaves(void);
void flush_rcu_sheaves_on_cache(struct kmem_cache *s);

#define SLAB_CORE_FLAGS (SLAB_HWCACHE_ALIGN | SLAB_CACHE_DMA | \
			 SLAB_CACHE_DMA32 | SLAB_PANIC | \
			 SLAB_TYPESAFE_BY_RCU | SLAB_DEBUG_OBJECTS | \
			 SLAB_NOLEAKTRACE | SLAB_RECLAIM_ACCOUNT | \
			 SLAB_TEMPORARY | SLAB_ACCOUNT | \
			 SLAB_NO_USER_FLAGS | SLAB_KMALLOC | SLAB_NO_MERGE)

#define SLAB_DEBUG_FLAGS (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER | \
			  SLAB_TRACE | SLAB_CONSISTENCY_CHECKS)

#define SLAB_FLAGS_PERMITTED (SLAB_CORE_FLAGS | SLAB_DEBUG_FLAGS)

bool __kmem_cache_empty(struct kmem_cache *);
int __kmem_cache_shutdown(struct kmem_cache *);
void __kmem_cache_release(struct kmem_cache *);
int __kmem_cache_shrink(struct kmem_cache *);
void slab_kmem_cache_release(struct kmem_cache *);

struct seq_file;
struct file;

struct slabinfo {
	unsigned long active_objs;
	unsigned long num_objs;
	unsigned long active_slabs;
	unsigned long num_slabs;
	unsigned long shared_avail;
	unsigned int limit;
	unsigned int batchcount;
	unsigned int shared;
	unsigned int objects_per_slab;
	unsigned int cache_order;
};

void get_slabinfo(struct kmem_cache *s, struct slabinfo *sinfo);

#ifdef CONFIG_SLUB_DEBUG
#ifdef CONFIG_SLUB_DEBUG_ON
DECLARE_STATIC_KEY_TRUE(slub_debug_enabled);
#else
DECLARE_STATIC_KEY_FALSE(slub_debug_enabled);
#endif
extern void print_tracking(struct kmem_cache *s, void *object);
long validate_slab_cache(struct kmem_cache *s);
static inline bool __slub_debug_enabled(void)
{
	return static_branch_unlikely(&slub_debug_enabled);
}
#else
static inline void print_tracking(struct kmem_cache *s, void *object)
{
}
static inline bool __slub_debug_enabled(void)
{
	return false;
}
#endif

/*
 * Returns true if any of the specified slab_debug flags is enabled for the
 * cache. Use only for flags parsed by setup_slub_debug() as it also enables
 * the static key.
 */
static inline bool kmem_cache_debug_flags(struct kmem_cache *s, slab_flags_t flags)
{
	if (IS_ENABLED(CONFIG_SLUB_DEBUG))
		VM_WARN_ON_ONCE(!(flags & SLAB_DEBUG_FLAGS));
	if (__slub_debug_enabled())
		return s->flags & flags;
	return false;
}

#if IS_ENABLED(CONFIG_SLUB_DEBUG) && IS_ENABLED(CONFIG_KUNIT)
bool slab_in_kunit_test(void);
#else
static inline bool slab_in_kunit_test(void) { return false; }
#endif

/*
 * slub is about to manipulate internal object metadata.  This memory lies
 * outside the range of the allocated object, so accessing it would normally
 * be reported by kasan as a bounds error.  metadata_access_enable() is used
 * to tell kasan that these accesses are OK.
 */
static inline void metadata_access_enable(void)
{
	kasan_disable_current();
	kmsan_disable_current();
}

static inline void metadata_access_disable(void)
{
	kmsan_enable_current();
	kasan_enable_current();
}

/*
 * Return true if KMALLOC_NORMAL caches may need obj_exts arrays.
 *
 * Memory allocation profiling requires obj_exts for all caches.
 * Memcg usually doesn't need them for normal kmalloc caches, but kmalloc types
 * with a priority higher than KMALLOC_CGROUP can be aliased with KMALLOC_NORMAL.
 */
static inline bool need_kmalloc_no_objext(void)
{
	if (!mem_alloc_profiling_permanently_disabled())
		return true;

	if (!mem_cgroup_kmem_disabled() &&
			(KMALLOC_NORMAL == KMALLOC_RECLAIM))
		return true;

	return false;
}

#ifdef CONFIG_SLAB_OBJ_EXT

/*
 * slab_obj_exts - get the pointer to the slab object extension vector
 * associated with a slab.
 * @slab: a pointer to the slab struct
 *
 * Returns the address of the object extension vector associated with the slab,
 * or zero if no such vector has been associated yet.
 * Do not dereference the return value directly; use get/put_slab_obj_exts()
 * pair and slab_obj_ext() to access individual elements.
 *
 * Example usage:
 *
 * obj_exts = slab_obj_exts(slab);
 * if (obj_exts) {
 *         get_slab_obj_exts(obj_exts);
 *         obj_ext = slab_obj_ext(slab, obj_exts, obj_to_index(s, slab, obj));
 *         // do something with obj_ext
 *         put_slab_obj_exts(obj_exts);
 * }
 *
 * Note that the get/put semantics does not involve reference counting.
 * Instead, it updates kasan/kmsan depth so that accesses to slabobj_ext
 * won't be reported as access violations.
 */
static inline unsigned long slab_obj_exts(struct slab *slab)
{
	unsigned long obj_exts = READ_ONCE(slab->obj_exts);

#ifdef CONFIG_MEMCG
	/*
	 * obj_exts should be either NULL, a valid pointer with
	 * MEMCG_DATA_OBJEXTS bit set or be equal to OBJEXTS_ALLOC_FAIL.
	 */
	VM_BUG_ON_PAGE(obj_exts && !(obj_exts & MEMCG_DATA_OBJEXTS) &&
		       obj_exts != OBJEXTS_ALLOC_FAIL, slab_page(slab));
	VM_BUG_ON_PAGE(obj_exts & MEMCG_DATA_KMEM, slab_page(slab));
#endif

	return obj_exts & ~OBJEXTS_FLAGS_MASK;
}

static inline void get_slab_obj_exts(unsigned long obj_exts)
{
	VM_WARN_ON_ONCE(!obj_exts);
	metadata_access_enable();
}

static inline void put_slab_obj_exts(unsigned long obj_exts)
{
	metadata_access_disable();
}

#ifdef CONFIG_64BIT
static inline void slab_set_stride(struct slab *slab, unsigned int stride)
{
	slab->stride = stride;
}
static inline unsigned int slab_get_stride(struct slab *slab)
{
	return slab->stride;
}
#else
static inline void slab_set_stride(struct slab *slab, unsigned int stride)
{
	VM_WARN_ON_ONCE(stride != sizeof(struct slabobj_ext));
}
static inline unsigned int slab_get_stride(struct slab *slab)
{
	return sizeof(struct slabobj_ext);
}
#endif

/*
 * slab_obj_ext - get the pointer to the slab object extension metadata
 * associated with an object in a slab.
 * @slab: a pointer to the slab struct
 * @obj_exts: a pointer to the object extension vector
 * @index: an index of the object
 *
 * Returns a pointer to the object extension associated with the object.
 * Must be called within a section covered by get/put_slab_obj_exts().
 */
static inline struct slabobj_ext *slab_obj_ext(struct slab *slab,
					       unsigned long obj_exts,
					       unsigned int index)
{
	struct slabobj_ext *obj_ext;

	VM_WARN_ON_ONCE(obj_exts != slab_obj_exts(slab));

	obj_ext = (struct slabobj_ext *)(obj_exts +
					 slab_get_stride(slab) * index);
	return kasan_reset_tag(obj_ext);
}

int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
			gfp_t gfp, unsigned int alloc_flags);

#else /* CONFIG_SLAB_OBJ_EXT */

static inline unsigned long slab_obj_exts(struct slab *slab)
{
	return 0;
}

static inline struct slabobj_ext *slab_obj_ext(struct slab *slab,
					       unsigned long obj_exts,
					       unsigned int index)
{
	return NULL;
}

static inline void slab_set_stride(struct slab *slab, unsigned int stride) { }
static inline unsigned int slab_get_stride(struct slab *slab) { return 0; }


#endif /* CONFIG_SLAB_OBJ_EXT */

static inline enum node_stat_item cache_vmstat_idx(struct kmem_cache *s)
{
	return (s->flags & SLAB_RECLAIM_ACCOUNT) ?
		NR_SLAB_RECLAIMABLE_B : NR_SLAB_UNRECLAIMABLE_B;
}

#ifdef CONFIG_MEMCG
bool __memcg_slab_post_alloc_hook(struct kmem_cache *s, struct list_lru *lru,
				  gfp_t flags, unsigned int slab_alloc_flags,
				  size_t size, void **p);
void __memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
			    void **p, int objects, unsigned long obj_exts);
#endif

void kvfree_rcu_cb(struct rcu_head *head);

static inline unsigned int large_kmalloc_order(const struct page *page)
{
	return page[1].flags.f & 0xff;
}

static inline size_t large_kmalloc_size(const struct page *page)
{
	return PAGE_SIZE << large_kmalloc_order(page);
}

#ifdef CONFIG_SLUB_DEBUG
void dump_unreclaimable_slab(void);
#else
static inline void dump_unreclaimable_slab(void)
{
}
#endif

void ___cache_free(struct kmem_cache *cache, void *x, unsigned long addr);

#ifdef CONFIG_SLAB_FREELIST_RANDOM
int cache_random_seq_create(struct kmem_cache *cachep, unsigned int count,
			gfp_t gfp);
void cache_random_seq_destroy(struct kmem_cache *cachep);
#else
static inline int cache_random_seq_create(struct kmem_cache *cachep,
					unsigned int count, gfp_t gfp)
{
	return 0;
}
static inline void cache_random_seq_destroy(struct kmem_cache *cachep) { }
#endif /* CONFIG_SLAB_FREELIST_RANDOM */

static inline bool slab_want_init_on_alloc(gfp_t flags, struct kmem_cache *c)
{
	if (static_branch_maybe(CONFIG_INIT_ON_ALLOC_DEFAULT_ON,
				&init_on_alloc)) {
		if (c->ctor)
			return false;
		if (c->flags & (SLAB_TYPESAFE_BY_RCU | SLAB_POISON))
			return flags & __GFP_ZERO;
		return true;
	}
	return flags & __GFP_ZERO;
}

static inline bool slab_want_init_on_free(struct kmem_cache *c)
{
	if (static_branch_maybe(CONFIG_INIT_ON_FREE_DEFAULT_ON,
				&init_on_free))
		return !(c->ctor ||
			 (c->flags & (SLAB_TYPESAFE_BY_RCU | SLAB_POISON)));
	return false;
}

#if defined(CONFIG_DEBUG_FS) && defined(CONFIG_SLUB_DEBUG)
void debugfs_slab_release(struct kmem_cache *);
#else
static inline void debugfs_slab_release(struct kmem_cache *s) { }
#endif

#ifdef CONFIG_PRINTK
#define KS_ADDRS_COUNT 16
struct kmem_obj_info {
	void *kp_ptr;
	struct slab *kp_slab;
	void *kp_objp;
	unsigned long kp_data_offset;
	struct kmem_cache *kp_slab_cache;
	void *kp_ret;
	void *kp_stack[KS_ADDRS_COUNT];
	void *kp_free_stack[KS_ADDRS_COUNT];
};
void __kmem_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *slab);
#endif

void __check_heap_object(const void *ptr, unsigned long n,
			 const struct slab *slab, bool to_user);

void defer_free_barrier(void);

static inline bool slub_debug_orig_size(struct kmem_cache *s)
{
	return (kmem_cache_debug_flags(s, SLAB_STORE_USER) &&
			(s->flags & SLAB_KMALLOC));
}

#ifdef CONFIG_SLUB_DEBUG
void skip_orig_size_check(struct kmem_cache *s, const void *object);
#endif

#endif /* MM_SLAB_H */
