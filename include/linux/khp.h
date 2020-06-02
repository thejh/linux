#ifndef _LINUX_KHP_H
#define _LINUX_KHP_H

#include <asm-generic/khp.h>

#ifdef CONFIG_KHP

struct task_struct;
struct kmem_cache;

/* in task->khp_flags */
/* set on migration, cleared on next sched-in */
#define KHP_MIGRATED_BIT 0L

#define KHP_LIST_END 0xffffffffU

#include <linux/types.h>

#define KHP_IDENTIFIERS_PER_REGION (1<<30)
#define KHP_REGION_SIZE (sizeof(struct khp_meta) * KHP_IDENTIFIERS_PER_REGION)
#define KHP_META_AREA_SIZE (KHP_REGION_SIZE * 2)

extern struct khp_meta *khp_region_start;

struct khp_region {
	/* constant after init */
	struct khp_meta *start;
	u32 start_idx;
	/* written under khp_alloc_lock, read locklessly */
	struct khp_meta *used_end;
	/* protected by khp_alloc_lock */
	struct khp_meta *alloc_end;
};
extern struct khp_region khp_orig_region;
extern struct khp_region khp_fallback_region;

void khp_init(void);
void arch_khp_init(void);
s64 khp_alloc_normal_area(unsigned int num_entries, int gfp_flags);

/* for allocator integration */
void *khp_init_alloc(int cpu, unsigned int khp_index, void *raw_ptr,
		     int gfp_flags);
void *khp_release_alloc(void *ptr);
void khp_push_external_freelist(unsigned int obj_idx, unsigned int nr,
				unsigned int *head);
unsigned int khp_pop_external_freelist(unsigned int *head, unsigned int nr);
void khp_mark_free(struct kmem_cache *s, void *ptr);

/* for arch stack walking code */
void khp_refcount_inc(struct khp_meta *meta);
void khp_refcount_dec(struct khp_meta *meta, bool freeing, u16 expected_cookie);

bool ptr_is_khp_alias(void *ptr);
void *khp_unsafe_rewrap(void *raw_ptr);

/* implemented in arch code */
void khp_stack_scan(struct task_struct *task, int direction);

/* for the scheduler */
void khp_migrate(struct task_struct *t);
void khp_assert_active(void);

/* context tracking */
void khp_kernel_entry(void);
void khp_kernel_exit(void);

void khp_non_canonical_hook(unsigned long addr);

#else // CONFIG_KHP

static inline void khp_init(void) {}
static inline void khp_stack_scan(struct task_struct *task, int direction) { }
static inline bool ptr_is_khp_alias(void *ptr) { return false; }

static inline void *khp_unsafe_rewrap(void *raw_ptr) { return raw_ptr; }

static inline void khp_migrate(struct task_struct *t) {}
static inline void khp_assert_active(void) {}

static inline void khp_kernel_entry(void) {}
static inline void khp_kernel_exit(void) {}

static inline void khp_non_canonical_hook(unsigned long addr) { }

#endif // defined(CONFIG_KHP)

#endif // _LINUX_KHP_H
