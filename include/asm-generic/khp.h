#ifndef _ASM_GENERIC_KHP_H
#define _ASM_GENERIC_KHP_H

#ifdef CONFIG_KHP
/*
 * A khp_meta struct can be in a few different states:
 *  - allocated: the corresponding heap object may be accessed legitimately
 *  - floating: refcount-delayed - after-free references still exist from
 *    inactive tasks and may exist from active tasks
 *  - queued: waiting for a local scan or a global scan
 *  - depleted original: we forward everything to another metadata slot in the
 *    fallback area
 *  - free-orig: the corresponding heap object is protected from UAF; the object
 *    may be reallocated, and the object ID may also be reassociated with a
 *    different physical address
 *  - free-fb: queued on a percpu freelist of fallback allocations
 *  - cached: a free heap object references this fallback allocation
 *
 * In all states other than "allocated", the two high bits of the extag are set
 * such that access checks against the object can never succeed.
 * The khp_cookie must be preserved in all states.
 *
 * `allocated` state uses one layout, all other states share a different layout.
 * The object not having been freed yet is counted towards the refcount.
 * An object may repeatedly move back and forth between `refcount-delayed` and
 * `scan-delayed` state if a task is repeatedly scheduled out.
 *
 * Note that this structure is designed for little-endian.
 */
struct khp_meta {
	union {
		struct {
			/*
			 * first 8 bytes
			 */
			union {
				/* allocated: pointer to heap object */
				void *khp_raw_ptr;

				/* queued/floating/free-fb */
				struct {
					/*
					 * queued: forward pointer in local or
					 *         global delayed freeing list
					 * floating: unused
					 * free-fb: next free
					 */
					unsigned int khp_next;
					union {
						/* queued/floating */
						unsigned int khp_raw_phys_low32;
					};
				};

				/* depleted/free-orig */
				struct {
					/* either a meta idx or KHP_LIST_END */
					union {
						/*
						 * when meta range is not
						 * associated with memory, on
						 * SLUB-managed freelist:
						 * next freelist element.
						 */
						unsigned int extern_free_next;
						/*
						 * else: associated fallback
						 */
						unsigned int fb_idx;
					};
					u16 alloc_cpu;
					/*
					 * when meta range is not associated
					 * with memory: freelist element size
					 */
					u16 extern_free_size;
				};
			};

			/* next 4 bytes */
			u16 khp_raw_phys_high16; /* queued/floating */
			u16 khp_cookie; /* any state */

			/* last 4 bytes */
			struct khp_layout_and_refcount {
				/*
				 * any state:
				 * Just a simple 16-bit saturating refcount for
				 * now.
				 * NOTE: The refcount can be elevated even when
				 * the allocation is free.
				 */
				u16 khp_refcount;
				struct khp_extag_and_cpu {
					#define KHP_CPU_MASK_INV_GLOBAL 0U
					u8 khp_cpu_mask_inv;

					/* high 2 bits of khp_extag (type): */
					#define KHP_ETT_MASK     0xc0
					/* 00: delayed-layout, queued or free */
					#define KHP_ETT_QUEUED   0x00
					/* 01: KHP normal, allocated */
					#define KHP_ETT_ALLOC    0x40
					/* 10: KHP fallback, allocated */
					#define KHP_ETT_ALLOC_FB 0x80
					/* 11: delayed-layout, unqueued */
					#define KHP_ETT_FLOATING 0xc0

					/* only valid if TYPE_QUEUED: */
					#define KHP_SEQ_MASK 0x3
					#define KHP_EXTAG_GLOBAL_QUEUE 0x4
					/*
					 * if TYPE_QUEUED: memory has been
					 * released to allocator
					 */
					#define KHP_EXTAG_RELEASED 0x8

					u8 khp_extag_;
				} etac;
			} lar;
		};
		unsigned long halves[2];
	};
};
#define khp_extag lar.etac.khp_extag_

struct khp_pins_frame {
	struct khp_pins_frame *next_pin_frame;
	unsigned long pin_count;
	struct khp_meta *pins[];
};

static inline bool is_khp_tagged_ptr(unsigned long fat_pointer)
{
#ifdef __x86_64__
	unsigned long pointer_type = fat_pointer >> 62;

	return pointer_type == (KHP_ETT_ALLOC>>6) ||
		pointer_type == (KHP_ETT_ALLOC_FB>>6);
#else
	/* make 32-bit code build properly, even if this isn't used */
	return false;
#endif
}

#else /* CONFIG_KHP */

#define is_khp_tagged_ptr(fat_pointer) false

#endif /* CONFIG_KHP */


/* vDSO code and such should always compile without KHP-instrumented atomics */
#ifdef __KHP_INSTRUMENT__
/* Must be marked as pure so that LLVM can optimize dead code away properly. */
__attribute__((pure)) void *__khp_unsafe_decode(void *ptr);

void khp_non_canonical_bug(void *);
/*
 * For when you don't immediately access memory, but instead are planning to
 * convert the pointer into a physical address or so.
 */
#define khp_unsafe_decode_noderef(ptr) ({				\
	void *ptr__ = __khp_unsafe_decode((void*)(ptr));		\
	unsigned long ptr_type__ = ((unsigned long)ptr__) >> 62;	\
	if (ptr_type__ == 1 || ptr_type__ == 2) {			\
		/* will not return */					\
		khp_non_canonical_bug(ptr__);				\
	}								\
	(__typeof__(ptr))ptr__;						\
})
#else
static __always_inline void *__khp_unsafe_decode(void *ptr) { return ptr; }
#define khp_unsafe_decode_noderef(ptr) (ptr)
#endif

#define khp_unsafe_decode(ptr) ( (__typeof__(ptr))__khp_unsafe_decode((void*)(ptr)) )
#define khp_unsafe_ref(lvalue) (*khp_unsafe_decode(&(lvalue)))

#endif /* _ASM_GENERIC_KHP_H */
