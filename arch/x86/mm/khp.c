#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/khp.h>
#include <asm/text-patching.h>

/* returns false on error */
static inline void handle_pin(struct khp_meta *pin, int direction,
			      bool migrated)
{
	if (direction == 1) {
		khp_refcount_inc(pin);
	} else {
		if (migrated)
			khp_mark_migrated_global(pin);

		khp_refcount_dec(pin, false, 0);
	}
}

#include <asm/unwind.h>
static void khp_dump_task_stack(struct task_struct *task)
{
	struct khp_pins_frame *pin_frame = task->thread.khp_pin_head;
	struct unwind_state state;

	unwind_start(&state, task, NULL, NULL);

	/* WARNING: dodgy stack pointer comparisons if we have a split stack */
	while (!unwind_done(&state)) {
		if (pin_frame && (unsigned long)pin_frame < state.sp) {
			unsigned long i;
			pr_emerg("%p: 0x%lx KHP pins:\n", pin_frame, pin_frame->pin_count);
			if (pin_frame->pin_count > 0x1000) {
				pr_emerg("BAD PIN COUNT, STOPPING\n");
				pin_frame = NULL;
			} else {
				for (i = 0; i < pin_frame->pin_count; i++) {
					pr_emerg("  %p\n", pin_frame->pins[i]);
				}
				pin_frame = pin_frame->next_pin_frame;
			}
		} else {
			pr_emerg("%p: %pB\n", unwind_get_return_address_ptr(&state), (void*)state.ip);
			unwind_next_frame(&state);
		}
	}
	pr_emerg("UNWIND DONE, CHECKING REMAINING KHP\n");
	while (pin_frame) {
		unsigned long i;
		pr_emerg("%p: 0x%lx KHP pins:\n", pin_frame, pin_frame->pin_count);
		if (pin_frame->pin_count > 0x1000) {
			pr_emerg("BAD PIN COUNT, STOPPING\n");
			pin_frame = NULL;
		} else {
			for (i = 0; i < pin_frame->pin_count; i++) {
				pr_emerg("  %p\n", pin_frame->pins[i]);
			}
			pin_frame = pin_frame->next_pin_frame;
		}
	}
	pr_emerg("UNWIND FULLY DONE\n");
	show_trace_log_lvl(task, NULL, NULL, KERN_EMERG);
	pr_emerg("SECOND UNWIND FULLY DONE\n");
}

/*
 * @direction is either +1 (for adding refcounts) or -1 (for removing refcounts)
 */
void khp_stack_scan(struct task_struct *task, int direction) {
	struct khp_pins_frame *pin_frame = task->thread.khp_pin_head;
	struct khp_meta *orig_start = khp_orig_region.start;
	struct khp_meta *orig_end = READ_ONCE(khp_orig_region.used_end);
	struct khp_meta *fb_start = khp_fallback_region.start;
	struct khp_meta *fb_end = READ_ONCE(khp_fallback_region.used_end);
	bool migrated = test_bit(KHP_MIGRATED_BIT, &task->khp_flags);

	/*
	 * Note: KHP_MIGRATED_BIT can be set on direction +1 if we failed the
	 * last khp_stack_scan().
	 * That means we lost KHP protection for a bit, and it shouldn't happen,
	 * but we might be able to go on.
	 */
	if (migrated && direction == 1)
		printk_deferred(KERN_EMERG "khp_stack_scan() switching MIGRATED task to refcounted mode\n");

	while (pin_frame != NULL) {
		int i;
		unsigned long pin_count = pin_frame->pin_count;

#ifdef CONFIG_KHP_DEBUG
		if (pin_count > THREAD_SIZE / sizeof(void*)) {
			pr_emerg("stack unwind encountered bad pin_count: 0x%lx\n",
				pin_count);
			return;
		}
#endif

		for (i = 0; i < pin_count; i++) {
			struct khp_meta *pin = pin_frame->pins[i];
			unsigned long pin_ = (unsigned long)pin;

			if (pin == NULL)
				continue;

			/*
			 * This can legitimately happen when scheduling out
			 * due to speculative decoding of bogus pointers.
			 * If we just did "continue" here, the metadata slot
			 * could become valid before we schedule back in, and
			 * we'd be left with the refcount one too low.
			 * So we have to clear out the pin in this case.
			 *
			 * It is possible for this to race such that
			 * __khp_decode_ptr() will observe a valid pin even
			 * though we've cleared out the pin slot; but if the
			 * decoded pointer is then actually used, that indicates
			 * an application bug other than a UAF (some sort of
			 * completely wild pointer dereference), so that's fine.
			 */
			if (unlikely(pin >= (pin < fb_start ? orig_end : fb_end))) {
				WARN_ON_ONCE(direction==-1);
				pin_frame->pins[i] = NULL;
				continue;
			}
#ifdef CONFIG_KHP_DEBUG
			/*
			 * sanity check: must be aligned and in an allocated
			 * part of KHP region
			 */
			if ((pin_ & (sizeof(struct khp_meta)-1)) != 0 ||
			    ((pin < orig_start || pin >= orig_end) && (pin < fb_start || pin >= fb_end))) {
				pr_emerg("stack unwind encountered bad weakptr: 0x%lx; should be in [%p,%p) or [%p,%p)\n",
					pin_, orig_start, orig_end, fb_start, fb_end);
				pr_emerg("  pin_frame at %p: next=%p, count=0x%lx\n",
					pin_frame, pin_frame->next_pin_frame, pin_frame->pin_count);
				khp_dump_task_stack(task);
				return;
			}
#endif

			handle_pin(pin, direction, migrated);
		}

		pin_frame = pin_frame->next_pin_frame;
	}

	if (migrated)
		clear_bit(KHP_MIGRATED_BIT, &task->khp_flags);
}

struct khp_movabs {
	u8 rex_prefix;
	u8 opcode;
	struct khp_meta *value;
} __packed;

extern struct khp_movabs khp_region_start_movabs_shifted;

void __init arch_khp_init(void)
{
	/*
	 * shifted such that you can index with the upper half of a pointer,
	 * without subtracting 0x40000000 from it first
	 */
	struct khp_movabs movabs_region_shifted = {
		.rex_prefix = 0x49,
		.opcode = 0xbb,
		.value = khp_region_start - (1UL << 30)
	};

	text_poke_early(&khp_region_start_movabs_shifted,
			&movabs_region_shifted, sizeof(movabs_region_shifted));
}

void khp_non_canonical_hook(unsigned long addr)
{
	unsigned long type = addr >> 62;
	u32 obj_idx = (addr >> 32) - 0x40000000UL;
	struct khp_meta *meta;
	unsigned long expected;

	/* skip anything that doesn't look like a KHP pointer */
	if (type == 0 || type == 3)
		return;

	meta = khp_region_start + obj_idx;
	expected = READ_ONCE(meta->halves[1]);

	pr_emerg("Missing KHP decode annotation, negative OOB pointer, or UAF?\n");
	pr_emerg("fullmask=0xff000000ffff0000\n");
	pr_emerg(" pointer=0x%016lx\n", addr);
	pr_emerg("expected=0x%016lx\n", expected);
}

void khp_non_canonical_bug(void *ptr)
{
	khp_non_canonical_hook((unsigned long)ptr);
	BUG();
}
