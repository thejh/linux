// SPDX-License-Identifier: GPL-2.0
#ifndef __LINUX_KBUILD_H
# error "Please do not build this file directly, build asm-offsets.c instead"
#endif

#include <asm/ia32.h>

#if defined(CONFIG_KVM_GUEST) && defined(CONFIG_PARAVIRT_SPINLOCKS)
#include <asm/kvm_para.h>
#endif

#ifdef CONFIG_KHP
#include <asm-generic/khp.h>
#endif

int main(void)
{
#ifdef CONFIG_PARAVIRT
#ifdef CONFIG_PARAVIRT_XXL
	OFFSET(PV_CPU_usergs_sysret64, paravirt_patch_template,
	       cpu.usergs_sysret64);
	OFFSET(PV_CPU_swapgs, paravirt_patch_template, cpu.swapgs);
#ifdef CONFIG_DEBUG_ENTRY
	OFFSET(PV_IRQ_save_fl, paravirt_patch_template, irq.save_fl);
#endif
#endif
	BLANK();
#endif

#if defined(CONFIG_KVM_GUEST) && defined(CONFIG_PARAVIRT_SPINLOCKS)
	OFFSET(KVM_STEAL_TIME_preempted, kvm_steal_time, preempted);
	BLANK();
#endif

#define ENTRY(entry) OFFSET(pt_regs_ ## entry, pt_regs, entry)
	ENTRY(bx);
	ENTRY(cx);
	ENTRY(dx);
	ENTRY(sp);
	ENTRY(bp);
	ENTRY(si);
	ENTRY(di);
	ENTRY(r8);
	ENTRY(r9);
	ENTRY(r10);
	ENTRY(r11);
	ENTRY(r12);
	ENTRY(r13);
	ENTRY(r14);
	ENTRY(r15);
	ENTRY(flags);
	BLANK();
#undef ENTRY

#define ENTRY(entry) OFFSET(saved_context_ ## entry, saved_context, entry)
	ENTRY(cr0);
	ENTRY(cr2);
	ENTRY(cr3);
	ENTRY(cr4);
	ENTRY(gdt_desc);
	BLANK();
#undef ENTRY

	OFFSET(TSS_ist, tss_struct, x86_tss.ist);
	DEFINE(DB_STACK_OFFSET, offsetof(struct cea_exception_stacks, DB_stack) -
	       offsetof(struct cea_exception_stacks, DB1_stack));
	BLANK();

#ifdef CONFIG_STACKPROTECTOR
	DEFINE(stack_canary_offset, offsetof(struct fixed_percpu_data, stack_canary));
	BLANK();
#endif

#ifdef CONFIG_KHP
	/* struct khp_meta */
	DEFINE(khp_raw_ptr_offset, offsetof(struct khp_meta, khp_raw_ptr));
	DEFINE(khp_cookie_offset, offsetof(struct khp_meta, khp_cookie));
	DEFINE(khp_second_half_offset, offsetof(struct khp_meta, halves[1]));
	DEFINE(khp_extag_and_cpu_offset, offsetof(struct khp_meta, lar.etac));
	DEFINE(khp_cpu_mask_offset, offsetof(struct khp_meta, lar.etac.khp_cpu_mask_inv));
#ifdef CONFIG_KHP_DEBUG
	DEFINE(TASK_khp_recursion, offsetof(struct task_struct, khp_recursion));
#endif
	BLANK();
#endif
#ifdef CONFIG_KHP_PUREINST
	/* fixed_percpu_data */
	DEFINE(khp_pcpu_pin_head_offset, offsetof(struct fixed_percpu_data, khp_pcpu_pin_head));
	BLANK();
	/* task_struct */
	DEFINE(khp_task_pin_head_offset, offsetof(struct task_struct, thread.khp_pin_head));
	BLANK();
#endif

	return 0;
}
