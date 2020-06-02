/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/linkage.h>
#include <asm/asm.h>
#include <asm/asm-offsets.h>
#include <asm/percpu.h>
#include <asm/smap.h>

/*
 * Decodes a (potentially) encoded pointer, and checks that the cookie is still
 * valid.
 * This must not be used on unchecked user pointers; doing so would trivially
 * allow userspace to perform a denial-of-service attack against the kernel.
 *
 * This function adheres to the `preserve_most` calling convention of clang,
 * which means that it can only use the following registers without spilling to
 * the stack:
 *  - rdi: encoded pointer (readonly!)
 *  - rsi: pointer to pin area (readonly!)
 *  - rax: return value, can be used as scratch before
 *  - r11: scratch via calling convention
 */
SYM_FUNC_START(__khp_decode_ptr)
	/* Make sure we are not dealing with an unencoded pointer. */
	mov %rdi, %rax
	shr $32, %rax
	/* rax is now 32-bit 11..., 00..., or shifted object identifier */
	cmp $0x40000000, %eax
	/*
	 * discarded subtraction result: object identifier, if this is a
	 * KHP pointer
	 *
	 *    eax : USER ORIG FALL KERN
	 *  result: ORIG FALL KERN USER
	 *          SF=0 SF=0 SF=1 SF=1
	 *          OF=0 OF=1 OF=0 OF=0
	 *          CF=0 CF=0 CF=0 CF=1
	 *
	 * EFLAGS.SF: set if native pointer (kernel or user)
	 * EFLAGS.OF: set if KHP fallback
	 * EFLAGS.CF: set if userspace pointer
	 */
	js .Lunencoded_pointer

	/*
	 * Load a pointer to the metadata region. The following instructions
	 * will be patched into "movabs <imm>, %r11" (10 bytes) at boottime,
	 * before any KHP pointers exist on the system.
	 * Note that this branch can theoretically be reached before that point
	 * due to compiler speculation.
	 * This value is `khp_region_start - sizeof(khp_meta)*0x40000000`, so
	 * we can directly add bits from the encoded pointer to it.
	 */
SYM_INNER_LABEL(khp_region_start_movabs_shifted, SYM_L_GLOBAL)
	jmp .Lunencoded_pointer
	.skip (10 - (. - khp_region_start_movabs_shifted)), 0xcc

	/* Construct a pointer to our metadata in r11. */
	shl $4, %rax /* LEA only works for multipliers up to 8, we need 16... */
	add %rax, %r11

	/*
	 * Store pointer to metadata struct in pin area.
	 * Ordering matters here: Because we store the decoded pointer before
	 * loading the expected cookie, we can be interrupted safely anywhere in
	 * this function.
	 * Up to this instruction, we are safe because we have not yet loaded
	 * the cookie; after this instruction, we are safe because we hold a
	 * pin (through the pin area of our caller).
	 */
	mov %r11, (%rsi)

	/*
	 * Track whether this allocation is being accessed from a foreign CPU
	 * while marked as CPU-local. If so, remove the CPU-local marker.
	 */
	movl PER_CPU_VAR(cpu_fixedhamming_id), %eax
SYM_INNER_LABEL(khp_first_metadata_access, SYM_L_GLOBAL)
	testb %al, khp_cpu_mask_offset(%r11)
	jnz .Lnonlocal_slowpath

.Lpointer_load:
	/* Assign rax = raw pointer, ready for function return. */
	xor %eax, %eax
	mov %di, %ax
	add khp_raw_ptr_offset(%r11), %rax

	/*
	 * Verify cookie and extag, away from the critical path, using only r11
	 * (touching any other register here is forbidden).
	 * Test for:
	 * (encoded_pointer ^ meta->khp_second_half) & 0xFF000000FFFF0000 == 0
	 *                                               ^^      ^^^^
	 *                                               |       cookie
	 *                                               |
	 *                                               extag
	 *
	 * Note that using a single load on meta->khp_second_half also means
	 * that we do not have to worry about consistency issues between the
	 * cookie and the extag.
	 */
	movq khp_second_half_offset(%r11), %r11
	xor %rdi, %r11
	test $0xffff0000, %r11d
	jnz .Ldecode_fail
	shr $56, %r11
	jnz .Ldecode_fail

	ret


.Lunencoded_pointer:
	movq %rdi, %rax
	ret


.Lnonlocal_slowpath:
#ifdef CONFIG_KHP_DEBUG
	pushf
	ASM_CLAC
	push %r11
	push %r15

	mov PER_CPU_VAR(current_task), %r15
	lea TASK_khp_recursion(%r15), %r15
	cmpl $0, (%r15)
	jne .Lnonlocal_skip_debug
	incl (%r15)
	call __khp_mark_global_debug
	decl (%r15)

.Lnonlocal_skip_debug:
	pop %r15
	pop %r11
	popf
#endif

	push %rbx

	/*
	 * Mark the allocation as global. While a use-after-free write here is
	 * conceptually not a big problem, it would be nicer to avoid it if the
	 * object has already been switched to free layout.
	 * Therefore, use cmpxchg to atomically verify the object layout type
	 * when performing the write.
	 *
	 * rax = (extag << 8) | old_cpu_offset
	 * rbx = (extag << 8)
	 */
	movq %rdi, %rbx
	shr $48, %rbx      /* derive extag from encoded pointer */
	and $0xff00, %ebx
	movl %ebx, %eax
	movb khp_cpu_mask_offset(%r11), %al

	cmpxchgw %bx, khp_extag_and_cpu_offset(%r11)
	jne .Lnonlocal_zeroing_failed
.Lnonlocal_zeroing_raced:

	pop %rbx
	jmp .Lpointer_load


.Lnonlocal_zeroing_failed:
	cmp %eax, %ebx
	je .Lnonlocal_zeroing_raced
	/* UAF either with a tight race or with different extag */
	pop %rbx
	jmp .Ldecode_fail

/* PF handler will jump us here if khp_first_metadata_access fails */
SYM_INNER_LABEL(khp_meta_not_present_fixup, SYM_L_GLOBAL)
/*
 * Pointer decoding failed for some reason.
 * We cannot abort execution here because we allow the compiler to speculatively
 * invoke __khp_decode_ptr() before knowing whether an access will actually
 * happen; so instead, if the decoding fails, we return the original KHP
 * pointer, which is guaranteed to generate a GPF when an actual access happens.
 * (Note that KHP users who convert the function return value into a physical
 * address must perform an extra check due to this.)
 *
 * As a future improvement, it might make sense to record the bailout reason
 * in out-of-line storage here; then khp_non_canonical_hook() could more
 * precisely diagnose what happened in most cases.
 */
.Ldecode_fail:
	mov %rdi, %rax
	ret
SYM_FUNC_END(__khp_decode_ptr)
_ASM_NOKPROBE(__khp_decode_ptr)
