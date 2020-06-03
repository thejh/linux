/* SPDX-License-Identifier: GPL-2.0 */
/*
 * __put_user functions.
 *
 * (C) Copyright 2005 Linus Torvalds
 * (C) Copyright 2005 Andi Kleen
 * (C) Copyright 2008 Glauber Costa
 *
 * These functions have a non-standard call interface
 * to make them more efficient, especially as they
 * return an error value in addition to the "real"
 * return value.
 */
#include <linux/linkage.h>
#include <asm/thread_info.h>
#include <asm/errno.h>
#include <asm/asm.h>
#include <asm/smap.h>
#include <asm/export.h>


/*
 * __put_user_X
 *
 * Inputs:	%eax[:%edx] contains the data
 *		%ecx contains the address
 *
 * Outputs:	%eax is error code (0 or -EFAULT)
 *
 * These functions should not modify any other registers,
 * as they get called from within inline assembly.
 */

.text

.macro generate_put_user_fn name:req, size:req, source_reg:req
SYM_FUNC_START(\name)
	mov PER_CPU_VAR(current_task), %_ASM_BX

	.if \size == 1
	cmp TASK_addr_limit(%_ASM_BX),%_ASM_CX
	jae .Lbad_put_user
	.else
	mov TASK_addr_limit(%_ASM_BX),%_ASM_BX
	sub $(\size - 1),%_ASM_BX
	cmp %_ASM_BX,%_ASM_CX
	jae .Lbad_put_user
	.endif

#ifdef CONFIG_KHP
	/*
	 * Jump into the slowpath if the pointer is either a raw kernel pointer
	 * (high bits 11) or a KHP-encoded pointer (high bits 01/10).
	 * This *MUST* be after the address limit check to ensure that userspace
	 * cannot trick us into passing userspace-controlled values into the
	 * KHP infrastructure.
	 */
	mov %rcx, %rbx
	shr $62, %rbx
	jnz 3f
4:
#endif

	ASM_STAC

1:	mov \source_reg, (%_ASM_CX)
	_ASM_EXTABLE_UA(1b, .Lbad_put_user_clac)
	.if \size == 8 && IS_ENABLED(CONFIG_X86_32)
2:	movl %edx,4(%_ASM_CX)
	_ASM_EXTABLE_UA(2b, .Lbad_put_user_clac)
	.endif

	xor %eax,%eax
	ASM_CLAC
	ret

#ifdef CONFIG_KHP
3:
	/*
	 * If we are dealing with a plain kernel pointer, jump back into
	 * fastpath.
	 */
	cmp $3, %rbx
	je 4b

	/*
	 * Setup scratch registers (also necessary for __khp_decode_ptr calling
	 * convention).
	 */
	pushq %rdi
	pushq %rsi
	pushq %r11

	/* Create KHP pin area and push it on the list. */
	pushq $0 /* reserve pin slot */
	mov %rsp, %rsi /* pass slot to __khp_decode_ptr as arg2 */
	pushq $1 /* pin count */
	pushq PER_CPU_VAR(fixed_percpu_data) + khp_pcpu_pin_head_offset
	movq %rsp, PER_CPU_VAR(fixed_percpu_data) + khp_pcpu_pin_head_offset

	/*
	 * %rcx = __khp_decode_ptr(%rcx, <pin>)
	 * (with a special calling convention)
	 */
	movq %rcx, %rdi
	pushq %rax /* stash input data */
	call __khp_decode_ptr
	movq %rax, %rcx
	popq %rax /* restore input data */

	ASM_STAC
5:	mov \source_reg, (%rcx)
	xor %eax,%eax
6:	ASM_CLAC

	/* restore and return */
	popq PER_CPU_VAR(fixed_percpu_data) + khp_pcpu_pin_head_offset
	add $16, %rsp /* pin count and pin slot */
	popq %r11
	popq %rsi
	popq %rdi
	ret

7:	/* Handle failed uaccess to KHP pointer. */
	mov $(-EFAULT), %rax
	jmp 6b

	_ASM_EXTABLE_UA(5b, 7b)
#endif
SYM_FUNC_END(\name)
EXPORT_SYMBOL(\name)
.endm

generate_put_user_fn __put_user_1, 1, %al
generate_put_user_fn __put_user_2, 2, %ax
generate_put_user_fn __put_user_4, 4, %eax
generate_put_user_fn __put_user_8, 8, %_ASM_AX

SYM_CODE_START_LOCAL(.Lbad_put_user_clac)
	ASM_CLAC
.Lbad_put_user:
	movl $-EFAULT,%eax
	RET
SYM_CODE_END(.Lbad_put_user_clac)
