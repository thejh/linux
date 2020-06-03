/* SPDX-License-Identifier: GPL-2.0 */
/*
 * __get_user functions.
 *
 * (C) Copyright 1998 Linus Torvalds
 * (C) Copyright 2005 Andi Kleen
 * (C) Copyright 2008 Glauber Costa
 *
 * These functions have a non-standard call interface
 * to make them more efficient, especially as they
 * return an error value in addition to the "real"
 * return value.
 */

/*
 * __get_user_X
 *
 * Inputs:	%[r|e]ax contains the address.
 *
 * Outputs:	%[r|e]ax is error code (0 or -EFAULT)
 *		%[r|e]dx contains zero-extended value
 *		%ecx contains the high half for 32-bit __get_user_8
 *
 *
 * These functions should not modify any other registers,
 * as they get called from within inline assembly.
 */

#include <linux/linkage.h>
#include <asm/page_types.h>
#include <asm/errno.h>
#include <asm/asm-offsets.h>
#include <asm/thread_info.h>
#include <asm/asm.h>
#include <asm/smap.h>
#include <asm/export.h>

	.text

.macro generate_get_user_fn name:req, size:req, bad_address_label:req, mov_insn
SYM_FUNC_START(\name)
	/* compute address of last byte and detect overflow */
	.if \size != 1
	add $(\size - 1),%_ASM_AX
	jc \bad_address_label
	.endif

	/* if (addr >= current->addr_limit) ... */
	mov PER_CPU_VAR(current_task), %_ASM_DX
	cmp TASK_addr_limit(%_ASM_DX),%_ASM_AX
	jae \bad_address_label

	/* array_index_mask_nospec() */
	sbb %_ASM_DX, %_ASM_DX
	and %_ASM_DX, %_ASM_AX

#ifdef CONFIG_KHP
	/*
	 * Jump into the slowpath if the pointer is either a raw kernel pointer
	 * (high bits 11) or a KHP-encoded pointer (high bits 01/10).
	 * This should be after the address limit check to avoid passing
	 * userspace-controlled values into the KHP infrastructure when
	 * possible.
	 */
	mov %rax, %rdx
	shr $62, %rdx
	jnz 3f
4:
#endif

	ASM_STAC

	.if \size == 8 && IS_ENABLED(CONFIG_X86_32)
1:	\mov_insn -7(%_ASM_AX),%edx
2:	\mov_insn -3(%_ASM_AX),%ecx
	.elseif \size == 8
1:	\mov_insn -7(%_ASM_AX),%rdx
	.else
1:	\mov_insn -\size + 1(%_ASM_AX), %edx
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
	cmp $3, %rdx
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
	 * Decode the pointer. Note that __khp_decode_ptr uses a special calling
	 * convention!
	 */
	movq %rax, %rdi
	call __khp_decode_ptr

	ASM_STAC
	.if \size == 8
5:	\mov_insn -\size + 1(%rax), %rdx
	.else
5:	\mov_insn -\size + 1(%rax), %edx
	.endif
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
	xor %rdx, %rdx
	mov $(-EFAULT), %rax
	jmp 6b

	_ASM_EXTABLE_UA(5b, 7b)
#endif
SYM_FUNC_END(\name)
EXPORT_SYMBOL(\name)

	.if \size == 8 && IS_ENABLED(CONFIG_X86_32)
	_ASM_EXTABLE_UA(1b, .Lbad_get_user_8_clac)
	_ASM_EXTABLE_UA(2b, .Lbad_get_user_8_clac)
	.else
	_ASM_EXTABLE_UA(1b, .Lbad_get_user_clac)
	.endif
.endm

generate_get_user_fn __get_user_1, 1, bad_get_user, movzbl
generate_get_user_fn __get_user_2, 2, bad_get_user, movzwl
generate_get_user_fn __get_user_4, 4, bad_get_user, movl
#ifdef CONFIG_X86_64
generate_get_user_fn __get_user_8, 8, bad_get_user, movq
#else
generate_get_user_fn __get_user_8, 8, bad_get_user_8, movl
#endif


SYM_CODE_START_LOCAL(.Lbad_get_user_clac)
	ASM_CLAC
bad_get_user:
	xor %edx,%edx
	mov $(-EFAULT),%_ASM_AX
	ret
SYM_CODE_END(.Lbad_get_user_clac)

#ifdef CONFIG_X86_32
SYM_CODE_START_LOCAL(.Lbad_get_user_8_clac)
	ASM_CLAC
bad_get_user_8:
	xor %edx,%edx
	xor %ecx,%ecx
	mov $(-EFAULT),%_ASM_AX
	ret
SYM_CODE_END(.Lbad_get_user_8_clac)
#endif
