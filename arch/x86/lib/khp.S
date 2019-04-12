/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/linkage.h>
#include <asm/asm.h>

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
 *  - rax: return value, can be used as scratch before
 *  - r11: scratch via calling convention
 */
SYM_FUNC_START(__khp_decode_ptr)
	movq %rdi, %rax
	ret
SYM_FUNC_END(__khp_decode_ptr)
_ASM_NOKPROBE(__khp_decode_ptr)
