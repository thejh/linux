/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This header provides generic wrappers for memory access instrumentation that
 * the compiler cannot emit for: KASAN, KCSAN, KMSAN.
 */
#ifndef _LINUX_INSTRUMENTED_H
#define _LINUX_INSTRUMENTED_H

#include <linux/bug.h>
#include <linux/compiler.h>
#include <linux/kasan-checks.h>
#include <linux/kcsan-checks.h>
#include <linux/kmsan-checks.h>
#include <linux/types.h>
#ifdef CONFIG_KCOV_MEMORY
/* For build speed, only include this header in builds that actually need it. */
#include <uapi/linux/kcov.h>
#endif

#ifdef CONFIG_KCOV_MEMORY
void _kcov_handle_memaccess(const volatile void *p, size_t size, unsigned int type);
#else
static __always_inline void _kcov_handle_memaccess(const volatile void *p,
		size_t size, unsigned int type) {}
/* Discard type argument to avoid depending on kcov header. */
#define _kcov_handle_memaccess(p, size, type) _kcov_handle_memaccess((p), (size), 0)
#endif

#if defined(__SANITIZE_ADDRESS__) || !defined(CONFIG_KCOV_MEMORY)
#define kcov_handle_memaccess _kcov_handle_memaccess
#else
static __always_inline void kcov_handle_memaccess(const volatile void *p,
		size_t size, unsigned int type) {}
#endif

/**
 * instrument_read - instrument regular read access
 * @v: address of access
 * @size: size of access
 *
 * Instrument a regular read access. The instrumentation should be inserted
 * before the actual read happens.
 */
static __always_inline void instrument_read(const volatile void *v, size_t size)
{
	kcov_handle_memaccess(v, size, 0);
	kasan_check_read(v, size);
	kcsan_check_read(v, size);
}

/**
 * instrument_write - instrument regular write access
 * @v: address of access
 * @size: size of access
 *
 * Instrument a regular write access. The instrumentation should be inserted
 * before the actual write happens.
 */
static __always_inline void instrument_write(const volatile void *v, size_t size)
{
	kcov_handle_memaccess(v, size, MEMORY_ACCESS_RECORD_WRITE);
	kasan_check_write(v, size);
	kcsan_check_write(v, size);
}

/**
 * instrument_read_write - instrument regular read-write access
 * @v: address of access
 * @size: size of access
 *
 * Instrument a regular write access. The instrumentation should be inserted
 * before the actual write happens.
 */
static __always_inline void instrument_read_write(const volatile void *v, size_t size)
{
	kcov_handle_memaccess(v, size, MEMORY_ACCESS_RECORD_RMW);
	kasan_check_write(v, size);
	kcsan_check_read_write(v, size);
}

static __always_inline void instrument_atomic_check_alignment(const volatile void *v, size_t size)
{
#ifndef __DISABLE_EXPORTS
	if (IS_ENABLED(CONFIG_DEBUG_ATOMIC)) {
		unsigned int mask = size - 1;

		if (IS_ENABLED(CONFIG_DEBUG_ATOMIC_LARGEST_ALIGN))
			mask &= sizeof(struct { long x; } __aligned_largest) - 1;
		WARN_ON_ONCE((unsigned long)v & mask);
	}
#endif
}

/**
 * instrument_atomic_read - instrument atomic read access
 * @v: address of access
 * @size: size of access
 *
 * Instrument an atomic read access. The instrumentation should be inserted
 * before the actual read happens.
 */
static __always_inline void instrument_atomic_read(const volatile void *v, size_t size)
{
	kcov_handle_memaccess(v, size, MEMORY_ACCESS_RECORD_ATOMIC);
	kasan_check_read(v, size);
	kcsan_check_atomic_read(v, size);
	instrument_atomic_check_alignment(v, size);
}

/**
 * instrument_atomic_write - instrument atomic write access
 * @v: address of access
 * @size: size of access
 *
 * Instrument an atomic write access. The instrumentation should be inserted
 * before the actual write happens.
 */
static __always_inline void instrument_atomic_write(const volatile void *v, size_t size)
{
	kcov_handle_memaccess(v, size, MEMORY_ACCESS_RECORD_WRITE|MEMORY_ACCESS_RECORD_ATOMIC);
	kasan_check_write(v, size);
	kcsan_check_atomic_write(v, size);
	instrument_atomic_check_alignment(v, size);
}

/**
 * instrument_atomic_read_write - instrument atomic read-write access
 * @v: address of access
 * @size: size of access
 *
 * Instrument an atomic read-write access. The instrumentation should be
 * inserted before the actual write happens.
 */
static __always_inline void instrument_atomic_read_write(const volatile void *v, size_t size)
{
	kcov_handle_memaccess(v, size, MEMORY_ACCESS_RECORD_RMW|MEMORY_ACCESS_RECORD_ATOMIC);
	kasan_check_write(v, size);
	kcsan_check_atomic_read_write(v, size);
	instrument_atomic_check_alignment(v, size);
}

/**
 * instrument_copy_to_user - instrument reads of copy_to_user
 * @to: destination address
 * @from: source address
 * @n: number of bytes to copy
 *
 * Instrument reads from kernel memory, that are due to copy_to_user (and
 * variants). The instrumentation must be inserted before the accesses.
 */
static __always_inline void
instrument_copy_to_user(void __user *to, const void *from, unsigned long n)
{
	kcov_handle_memaccess(from, n, 0);
	kasan_check_read(from, n);
	kcsan_check_read(from, n);
	kmsan_copy_to_user(to, from, n, 0);
}

/**
 * instrument_copy_from_user_before - add instrumentation before copy_from_user
 * @to: destination address
 * @from: source address
 * @n: number of bytes to copy
 *
 * Instrument writes to kernel memory, that are due to copy_from_user (and
 * variants). The instrumentation should be inserted before the accesses.
 */
static __always_inline void
instrument_copy_from_user_before(const void *to, const void __user *from, unsigned long n)
{
	kcov_handle_memaccess(to, n, MEMORY_ACCESS_RECORD_WRITE);
	kasan_check_write(to, n);
	kcsan_check_write(to, n);
}

/**
 * instrument_copy_from_user_after - add instrumentation after copy_from_user
 * @to: destination address
 * @from: source address
 * @n: number of bytes to copy
 * @left: number of bytes not copied (as returned by copy_from_user)
 *
 * Instrument writes to kernel memory, that are due to copy_from_user (and
 * variants). The instrumentation should be inserted after the accesses.
 */
static __always_inline void
instrument_copy_from_user_after(const void *to, const void __user *from,
				unsigned long n, unsigned long left)
{
	kmsan_unpoison_memory(to, n - left);
}

/**
 * instrument_memcpy_before - add instrumentation before non-instrumented memcpy
 * @to: destination address
 * @from: source address
 * @n: number of bytes to copy
 *
 * Instrument memory accesses that happen in custom memcpy implementations. The
 * instrumentation should be inserted before the memcpy call.
 */
static __always_inline void instrument_memcpy_before(void *to, const void *from,
						     unsigned long n)
{
	kcov_handle_memaccess(from, n, 0);
	kcov_handle_memaccess(to, n, MEMORY_ACCESS_RECORD_WRITE);
	kasan_check_write(to, n);
	kasan_check_read(from, n);
	kcsan_check_write(to, n);
	kcsan_check_read(from, n);
}

/**
 * instrument_memcpy_after - add instrumentation after non-instrumented memcpy
 * @to: destination address
 * @from: source address
 * @n: number of bytes to copy
 * @left: number of bytes not copied (if known)
 *
 * Instrument memory accesses that happen in custom memcpy implementations. The
 * instrumentation should be inserted after the memcpy call.
 */
static __always_inline void instrument_memcpy_after(void *to, const void *from,
						    unsigned long n,
						    unsigned long left)
{
	kmsan_memmove(to, from, n - left);
}

/**
 * instrument_get_user() - add instrumentation to get_user()-like macros
 * @to: destination variable, may not be address-taken
 *
 * get_user() and friends are fragile, so it may depend on the implementation
 * whether the instrumentation happens before or after the data is copied from
 * the userspace.
 */
#define instrument_get_user(to)				\
({							\
	u64 __tmp = (u64)(to);				\
	kmsan_unpoison_memory(&__tmp, sizeof(__tmp));	\
	to = __tmp;					\
})


/**
 * instrument_put_user() - add instrumentation to put_user()-like macros
 * @from: source address
 * @ptr: userspace pointer to copy to
 * @size: number of bytes to copy
 *
 * put_user() and friends are fragile, so it may depend on the implementation
 * whether the instrumentation happens before or after the data is copied from
 * the userspace.
 */
#define instrument_put_user(from, ptr, size)			\
({								\
	kmsan_copy_to_user(ptr, &from, sizeof(from), 0);	\
})

#endif /* _LINUX_INSTRUMENTED_H */
