#ifndef _ASM_GENERIC_KHP_H
#define _ASM_GENERIC_KHP_H

/* vDSO code and such should always compile without KHP-instrumented atomics */
#ifdef __KHP_INSTRUMENT__
/* Must be marked as pure so that LLVM can optimize dead code away properly. */
__attribute__((pure)) void *__khp_unsafe_decode(void *ptr);
#else
static __always_inline void *__khp_unsafe_decode(void *ptr) { return ptr; }
#endif

#define khp_unsafe_decode(ptr) ( (__typeof__(ptr))__khp_unsafe_decode((void*)(ptr)) )
#define khp_unsafe_ref(lvalue) (*khp_unsafe_decode(&(lvalue)))

#endif /* _ASM_GENERIC_KHP_H */
