/*-
 * Copyright (c) 2013-2016 Robert N. M. Watson
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _SYS_CHERIC_H_
#define	_SYS_CHERIC_H_

#include <sys/cdefs.h>
#include <sys/types.h>

#include <machine/cherireg.h>	/* Permission definitions. */

#if __has_feature(capabilities) || defined(__CHERI__)

/*
 * Programmer-friendly macros for CHERI-aware C code -- requires use of
 * CHERI-aware Clang/LLVM, and full capability context switching.
 */
#define	cheri_getlen(x)		__builtin_cheri_length_get((x))
#define	cheri_getbase(x)	__builtin_cheri_base_get((x))
#define	cheri_getoffset(x)	__builtin_cheri_offset_get((x))
#define	cheri_getaddress(x)	__builtin_cheri_address_get((x))
#define	cheri_getperm(x)	__builtin_cheri_perms_get((x))
#define	cheri_getsealed(x)	__builtin_cheri_sealed_get((x))
#define	cheri_gettag(x)		__builtin_cheri_tag_get((x))
#define	cheri_gettype(x)	((long)__builtin_cheri_type_get((x)))

#define	cheri_andperm(x, y)	__builtin_cheri_perms_and((x), (y))
#define	cheri_clearperm(x, y)	__builtin_cheri_perms_and((x), ~(y))
#define	cheri_cleartag(x)	__builtin_cheri_tag_clear((x))
#define	cheri_incoffset(x, y)	__builtin_cheri_offset_increment((x), (y))
#define	cheri_setoffset(x, y)	__builtin_cheri_offset_set((x), (y))
#define	cheri_setaddress(x, y)	__builtin_cheri_address_set((x), (y))

#define	cheri_seal(x, y)	__builtin_cheri_seal((x), (y))
#define	cheri_unseal(x, y)	__builtin_cheri_unseal((x), (y))

#define	cheri_getcause()	__builtin_mips_cheri_get_cause()
#define	cheri_setcause(x)	__builtin_mips_cheri_set_cause(x)

#define	cheri_ccheckperm(c, p)	__builtin_cheri_perms_check((c), (p))
#define	cheri_cchecktype(c, t)	__builtin_cheri_type_check((c), (t))

#define	cheri_getdefault()	__builtin_cheri_global_data_get()
#define	cheri_getidc()		__builtin_mips_cheri_get_invoke_data_cap()
#define	cheri_getkr1c()		__builtin_mips_cheri_get_kernel_cap1()
#define	cheri_getkr2c()		__builtin_mips_cheri_get_kernel_cap2()
#define	cheri_getkcc()		__builtin_mips_cheri_get_kernel_code_cap()
#define	cheri_getkdc()		__builtin_mips_cheri_get_kernel_data_cap()
#define	cheri_getepcc()		__builtin_mips_cheri_get_exception_program_counter_cap()
#define	cheri_getpcc()		__builtin_cheri_program_counter_get()
#define	cheri_getstack()	__builtin_cheri_stack_get()

#define	cheri_local(c)		cheri_andperm((c), ~CHERI_PERM_GLOBAL)

#define	cheri_csetbounds(x, y)	__builtin_cheri_bounds_set((x), (y))
#define	cheri_csetboundsexact(x, y)	__builtin_cheri_bounds_set_exact((x), (y))
/* XXXAR: shouldn't this be the default and we add cheri_csetbounds_untyped? */
#define	cheri_csetbounds_changetype(type, x, y)	\
	(type)cheri_csetbounds((x), (y)))
#define	cheri_csetbounds_sametype(x, y)	\
	((__typeof__(x))cheri_csetbounds((x), (y)))

/* Create an untagged capability from an integer */
#define cheri_fromint(x)	cheri_incoffset(NULL, x)

/* Increment @p dst to have the address of @p src */
static __always_inline inline void * __capability
cheri_copyaddress(const void * __capability dst, const void * __capability src)
{
	return (cheri_incoffset(dst,
	    (const char* __capability)src - (const char* __capability)dst));
}

/* Get the top of a capability (i.e. one byte past the last accessible one) */
static __always_inline inline vaddr_t
cheri_gettop(const void * __capability cap)
{
	return (cheri_getbase(cap) + cheri_getlen(cap));
}

/* Check if the address is between cap.base and cap.top, i.e. in bounds */
#ifdef __cplusplus
static __always_inline inline bool
#else
static __always_inline inline _Bool
#endif
cheri_is_address_inbounds(const void * __capability cap, vaddr_t addr)
{
	return (addr >= cheri_getbase(cap) && addr < cheri_gettop(cap));
}

/*
 * Two variations on cheri_ptr() based on whether we are looking for a code or
 * data capability.  The compiler's use of CFromPtr will be with respect to
 * $ddc or $pcc depending on the type of the pointer derived, so we need to
 * use types to differentiate the two versions at compile time.  We don't
 * provide the full set of function variations for code pointers as they
 * haven't proven necessary as yet.
 *
 * XXXRW: Ideally, casting via a function pointer would cause the compiler to
 * derive the capability using CFromPtr on $pcc rather than on $ddc.  This
 * appears not currently to be the case, so manually derive using
 * cheri_getpcc() for now.
 */
static __inline void * __capability
cheri_codeptr(const void *ptr, size_t len)
{
#ifdef NOTYET
	void (* __capability c)(void) = ptr;
#else
	void * __capability c = cheri_setaddress(cheri_getpcc(),
	    (register_t)ptr);
#endif

	/* Assume CFromPtr without base set, availability of CSetBounds. */
	return (cheri_csetbounds(c, len));
}

static __inline void * __capability
cheri_codeptrperm(const void *ptr, size_t len, register_t perm)
{

	return (cheri_andperm(cheri_codeptr(ptr, len),
	    perm | CHERI_PERM_GLOBAL));
}

static __inline void * __capability
cheri_ptr(const void *ptr, size_t len)
{

	/* Assume CFromPtr without base set, availability of CSetBounds. */
	return (cheri_csetbounds((__cheri_tocap const void * __capability)ptr, len));
}

static __inline void * __capability
cheri_ptrperm(const void *ptr, size_t len, register_t perm)
{

	return (cheri_andperm(cheri_ptr(ptr, len), perm | CHERI_PERM_GLOBAL));
}

static __inline void * __capability
cheri_ptrpermoff(const void *ptr, size_t len, register_t perm, off_t off)
{

	return (cheri_setoffset(cheri_ptrperm(ptr, len, perm), off));
}

/*
 * Construct a capability suitable to describe a type identified by 'ptr';
 * set it to zero-length with the offset equal to the base.  The caller must
 * provide a root capability (in the old world order, derived from $ddc, but
 * in the new world order, likely extracted from the kernel using sysarch(2)).
 *
 * The caller may wish to assert various properties about the returned
 * capability, including that CHERI_PERM_SEAL is set.
 */
static __inline otype_t
cheri_maketype(void * __capability root_type, register_t type)
{
	void * __capability c;

	c = root_type;
	c = cheri_setoffset(c, type);	/* Set type as desired. */
	c = cheri_csetbounds(c, 1);	/* ISA implies length of 1. */
	c = cheri_andperm(c, CHERI_PERM_GLOBAL | CHERI_PERM_SEAL); /* Perms. */
	return (c);
}

static __inline void * __capability
cheri_zerocap(void)
{
	return (void * __capability)0;
}

static __inline uint64_t
cheri_bytes_remaining(const void * __capability cap)
{
	if (cheri_getoffset(cap) >= cheri_getlen(cap))
		return 0;
	return cheri_getlen(cap) - cheri_getoffset(cap);
}

/*
 * Turn a pointer into a capability with the bounds set to
 * sizeof(*ptr)
 */
/* XXX: work around CTSRD-CHERI/clang#157 */
#ifdef __CHERI_PURE_CAPABILITY__
#define cheri_ptr_to_bounded_cap(ptr)	__extension__({	\
	typedef __typeof__(ptr) __ptr_type;		\
	(__ptr_type)cheri_ptr((ptr), sizeof(*(ptr)));	\
	})
#else
#define	cheri_ptr_to_bounded_cap(ptr) cheri_ptr((ptr), sizeof(*(ptr)))
#endif
/*
 * Convert a capability to a pointer. Returns NULL if there are less than
 * min_size accessible bytes remiaing in cap.
 */
#define cheri_cap_to_ptr(cap, min_size)	__extension__({			\
	typedef __typeof__(*(cap)) __underlying_type;			\
	__underlying_type* __result = 0;				\
	if (cheri_gettag(cap) && cheri_bytes_remaining(cap) >= (uint64_t)min_size) { \
		__result = (__cheri_fromcap __underlying_type*)(cap);	\
	} __result; })

/*
 * Convert an untyped capability to a pointer of type \p type.
 * This macro checks that there are at least sizeof(type) bytes accessible
 * from \p cap.
 */
#define cheri_cap_to_typed_ptr(cap, type)				\
	(type *)cheri_cap_to_ptr(cap, sizeof(type))

#define _CHERI_PRINTF_CAP_FMT  "v:%lu s:%lu p:%08lx b:%016jx l:%016zx o:%jx t:%ld"
#define _CHERI_PRINTF_CAP_ARG(ptr)					\
	    (unsigned long)cheri_gettag((const void * __capability)(ptr)),		\
	    (unsigned long)cheri_getsealed((const void * __capability)(ptr)),		\
	    cheri_getperm((const void * __capability)(ptr)),		\
	    cheri_getbase((const void * __capability)(ptr)),		\
	    cheri_getlen((const void * __capability)(ptr)),		\
	    cheri_getoffset((const void * __capability)(ptr)),		\
	    (long)cheri_gettype((const void * __capability)(ptr))

#define _CHERI_PRINT_PTR_FMT(ptr)					\
	    "%s: " #ptr " " _CHERI_PRINTF_CAP_FMT "\n", __func__,	\
	    _CHERI_PRINTF_CAP_ARG(ptr)

#define CHERI_PRINT_PTR(ptr)						\
	printf(_CHERI_PRINT_PTR_FMT(ptr))

#define CHERI_FPRINT_PTR(f, ptr)					\
	fprintf(f, _CHERI_PRINT_PTR_FMT(ptr))
#endif

/*
 * The cheri_{get,set,clear}_low_pointer_bits() functions work both with and
 * without CHERI support so can be used unconditionally to fix
 * -Wcheri-bitwise-operations warnings.
 *
 * XXXAR: Should kept in sync with the version from clang's cheri.h.
 */

static inline __always_inline __result_use_check size_t
__cheri_get_low_ptr_bits(uintptr_t ptr, size_t mask) {
  /*
   * Note: we continue to use bitwise and on the uintcap value and silence the
   * warning instead of using __builtin_cheri_offset_get() in case we decide
   * to use a virtual-address instead offset interpretation of capabilities in
   * the future.
   */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcheri-bitwise-operations"
  /*
   * We mustn't return a LHS-derived capability here so we need to explicitly
   * cast the result to a non-capability integer
   */
  return (size_t)(ptr & mask);
#pragma clang diagnostic pop
}

static inline __always_inline __result_use_check uintptr_t
__cheri_set_low_ptr_bits(uintptr_t ptr, size_t bits) {
  /*
   * We want to return a LHS-derived capability here so using the default
   * uintcap_t semantics is fine.
   */
  return ptr | bits;
}

static inline __always_inline __result_use_check uintptr_t
__cheri_clear_low_ptr_bits(uintptr_t ptr, size_t bits_mask) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcheri-bitwise-operations"
  /*
   * We want to return a LHS-derived capability here so using the default
   * uintcap_t semantics is fine.
   */
  return ptr & (~bits_mask);
#pragma clang diagnostic pop
}

/* Turn on the checking by default for now (until we have fixed everything)*/
#define __check_low_ptr_bits_assignment
#if defined(_KERNEL) /* Don't pull in assert.h when building the kernel */
#define _cheri_bits_assert(e) (void)0
#endif
#ifdef __check_low_ptr_bits_assignment
#ifndef _cheri_bits_assert
#ifndef assert
#include <assert.h>
#endif
#define _cheri_bits_assert(e) assert(e)
#endif
#define __runtime_assert_sensible_low_bits(bits)                               \
  __extension__({                                                              \
    _cheri_bits_assert(bits < 32 && "Should only use the low 5 pointer bits"); \
    bits;                                                                      \
  })
#else
#define __runtime_assert_sensible_low_bits(bits) bits
#endif
#define __static_assert_sensible_low_bits(bits)                                \
  __extension__({                                                              \
    _Static_assert(bits < 32, "Should only use the low 5 pointer bits");       \
    bits;                                                                      \
  })

/*
 * Get the low bits defined in @p mask from the capability/pointer @p ptr.
 * @p mask must be a compile-time constant less than 31.
 * TODO: should we allow non-constant masks?
 *
 * @param ptr the uintptr_t that may have low bits sets
 * @param mask the mask for the low pointer bits to retrieve
 * @return a size_t containing the the low bits from @p ptr
 *
 * Rationale: this function is needed because extracting the low bits using a
 * bitwise-and operation returns a LHS-derived capability with the offset
 * field set to LHS.offset & mask. This is almost certainly not what the user
 * wanted since it will always compare not equal to any integer constant.
 * For example lots of mutex code uses something like `if ((x & 1) == 1)` to
 * detect if the lock is currently contented. This comparison always returns
 * false under CHERI the LHS of the == is a valid capability with offset 3 and
 * the RHS is an untagged intcap_t with offset 3.
 * See https://github.com/CTSRD-CHERI/clang/issues/189
 */
#define cheri_get_low_ptr_bits(ptr, mask)                                      \
  __cheri_get_low_ptr_bits((uintptr_t)(ptr), __static_assert_sensible_low_bits(mask))

/*
 * Set low bits in a uintptr_t
 *
 * @param ptr the uintptr_t that may have low bits sets
 * @param bits the value to bitwise-or with @p ptr.
 * @return a uintptr_t that has the low bits defined in @p mask set to @p bits
 *
 * @note this function is not strictly required since a plain bitwise or will
 * generally give the behaviour that is expected from other platforms but.
 * However, we can't really make the warning "-Wcheri-bitwise-operations"
 * trigger based on of the right hand side expression since it may not be a
 * compile-time constant.
 */
#define cheri_set_low_ptr_bits(ptr, bits)                                      \
  __cheri_set_low_ptr_bits((uintptr_t)(ptr), __runtime_assert_sensible_low_bits(bits))

/*
 * Clear the bits in @p mask from the capability/pointer @p ptr. Mask must be
 * a compile-time constant less than 31
 *
 * TODO: should we allow non-constant masks?
 *
 * @param ptr the uintptr_t that may have low bits sets
 * @param mask this is the mask for the low pointer bits, not the mask for
 * the bits that should remain set.
 * @return a uintptr_t that has the low bits defined in @p mask set to zeroes
 *
 * @note this function is not strictly required since a plain bitwise or will
 * generally give the behaviour that is expected from other platforms but.
 * However, we can't really make the warning "-Wcheri-bitwise-operations"
 * trigger based on of the right hand side expression since it may not be a
 * compile-time constant.
 *
 */
#define cheri_clear_low_ptr_bits(ptr, mask)                                    \
  __cheri_clear_low_ptr_bits((uintptr_t)(ptr), __static_assert_sensible_low_bits(mask))

#include <machine/cheric.h>

#endif /* _SYS_CHERIC_H_ */
