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

/* XXX-AM: causes circular dependency with pcpu.h through machine/pte.h */
//#include <sys/systm.h>
#include <sys/cdefs.h>
#include <sys/types.h>

#include <cheri/cherireg.h>	/* Permission definitions. */

#if __has_feature(capabilities)

/*
 * Programmer-friendly macros for CHERI-aware C code -- requires use of
 * CHERI-aware Clang/LLVM, and full capability context switching.
 */
#define	cheri_getlen(x)		__builtin_cheri_length_get((x))
#define	cheri_getlength(x)	__builtin_cheri_length_get((x))
#define	cheri_getbase(x)	__builtin_cheri_base_get((x))
#define	cheri_getoffset(x)	__builtin_cheri_offset_get((x))
#define	cheri_getaddress(x)	__builtin_cheri_address_get((x))
#define	cheri_getflags(x)	__builtin_cheri_flags_get((x))
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
#define	cheri_setflags(x, y)	__builtin_cheri_flags_set((x), (y))

#define	cheri_seal(x, y)	__builtin_cheri_seal((x), (y))
#define	cheri_unseal(x, y)	__builtin_cheri_unseal((x), (y))
#define	cheri_sealentry(x)	__builtin_cheri_seal_entry((x))

#define	cheri_ccheckperm(c, p)	__builtin_cheri_perms_check((c), (p))
#define	cheri_cchecktype(c, t)	__builtin_cheri_type_check((c), (t))

#define	cheri_getdefault()	__builtin_cheri_global_data_get()
#define	cheri_getpcc()		__builtin_cheri_program_counter_get()
#define	cheri_getstack()	__builtin_cheri_stack_get()

#define	cheri_local(c)		cheri_andperm((c), ~CHERI_PERM_GLOBAL)

#define	cheri_setbounds(x, y)	__builtin_cheri_bounds_set((x), (y))
#define	cheri_setboundsexact(x, y)	__builtin_cheri_bounds_set_exact((x), (y))

/* Create an untagged capability from an integer */
#define cheri_fromint(x)	cheri_incoffset(NULL, x)

/* Increment @p dst to have the address of @p src */
#define cheri_copyaddress(dst, src)	(cheri_setaddress(dst, cheri_getaddress(src)))

/*
 * XXX-AM: Ugly thing to make this importable from linux compat,
 * which redefines __always_inline
 */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wduplicate-decl-specifier"
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
 * Check whether a capability is NULL-derived
 */
#ifdef __cplusplus
static __always_inline inline bool
#else
static __always_inline inline _Bool
#endif
cheri_is_null_derived(const void * __capability cap)
{

	return (__builtin_cheri_equal_exact((uintcap_t)cheri_getaddress(cap),
	    cap));
}

#pragma clang diagnostic pop

#ifdef _KERNEL
/*
 * Test whether a capability is a subset of another.
 * This mimics the semantics of the experimental ctestsubset instruction.
 */
static __inline _Bool
cheri_is_subset(const void * __capability parent, const void * __capability ptr)
{

	return (cheri_gettag(parent) == cheri_gettag(ptr) &&
		cheri_getbase(ptr) >= cheri_getbase(parent) &&
		cheri_gettop(ptr) <= cheri_gettop(parent) &&
		(cheri_getperm(ptr) & cheri_getperm(parent)) == cheri_getperm(ptr));
}

#ifdef __CHERI_PURE_CAPABILITY__

/* Check that a capability is tagged */
#define	CHERI_ASSERT_VALID(ptr)						\
	KASSERT(cheri_gettag(ptr),					\
	    ("Expect valid capability %s %s:%d", __func__,		\
	        __FILE__, __LINE__))

/* Check that a capability is not sealed */
#define	CHERI_ASSERT_UNSEALED(ptr)					\
	KASSERT(!cheri_getsealed(ptr),					\
	    ("Expect unsealed capability %s %s:%d", __func__,		\
	        __FILE__, __LINE__))

/*
 * Check that bounds are within the given size, padded to
 * representable size
 */
#define	CHERI_ASSERT_BOUNDS(ptr, expect) do {				\
		KASSERT(cheri_getlen(ptr) <=				\
		    CHERI_REPRESENTABLE_LENGTH(expect),			\
		    ("Invalid bounds on pointer in %s %s:%d "		\
			 "expected %zx, found %zx",			\
			__func__, __FILE__, __LINE__,			\
			(size_t)expect,					\
			(size_t)cheri_getlen(ptr)));			\
	} while (0)

/* Check that bounds are exactly the given size */
#define	CHERI_ASSERT_EXBOUNDS(ptr, len) do {				\
		KASSERT(cheri_getlen(ptr) == len,			\
		    ("Inexact bounds on pointer in %s %s:%d "		\
			"expected %zx, found %zx",			\
			__func__, __FILE__, __LINE__,			\
			(size_t)len,					\
			(size_t)cheri_getlen(ptr)));			\
	} while (0)

#else /* !__CHERI_PURE_CAPABILITY__ */
#define	CHERI_ASSERT_VALID(ptr)
#define	CHERI_ASSERT_UNSEALED(ptr)
#define	CHERI_ASSERT_BOUNDS(ptr, expect)
#define	CHERI_ASSERT_EXBOUNDS(ptr, expect)
#endif /* !__CHERI_PURE_CAPABILITY__ */

/* Check that bounds are exactly the size of a pointer */
#define	CHERI_ASSERT_PTRSIZE_BOUNDS(ptr)		\
	CHERI_ASSERT_EXBOUNDS(ptr, sizeof(void * __capability))

#endif

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
#define cheri_codeptr(ptr, len)	\
	cheri_setbounds(__builtin_cheri_cap_from_pointer(cheri_getpcc(), ptr), len)

#define cheri_codeptrperm(ptr, len, perm)	\
	cheri_andperm(cheri_codeptr(ptr, len), perm | CHERI_PERM_GLOBAL)

#define cheri_ptr(ptr, len)	\
	cheri_setbounds(    \
	    (__cheri_tocap __typeof__(&*(ptr)) __capability)ptr, len)

#define cheri_ptrperm(ptr, len, perm)	\
	cheri_andperm(cheri_ptr(ptr, len), perm | CHERI_PERM_GLOBAL)

#define cheri_ptrpermoff(ptr, len, perm, off)	\
	cheri_setoffset(cheri_ptrperm(ptr, len, perm), off)

/*
 * Construct a capability suitable to describe a type identified by 'ptr';
 * set it to zero-length with the offset equal to the base.  The caller must
 * provide a root sealing capability.
 *
 * The caller may wish to assert various properties about the returned
 * capability, including that CHERI_PERM_SEAL is set.
 */
static inline otype_t
cheri_maketype(void * __capability root_type, register_t type)
{
	void * __capability c;

	c = root_type;
	c = cheri_setoffset(c, type);	/* Set type as desired. */
	c = cheri_setbounds(c, 1);	/* ISA implies length of 1. */
	c = cheri_andperm(c, CHERI_PERM_GLOBAL | CHERI_PERM_SEAL); /* Perms. */
	return (c);
}

static inline void * __capability
cheri_zerocap(void)
{
	return (void * __capability)0;
}

static inline uint64_t
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

#else /* ! __has_feature(capabilities) */
#ifdef _KERNEL
#define	CHERI_ASSERT_VALID(ptr)
#define	CHERI_ASSERT_BOUNDS(ptr, expect)
#define	CHERI_ASSERT_EXBOUNDS(ptr, len)
#define	CHERI_ASSERT_PTRSIZE_BOUNDS(ptr)
#endif
#endif /* ! __has_feature(capabilities) */

#if defined(_KERNEL) && defined(__CHERI_PURE_CAPABILITY__)
#define	cheri_kern_gettag(x)		cheri_gettag(x)
#define	cheri_kern_setbounds(x, y)	cheri_setbounds(x, y)
#define	cheri_kern_setboundsexact(x, y)	cheri_setboundsexact(x, y)
#define	cheri_kern_setaddress(x, y)	cheri_setaddress(x, y)
#define	cheri_kern_getaddress(x)	cheri_setaddress(x)
#define	cheri_kern_getbase(x)		cheri_getbase(x)
#else
#define	cheri_kern_gettag(x)					\
	(((x) == NULL || (vm_offset_t)(x) < 4096) ? 0 : 1)
#define	cheri_kern_setbounds(x, y)	(x)
#define	cheri_kern_setboundsexact(x, y)	(x)
#define	cheri_kern_setaddress(x, y)	((__typeof__(x))(y))
#define	cheri_kern_getaddress(x)	((uintptr_t)(x))
#define	cheri_kern_getbase(x)		((uintptr_t)(x))
#endif

/*
 * The cheri_{get,set,clear}_low_pointer_bits() functions work both with and
 * without CHERI support so can be used unconditionally to fix
 * -Wcheri-bitwise-operations warnings.
 *
 * XXXAR: Should kept in sync with the version from clang's cheri.h.
 */

/*
 * XXX-AM: Ugly thing to make this importable from linux compat,
 * which redefines __always_inline
 */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wduplicate-decl-specifier"

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
#pragma clang diagnostic pop

/* Turn on the checking by default for now (until we have fixed everything)*/
#define __check_low_ptr_bits_assignment
#if defined(_KERNEL) || !defined(assert) /* Don't pull in assert.h when building the kernel */
#define _cheri_bits_assert(e) (void)0
#endif
#ifdef __check_low_ptr_bits_assignment
#ifndef _cheri_bits_assert
#define _cheri_bits_assert(e) assert(e)
#endif
#define __runtime_assert_sensible_low_bits(bits)                               \
  __extension__({                                                              \
    _cheri_bits_assert((bits) < 32 && "Should only use the low 5 pointer bits"); \
    bits;                                                                      \
  })
#else
#define __runtime_assert_sensible_low_bits(bits) bits
#endif
#define __static_assert_sensible_low_bits(bits)                                \
  __extension__({                                                              \
    _Static_assert((bits) < 32, "Should only use the low 5 pointer bits");     \
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
  __cheri_clear_low_ptr_bits((uintptr_t)(ptr), __runtime_assert_sensible_low_bits(mask))

#if __has_feature(capabilities)
#include <machine/cheric.h>
#endif

#endif /* _SYS_CHERIC_H_ */
// CHERI CHANGES START
// {
//   "updated": 20190531,
//   "target_type": "header",
//   "changes_purecap": [
//     "support"
//   ]
// }
// CHERI CHANGES END
