/*-
 * Copyright (c) 2013-2016 Robert N. M. Watson
 * Copyright (c) 2021 Microsoft Corp.
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
#include <sys/stddef.h>
#include <sys/types.h>

#if __has_feature(capabilities)
#if !defined(_KERNEL) && !defined(_STANDALONE)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wignored-attributes"
#include <cheriintrin.h>
#pragma GCC diagnostic pop
#include <stdbool.h>
#endif

#include <cheri/cherireg.h>	/* Permission definitions. */

#if defined(_KERNEL) || defined(_STANDALONE)
/*
 * Programmer-friendly macros for CHERI-aware C code.  Mirrors
 * cheriintrin.h from Clang.
 */
#define	cheri_flags_get(x)	__builtin_cheri_flags_get(x)
#define	cheri_flags_set(x, y)	__builtin_cheri_flags_set((x), (y))
#define cheri_address_get(x)	__builtin_cheri_address_get(x)
#define cheri_address_set(x, y)	__builtin_cheri_address_set((x), (y))
#define cheri_base_get(x)	__builtin_cheri_base_get(x)
#define cheri_bounds_get(x)	__builtin_cheri_bounds_get(x)
#define cheri_bounds_set(x, y) __builtin_cheri_bounds_set((x), (y))
#define cheri_bounds_set_exact(x, y)					\
    __builtin_cheri_bounds_set_exact((x), (y))
#define cheri_cap_build(x, y)	__builtin_cheri_cap_build((x), (y))
#define cheri_ddc_get()		__builtin_cheri_global_data_get()
#define cheri_high_get(x)	__builtin_cheri_high_get(x)
#define cheri_high_set(x, y)	__builtin_cheri_high_set((x), (y))
#define cheri_is_equal_exact(x, y)					\
    __builtin_cheri_equal_exact((x), (y))
#define cheri_is_invalid(x)	(!__builtin_cheri_tag_get(x))
#define cheri_is_sealed(x)	__builtin_cheri_sealed_get(x)
#define cheri_is_sentry(x)						\
    (__builtin_cheri_type_get(x) == CHERI_OTYPE_SENTRY)
#define cheri_is_unsealed(x)	(!__builtin_cheri_sealed_get(x))
#define cheri_is_valid(x)	__builtin_cheri_tag_get(x)
#define cheri_length_get(x)	__builtin_cheri_length_get(x)
#define cheri_offset_get(x)	__builtin_cheri_offset_get(x)
#define cheri_offset_set(x, y)	__builtin_cheri_offset_set((x), (y))
#define cheri_pcc_get()		__builtin_cheri_program_counter_get()
#define cheri_perms_and(x, y)						\
    __builtin_cheri_perms_and((x), (__SIZE_TYPE__)(y))
#define cheri_perms_clear(x, y)						\
    __builtin_cheri_perms_and((x), ~(__SIZE_TYPE__)(y))
#define cheri_perms_get(x)	__builtin_cheri_perms_get(x)
#define cheri_seal(x, y)	__builtin_cheri_seal((x), (y))
#define cheri_seal_conditionally(x, y)				 	\
    __builtin_cheri_conditional_seal((x), (y))
#define cheri_sentry_create(x)	__builtin_cheri_seal_entry(x)
#define cheri_tag_clear(x)	__builtin_cheri_tag_clear(x)
#define cheri_tag_get(x)	__builtin_cheri_tag_get(x)
#define cheri_type_copy(x, y)	__builtin_cheri_cap_type_copy((x), (y))
#define cheri_type_get(x)	__builtin_cheri_type_get(x)
#define cheri_unseal(x, y)	__builtin_cheri_unseal((x), (y))

#endif /* defined(_KERNEL) || defined(_STANDALONE) */

#define __WANT_OLD_CHERI_MACROS
#ifdef __WANT_OLD_CHERI_MACROS
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

#define	cheri_buildcap(x, y)	__builtin_cheri_cap_build((x), (y))

#define	cheri_copytype(x, y)	__builtin_cheri_cap_type_copy((x), (y))

#define	cheri_seal(x, y)	__builtin_cheri_seal((x), (y))
#define	cheri_unseal(x, y)	__builtin_cheri_unseal((x), (y))
#define	cheri_sealentry(x)	__builtin_cheri_seal_entry((x))
#define	cheri_condseal(x, y)	__builtin_cheri_conditional_seal((x), (y))

#define	cheri_ccheckperm(c, p)	__builtin_cheri_perms_check((c), (p))
#define	cheri_cchecktype(c, t)	__builtin_cheri_type_check((c), (t))

#define	cheri_getdefault()	__builtin_cheri_global_data_get()
#define	cheri_getpcc()		__builtin_cheri_program_counter_get()
#define	cheri_getstack()	__builtin_cheri_stack_get()

#define	cheri_local(c)		cheri_andperm((c), ~CHERI_PERM_GLOBAL)

#define	cheri_setbounds(x, y)	__builtin_cheri_bounds_set((x), (y))
#define	cheri_setboundsexact(x, y)	__builtin_cheri_bounds_set_exact((x), (y))

/* Compare capabilities including bounds and perms etc. */
#define cheri_equal_exact(x, y) __builtin_cheri_equal_exact(x, y)

#endif /* __WANT_OLD_CHERI_MACROS */

#ifdef __riscv
#define	cheri_loadtags(m)						\
	__builtin_cheri_cap_load_tags((__cheri_tocap void * __capability)(m))
#else
#define	cheri_loadtags(m)	__builtin_cheri_cap_load_tags((m))
#endif

/*
 * Soft implementation of cheri_subset_test().
 * Test whether a capability is a subset of another.
 * NOTE: This is to be replaced by LLVM intrinsic once the intrinsic and
 * related instruction arguments are stable.
 */
#undef cheri_is_subset
#define        cheri_is_subset(parent, ptr)				\
	(cheri_tag_get(parent) == cheri_tag_get(ptr) &&			\
	 cheri_base_get(ptr) >= cheri_base_get(parent) &&		\
	 cheri_top_get(ptr) <= cheri_top_get(parent) &&			\
	 (cheri_perms_get(ptr) & cheri_perms_get(parent)) == cheri_perms_get(ptr))

#define	cheri_is_null_derived(x)					\
	cheri_is_equal_exact((uintcap_t)cheri_address_get(x), x)

/* Increment @p dst to have the address of @p src */
#define cheri_address_copy(dst, src)					\
	(cheri_address_set(dst, cheri_address_get(src)))

/* Get the top of a capability (i.e. one byte past the last accessible one) */
#define	cheri_top_get(cap)	__extension__({			\
	__typeof__(cap) c = (cap);				\
	(cheri_base_get(c) + cheri_length_get(c));		\
})

/* Check if the address is between cap.base and cap.top, i.e. in bounds */
static inline bool
cheri_is_address_inbounds(const void * __capability cap, ptraddr_t addr)
{
	return (addr >= cheri_base_get(cap) && addr < cheri_top_get(cap));
}

static inline size_t
cheri_bytes_remaining(const void * __capability cap)
{
	if (cheri_offset_get(cap) >= cheri_length_get(cap))
		return 0;
	return cheri_length_get(cap) - cheri_offset_get(cap);
}

#ifdef _KERNEL
/*
 * Check if the capability is valid, unsealed, has the given permissions and
 * grants access to length bytes at the current address
 */
static inline bool
cheri_can_access(const void * __capability cap, ptraddr_t perms,
    size_t length)
{
	return (cheri_tag_get(cap) && !cheri_is_sealed(cap) &&
	    (cheri_perms_get(cap) & perms) == perms &&
	    cheri_address_get(cap) >= cheri_base_get(cap) &&
	    length <= cheri_bytes_remaining(cap));
}
#endif

#define	cheri_stack_get()	__builtin_cheri_stack_get()

#endif	/* __has_feature(capabilities) */

#ifdef _KERNEL
#ifdef __CHERI_PURE_CAPABILITY__
#define	cheri_kern_tag_get(x)		cheri_tag_get(x)
#define	cheri_kern_bounds_set(x, y)	cheri_bounds_set(x, y)
#define	cheri_kern_bounds_set_exact(x, y)	cheri_bounds_set_exact(x, y)
#define	cheri_kern_address_set(x, y)	cheri_address_set(x, y)
#define	cheri_kern_address_get(x)	cheri_address_get(x)
#define	cheri_kern_perms_and(x, y)	cheri_perms_and(x, y)
#else
#define	cheri_kern_tag_get(x)		1
#define	cheri_kern_bounds_set(x, y)	(x)
#define	cheri_kern_bounds_set_exact(x, y)	(x)
#define	cheri_kern_address_set(x, y)	((__typeof__(x))(y))
#define	cheri_kern_address_get(x)	((uintptr_t)(x))
#define	cheri_kern_perms_and(x, y)	(x)
#endif	/* __CHERI_PURE_CAPABILITY__ */
#endif	/* _KERNEL */

#if __has_feature(capabilities)
#define	CHERI_REPRESENTABLE_LENGTH(len) \
	__builtin_cheri_round_representable_length(len)
#define	CHERI_REPRESENTABLE_ALIGNMENT_MASK(len) \
	__builtin_cheri_representable_alignment_mask(len)

#define	CHERI_ALIGN_SHIFT(l)	\
	__builtin_ctzll(CHERI_REPRESENTABLE_ALIGNMENT_MASK(l))

#else /* !__has_feature(capabilities) */
#define	CHERI_REPRESENTABLE_LENGTH(len) (len)
#define	CHERI_REPRESENTABLE_ALIGNMENT_MASK(len) UINT64_MAX
#endif /* !__has_feature(capabilities) */

/* Provide macros to make it easier to work with the raw CRAM/CRRL results: */
#define	CHERI_REPRESENTABLE_ALIGNMENT(len) \
	(~CHERI_REPRESENTABLE_ALIGNMENT_MASK(len) + 1)
#define	CHERI_REPRESENTABLE_ALIGN_DOWN(base, len) \
	((base) & CHERI_REPRESENTABLE_ALIGNMENT_MASK(len))

#if __has_feature(capabilities)
#define	CHERI_REPRESENTABLE_ALIGN_UP(base, len) \
	__align_up((base), CHERI_REPRESENTABLE_ALIGNMENT(len))
#else
#define	CHERI_REPRESENTABLE_ALIGN_UP(base, len) (base)
#endif

#define	CHERI_ALIGN_MASK(l)		~(CHERI_REPRESENTABLE_ALIGNMENT_MASK(l))

#if __has_feature(capabilities)
#include <machine/cheric.h>
#endif

#ifndef _KERNEL
ssize_t	strfcap(char * __restrict buf, size_t maxsize,
    const char * __restrict format, uintcap_t cap);
#endif

#endif /* _SYS_CHERIC_H_ */
// CHERI CHANGES START
// {
//   "updated": 20230509,
//   "target_type": "header",
//   "changes": [
//     "support",
//     "ctoptr"
//   ],
//   "changes_purecap": [
//     "support"
//   ]
// }
// CHERI CHANGES END
