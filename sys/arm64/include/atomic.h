/*-
 * Copyright (c) 2013 Andrew Turner <andrew@freebsd.org>
 * All rights reserved.
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
 *
 * $FreeBSD$
 */

#ifndef	_MACHINE_ATOMIC_H_
#define	_MACHINE_ATOMIC_H_

#include <machine/cheri.h>

#define	isb()		__asm __volatile("isb" : : : "memory")

/*
 * Options for DMB and DSB:
 *	oshld	Outer Shareable, load
 *	oshst	Outer Shareable, store
 *	osh	Outer Shareable, all
 *	nshld	Non-shareable, load
 *	nshst	Non-shareable, store
 *	nsh	Non-shareable, all
 *	ishld	Inner Shareable, load
 *	ishst	Inner Shareable, store
 *	ish	Inner Shareable, all
 *	ld	Full system, load
 *	st	Full system, store
 *	sy	Full system, all
 */
#define	dsb(opt)	__asm __volatile("dsb " __STRING(opt) : : : "memory")
#define	dmb(opt)	__asm __volatile("dmb " __STRING(opt) : : : "memory")

#define	mb()	dmb(sy)	/* Full system memory barrier all */
#define	wmb()	dmb(st)	/* Full system memory barrier store */
#define	rmb()	dmb(ld)	/* Full system memory barrier load */

#if defined(SAN_NEEDS_INTERCEPTORS) && !defined(SAN_RUNTIME)
#include <sys/atomic_san.h>
#else

#include <sys/atomic_common.h>

#ifdef _KERNEL
extern bool lse_supported;

#ifdef LSE_ATOMICS
#define	_ATOMIC_LSE_SUPPORTED	1
#else
#define	_ATOMIC_LSE_SUPPORTED	lse_supported
#endif
#else
#define	_ATOMIC_LSE_SUPPORTED	0
#endif

#define	_ATOMIC_OP_PROTO(t, op, bar, flav)				\
static __inline void							\
atomic_##op##_##bar##t##flav(volatile uint##t##_t *p, uint##t##_t val)

#define	_ATOMIC_OP_IMPL(t, w, s, op, llsc_asm_op, lse_asm_op, pre, bar, a, l) \
_ATOMIC_OP_PROTO(t, op, bar, _llsc)					\
{									\
	uint##t##_t tmp;						\
	int res;							\
									\
	pre;								\
	__asm __volatile(						\
	    "1: ld"#a"xr"#s"	%"#w"0, [%2]\n"				\
	    "   "#llsc_asm_op"	%"#w"0, %"#w"0, %"#w"3\n"		\
	    "   st"#l"xr"#s"	%w1, %"#w"0, [%2]\n"			\
	    "   cbnz		%w1, 1b\n"				\
	    : "=&r"(tmp), "=&r"(res)					\
	    : ASM_PTR_CONSTR (p), "r" (val)				\
	    : "memory"							\
	);								\
}									\
									\
_ATOMIC_OP_PROTO(t, op, bar, _lse)					\
{									\
	uint##t##_t tmp;						\
									\
	pre;								\
	__asm __volatile(						\
	    ".arch_extension lse\n"					\
	    "ld"#lse_asm_op#a#l#s"	%"#w"2, %"#w"0, [%1]\n"		\
	    ".arch_extension nolse\n"					\
	    : "=r" (tmp)						\
	    : ASM_PTR_CONSTR (p), "r" (val)				\
	    : "memory"							\
	);								\
}									\
									\
_ATOMIC_OP_PROTO(t, op, bar, )						\
{									\
	if (_ATOMIC_LSE_SUPPORTED)					\
		atomic_##op##_##bar##t##_lse(p, val);			\
	else								\
		atomic_##op##_##bar##t##_llsc(p, val);			\
}

#define	__ATOMIC_OP(op, llsc_asm_op, lse_asm_op, pre, bar, a, l)	\
	_ATOMIC_OP_IMPL(8,  w, b, op, llsc_asm_op, lse_asm_op, pre,	\
	    bar, a, l)							\
	_ATOMIC_OP_IMPL(16, w, h, op, llsc_asm_op, lse_asm_op, pre,	\
	    bar, a, l)							\
	_ATOMIC_OP_IMPL(32, w,  , op, llsc_asm_op, lse_asm_op, pre,	\
	    bar, a, l)							\
	_ATOMIC_OP_IMPL(64,  ,  , op, llsc_asm_op, lse_asm_op, pre,	\
	    bar, a, l)

#define	_ATOMIC_OP(op, llsc_asm_op, lse_asm_op, pre)			\
	__ATOMIC_OP(op, llsc_asm_op, lse_asm_op, pre,     ,  ,  )	\
	__ATOMIC_OP(op, llsc_asm_op, lse_asm_op, pre, acq_, a,  )	\
	__ATOMIC_OP(op, llsc_asm_op, lse_asm_op, pre, rel_,  , l)

_ATOMIC_OP(add,      add, add, )
_ATOMIC_OP(clear,    bic, clr, )
_ATOMIC_OP(set,      orr, set, )
_ATOMIC_OP(subtract, add, add, val = -val)

#define	atomic_add_8		atomic_add_8
#define	atomic_clear_8		atomic_clear_8
#define	atomic_set_8		atomic_set_8
#define	atomic_subtract_8	atomic_subtract_8
#define	atomic_add_16		atomic_add_16
#define	atomic_clear_16		atomic_clear_16
#define	atomic_set_16		atomic_set_16
#define	atomic_subtract_16	atomic_subtract_16

#define	_ATOMIC_CMPSET_PROTO(t, bar, flav)				\
static __inline int							\
atomic_cmpset_##bar##t##flav(volatile uint##t##_t *p,			\
    uint##t##_t cmpval, uint##t##_t newval)

#define	_ATOMIC_FCMPSET_PROTO(t, bar, flav)				\
static __inline int							\
atomic_fcmpset_##bar##t##flav(volatile uint##t##_t *p,			\
    uint##t##_t *cmpval, uint##t##_t newval)

#define	_ATOMIC_CMPSET_IMPL(t, w, s, bar, a, l)				\
_ATOMIC_CMPSET_PROTO(t, bar, _llsc)					\
{									\
	uint##t##_t tmp;						\
	int res;							\
									\
	__asm __volatile(						\
	    "1: mov		%w1, #1\n"				\
	    "   ld"#a"xr"#s"	%"#w"0, [%2]\n"				\
	    "   cmp		%"#w"0, %"#w"3\n"			\
	    "   b.ne		2f\n"					\
	    "   st"#l"xr"#s"	%w1, %"#w"4, [%2]\n"			\
	    "   cbnz		%w1, 1b\n"				\
	    "2:"							\
	    : "=&r"(tmp), "=&r"(res)					\
	    : ASM_PTR_CONSTR (p), "r" (cmpval), "r" (newval)		\
	    : "cc", "memory"						\
	);								\
									\
	return (!res);							\
}									\
									\
_ATOMIC_CMPSET_PROTO(t, bar, _lse)					\
{									\
	uint##t##_t oldval;						\
	int res;							\
									\
	oldval = cmpval;						\
	__asm __volatile(						\
	    ".arch_extension lse\n"					\
	    "cas"#a#l#s"	%"#w"1, %"#w"4, [%3]\n"			\
	    "cmp		%"#w"1, %"#w"2\n"			\
	    "cset		%w0, eq\n"				\
	    ".arch_extension nolse\n"					\
	    : "=r" (res), "+&r" (cmpval)				\
	    : "r" (oldval), ASM_PTR_CONSTR (p), "r" (newval)		\
	    : "cc", "memory"						\
	);								\
									\
	return (res);							\
}									\
									\
_ATOMIC_CMPSET_PROTO(t, bar, )						\
{									\
	if (_ATOMIC_LSE_SUPPORTED)					\
		return (atomic_cmpset_##bar##t##_lse(p, cmpval,		\
		    newval));						\
	else								\
		return (atomic_cmpset_##bar##t##_llsc(p, cmpval,	\
		    newval));						\
}									\
									\
_ATOMIC_FCMPSET_PROTO(t, bar, _llsc)					\
{									\
	uint##t##_t _cmpval, tmp;					\
	int res;							\
									\
	_cmpval = *cmpval;						\
	__asm __volatile(						\
	    "   mov		%w1, #1\n"				\
	    "   ld"#a"xr"#s"	%"#w"0, [%2]\n"				\
	    "   cmp		%"#w"0, %"#w"3\n"			\
	    "   b.ne		1f\n"					\
	    "   st"#l"xr"#s"	%w1, %"#w"4, [%2]\n"			\
	    "1:"							\
	    : "=&r"(tmp), "=&r"(res)					\
	    : ASM_PTR_CONSTR (p), "r" (_cmpval), "r" (newval)		\
	    : "cc", "memory"						\
	);								\
	*cmpval = tmp;							\
									\
	return (!res);							\
}									\
									\
_ATOMIC_FCMPSET_PROTO(t, bar, _lse)					\
{									\
	uint##t##_t _cmpval, tmp;					\
	int res;							\
									\
	_cmpval = tmp = *cmpval;					\
	__asm __volatile(						\
	    ".arch_extension lse\n"					\
	    "cas"#a#l#s"	%"#w"1, %"#w"4, [%3]\n"			\
	    "cmp		%"#w"1, %"#w"2\n"			\
	    "cset		%w0, eq\n"				\
	    ".arch_extension nolse\n"					\
	    : "=r" (res), "+&r" (tmp)					\
	    : "r" (_cmpval), ASM_PTR_CONSTR (p), "r" (newval)	\
	    : "cc", "memory"						\
	);								\
	*cmpval = tmp;							\
									\
	return (res);							\
}									\
									\
_ATOMIC_FCMPSET_PROTO(t, bar, )						\
{									\
	if (_ATOMIC_LSE_SUPPORTED)					\
		return (atomic_fcmpset_##bar##t##_lse(p, cmpval,	\
		    newval));						\
	else								\
		return (atomic_fcmpset_##bar##t##_llsc(p, cmpval,	\
		    newval));						\
}

#define	_ATOMIC_CMPSET(bar, a, l)					\
	_ATOMIC_CMPSET_IMPL(8,  w, b, bar, a, l)			\
	_ATOMIC_CMPSET_IMPL(16, w, h, bar, a, l)			\
	_ATOMIC_CMPSET_IMPL(32, w,  , bar, a, l)			\
	_ATOMIC_CMPSET_IMPL(64,  ,  , bar, a, l)

#define	atomic_cmpset_8		atomic_cmpset_8
#define	atomic_fcmpset_8	atomic_fcmpset_8
#define	atomic_cmpset_16	atomic_cmpset_16
#define	atomic_fcmpset_16	atomic_fcmpset_16

_ATOMIC_CMPSET(    ,  , )
_ATOMIC_CMPSET(acq_, a, )
_ATOMIC_CMPSET(rel_,  ,l)

#define	_ATOMIC_FETCHADD_PROTO(t, flav)					\
static __inline uint##t##_t						\
atomic_fetchadd_##t##flav(volatile uint##t##_t *p, uint##t##_t val)

#define	_ATOMIC_FETCHADD_IMPL(t, w)					\
_ATOMIC_FETCHADD_PROTO(t, _llsc)					\
{									\
	uint##t##_t ret, tmp;						\
	int res;							\
									\
	__asm __volatile(						\
	    "1: ldxr	%"#w"2, [%3]\n"					\
	    "   add	%"#w"0, %"#w"2, %"#w"4\n"			\
	    "   stxr	%w1, %"#w"0, [%3]\n"				\
            "   cbnz	%w1, 1b\n"					\
	    : "=&r" (tmp), "=&r" (res), "=&r" (ret)			\
	    : ASM_PTR_CONSTR (p), "r" (val)				\
	    : "memory"							\
	);								\
									\
	return (ret);							\
}									\
									\
_ATOMIC_FETCHADD_PROTO(t, _lse)						\
{									\
	uint##t##_t ret;						\
									\
	__asm __volatile(						\
	    ".arch_extension lse\n"					\
	    "ldadd	%"#w"2, %"#w"0, [%1]\n"				\
	    ".arch_extension nolse\n"					\
	    : "=r" (ret)						\
	    : ASM_PTR_CONSTR (p), "r" (val)				\
	    : "memory"							\
	);								\
									\
	return (ret);							\
}									\
									\
_ATOMIC_FETCHADD_PROTO(t, )						\
{									\
	if (_ATOMIC_LSE_SUPPORTED)					\
		return (atomic_fetchadd_##t##_lse(p, val));		\
	else								\
		return (atomic_fetchadd_##t##_llsc(p, val));		\
}

_ATOMIC_FETCHADD_IMPL(32, w)
_ATOMIC_FETCHADD_IMPL(64,  )

#define	_ATOMIC_SWAP_PROTO(t, flav)					\
static __inline uint##t##_t						\
atomic_swap_##t##flav(volatile uint##t##_t *p, uint##t##_t val)

#define	_ATOMIC_READANDCLEAR_PROTO(t, flav)				\
static __inline uint##t##_t						\
atomic_readandclear_##t##flav(volatile uint##t##_t *p)

#define	_ATOMIC_SWAP_IMPL(t, w, zreg)					\
_ATOMIC_SWAP_PROTO(t, _llsc)						\
{									\
	uint##t##_t ret;						\
	int res;							\
									\
	__asm __volatile(						\
	    "1: ldxr	%"#w"1, [%2]\n"					\
	    "   stxr	%w0, %"#w"3, [%2]\n"				\
            "   cbnz	%w0, 1b\n"					\
	    : "=&r" (res), "=&r" (ret)					\
	    : ASM_PTR_CONSTR (p), "r" (val)				\
	    : "memory"							\
	);								\
									\
	return (ret);							\
}									\
									\
_ATOMIC_SWAP_PROTO(t, _lse)						\
{									\
	uint##t##_t ret;						\
									\
	__asm __volatile(						\
	    ".arch_extension lse\n"					\
	    "swp	%"#w"2, %"#w"0, [%1]\n"				\
	    ".arch_extension nolse\n"					\
	    : "=r" (ret)						\
	    : ASM_PTR_CONSTR (p), "r" (val)				\
	    : "memory"							\
	);								\
									\
	return (ret);							\
}									\
									\
_ATOMIC_SWAP_PROTO(t, )							\
{									\
	if (_ATOMIC_LSE_SUPPORTED)					\
		return (atomic_swap_##t##_lse(p, val));			\
	else								\
		return (atomic_swap_##t##_llsc(p, val));		\
}									\
									\
_ATOMIC_READANDCLEAR_PROTO(t, _llsc)					\
{									\
	uint##t##_t ret;						\
	int res;							\
									\
	__asm __volatile(						\
	    "1: ldxr	%"#w"1, [%2]\n"					\
	    "   stxr	%w0, "#zreg", [%2]\n"				\
	    "   cbnz	%w0, 1b\n"					\
	    : "=&r" (res), "=&r" (ret)					\
	    : ASM_PTR_CONSTR (p)					\
	    : "memory"							\
	);								\
									\
	return (ret);							\
}									\
									\
_ATOMIC_READANDCLEAR_PROTO(t, _lse)					\
{									\
	return (atomic_swap_##t##_lse(p, 0));				\
}									\
									\
_ATOMIC_READANDCLEAR_PROTO(t, )						\
{									\
	if (_ATOMIC_LSE_SUPPORTED)					\
		return (atomic_readandclear_##t##_lse(p));		\
	else								\
		return (atomic_readandclear_##t##_llsc(p));		\
}

_ATOMIC_SWAP_IMPL(32, w, wzr)
_ATOMIC_SWAP_IMPL(64,  , xzr)

#define	_ATOMIC_TEST_OP_PROTO(t, op, bar, flav)				\
static __inline int							\
atomic_testand##op##_##bar##t##flav(volatile uint##t##_t *p, u_int val)

#define	_ATOMIC_TEST_OP_IMPL(t, w, op, llsc_asm_op, lse_asm_op, bar, a)	\
_ATOMIC_TEST_OP_PROTO(t, op, bar, _llsc)				\
{									\
	uint##t##_t mask, old, tmp;					\
	int res;							\
									\
	mask = ((uint##t##_t)1) << (val & (t - 1));			\
	__asm __volatile(						\
	    "1: ld"#a"xr	%"#w"2, [%3]\n"				\
	    "  "#llsc_asm_op"	%"#w"0, %"#w"2, %"#w"4\n"		\
	    "   stxr		%w1, %"#w"0, [%3]\n"			\
	    "   cbnz		%w1, 1b\n"				\
	    : "=&r" (tmp), "=&r" (res), "=&r" (old)			\
	    : ASM_PTR_CONSTR (p), "r" (mask)				\
	    : "memory"							\
	);								\
									\
	return ((old & mask) != 0);					\
}									\
									\
_ATOMIC_TEST_OP_PROTO(t, op, bar, _lse)					\
{									\
	uint##t##_t mask, old;						\
									\
	mask = ((uint##t##_t)1) << (val & (t - 1));			\
	__asm __volatile(						\
	    ".arch_extension lse\n"					\
	    "ld"#lse_asm_op#a"	%"#w"2, %"#w"0, [%1]\n"			\
	    ".arch_extension nolse\n"					\
	    : "=r" (old)						\
	    : ASM_PTR_CONSTR (p), "r" (mask)			\
	    : "memory"							\
	);								\
									\
	return ((old & mask) != 0);					\
}									\
									\
_ATOMIC_TEST_OP_PROTO(t, op, bar, )					\
{									\
	if (_ATOMIC_LSE_SUPPORTED)					\
		return (atomic_testand##op##_##bar##t##_lse(p, val));	\
	else								\
		return (atomic_testand##op##_##bar##t##_llsc(p, val));	\
}

#define	_ATOMIC_TEST_OP(op, llsc_asm_op, lse_asm_op)			\
	_ATOMIC_TEST_OP_IMPL(32, w, op, llsc_asm_op, lse_asm_op,     ,  ) \
	_ATOMIC_TEST_OP_IMPL(32, w, op, llsc_asm_op, lse_asm_op, acq_, a) \
	_ATOMIC_TEST_OP_IMPL(64,  , op, llsc_asm_op, lse_asm_op,     ,  ) \
	_ATOMIC_TEST_OP_IMPL(64,  , op, llsc_asm_op, lse_asm_op, acq_, a)

_ATOMIC_TEST_OP(clear, bic, clr)
_ATOMIC_TEST_OP(set,   orr, set)

#define	_ATOMIC_LOAD_ACQ_IMPL(t, w, s)					\
static __inline uint##t##_t						\
atomic_load_acq_##t(volatile uint##t##_t *p)				\
{									\
	uint##t##_t ret;						\
									\
	__asm __volatile(						\
	    "ldar"#s"	%"#w"0, [%1]\n"					\
	    : "=&r" (ret)						\
	    : ASM_PTR_CONSTR (p)					\
	    : "memory");						\
									\
	return (ret);							\
}

#define	atomic_load_acq_8	atomic_load_acq_8
#define	atomic_load_acq_16	atomic_load_acq_16
_ATOMIC_LOAD_ACQ_IMPL(8,  w, b)
_ATOMIC_LOAD_ACQ_IMPL(16, w, h)
_ATOMIC_LOAD_ACQ_IMPL(32, w,  )
_ATOMIC_LOAD_ACQ_IMPL(64,  ,  )

#define	_ATOMIC_STORE_REL_IMPL(t, w, s)					\
static __inline void							\
atomic_store_rel_##t(volatile uint##t##_t *p, uint##t##_t val)		\
{									\
	__asm __volatile(						\
	    "stlr"#s"	%"#w"0, [%1]\n"					\
	    :								\
	    : "r" (val), ASM_PTR_CONSTR (p)				\
	    : "memory");						\
}

_ATOMIC_STORE_REL_IMPL(8,  w, b)
_ATOMIC_STORE_REL_IMPL(16, w, h)
_ATOMIC_STORE_REL_IMPL(32, w,  )
_ATOMIC_STORE_REL_IMPL(64,  ,  )

#define	atomic_add_char			atomic_add_8
#define	atomic_fcmpset_char		atomic_fcmpset_8
#define	atomic_clear_char		atomic_clear_8
#define	atomic_cmpset_char		atomic_cmpset_8
#define	atomic_fetchadd_char		atomic_fetchadd_8
#define	atomic_readandclear_char	atomic_readandclear_8
#define	atomic_set_char			atomic_set_8
#define	atomic_swap_char		atomic_swap_8
#define	atomic_subtract_char		atomic_subtract_8
#define	atomic_testandclear_char	atomic_testandclear_8
#define	atomic_testandset_char		atomic_testandset_8

#define	atomic_add_acq_char		atomic_add_acq_8
#define	atomic_fcmpset_acq_char		atomic_fcmpset_acq_8
#define	atomic_clear_acq_char		atomic_clear_acq_8
#define	atomic_cmpset_acq_char		atomic_cmpset_acq_8
#define	atomic_load_acq_char		atomic_load_acq_8
#define	atomic_set_acq_char		atomic_set_acq_8
#define	atomic_subtract_acq_char	atomic_subtract_acq_8
#define	atomic_testandset_acq_char	atomic_testandset_acq_8

#define	atomic_add_rel_char		atomic_add_rel_8
#define	atomic_fcmpset_rel_char		atomic_fcmpset_rel_8
#define	atomic_clear_rel_char		atomic_clear_rel_8
#define	atomic_cmpset_rel_char		atomic_cmpset_rel_8
#define	atomic_set_rel_char		atomic_set_rel_8
#define	atomic_subtract_rel_char	atomic_subtract_rel_8
#define	atomic_store_rel_char		atomic_store_rel_8

#define	atomic_add_short		atomic_add_16
#define	atomic_fcmpset_short		atomic_fcmpset_16
#define	atomic_clear_short		atomic_clear_16
#define	atomic_cmpset_short		atomic_cmpset_16
#define	atomic_fetchadd_short		atomic_fetchadd_16
#define	atomic_readandclear_short	atomic_readandclear_16
#define	atomic_set_short		atomic_set_16
#define	atomic_swap_short		atomic_swap_16
#define	atomic_subtract_short		atomic_subtract_16
#define	atomic_testandclear_short	atomic_testandclear_16
#define	atomic_testandset_short		atomic_testandset_16

#define	atomic_add_acq_short		atomic_add_acq_16
#define	atomic_fcmpset_acq_short	atomic_fcmpset_acq_16
#define	atomic_clear_acq_short		atomic_clear_acq_16
#define	atomic_cmpset_acq_short		atomic_cmpset_acq_16
#define	atomic_load_acq_short		atomic_load_acq_16
#define	atomic_set_acq_short		atomic_set_acq_16
#define	atomic_subtract_acq_short	atomic_subtract_acq_16
#define	atomic_testandset_acq_short	atomic_testandset_acq_16

#define	atomic_add_rel_short		atomic_add_rel_16
#define	atomic_fcmpset_rel_short	atomic_fcmpset_rel_16
#define	atomic_clear_rel_short		atomic_clear_rel_16
#define	atomic_cmpset_rel_short		atomic_cmpset_rel_16
#define	atomic_set_rel_short		atomic_set_rel_16
#define	atomic_subtract_rel_short	atomic_subtract_rel_16
#define	atomic_store_rel_short		atomic_store_rel_16

#define	atomic_add_int			atomic_add_32
#define	atomic_fcmpset_int		atomic_fcmpset_32
#define	atomic_clear_int		atomic_clear_32
#define	atomic_cmpset_int		atomic_cmpset_32
#define	atomic_fetchadd_int		atomic_fetchadd_32
#define	atomic_readandclear_int		atomic_readandclear_32
#define	atomic_set_int			atomic_set_32
#define	atomic_swap_int			atomic_swap_32
#define	atomic_subtract_int		atomic_subtract_32
#define	atomic_testandclear_int		atomic_testandclear_32
#define	atomic_testandset_int		atomic_testandset_32

#define	atomic_add_acq_int		atomic_add_acq_32
#define	atomic_fcmpset_acq_int		atomic_fcmpset_acq_32
#define	atomic_clear_acq_int		atomic_clear_acq_32
#define	atomic_cmpset_acq_int		atomic_cmpset_acq_32
#define	atomic_load_acq_int		atomic_load_acq_32
#define	atomic_set_acq_int		atomic_set_acq_32
#define	atomic_subtract_acq_int		atomic_subtract_acq_32
#define	atomic_testandset_acq_int	atomic_testandset_acq_32

#define	atomic_add_rel_int		atomic_add_rel_32
#define	atomic_fcmpset_rel_int		atomic_fcmpset_rel_32
#define	atomic_clear_rel_int		atomic_clear_rel_32
#define	atomic_cmpset_rel_int		atomic_cmpset_rel_32
#define	atomic_set_rel_int		atomic_set_rel_32
#define	atomic_subtract_rel_int		atomic_subtract_rel_32
#define	atomic_store_rel_int		atomic_store_rel_32

#define	atomic_add_long			atomic_add_64
#define	atomic_fcmpset_long		atomic_fcmpset_64
#define	atomic_clear_long		atomic_clear_64
#define	atomic_cmpset_long		atomic_cmpset_64
#define	atomic_fetchadd_long		atomic_fetchadd_64
#define	atomic_readandclear_long	atomic_readandclear_64
#define	atomic_set_long			atomic_set_64
#define	atomic_swap_long		atomic_swap_64
#define	atomic_subtract_long		atomic_subtract_64
#define	atomic_testandclear_long	atomic_testandclear_64
#define	atomic_testandset_long		atomic_testandset_64

#ifndef __CHERI_PURE_CAPABILITY__
#define	atomic_add_ptr			atomic_add_64
#define	atomic_fcmpset_ptr		atomic_fcmpset_64
#define	atomic_clear_ptr		atomic_clear_64
#define	atomic_cmpset_ptr		atomic_cmpset_64
#define	atomic_fetchadd_ptr		atomic_fetchadd_64
#define	atomic_readandclear_ptr		atomic_readandclear_64
#define	atomic_set_ptr			atomic_set_64
#define	atomic_swap_ptr			atomic_swap_64
#define	atomic_subtract_ptr		atomic_subtract_64
#endif

#define	atomic_add_acq_long		atomic_add_acq_64
#define	atomic_fcmpset_acq_long		atomic_fcmpset_acq_64
#define	atomic_clear_acq_long		atomic_clear_acq_64
#define	atomic_cmpset_acq_long		atomic_cmpset_acq_64
#define	atomic_load_acq_long		atomic_load_acq_64
#define	atomic_set_acq_long		atomic_set_acq_64
#define	atomic_subtract_acq_long	atomic_subtract_acq_64
#define	atomic_testandset_acq_long	atomic_testandset_acq_64

#ifndef __CHERI_PURE_CAPABILITY__
#define	atomic_add_acq_ptr		atomic_add_acq_64
#define	atomic_fcmpset_acq_ptr		atomic_fcmpset_acq_64
#define	atomic_clear_acq_ptr		atomic_clear_acq_64
#define	atomic_cmpset_acq_ptr		atomic_cmpset_acq_64
#define	atomic_load_acq_ptr		atomic_load_acq_64
#define	atomic_set_acq_ptr		atomic_set_acq_64
#define	atomic_subtract_acq_ptr		atomic_subtract_acq_64
#endif

#define	atomic_add_rel_long		atomic_add_rel_64
#define	atomic_fcmpset_rel_long		atomic_fcmpset_rel_64
#define	atomic_clear_rel_long		atomic_clear_rel_64
#define	atomic_cmpset_rel_long		atomic_cmpset_rel_64
#define	atomic_set_rel_long		atomic_set_rel_64
#define	atomic_subtract_rel_long	atomic_subtract_rel_64
#define	atomic_store_rel_long		atomic_store_rel_64

#ifndef __CHERI_PURE_CAPABILITY__
#define	atomic_add_rel_ptr		atomic_add_rel_64
#define	atomic_fcmpset_rel_ptr		atomic_fcmpset_rel_64
#define	atomic_clear_rel_ptr		atomic_clear_rel_64
#define	atomic_cmpset_rel_ptr		atomic_cmpset_rel_64
#define	atomic_set_rel_ptr		atomic_set_rel_64
#define	atomic_subtract_rel_ptr		atomic_subtract_rel_64
#define	atomic_store_rel_ptr		atomic_store_rel_64
#endif

#ifdef __CHERI_PURE_CAPABILITY__

#define	_ATOMIC_OP_PTR_IMPL(op, asm_op, bar, a, l)			\
static __inline void							\
atomic_##op##_##bar##ptr(volatile uintptr_t *p, uintptr_t val)		\
{									\
	uintptr_t previous;						\
	ptraddr_t tmp1, tmp2;						\
	int res;							\
									\
	__asm __volatile(						\
		"1:"							\
		"ld" #a "xr %0, [%4]\n"					\
		"gcvalue %2, %0\n"					\
		"gcvalue %3, %5\n"					\
		"" #asm_op " %2, %2, %3\n"				\
		"scvalue %0, %0, %2\n"					\
		"st" #l "xr %w1, %0, [%4]\n"				\
		"cbnz %w1, 1b"						\
		: "=&C" (previous), "=&r" (res), "=&r" (tmp1),		\
		"=&r" (tmp2)						\
		: "C" (p), "C" (val)					\
		: "memory", "cc");					\
}

#define	_ATOMIC_OP_PTR(op, asm_op)			\
	_ATOMIC_OP_PTR_IMPL(op, asm_op, , , )		\
	_ATOMIC_OP_PTR_IMPL(op, asm_op, acq_, a, )	\
	_ATOMIC_OP_PTR_IMPL(op, asm_op, rel_, , l)	\

_ATOMIC_OP_PTR(add, add)
_ATOMIC_OP_PTR(subtract, sub)
_ATOMIC_OP_PTR(clear, bic)
_ATOMIC_OP_PTR(set, orr)

static __inline uintptr_t
atomic_load_acq_ptr(volatile uintptr_t *p)
{
	return (__atomic_load_n(p, __ATOMIC_ACQUIRE));
}

static __inline void
atomic_store_rel_ptr(volatile uintptr_t *p, uintptr_t val)
{
	return (__atomic_store_n(p, val, __ATOMIC_RELEASE));
}

/*
 * XXX-AM: Do not use CAS in order to implement tag+VA comparison semantic
 * instead of bitwise capability equality.
 * The equality requirements for capability CAS require consistent
 * hi register bits clearing in locking code that is currently missing.
 */
#ifdef NOTYET
#define _ATOMIC_CMPSET_PTR_IMPL(bar, a, l, order)			\
_ATOMIC_CMPSET_PROTO(ptr, bar, )					\
{									\
	return (__atomic_compare_exchange_n(p, &cmpval, newval, 0,	\
	    order, order));						\
}									\
									\
_ATOMIC_FCMPSET_PROTO(ptr, bar, )					\
{									\
	return (__atomic_compare_exchange_n(p, cmpval, newval, 1,	\
	    order, order));						\
}
#else
#define _ATOMIC_CMPSET_PTR_IMPL(bar, a, l, _unused)			\
_ATOMIC_CMPSET_PROTO(ptr, bar, )					\
{									\
	uintptr_t tmp;							\
	int res;							\
									\
	__asm __volatile(						\
	    "1: mov		%w1, #1\n"				\
	    "   ld"#a"xr	%0, [%2]\n"				\
	    "   cmp		%0, %3\n"				\
	    "   b.ne		2f\n"					\
	    "   st"#l"xr	%w1, %4, [%2]\n"			\
	    "   cbnz		%w1, 1b\n"				\
	    "2:"							\
	    : "=&C"(tmp), "=&r"(res)					\
	    : "C" (p), "C" (cmpval), "C" (newval)			\
	    : "cc", "memory"						\
	);								\
									\
	return (!res);							\
}									\
									\
_ATOMIC_FCMPSET_PROTO(ptr, bar, )					\
{									\
	uintptr_t _cmpval, tmp;						\
	int res;							\
									\
	_cmpval = *cmpval;						\
	__asm __volatile(						\
	    "   mov		%w1, #1\n"				\
	    "   ld"#a"xr	%0, [%2]\n"				\
	    "   cmp		%0, %3\n"				\
	    "   b.ne		1f\n"					\
	    "   st"#l"xr	%w1, %4, [%2]\n"			\
	    "1:"							\
	    : "=&C"(tmp), "=&r"(res)					\
	    : "C" (p), "C" (_cmpval), "C" (newval)			\
	    : "cc", "memory"						\
	);								\
	*cmpval = tmp;							\
									\
	return (!res);							\
}
#endif

_ATOMIC_CMPSET_PTR_IMPL( , , , __ATOMIC_RELAXED)
_ATOMIC_CMPSET_PTR_IMPL(acq_, a, , __ATOMIC_ACQUIRE)
_ATOMIC_CMPSET_PTR_IMPL(rel_, , l, __ATOMIC_RELEASE)

static __inline uintptr_t
atomic_swap_ptr(volatile uintptr_t *p, uintptr_t val)
{

	return (__atomic_exchange_n(p, val, __ATOMIC_RELAXED));
}

static __inline uintptr_t
atomic_readandclear_ptr(volatile uintptr_t *p)
{
	return (__atomic_exchange_n(p, 0, __ATOMIC_RELAXED));
}

static __inline uintptr_t
atomic_fetchadd_ptr(volatile uintptr_t *p, uintptr_t val)
{
	return (__atomic_fetch_add(p, val, __ATOMIC_RELAXED));
}
#endif /* __CHERI_PURE_CAPABILITY__ */

static __inline void
atomic_thread_fence_acq(void)
{

	dmb(ld);
}

static __inline void
atomic_thread_fence_rel(void)
{

	dmb(sy);
}

static __inline void
atomic_thread_fence_acq_rel(void)
{

	dmb(sy);
}

static __inline void
atomic_thread_fence_seq_cst(void)
{

	dmb(sy);
}

#endif /* KCSAN && !KCSAN_RUNTIME */
#endif /* _MACHINE_ATOMIC_H_ */
