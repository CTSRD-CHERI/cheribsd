/*-
 * Copyright (c) 2015 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * Portions of this software were developed by SRI International and the
 * University of Cambridge Computer Laboratory under DARPA/AFRL contract
 * FA8750-10-C-0237 ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Portions of this software were developed by the University of Cambridge
 * Computer Laboratory as part of the CTSRD Project, with support from the
 * UK Higher Education Innovation Fund (HEIF).
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

#include <sys/atomic_common.h>

#define	fence()	__asm __volatile("fence" ::: "memory");
#define	mb()	fence()
#define	rmb()	fence()
#define	wmb()	fence()

static __inline int atomic_cmpset_8(__volatile uint8_t *, uint8_t, uint8_t);
static __inline int atomic_fcmpset_8(__volatile uint8_t *, uint8_t *, uint8_t);
static __inline int atomic_cmpset_16(__volatile uint16_t *, uint16_t, uint16_t);
static __inline int atomic_fcmpset_16(__volatile uint16_t *, uint16_t *,
    uint16_t);

#define	ATOMIC_ACQ_REL(NAME, WIDTH)					\
static __inline  void							\
atomic_##NAME##_acq_##WIDTH(__volatile uint##WIDTH##_t *p, uint##WIDTH##_t v)\
{									\
	atomic_##NAME##_##WIDTH(p, v);					\
	fence(); 							\
}									\
									\
static __inline  void							\
atomic_##NAME##_rel_##WIDTH(__volatile uint##WIDTH##_t *p, uint##WIDTH##_t v)\
{									\
	fence();							\
	atomic_##NAME##_##WIDTH(p, v);					\
}

#define	ATOMIC_CMPSET_ORDER(WIDTH, SUFFIX, ORDER)			\
static __inline  int							\
atomic_cmpset##SUFFIX##WIDTH(__volatile uint##WIDTH##_t *p,		\
    uint##WIDTH##_t cmpval, uint##WIDTH##_t newval)			\
{									\
									\
	/* Return 1 on success, 0 on failure */				\
	return (__atomic_compare_exchange_n(				\
	    p, &cmpval, newval, 0, ORDER, ORDER));			\
}

#define	ATOMIC_FCMPSET_ORDER(WIDTH, SUFFIX, ORDER)			\
static __inline  int							\
atomic_fcmpset##SUFFIX##WIDTH(__volatile uint##WIDTH##_t *p,		\
    uint##WIDTH##_t* cmpval, uint##WIDTH##_t newval)			\
{									\
									\
	/* fcmpset updates cmpval on failure and uses weak cmpxchg */	\
	return (__atomic_compare_exchange_n(				\
	    p, cmpval, newval, 1, ORDER, ORDER));			\
}


#define	ATOMIC_CMPSET_ACQ_REL(WIDTH)					\
	ATOMIC_CMPSET_ORDER(WIDTH, _acq_, __ATOMIC_ACQUIRE)		\
	ATOMIC_CMPSET_ORDER(WIDTH, _rel_, __ATOMIC_RELEASE)

#define	ATOMIC_CMPSET(WIDTH)						\
	ATOMIC_CMPSET_ORDER(WIDTH, _, __ATOMIC_RELAXED)			\
	ATOMIC_CMPSET_ACQ_REL(WIDTH)

#define	ATOMIC_FCMPSET_ACQ_REL(WIDTH)					\
	ATOMIC_FCMPSET_ORDER(WIDTH, _acq_, __ATOMIC_ACQUIRE)		\
	ATOMIC_FCMPSET_ORDER(WIDTH, _rel_, __ATOMIC_RELEASE)

#define	ATOMIC_FCMPSET(WIDTH)						\
	ATOMIC_FCMPSET_ORDER(WIDTH, _, __ATOMIC_RELAXED)		\
	ATOMIC_FCMPSET_ACQ_REL(WIDTH)					\

#ifdef __CHERI_PURE_CAPABILITY__
/*
 * In a purecap kernel we cannot use the generic sub-word implementation.
 */
ATOMIC_CMPSET(8);
ATOMIC_FCMPSET(8);
ATOMIC_CMPSET(16);
ATOMIC_FCMPSET(16);
#define	atomic_cmpset_8		atomic_cmpset_8
#define	atomic_fcmpset_8		atomic_fcmpset_8
#define	atomic_cmpset_16		atomic_cmpset_16
#define	atomic_fcmpset_16		atomic_fcmpset_16
#else
ATOMIC_CMPSET_ACQ_REL(8);
ATOMIC_FCMPSET_ACQ_REL(8);
ATOMIC_CMPSET_ACQ_REL(16);
ATOMIC_FCMPSET_ACQ_REL(16);
#endif

#define	atomic_cmpset_char		atomic_cmpset_8
#define	atomic_cmpset_acq_char		atomic_cmpset_acq_8
#define	atomic_cmpset_rel_char		atomic_cmpset_rel_8
#define	atomic_fcmpset_char		atomic_fcmpset_8
#define	atomic_fcmpset_acq_char		atomic_fcmpset_acq_8
#define	atomic_fcmpset_rel_char		atomic_fcmpset_rel_8

#define	atomic_cmpset_short		atomic_cmpset_16
#define	atomic_cmpset_acq_short		atomic_cmpset_acq_16
#define	atomic_cmpset_rel_short		atomic_cmpset_rel_16
#define	atomic_fcmpset_short		atomic_fcmpset_16
#define	atomic_fcmpset_acq_short	atomic_fcmpset_acq_16
#define	atomic_fcmpset_rel_short	atomic_fcmpset_rel_16

#define	ATOMIC_OP_IMPL(WIDTH, OP, FN, PRE)					\
	static __inline void							\
	atomic_##OP##_##WIDTH(volatile uint##WIDTH##_t *p, uint##WIDTH##_t val)	\
	{									\
		PRE;								\
		(void)__atomic_##FN##_fetch(p, val, __ATOMIC_RELAXED);		\
	}

#define	ATOMIC_SET(WIDTH) ATOMIC_OP_IMPL(WIDTH, set, or, )
#define	ATOMIC_CLEAR(WIDTH) ATOMIC_OP_IMPL(WIDTH, clear, and, val = ~val)
#define	ATOMIC_ADD(WIDTH) ATOMIC_OP_IMPL(WIDTH, add, add, )
#define	ATOMIC_SUB(WIDTH) ATOMIC_OP_IMPL(WIDTH, subtract, sub, )

#ifdef __CHERI_PURE_CAPABILITY__
ATOMIC_SET(8)
ATOMIC_SET(16)
#define	atomic_set_8	atomic_set_8
#define	atomic_set_16	atomic_set_16

ATOMIC_CLEAR(8)
ATOMIC_CLEAR(16)
#define	atomic_clear_8	atomic_clear_8
#define	atomic_clear_16	atomic_clear_16

ATOMIC_ADD(8)
ATOMIC_ADD(16)
#define	atomic_add_8	atomic_add_8
#define	atomic_add_16	atomic_add_16

ATOMIC_SUB(8)
ATOMIC_SUB(16)
#define	atomic_subtract_8	atomic_subtract_8
#define	atomic_subtract_16	atomic_subtract_16

ATOMIC_ACQ_REL(set, 8)
ATOMIC_ACQ_REL(set, 16)
ATOMIC_ACQ_REL(clear, 8)
ATOMIC_ACQ_REL(clear, 16)
ATOMIC_ACQ_REL(add, 8)
ATOMIC_ACQ_REL(add, 16)
ATOMIC_ACQ_REL(subtract, 8)
ATOMIC_ACQ_REL(subtract, 16)
#endif

ATOMIC_ADD(32)
ATOMIC_SUB(32)
ATOMIC_SET(32)
ATOMIC_CLEAR(32)

static __inline uint32_t
atomic_fetchadd_32(volatile uint32_t *p, uint32_t val)
{

	return (__atomic_fetch_add(p, val, __ATOMIC_RELAXED));
}

static __inline uint32_t
atomic_readandclear_32(volatile uint32_t *p)
{

	return (__atomic_exchange_n(p, 0, __ATOMIC_RELAXED));
}

#define	atomic_add_int		atomic_add_32
#define	atomic_clear_int	atomic_clear_32
#define	atomic_cmpset_int	atomic_cmpset_32
#define	atomic_fcmpset_int	atomic_fcmpset_32
#define	atomic_fetchadd_int	atomic_fetchadd_32
#define	atomic_readandclear_int	atomic_readandclear_32
#define	atomic_set_int		atomic_set_32
#define	atomic_subtract_int	atomic_subtract_32

ATOMIC_ACQ_REL(set, 32)
ATOMIC_ACQ_REL(clear, 32)
ATOMIC_ACQ_REL(add, 32)
ATOMIC_ACQ_REL(subtract, 32)

ATOMIC_CMPSET(32)
ATOMIC_FCMPSET(32)

static __inline uint32_t
atomic_load_acq_32(volatile uint32_t *p)
{

	return (__atomic_load_n(p, __ATOMIC_ACQUIRE));
}

static __inline void
atomic_store_rel_32(volatile uint32_t *p, uint32_t val)
{

	__atomic_store_n(p, val, __ATOMIC_RELEASE);
}

#define	atomic_add_acq_int	atomic_add_acq_32
#define	atomic_clear_acq_int	atomic_clear_acq_32
#define	atomic_cmpset_acq_int	atomic_cmpset_acq_32
#define	atomic_fcmpset_acq_int	atomic_fcmpset_acq_32
#define	atomic_load_acq_int	atomic_load_acq_32
#define	atomic_set_acq_int	atomic_set_acq_32
#define	atomic_subtract_acq_int	atomic_subtract_acq_32

#define	atomic_add_rel_int	atomic_add_rel_32
#define	atomic_clear_rel_int	atomic_clear_rel_32
#define	atomic_cmpset_rel_int	atomic_cmpset_rel_32
#define	atomic_fcmpset_rel_int	atomic_fcmpset_rel_32
#define	atomic_set_rel_int	atomic_set_rel_32
#define	atomic_subtract_rel_int	atomic_subtract_rel_32
#define	atomic_store_rel_int	atomic_store_rel_32

ATOMIC_ADD(64)
ATOMIC_SUB(64)
ATOMIC_SET(64)
ATOMIC_CLEAR(64)

static __inline uint64_t
atomic_fetchadd_64(volatile uint64_t *p, uint64_t val)
{

	return (__atomic_fetch_add(p, val, __ATOMIC_RELAXED));
}

static __inline uint64_t
atomic_readandclear_64(volatile uint64_t *p)
{

	return (__atomic_exchange_n(p, 0, __ATOMIC_RELAXED));
}

static __inline uint32_t
atomic_swap_32(volatile uint32_t *p, uint32_t val)
{

	return (__atomic_exchange_n(p, val, __ATOMIC_RELAXED));
}

static __inline uint64_t
atomic_swap_64(volatile uint64_t *p, uint64_t val)
{

	return (__atomic_exchange_n(p, val, __ATOMIC_RELAXED));
}

#ifdef __CHERI_PURE_CAPABILITY__
static __inline uintptr_t
atomic_swap_ptr(volatile uintptr_t *p, uintptr_t val)
{

	return (__atomic_exchange_n(p, val, __ATOMIC_RELAXED));
}
#endif

#define	atomic_swap_int			atomic_swap_32

#define	atomic_add_long			atomic_add_64
#define	atomic_clear_long		atomic_clear_64
#define	atomic_cmpset_long		atomic_cmpset_64
#define	atomic_fcmpset_long		atomic_fcmpset_64
#define	atomic_fetchadd_long		atomic_fetchadd_64
#define	atomic_readandclear_long	atomic_readandclear_64
#define	atomic_set_long			atomic_set_64
#define	atomic_subtract_long		atomic_subtract_64
#define	atomic_swap_long		atomic_swap_64

#ifndef __CHERI_PURE_CAPABILITY__
#define	atomic_add_ptr			atomic_add_64
#define	atomic_clear_ptr		atomic_clear_64
#define	atomic_cmpset_ptr		atomic_cmpset_64
#define	atomic_fcmpset_ptr		atomic_fcmpset_64
#define	atomic_fetchadd_ptr		atomic_fetchadd_64
#define	atomic_readandclear_ptr		atomic_readandclear_64
#define	atomic_set_ptr			atomic_set_64
#define	atomic_subtract_ptr		atomic_subtract_64
#define	atomic_swap_ptr			atomic_swap_64
#endif

ATOMIC_ACQ_REL(set, 64)
ATOMIC_ACQ_REL(clear, 64)
ATOMIC_ACQ_REL(add, 64)
ATOMIC_ACQ_REL(subtract, 64)

ATOMIC_CMPSET(64)
ATOMIC_FCMPSET(64)

static __inline uint64_t
atomic_load_acq_64(volatile uint64_t *p)
{

	return (__atomic_load_n(p, __ATOMIC_ACQUIRE));
}

static __inline void
atomic_store_rel_64(volatile uint64_t *p, uint64_t val)
{

	__atomic_store_n(p, val, __ATOMIC_RELEASE);
}

#define	atomic_add_acq_long		atomic_add_acq_64
#define	atomic_clear_acq_long		atomic_clear_acq_64
#define	atomic_cmpset_acq_long		atomic_cmpset_acq_64
#define	atomic_fcmpset_acq_long		atomic_fcmpset_acq_64
#define	atomic_load_acq_long		atomic_load_acq_64
#define	atomic_set_acq_long		atomic_set_acq_64
#define	atomic_subtract_acq_long	atomic_subtract_acq_64

#ifndef __CHERI_PURE_CAPABILITY__
#define	atomic_add_acq_ptr		atomic_add_acq_64
#define	atomic_clear_acq_ptr		atomic_clear_acq_64
#define	atomic_cmpset_acq_ptr		atomic_cmpset_acq_64
#define	atomic_fcmpset_acq_ptr		atomic_fcmpset_acq_64
#define	atomic_load_acq_ptr		atomic_load_acq_64
#define	atomic_set_acq_ptr		atomic_set_acq_64
#define	atomic_subtract_acq_ptr		atomic_subtract_acq_64
#endif

#ifdef __CHERI_PURE_CAPABILITY__
static __inline void
atomic_add_ptr(volatile uintptr_t *p, uintptr_t val)
{

	(void)__atomic_add_fetch(p, val, __ATOMIC_RELAXED);
}

static __inline void
atomic_subtract_ptr(volatile uintptr_t *p, uintptr_t val)
{

	(void)__atomic_sub_fetch(p, val, __ATOMIC_RELAXED);

}

static __inline void
atomic_set_ptr(volatile uintptr_t *p, uintptr_t val)
{

#ifdef notyet
	(void)__atomic_or_fetch(p, val, __ATOMIC_RELAXED);
#else
	uintptr_t temp1;
	u_long temp2;

	__asm __volatile(
		"1:	clr.c	%1, %0\n"
		"	cgetaddr %2, %1\n"
		"	or	%2, %2, %3\n"
		"	csetaddr %1, %1, %2\n"
		"	csc.c	%2, %1, %0\n"
		"	bnez	%2, 1b\n"
		: "+A" (*p), "=&C" (temp1), "=&r" (temp2)
		: "r" ((ptraddr_t)val)
		: "memory");
#endif
}

static __inline void
atomic_clear_ptr(volatile uintptr_t *p, uintptr_t val)
{

#ifdef notyet
	(void)__atomic_and_fetch(p, ~val, __ATOMIC_RELAXED);
#else
	uintptr_t temp1;
	u_long temp2;

	__asm __volatile(
		"1:	clr.c	%1, %0\n"
		"	cgetaddr %2, %1\n"
		"	and	%2, %2, %3\n"
		"	csetaddr %1, %1, %2\n"
		"	csc.c	%2, %1, %0\n"
		"	bnez	%2, 1b\n"
		: "+A" (*p), "=&C" (temp1), "=&r" (temp2)
		: "r" (~(ptraddr_t)val)
		: "memory");
#endif
}

static __inline uintptr_t
atomic_fetchadd_ptr(volatile uintptr_t *p, uintptr_t val)
{

	return (__atomic_fetch_add(p, val, __ATOMIC_RELAXED));
}

static __inline uintptr_t
atomic_readandclear_ptr(volatile uintptr_t *p)
{

	return (__atomic_exchange_n(p, 0, __ATOMIC_RELAXED));
}

ATOMIC_ACQ_REL(set, ptr);
ATOMIC_ACQ_REL(clear, ptr);
ATOMIC_ACQ_REL(add, ptr);
ATOMIC_ACQ_REL(subtract, ptr);

ATOMIC_CMPSET(ptr);
ATOMIC_FCMPSET(ptr);

static __inline uintptr_t
atomic_load_acq_ptr(volatile uintptr_t *p)
{

	return (__atomic_load_n(p, __ATOMIC_ACQUIRE));
}

static __inline void
atomic_store_rel_ptr(volatile uintptr_t *p, uintptr_t val)
{

	__atomic_store_n(p, val, __ATOMIC_RELEASE);
}
#endif

#undef ATOMIC_ACQ_REL

static __inline void
atomic_thread_fence_acq(void)
{

	__atomic_thread_fence(__ATOMIC_ACQUIRE);
}

static __inline void
atomic_thread_fence_rel(void)
{

	__atomic_thread_fence(__ATOMIC_RELEASE);
}

static __inline void
atomic_thread_fence_acq_rel(void)
{

	__atomic_thread_fence(__ATOMIC_ACQ_REL);
}

static __inline void
atomic_thread_fence_seq_cst(void)
{

	__atomic_thread_fence(__ATOMIC_SEQ_CST);
}

#define	atomic_add_rel_long		atomic_add_rel_64
#define	atomic_clear_rel_long		atomic_clear_rel_64

#define	atomic_add_rel_long		atomic_add_rel_64
#define	atomic_clear_rel_long		atomic_clear_rel_64
#define	atomic_cmpset_rel_long		atomic_cmpset_rel_64
#define	atomic_fcmpset_rel_long		atomic_fcmpset_rel_64
#define	atomic_set_rel_long		atomic_set_rel_64
#define	atomic_subtract_rel_long	atomic_subtract_rel_64
#define	atomic_store_rel_long		atomic_store_rel_64

#ifndef __CHERI_PURE_CAPABILITY__
#define	atomic_add_rel_ptr		atomic_add_rel_64
#define	atomic_clear_rel_ptr		atomic_clear_rel_64
#define	atomic_cmpset_rel_ptr		atomic_cmpset_rel_64
#define	atomic_fcmpset_rel_ptr		atomic_fcmpset_rel_64
#define	atomic_set_rel_ptr		atomic_set_rel_64
#define	atomic_subtract_rel_ptr		atomic_subtract_rel_64
#define	atomic_store_rel_ptr		atomic_store_rel_64
#endif

#include <sys/_atomic_subword.h>

#endif /* _MACHINE_ATOMIC_H_ */
// CHERI CHANGES START
// {
//   "updated": 20221205,
//   "target_type": "kernel",
//   "changes_purecap": [
//     "pointer_as_integer"
//   ]
// }
// CHERI CHANGES END
