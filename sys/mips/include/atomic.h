/*-
 * Copyright (c) 1998 Doug Rabson
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
 *	from: src/sys/alpha/include/atomic.h,v 1.21.2.3 2005/10/06 18:12:05 jhb
 * $FreeBSD$
 */

#ifndef _MACHINE_ATOMIC_H_
#define	_MACHINE_ATOMIC_H_

#ifndef _SYS_CDEFS_H_
#error this file needs sys/cdefs.h as a prerequisite
#endif
//#include <stdatomic.h>

/* XXX-AM: defines similar to what stdatomic provides */
#define atomic_thread_fence(order) __c11_atomic_thread_fence(order)
#define atomic_store(object, desired)			\
  __c11_atomic_store(object, desired, __ATOMIC_SEQ_CST)
#define atomic_store_explicit __c11_atomic_store

#define atomic_load(object) __c11_atomic_load(object, __ATOMIC_SEQ_CST)
#define atomic_load_explicit __c11_atomic_load

#define atomic_exchange(object, desired)			\
	__c11_atomic_exchange(object, desired, __ATOMIC_SEQ_CST)
#define atomic_exchange_explicit __c11_atomic_exchange

#define atomic_compare_exchange_strong(object, expected, desired)	\
  __c11_atomic_compare_exchange_strong(object, expected, desired,	\
				       __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
#define atomic_compare_exchange_strong_explicit \
  __c11_atomic_compare_exchange_strong

#define atomic_compare_exchange_weak(object, expected, desired)		\
  __c11_atomic_compare_exchange_weak(object, expected, desired,		\
				     __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
#define atomic_compare_exchange_weak_explicit	\
  __c11_atomic_compare_exchange_weak

#define atomic_fetch_add(object, operand)			\
  __c11_atomic_fetch_add(object, operand, __ATOMIC_SEQ_CST)
#define atomic_fetch_add_explicit __c11_atomic_fetch_add

#define atomic_fetch_sub(object, operand)			\
  __c11_atomic_fetch_sub(object, operand, __ATOMIC_SEQ_CST)
#define atomic_fetch_sub_explicit __c11_atomic_fetch_sub

#define atomic_fetch_or(object, operand)			\
  __c11_atomic_fetch_or(object, operand, __ATOMIC_SEQ_CST)
#define atomic_fetch_or_explicit __c11_atomic_fetch_or

#define atomic_fetch_xor(object, operand)			\
  __c11_atomic_fetch_xor(object, operand, __ATOMIC_SEQ_CST)
#define atomic_fetch_xor_explicit __c11_atomic_fetch_xor

#define atomic_fetch_and(object, operand)			\
  __c11_atomic_fetch_and(object, operand, __ATOMIC_SEQ_CST)
#define atomic_fetch_and_explicit __c11_atomic_fetch_and

/*
 * Note: All the 64-bit atomic operations are only atomic when running
 * in 64-bit mode.  It is assumed that code compiled for n32 and n64
 * fits into this definition and no further safeties are needed.
 *
 * It is also assumed that the add, subtract and other arithmetic is
 * done on numbers not pointers.  The special rules for n32 pointers
 * do not have atomic operations defined for them, but generally shouldn't
 * need atomic operations.
 */
#ifndef __MIPS_PLATFORM_SYNC_NOPS
#define __MIPS_PLATFORM_SYNC_NOPS ""
#endif

static __inline  void
mips_sync(void)
{
	__asm __volatile (".set noreorder\n"
			"\tsync\n"
			__MIPS_PLATFORM_SYNC_NOPS
			".set reorder\n"
			: : : "memory");
}

#define mb()	mips_sync()
#define wmb()	mips_sync()
#define rmb()	mips_sync()

/*
 * Various simple arithmetic on memory which is atomic in the presence
 * of interrupts and SMP safe.
 */

#define ATOMIC_SET(WIDTH, TYPE)						\
static __inline  void							\
atomic_set_##WIDTH(__volatile TYPE *p, TYPE v)				\
{									\
	__volatile _Atomic(TYPE) *ptr = (__volatile _Atomic(TYPE)*)p;	\
	TYPE expected = atomic_load(ptr), desired;			\
	do {								\
		desired = expected | v;					\
	} while (!(atomic_compare_exchange_weak(ptr, &expected, desired))); \
}

#define ATOMIC_CLEAR(WIDTH, TYPE)					\
static __inline void							\
atomic_clear_##WIDTH(__volatile TYPE *p, TYPE v)			\
{									\
	__volatile _Atomic(TYPE) *ptr = (__volatile _Atomic(TYPE)*)p;	\
	TYPE expected = atomic_load(ptr), desired;			\
	do {								\
		desired = expected & ~v;				\
	} while (!atomic_compare_exchange_weak(ptr, &expected, desired)); \
}

#define ATOMIC_ADD(WIDTH, TYPE)						\
static __inline void							\
atomic_add_##WIDTH(__volatile TYPE *p, TYPE v)				\
{									\
	atomic_fetch_add((__volatile _Atomic(TYPE)*)p, v);		\
}

#define ATOMIC_SUB(WIDTH, TYPE)						\
static __inline void							\
atomic_subtract_##WIDTH(__volatile TYPE *p, TYPE v)			\
{									\
		atomic_fetch_sub((__volatile _Atomic(TYPE)*)p, v);	\
}

#define ATOMIC_READANDCLEAR(WIDTH, TYPE)				\
static __inline TYPE							\
atomic_readandclear_##WIDTH(__volatile TYPE *addr)			\
{									\
	__volatile _Atomic(TYPE) *ptr = (__volatile _Atomic(TYPE)*)addr; \
	TYPE expected = atomic_load(ptr);				\
									\
	do {								\
	} while (!atomic_compare_exchange_weak(ptr, &expected, 0));	\
	return (expected);						\
}

#define ATOMIC_READANDSET(WIDTH, TYPE)					\
static __inline TYPE							\
atomic_readandset_##WIDTH(__volatile TYPE *addr, TYPE value)		\
{									\
	__volatile _Atomic(TYPE) *ptr = (__volatile _Atomic(TYPE)*)addr; \
	TYPE result = atomic_load(ptr), desired;			\
									\
	do {								\
		desired = result | value;				\
	} while (!atomic_compare_exchange_weak(ptr, &result, desired));	\
									\
	return result;							\
}

ATOMIC_SET(8, uint8_t)
ATOMIC_SET(16, uint16_t)
ATOMIC_SET(32, uint32_t)

ATOMIC_CLEAR(8, uint8_t)
ATOMIC_CLEAR(16, uint16_t)
ATOMIC_CLEAR(32, uint32_t)

ATOMIC_ADD(8, uint8_t)
ATOMIC_ADD(16, uint16_t)
ATOMIC_ADD(32, uint32_t)

ATOMIC_SUB(8, uint8_t)
ATOMIC_SUB(16, uint16_t)
ATOMIC_SUB(32, uint32_t)

ATOMIC_READANDCLEAR(32, uint32_t)
ATOMIC_READANDSET(32, uint32_t)

#if defined(__mips_n64) || defined(__mips_n32)
ATOMIC_SET(64, uint64_t)
ATOMIC_CLEAR(64, uint64_t)
ATOMIC_ADD(64, uint64_t)
ATOMIC_SUB(64, uint64_t)
ATOMIC_READANDCLEAR(64, uint64_t)
ATOMIC_READANDSET(64, uint64_t)

#ifdef __CHERI_PURE_CAPABILITY__
ATOMIC_SET(cap, uintptr_t)
ATOMIC_CLEAR(cap, uintptr_t)
ATOMIC_ADD(cap, uintptr_t)
ATOMIC_SUB(cap, uintptr_t)
ATOMIC_READANDCLEAR(cap, uintptr_t)
ATOMIC_READANDSET(cap, uintptr_t)
#endif /* __CHERI_PURE_CAPABILITY__ */
#endif /* __mips_n64 || __mips_n32 */

/*
 * Variants of simple arithmetic with memory barriers.
 * XXX-AM: TODO port in C by using __ATOMIC_ACQUIRE/__ATOMIC_RELEASE in explicits
 */
#define	ATOMIC_ACQ_REL(NAME, WIDTH)					\
static __inline  void							\
atomic_##NAME##_acq_##WIDTH(__volatile uint##WIDTH##_t *p, uint##WIDTH##_t v)\
{									\
	atomic_##NAME##_##WIDTH(p, v);					\
	mips_sync(); 							\
}									\
									\
static __inline  void							\
atomic_##NAME##_rel_##WIDTH(__volatile uint##WIDTH##_t *p, uint##WIDTH##_t v)\
{									\
	mips_sync();							\
	atomic_##NAME##_##WIDTH(p, v);					\
}

ATOMIC_ACQ_REL(set, 8)
ATOMIC_ACQ_REL(clear, 8)
ATOMIC_ACQ_REL(add, 8)
ATOMIC_ACQ_REL(subtract, 8)
ATOMIC_ACQ_REL(set, 16)
ATOMIC_ACQ_REL(clear, 16)
ATOMIC_ACQ_REL(add, 16)
ATOMIC_ACQ_REL(subtract, 16)
ATOMIC_ACQ_REL(set, 32)
ATOMIC_ACQ_REL(clear, 32)
ATOMIC_ACQ_REL(add, 32)
ATOMIC_ACQ_REL(subtract, 32)
#if defined(__mips_n64) || defined(__mips_n32)
ATOMIC_ACQ_REL(set, 64)
ATOMIC_ACQ_REL(clear, 64)
ATOMIC_ACQ_REL(add, 64)
ATOMIC_ACQ_REL(subtract, 64)
#ifdef __CHERI_PURE_CAPABILITY__
#endif /* __CHERI_PURE_CAPABILITY__ */
#endif /* __mips_n64 || __mips_n32 */

#undef ATOMIC_ACQ_REL

/*
 * Atomic load and store with memory barriers
 */
#define	ATOMIC_STORE_LOAD(WIDTH, TYPE)			\
static __inline TYPE					\
atomic_load_acq_##WIDTH(__volatile TYPE *p)		\
{							\
	return (atomic_load_explicit(			\
			(__volatile _Atomic(TYPE)*)p,	\
			__ATOMIC_ACQUIRE));		\
}							\
							\
static __inline  void					\
atomic_store_rel_##WIDTH(__volatile TYPE *p, TYPE v)	\
{							\
	atomic_store_explicit(				\
		(__volatile _Atomic(TYPE)*)p, v,	\
		__ATOMIC_RELEASE);			\
}

ATOMIC_STORE_LOAD(32, uint32_t)
ATOMIC_STORE_LOAD(64, uint64_t)
#ifdef __CHERI_PURE_CAPABILITY__
ATOMIC_STORE_LOAD(cap, uintptr_t)
#endif /* __CHERI_PURE_CAPABILITY__ */

#if !defined(__mips_n64) && !defined(__mips_n32)
void atomic_store_64(__volatile uint64_t *, uint64_t *);
void atomic_load_64(__volatile uint64_t *, uint64_t *);
#else
static __inline void
atomic_store_64(__volatile uint64_t *p, uint64_t *v)
{
	*p = *v;
}

static __inline void
atomic_load_64(__volatile uint64_t *p, uint64_t *v)
{
	*v = *p;
}
#endif

#undef ATOMIC_STORE_LOAD

/*
 * Atomic compare and fetch operations
 */

/*
 * Atomically compare the value stored at *p with cmpval and if the
 * two values are equal, update the value of *p with newval. Returns
 * zero if the compare failed, nonzero otherwise.
 */
#define ATOMIC_CMPSET(WIDTH, TYPE)					\
static __inline TYPE							\
atomic_cmpset_##WIDTH(__volatile TYPE *p, TYPE cmpval, TYPE newval)	\
{									\
	return (atomic_compare_exchange_weak((__volatile _Atomic(TYPE)*)p, \
					     &cmpval, newval));		\
}									\
									\
static __inline TYPE							\
atomic_cmpset_acq_##WIDTH(__volatile TYPE *p, TYPE cmpval, TYPE newval)	\
{									\
	return (atomic_compare_exchange_weak_explicit(			\
			(__volatile _Atomic(TYPE)*)p, &cmpval, newval,	\
			__ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE));		\
}									\
									\
static __inline TYPE							\
atomic_cmpset_rel_##WIDTH(__volatile TYPE *p, TYPE cmpval, TYPE newval)	\
{									\
	return (atomic_compare_exchange_weak_explicit(			\
			(__volatile _Atomic(TYPE)*)p, &cmpval, newval,	\
			__ATOMIC_RELEASE, __ATOMIC_RELEASE));		\
}									\


/*
 * Atomically compare the value stored at *p with cmpval and if the
 * two values are equal, update the value of *p with newval,
 * otherwise update the value of cmpval with the value loaded from *p.
 * Returns zero if the compare failed, nonzero otherwise.
 */
#define ATOMIC_FCMPSET(WIDTH, TYPE)					\
static __inline TYPE							\
atomic_fcmpset_##WIDTH(__volatile TYPE *p, TYPE *cmpval, TYPE newval)	\
{									\
	return (atomic_compare_exchange_weak((__volatile _Atomic(TYPE)*)p, \
					     cmpval, newval));		\
}									\
									\
static __inline TYPE							\
atomic_fcmpset_acq_##WIDTH(__volatile TYPE *p, TYPE *cmpval, TYPE newval) \
{									\
	return (atomic_compare_exchange_weak_explicit(			\
			(__volatile _Atomic(TYPE)*)p, cmpval, newval,	\
			__ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE));		\
}									\
									\
static __inline TYPE							\
atomic_fcmpset_rel_##WIDTH(__volatile TYPE *p, TYPE *cmpval, TYPE newval) \
{									\
	return (atomic_compare_exchange_weak_explicit(			\
			(__volatile _Atomic(TYPE)*)p, cmpval, newval,	\
			__ATOMIC_RELEASE, __ATOMIC_RELEASE));		\
}

/*
 * Atomically add the value of v to the integer pointed to by p and return
 * the previous value of *p.
 */
#define ATOMIC_FETCHADD(WIDTH, TYPE)					\
static __inline TYPE							\
atomic_fetchadd_##WIDTH(__volatile TYPE *p, TYPE v)			\
{									\
	return (atomic_fetch_add((__volatile _Atomic(TYPE)*)p, v));	\
}

ATOMIC_CMPSET(32, uint32_t)
ATOMIC_FCMPSET(32, uint32_t)
ATOMIC_FETCHADD(32, uint32_t)
#if defined(__mips_n64) || defined(__mips_n32)
ATOMIC_CMPSET(64, uint64_t)
ATOMIC_FCMPSET(64, uint64_t)
ATOMIC_FETCHADD(64, uint64_t)
#ifdef __CHERI_PURE_CAPABILITY__
ATOMIC_CMPSET(cap, uintptr_t)
ATOMIC_FCMPSET(cap, uintptr_t)
ATOMIC_FETCHADD(cap, uintptr_t)
#endif /* __CHERI_PURE_CAPABILITY__ */
#endif /* __mips_n64 || __mips_n32 */

static __inline void
atomic_thread_fence_acq(void)
{
	atomic_thread_fence(__ATOMIC_ACQUIRE);
}

static __inline void
atomic_thread_fence_rel(void)
{
	atomic_thread_fence(__ATOMIC_RELEASE);
}

static __inline void
atomic_thread_fence_acq_rel(void)
{
	atomic_thread_fence(__ATOMIC_ACQ_REL);
}

static __inline void
atomic_thread_fence_seq_cst(void)
{
	atomic_thread_fence(__ATOMIC_SEQ_CST);
}

/* Operations on chars. */
#define	atomic_set_char		atomic_set_8
#define	atomic_set_acq_char	atomic_set_acq_8
#define	atomic_set_rel_char	atomic_set_rel_8
#define	atomic_clear_char	atomic_clear_8
#define	atomic_clear_acq_char	atomic_clear_acq_8
#define	atomic_clear_rel_char	atomic_clear_rel_8
#define	atomic_add_char		atomic_add_8
#define	atomic_add_acq_char	atomic_add_acq_8
#define	atomic_add_rel_char	atomic_add_rel_8
#define	atomic_subtract_char	atomic_subtract_8
#define	atomic_subtract_acq_char	atomic_subtract_acq_8
#define	atomic_subtract_rel_char	atomic_subtract_rel_8

/* Operations on shorts. */
#define	atomic_set_short	atomic_set_16
#define	atomic_set_acq_short	atomic_set_acq_16
#define	atomic_set_rel_short	atomic_set_rel_16
#define	atomic_clear_short	atomic_clear_16
#define	atomic_clear_acq_short	atomic_clear_acq_16
#define	atomic_clear_rel_short	atomic_clear_rel_16
#define	atomic_add_short	atomic_add_16
#define	atomic_add_acq_short	atomic_add_acq_16
#define	atomic_add_rel_short	atomic_add_rel_16
#define	atomic_subtract_short	atomic_subtract_16
#define	atomic_subtract_acq_short	atomic_subtract_acq_16
#define	atomic_subtract_rel_short	atomic_subtract_rel_16

/* Operations on ints. */
#define	atomic_set_int		atomic_set_32
#define	atomic_set_acq_int	atomic_set_acq_32
#define	atomic_set_rel_int	atomic_set_rel_32
#define	atomic_clear_int	atomic_clear_32
#define	atomic_clear_acq_int	atomic_clear_acq_32
#define	atomic_clear_rel_int	atomic_clear_rel_32
#define	atomic_add_int		atomic_add_32
#define	atomic_add_acq_int	atomic_add_acq_32
#define	atomic_add_rel_int	atomic_add_rel_32
#define	atomic_subtract_int	atomic_subtract_32
#define	atomic_subtract_acq_int	atomic_subtract_acq_32
#define	atomic_subtract_rel_int	atomic_subtract_rel_32
#define	atomic_cmpset_int	atomic_cmpset_32
#define	atomic_cmpset_acq_int	atomic_cmpset_acq_32
#define	atomic_cmpset_rel_int	atomic_cmpset_rel_32
#define	atomic_fcmpset_int	atomic_fcmpset_32
#define	atomic_fcmpset_acq_int	atomic_fcmpset_acq_32
#define	atomic_fcmpset_rel_int	atomic_fcmpset_rel_32
#define	atomic_load_acq_int	atomic_load_acq_32
#define	atomic_store_rel_int	atomic_store_rel_32
#define	atomic_readandclear_int	atomic_readandclear_32
#define	atomic_readandset_int	atomic_readandset_32
#define	atomic_fetchadd_int	atomic_fetchadd_32

/*
 * I think the following is right, even for n32.  For n32 the pointers
 * are still 32-bits, so we need to operate on them as 32-bit quantities,
 * even though they are sign extended in operation.  For longs, there's
 * no question because they are always 32-bits.
 */
#ifdef __mips_n64
/* Operations on longs. */
#define	atomic_set_long		atomic_set_64
#define	atomic_set_acq_long	atomic_set_acq_64
#define	atomic_set_rel_long	atomic_set_rel_64
#define	atomic_clear_long	atomic_clear_64
#define	atomic_clear_acq_long	atomic_clear_acq_64
#define	atomic_clear_rel_long	atomic_clear_rel_64
#define	atomic_add_long		atomic_add_64
#define	atomic_add_acq_long	atomic_add_acq_64
#define	atomic_add_rel_long	atomic_add_rel_64
#define	atomic_subtract_long	atomic_subtract_64
#define	atomic_subtract_acq_long	atomic_subtract_acq_64
#define	atomic_subtract_rel_long	atomic_subtract_rel_64
#define	atomic_cmpset_long	atomic_cmpset_64
#define	atomic_cmpset_acq_long	atomic_cmpset_acq_64
#define	atomic_cmpset_rel_long	atomic_cmpset_rel_64
#define	atomic_fcmpset_long	atomic_fcmpset_64
#define	atomic_fcmpset_acq_long	atomic_fcmpset_acq_64
#define	atomic_fcmpset_rel_long	atomic_fcmpset_rel_64
#define	atomic_load_acq_long	atomic_load_acq_64
#define	atomic_store_rel_long	atomic_store_rel_64
#define	atomic_fetchadd_long	atomic_fetchadd_64
#define	atomic_readandclear_long	atomic_readandclear_64

#else /* !__mips_n64 */

/* Operations on longs. */
#define	atomic_set_long(p, v)						\
	atomic_set_32((volatile u_int *)(p), (u_int)(v))
#define	atomic_set_acq_long(p, v)					\
	atomic_set_acq_32((volatile u_int *)(p), (u_int)(v))
#define	atomic_set_rel_long(p, v)					\
	atomic_set_rel_32((volatile u_int *)(p), (u_int)(v))
#define	atomic_clear_long(p, v)						\
	atomic_clear_32((volatile u_int *)(p), (u_int)(v))
#define	atomic_clear_acq_long(p, v)					\
	atomic_clear_acq_32((volatile u_int *)(p), (u_int)(v))
#define	atomic_clear_rel_long(p, v)					\
	atomic_clear_rel_32((volatile u_int *)(p), (u_int)(v))
#define	atomic_add_long(p, v)						\
	atomic_add_32((volatile u_int *)(p), (u_int)(v))
#define	atomic_add_acq_long(p, v)					\
	atomic_add_32((volatile u_int *)(p), (u_int)(v))
#define	atomic_add_rel_long(p, v)					\
	atomic_add_32((volatile u_int *)(p), (u_int)(v))
#define	atomic_subtract_long(p, v)					\
	atomic_subtract_32((volatile u_int *)(p), (u_int)(v))
#define	atomic_subtract_acq_long(p, v)					\
	atomic_subtract_acq_32((volatile u_int *)(p), (u_int)(v))
#define	atomic_subtract_rel_long(p, v)					\
	atomic_subtract_rel_32((volatile u_int *)(p), (u_int)(v))
#define	atomic_cmpset_long(p, cmpval, newval)				\
	atomic_cmpset_32((volatile u_int *)(p), (u_int)(cmpval),	\
	    (u_int)(newval))
#define	atomic_cmpset_acq_long(p, cmpval, newval)			\
	atomic_cmpset_acq_32((volatile u_int *)(p), (u_int)(cmpval),	\
	    (u_int)(newval))
#define	atomic_cmpset_rel_long(p, cmpval, newval)			\
	atomic_cmpset_rel_32((volatile u_int *)(p), (u_int)(cmpval),	\
	    (u_int)(newval))
#define	atomic_fcmpset_long(p, cmpval, newval)				\
	atomic_fcmpset_32((volatile u_int *)(p), (u_int *)(cmpval),	\
	    (u_int)(newval))
#define	atomic_fcmpset_acq_long(p, cmpval, newval)			\
	atomic_fcmpset_acq_32((volatile u_int *)(p), (u_int *)(cmpval),	\
	    (u_int)(newval))
#define	atomic_fcmpset_rel_long(p, cmpval, newval)			\
	atomic_fcmpset_rel_32((volatile u_int *)(p), (u_int *)(cmpval),	\
	    (u_int)(newval))
#define	atomic_load_acq_long(p)						\
	(u_long)atomic_load_acq_32((volatile u_int *)(p))
#define	atomic_store_rel_long(p, v)					\
	atomic_store_rel_32((volatile u_int *)(p), (u_int)(v))
#define	atomic_fetchadd_long(p, v)					\
	atomic_fetchadd_32((volatile u_int *)(p), (u_int)(v))
#define	atomic_readandclear_long(p)					\
	atomic_readandclear_32((volatile u_int *)(p))

#endif /* __mips_n64 */

#ifndef CHERI_KERNEL
/* Operations on pointers. */
#define	atomic_set_ptr		atomic_set_long
#define	atomic_set_acq_ptr	atomic_set_acq_long
#define	atomic_set_rel_ptr	atomic_set_rel_long
#define	atomic_clear_ptr	atomic_clear_long
#define	atomic_clear_acq_ptr	atomic_clear_acq_long
#define	atomic_clear_rel_ptr	atomic_clear_rel_long
#define	atomic_add_ptr		atomic_add_long
#define	atomic_add_acq_ptr	atomic_add_acq_long
#define	atomic_add_rel_ptr	atomic_add_rel_long
#define	atomic_subtract_ptr	atomic_subtract_long
#define	atomic_subtract_acq_ptr	atomic_subtract_acq_long
#define	atomic_subtract_rel_ptr	atomic_subtract_rel_long
#define	atomic_cmpset_ptr	atomic_cmpset_long
#define	atomic_cmpset_acq_ptr	atomic_cmpset_acq_long
#define	atomic_cmpset_rel_ptr	atomic_cmpset_rel_long
#define	atomic_fcmpset_ptr	atomic_fcmpset_long
#define	atomic_fcmpset_acq_ptr	atomic_fcmpset_acq_long
#define	atomic_fcmpset_rel_ptr	atomic_fcmpset_rel_long
#define	atomic_load_acq_ptr	atomic_load_acq_long
#define	atomic_store_rel_ptr	atomic_store_rel_long
#define	atomic_readandclear_ptr	atomic_readandclear_long
#else /* CHERI_KERNEL */
#define	atomic_set_ptr		atomic_set_cap
#define	atomic_set_acq_ptr	atomic_set_acq_cap
#define	atomic_set_rel_ptr	atomic_set_rel_cap
#define	atomic_clear_ptr	atomic_clear_cap
#define	atomic_clear_acq_ptr	atomic_clear_acq_cap
#define	atomic_clear_rel_ptr	atomic_clear_rel_cap
#define	atomic_add_ptr		atomic_add_cap
#define	atomic_add_acq_ptr	atomic_add_acq_cap
#define	atomic_add_rel_ptr	atomic_add_rel_cap
#define	atomic_subtract_ptr	atomic_subtract_cap
#define	atomic_subtract_acq_ptr	atomic_subtract_acq_cap
#define	atomic_subtract_rel_ptr	atomic_subtract_rel_cap
#define	atomic_cmpset_ptr	atomic_cmpset_cap
#define	atomic_cmpset_acq_ptr	atomic_cmpset_acq_cap
#define	atomic_cmpset_rel_ptr	atomic_cmpset_rel_cap
#define	atomic_fcmpset_ptr	atomic_fcmpset_cap
#define	atomic_fcmpset_acq_ptr	atomic_fcmpset_acq_cap
#define	atomic_fcmpset_rel_ptr	atomic_fcmpset_rel_cap
#define	atomic_load_acq_ptr	atomic_load_acq_cap
#define	atomic_store_rel_ptr	atomic_store_rel_cap
#define	atomic_readandclear_ptr	atomic_readandclear_cap
#endif /* CHERI_KERNEL */

#endif /* ! _MACHINE_ATOMIC_H_ */
