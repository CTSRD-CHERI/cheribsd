/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
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

#include <sys/atomic_common.h>

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

//#define ATOMIC_NOTYET

#ifdef ATOMIC_NOTYET

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
	__c11_atomic_compare_exchange_weak(object, expected, desired,	\
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
#define	ATOMIC_ACQ_REL(NAME, WIDTH, TYPE)				\
static __inline  void							\
 atomic_##NAME##_acq_##WIDTH(__volatile TYPE *p, TYPE v)		\
{									\
	atomic_##NAME##_##WIDTH(p, v);					\
	mips_sync(); 							\
}									\
									\
static __inline  void							\
 atomic_##NAME##_rel_##WIDTH(__volatile TYPE *p, TYPE v)		\
{									\
	mips_sync();							\
	atomic_##NAME##_##WIDTH(p, v);					\
}

ATOMIC_ACQ_REL(set, 8, uint8_t)
ATOMIC_ACQ_REL(clear, 8, uint8_t)
ATOMIC_ACQ_REL(add, 8, uint8_t)
ATOMIC_ACQ_REL(subtract, 8, uint8_t)
ATOMIC_ACQ_REL(set, 16, uint16_t)
ATOMIC_ACQ_REL(clear, 16, uint16_t)
ATOMIC_ACQ_REL(add, 16, uint16_t)
ATOMIC_ACQ_REL(subtract, 16, uint16_t)
ATOMIC_ACQ_REL(set, 32, uint32_t)
ATOMIC_ACQ_REL(clear, 32, uint32_t)
ATOMIC_ACQ_REL(add, 32, uint32_t)
ATOMIC_ACQ_REL(subtract, 32, uint32_t)
#if defined(__mips_n64) || defined(__mips_n32)
ATOMIC_ACQ_REL(set, 64, uint64_t)
ATOMIC_ACQ_REL(clear, 64, uint64_t)
ATOMIC_ACQ_REL(add, 64, uint64_t)
ATOMIC_ACQ_REL(subtract, 64, uint64_t)
#ifdef __CHERI_PURE_CAPABILITY__
ATOMIC_ACQ_REL(set, cap, uintptr_t)
ATOMIC_ACQ_REL(clear, cap, uintptr_t)
ATOMIC_ACQ_REL(add, cap, uintptr_t)
ATOMIC_ACQ_REL(subtract, cap, uintptr_t)
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

#else /* ATOMIC_NOTYET */

/*
 * Various simple arithmetic on memory which is atomic in the presence
 * of interrupts and SMP safe.
 */

void atomic_set_8(__volatile uint8_t *, uint8_t);
void atomic_clear_8(__volatile uint8_t *, uint8_t);
void atomic_add_8(__volatile uint8_t *, uint8_t);
void atomic_subtract_8(__volatile uint8_t *, uint8_t);

void atomic_set_16(__volatile uint16_t *, uint16_t);
void atomic_clear_16(__volatile uint16_t *, uint16_t);
void atomic_add_16(__volatile uint16_t *, uint16_t);
void atomic_subtract_16(__volatile uint16_t *, uint16_t);

static __inline int atomic_cmpset_8(__volatile uint8_t *, uint8_t, uint8_t);
static __inline int atomic_fcmpset_8(__volatile uint8_t *, uint8_t *, uint8_t);
static __inline int atomic_cmpset_16(__volatile uint16_t *, uint16_t, uint16_t);
static __inline int atomic_fcmpset_16(__volatile uint16_t *, uint16_t *, uint16_t);

static __inline void
/* Work around https://github.com/CTSRD-CHERI/qemu/issues/4 */
#define QEMU_TLB_WORKAROUND32(register) \
	"clw $zero, $zero, 0(" register ")\n\t"
#define QEMU_TLB_WORKAROUND64(register) \
	"cld $zero, $zero, 0(" register ")\n\t"

/*
 * Avoid an error if the compiler decides to use $at as one of the registers.
 * This only seems to happen in the CHERI purecap case so far
 */
#define __INLINE_ASM_PUSH_NOAT	".set push\n\t.set noat\n\t"
#define __INLINE_ASM_POP_NOAT	".set pop"

atomic_set_32(__volatile uint32_t *p, uint32_t v)
{
	uint32_t temp;

#ifndef __CHERI_PURE_CAPABILITY__
	__asm __volatile (
		"1:\tll	%0, %1\n\t"		/* load old value */
		"or	%0, %2, %0\n\t"		/* calculate new value */
		"sc	%0, %1\n\t"		/* attempt to store */
		"beqz	%0, 1b\n\t"		/* spin if failed */
		: "=&r" (temp), "+m" (*p)
		: "r" (v)
		: "memory");
#else
	__asm __volatile (
		__INLINE_ASM_PUSH_NOAT
		"1:\n\t"
		QEMU_TLB_WORKAROUND32("%1")
		"cllw	%0, %1\n\t"		/* load old value */
		"or	%0, %2, %0\n\t"		/* calculate new value */
		"cscw	%0, %0, %1\n\t"		/* attempt to store */
		"beqz	%0, 1b\n\t"		/* spin if failed */
		__INLINE_ASM_POP_NOAT
		: "=&r" (temp), "+C" (p)
		: "r" (v)
		: "memory");
#endif

}

static __inline void
atomic_clear_32(__volatile uint32_t *p, uint32_t v)
{
	uint32_t temp;
	v = ~v;

#ifndef __CHERI_PURE_CAPABILITY__
	__asm __volatile (
		"1:\tll	%0, %1\n\t"		/* load old value */
		"and	%0, %2, %0\n\t"		/* calculate new value */
		"sc	%0, %1\n\t"		/* attempt to store */
		"beqz	%0, 1b\n\t"		/* spin if failed */
		: "=&r" (temp), "+m" (*p)
		: "r" (v)
		: "memory");
#else
	__asm __volatile (
		__INLINE_ASM_PUSH_NOAT
		"1:\n\t"
		QEMU_TLB_WORKAROUND32("%1")
		"cllw	%0, %1\n\t"		/* load old value */
		"and	%0, %2, %0\n\t"		/* calculate new value */
		"cscw	%0, %0, %1\n\t"		/* attempt to store */
		"beqz	%0, 1b\n\t"		/* spin if failed */
		__INLINE_ASM_POP_NOAT
		: "=&r" (temp), "+C" (p)
		: "r" (v)
		: "memory");
#endif
}

static __inline void
atomic_add_32(__volatile uint32_t *p, uint32_t v)
{
	uint32_t temp;

#ifndef __CHERI_PURE_CAPABILITY__
	__asm __volatile (
		"1:\tll	%0, %1\n\t"		/* load old value */
		"addu	%0, %2, %0\n\t"		/* calculate new value */
		"sc	%0, %1\n\t"		/* attempt to store */
		"beqz	%0, 1b\n\t"		/* spin if failed */
		: "=&r" (temp), "+m" (*p)
		: "r" (v)
		: "memory");
#else
	__asm __volatile (
		__INLINE_ASM_PUSH_NOAT
		"1:\n\t"
		QEMU_TLB_WORKAROUND32("%1")
		"cllw	%0, %1\n\t"	/* load old value */
		"addu	%0, %2, %0\n\t"		/* calculate new value */
		"cscw	%0, %0, %1\n\t"		/* attempt to store */
		"beqz	%0, 1b\n\t"		/* spin if failed */
		__INLINE_ASM_POP_NOAT
		: "=&r" (temp), "+C" (p)
		: "r" (v)
		: "memory");
#endif
}

static __inline void
atomic_subtract_32(__volatile uint32_t *p, uint32_t v)
{
	uint32_t temp;

#ifndef __CHERI_PURE_CAPABILITY__
	__asm __volatile (
		"1:\tll	%0, %1\n\t"		/* load old value */
		"subu	%0, %2\n\t"		/* calculate new value */
		"sc	%0, %1\n\t"		/* attempt to store */
		"beqz	%0, 1b\n\t"		/* spin if failed */
		: "=&r" (temp), "+m" (*p)
		: "r" (v)
		: "memory");
#else
	__asm __volatile (
		__INLINE_ASM_PUSH_NOAT
		"1:\n\t"
		QEMU_TLB_WORKAROUND32("%1")
		"cllw	%0, %1\n\t"		/* load old value */
		"subu	%0, %2\n\t"		/* calculate new value */
		"cscw	%0, %0, %1\n\t"		/* attempt to store */
		"beqz	%0, 1b\n\t"		/* spin if failed */
		__INLINE_ASM_POP_NOAT
		: "=&r" (temp), "+C" (p)
		: "r" (v)
		: "memory");
#endif
}

static __inline uint32_t
atomic_readandclear_32(__volatile uint32_t *addr)
{
	uint32_t result,temp;

#ifndef __CHERI_PURE_CAPABILITY__
	__asm __volatile (
		"1:\tll	 %0,%2\n\t"	/* load current value, asserting lock */
		"li	 %1,0\n\t"		/* value to store */
		"sc	 %1,%2\n\t"	/* attempt to store */
		"beqz	 %1, 1b\n\t"		/* if the store failed, spin */
		: "=&r"(result), "=&r"(temp), "+m" (*addr)
		:
		: "memory");
#else
	__asm __volatile (
		__INLINE_ASM_PUSH_NOAT
		"1:\n\t"
		QEMU_TLB_WORKAROUND32("%2")
		"cllw	%0, %2\n\t"	/* load current value, asserting lock */
		"li	%1, 0\n\t"	/* value to store */
		"cscw	%1, %1, %2\n\t"	/* attempt to store */
		"beqz	%1, 1b\n\t"	/* if the store failed, spin */
		__INLINE_ASM_POP_NOAT
		: "=&r"(result), "=&r"(temp), "+C" (addr)
		:
		: "memory");
#endif

	return result;
}

static __inline uint32_t
atomic_readandset_32(__volatile uint32_t *addr, uint32_t value)
{
	uint32_t result,temp;

#ifndef __CHERI_PURE_CAPABILITY__
	__asm __volatile (
		"1:\tll	 %0,%2\n\t"	/* load current value, asserting lock */
		"or      %1,$0,%3\n\t"
		"sc	 %1,%2\n\t"	/* attempt to store */
		"beqz	 %1, 1b\n\t"		/* if the store failed, spin */
		: "=&r"(result), "=&r"(temp), "+m" (*addr)
		: "r" (value)
		: "memory");
#else
	__asm __volatile (
		__INLINE_ASM_PUSH_NOAT
		"1:\n\t"
		QEMU_TLB_WORKAROUND32("%2")
		"cllw	%0, %2\n\t"	/* load current value, asserting lock */
		"or	%1, $0, %3\n\t"
		"cscw	%1, %1, %2\n\t"	/* attempt to store */
		"beqz	%1, 1b\n\t"	/* if the store failed, spin */
		__INLINE_ASM_POP_NOAT
		: "=&r"(result), "=&r"(temp), "+C" (addr)
		: "r" (value)
		: "memory");
#endif

	return result;
}

#if defined(__mips_n64) || defined(__mips_n32)
static __inline void
atomic_set_64(__volatile uint64_t *p, uint64_t v)
{
	uint64_t temp;

#ifndef __CHERI_PURE_CAPABILITY__
	__asm __volatile (
		"1:\n\t"
		"lld	%0, %1\n\t"		/* load old value */
		"or	%0, %2, %0\n\t"		/* calculate new value */
		"scd	%0, %1\n\t"		/* attempt to store */
		"beqz	%0, 1b\n\t"		/* spin if failed */
		: "=&r" (temp), "+m" (*p)
		: "r" (v)
		: "memory");
#else
	__asm __volatile (
		__INLINE_ASM_PUSH_NOAT
		"1:\n\t"
		QEMU_TLB_WORKAROUND64("%1")
		"clld	%0, %1\n\t"		/* load old value */
		"or	%0, %2, %0\n\t"		/* calculate new value */
		"cscd	%0, %0, %1\n\t"		/* attempt to store */
		"beqz	%0, 1b\n\t"		/* spin if failed */
		__INLINE_ASM_POP_NOAT
		: "=&r" (temp), "+C" (p)
		: "r" (v)
		: "memory");
#endif

}

static __inline void
atomic_clear_64(__volatile uint64_t *p, uint64_t v)
{
	uint64_t temp;
	v = ~v;

#ifndef __CHERI_PURE_CAPABILITY__
	__asm __volatile (
		"1:\n\t"
		"lld	%0, %1\n\t"		/* load old value */
		"and	%0, %2, %0\n\t"		/* calculate new value */
		"scd	%0, %1\n\t"		/* attempt to store */
		"beqz	%0, 1b\n\t"		/* spin if failed */
		: "=&r" (temp), "+m" (*p)
		: "r" (v)
		: "memory");
#else
	__asm __volatile (
		__INLINE_ASM_PUSH_NOAT
		"1:\n\t"
		QEMU_TLB_WORKAROUND64("%1")
		"clld	%0, %1\n\t"		/* load old value */
		"and	%0, %2, %0\n\t"		/* calculate new value */
		"cscd	%0, %0, %1\n\t"		/* attempt to store */
		"beqz	%0, 1b\n\t"		/* spin if failed */
		__INLINE_ASM_POP_NOAT
		: "=&r" (temp), "+C" (p)
		: "r" (v)
		: "memory");
#endif
}

static __inline void
atomic_add_64(__volatile uint64_t *p, uint64_t v)
{
	uint64_t temp;

#ifndef __CHERI_PURE_CAPABILITY__
	__asm __volatile (
		"1:\n\t"
		"lld	%0, %1\n\t"		/* load old value */
		"daddu	%0, %2, %0\n\t"		/* calculate new value */
		"scd	%0, %1\n\t"		/* attempt to store */
		"beqz	%0, 1b\n\t"		/* spin if failed */
		: "=&r" (temp), "+m" (*p)
		: "r" (v)
		: "memory");
#else
	__asm __volatile (
		__INLINE_ASM_PUSH_NOAT
		"1:\n\t"
		QEMU_TLB_WORKAROUND64("%1")
		"clld	%0, %1\n\t"		/* load old value */
		"daddu	%0, %2, %0\n\t"		/* calculate new value */
		"cscd	%0, %0, %1\n\t"		/* attempt to store */
		"beqz	%0, 1b\n\t"		/* spin if failed */
		__INLINE_ASM_POP_NOAT
		: "=&r" (temp), "+C" (p)
		: "r" (v)
		: "memory");
#endif
}

static __inline void
atomic_subtract_64(__volatile uint64_t *p, uint64_t v)
{
	uint64_t temp;

#ifndef __CHERI_PURE_CAPABILITY__
	__asm __volatile (
		"1:\n\t"
		"lld	%0, %1\n\t"		/* load old value */
		"dsubu	%0, %2\n\t"		/* calculate new value */
		"scd	%0, %1\n\t"		/* attempt to store */
		"beqz	%0, 1b\n\t"		/* spin if failed */
		: "=&r" (temp), "+m" (*p)
		: "r" (v)
		: "memory");
#else
	__asm __volatile (
		__INLINE_ASM_PUSH_NOAT
		"1:\n\t"
		QEMU_TLB_WORKAROUND64("%1")
		"clld	%0, %1\n\t"		/* load old value */
		"dsubu	%0, %2\n\t"		/* calculate new value */
		"cscd	%0, %0, %1\n\t"		/* attempt to store */
		"beqz	%0, 1b\n\t"		/* spin if failed */
		__INLINE_ASM_POP_NOAT
		: "=&r" (temp), "+C" (p)
		: "r" (v)
		: "memory");
#endif
}

static __inline uint64_t
atomic_readandclear_64(__volatile uint64_t *addr)
{
	uint64_t result,temp;

#ifndef __CHERI_PURE_CAPABILITY__
	__asm __volatile (
		"1:\n\t"
		"lld	 %0, %2\n\t"		/* load old value */
		"li	 %1, 0\n\t"		/* value to store */
		"scd	 %1, %2\n\t"		/* attempt to store */
		"beqz	 %1, 1b\n\t"		/* if the store failed, spin */
		: "=&r"(result), "=&r"(temp), "+m" (*addr)
		:
		: "memory");
#else
	__asm __volatile (
		__INLINE_ASM_PUSH_NOAT
		"1:\n\t"
		QEMU_TLB_WORKAROUND64("%2")
		"clld	 %0, %2\n\t"		/* load old value */
		"li	 %1, 0\n\t"		/* value to store */
		"cscd	 %1, %1, %2\n\t"	/* attempt to store */
		"beqz	 %1, 1b\n\t"		/* if the store failed, spin */
		__INLINE_ASM_POP_NOAT
		: "=&r"(result), "=&r"(temp), "+C" (addr)
		:
		: "memory");
#endif

	return result;
}

static __inline uint64_t
atomic_readandset_64(__volatile uint64_t *addr, uint64_t value)
{
	uint64_t result,temp;

#ifndef __CHERI_PURE_CAPABILITY__
	__asm __volatile (
		"1:\n\t"
		"lld	 %0,%2\n\t"		/* Load old value*/
		"or      %1,$0,%3\n\t"
		"scd	 %1,%2\n\t"		/* attempt to store */
		"beqz	 %1, 1b\n\t"		/* if the store failed, spin */
		: "=&r"(result), "=&r"(temp), "+m" (*addr)
		: "r" (value)
		: "memory");
#else
	__asm __volatile (
		__INLINE_ASM_PUSH_NOAT
		"1:\n\t"
		QEMU_TLB_WORKAROUND64("%2")
		"clld	 %0, %2\n\t"		/* load old value*/
		"or      %1, $0, %3\n\t"
		"cscd	 %1, %1, %2\n\t"	/* attempt to store */
		"beqz	 %1, 1b\n\t"		/* if the store failed, spin */
		__INLINE_ASM_POP_NOAT
		: "=&r"(result), "=&r"(temp), "+C" (addr)
		: "r" (value)
		: "memory");
#endif

	return result;
}
#endif

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

/* Variants of simple arithmetic with memory barriers. */
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
#endif

#undef ATOMIC_ACQ_REL

/*
 * We assume that a = b will do atomic loads and stores.
 */
#define	ATOMIC_STORE_LOAD(WIDTH)			\
static __inline  uint##WIDTH##_t			\
atomic_load_acq_##WIDTH(__volatile uint##WIDTH##_t *p)	\
{							\
	uint##WIDTH##_t v;				\
							\
	v = *p;						\
	mips_sync();					\
	return (v);					\
}							\
							\
static __inline  void					\
atomic_store_rel_##WIDTH(__volatile uint##WIDTH##_t *p, uint##WIDTH##_t v)\
{							\
	mips_sync();					\
	*p = v;						\
}

ATOMIC_STORE_LOAD(32)
ATOMIC_STORE_LOAD(64)
#undef ATOMIC_STORE_LOAD

#ifdef __mips_n32
#define	atomic_load_64	atomic_load_acq_64
#endif

/*
 * Atomically compare the value stored at *p with cmpval and if the
 * two values are equal, update the value of *p with newval. Returns
 * zero if the compare failed, nonzero otherwise.
 */
static __inline int
atomic_cmpset_32(__volatile uint32_t *p, uint32_t cmpval, uint32_t newval)
{
	int ret;

#ifndef __CHERI_PURE_CAPABILITY__
	__asm __volatile (
		"1:\tll	%0, %1\n\t"		/* load old value */
		"bne %0, %2, 2f\n\t"		/* compare */
		"move %0, %3\n\t"		/* value to store */
		"sc %0, %1\n\t"			/* attempt to store */
		"beqz %0, 1b\n\t"		/* if it failed, spin */
		"j 3f\n\t"
		"2:\n\t"
		"li	%0, 0\n\t"
		"3:\n"
		: "=&r" (ret), "+m" (*p)
		: "r" (cmpval), "r" (newval)
		: "memory");
#else
	__asm __volatile (
		__INLINE_ASM_PUSH_NOAT
		"1:\n\t"
		QEMU_TLB_WORKAROUND32("%1")
		"cllw	%0, %1\n\t"		/* load old value */
		"bne	%0, %2, 2f\n\t"		/* compare */
		"move	%0, %3\n\t"		/* value to store */
		"cscw	%0, %0, %1\n\t"		/* attempt to store */
		"beqz	%0, 1b\n\t"		/* if it failed, spin */
		"b 3f\n\t"
		"2:\n\t"
		"li	%0, 0\n\t"
		"3:\n"
		__INLINE_ASM_POP_NOAT
		: "=&r" (ret), "+C" (p)
		: "r" (cmpval), "r" (newval)
		: "memory");
#endif

	return ret;
}

/*
 * Atomically compare the value stored at *p with cmpval and if the
 * two values are equal, update the value of *p with newval. Returns
 * zero if the compare failed, nonzero otherwise.
 */
static __inline int
atomic_fcmpset_32(__volatile uint32_t *p, uint32_t *cmpval, uint32_t newval)
{
	int ret;

#ifndef __CHERI_PURE_CAPABILITY__
	/*
	 * The following sequence (similar to that in atomic_fcmpset_64) will
	 * attempt to update the value of *p with newval if the comparison
	 * succeeds.  Note that they'll exit regardless of whether the store
	 * actually succeeded, leaving *cmpval untouched.  This is in line with
	 * the documentation of atomic_fcmpset_<type>() in atomic(9) for ll/sc
	 * architectures.
	 */
	__asm __volatile (
		"ll	%0, %1\n\t"		/* load old value */
		"bne	%0, %4, 1f\n\t"		/* compare */
		"move	%0, %3\n\t"		/* value to store */
		"sc	%0, %1\n\t"		/* attempt to store */
		"j	2f\n\t"			/* exit regardless of success */
		"nop\n\t"			/* avoid delay slot accident */
		"1:\n\t"
		"sw	%0, %2\n\t"		/* save old value */
		"li	%0, 0\n\t"
		"2:\n"
		: "=&r" (ret), "+m" (*p), "=m" (*cmpval)
		: "r" (newval), "r" (*cmpval)
		: "memory");
#else
	uint32_t tmp;
	uint32_t expected = *cmpval;

	__asm __volatile (
		__INLINE_ASM_PUSH_NOAT
		"cllw	%[tmp], %[ptr]\n\t"		/* load old value */
		"bne	%[tmp], %[expected], 1f\n\t"	/* compare */
		"nop\n\t"
		"cscw	%[ret], %[newval], %[ptr]\n\t"	/* attempt to store */
		"j	2f\n\t"			/* exit regardless of success */
		"nop\n\t"			/* avoid delay slot accident */
		"1:\n\t"
		"csw	%[tmp], $0, 0(%[cmpval])\n\t"	/* store loaded value */
		"li	%[ret], 0\n\t"
		"2:\n"
		__INLINE_ASM_POP_NOAT
		: [ret] "=&r" (ret), [tmp] "=&r" (tmp), [ptr]"+C" (p),
		    [cmpval]"+C" (cmpval)
		: [newval] "r" (newval), [expected] "r" (expected)
		: "memory");
#endif
	return ret;
}

#define	ATOMIC_CMPSET_ACQ_REL(WIDTH)					\
static __inline  int							\
atomic_cmpset_acq_##WIDTH(__volatile uint##WIDTH##_t *p,		\
    uint##WIDTH##_t cmpval, uint##WIDTH##_t newval)			\
{									\
	int retval;							\
									\
	retval = atomic_cmpset_##WIDTH(p, cmpval, newval);		\
	mips_sync();							\
	return (retval);						\
}									\
									\
static __inline  int							\
atomic_cmpset_rel_##WIDTH(__volatile uint##WIDTH##_t *p,		\
    uint##WIDTH##_t cmpval, uint##WIDTH##_t newval)			\
{									\
	mips_sync();							\
	return (atomic_cmpset_##WIDTH(p, cmpval, newval));		\
}

#define	ATOMIC_FCMPSET_ACQ_REL(WIDTH)					\
static __inline  int							\
atomic_fcmpset_acq_##WIDTH(__volatile uint##WIDTH##_t *p,		\
    uint##WIDTH##_t *cmpval, uint##WIDTH##_t newval)			\
{									\
	int retval;							\
									\
	retval = atomic_fcmpset_##WIDTH(p, cmpval, newval);		\
	mips_sync();							\
	return (retval);						\
}									\
									\
static __inline  int							\
atomic_fcmpset_rel_##WIDTH(__volatile uint##WIDTH##_t *p,		\
    uint##WIDTH##_t *cmpval, uint##WIDTH##_t newval)			\
{									\
	mips_sync();							\
	return (atomic_fcmpset_##WIDTH(p, cmpval, newval));		\
}

/*
 * Atomically compare the value stored at *p with cmpval and if the
 * two values are equal, update the value of *p with newval. Returns
 * zero if the compare failed, nonzero otherwise.
 */
ATOMIC_CMPSET_ACQ_REL(8);
ATOMIC_CMPSET_ACQ_REL(16);
ATOMIC_CMPSET_ACQ_REL(32);
ATOMIC_FCMPSET_ACQ_REL(8);
ATOMIC_FCMPSET_ACQ_REL(16);
ATOMIC_FCMPSET_ACQ_REL(32);

/*
 * Atomically add the value of v to the integer pointed to by p and return
 * the previous value of *p.
 */
static __inline uint32_t
atomic_fetchadd_32(__volatile uint32_t *p, uint32_t v)
{
	uint32_t value, temp;

#ifndef __CHERI_PURE_CAPABILITY__
	__asm __volatile (
		"1:\tll %0, %1\n\t"		/* load old value */
		"addu %2, %3, %0\n\t"		/* calculate new value */
		"sc %2, %1\n\t"			/* attempt to store */
		"beqz %2, 1b\n\t"		/* spin if failed */
		: "=&r" (value), "+m" (*p), "=&r" (temp)
		: "r" (v));
#else
	__asm __volatile (
		__INLINE_ASM_PUSH_NOAT
		"1:\n\t"
		QEMU_TLB_WORKAROUND32("%1")
		"cllw	%0, %1\n\t"		/* load old value */
		"addu	%2, %3, %0\n\t"		/* calculate new value */
		"cscw	%2, %2, %1\n\t"		/* attempt to store */
		"beqz %2, 1b\n\t"		/* spin if failed */
		__INLINE_ASM_POP_NOAT
		: "=&r" (value), "+C" (p), "=&r" (temp)
		: "r" (v));
#endif
	return (value);
}

#if defined(__mips_n64) || defined(__mips_n32)
/*
 * Atomically compare the value stored at *p with cmpval and if the
 * two values are equal, update the value of *p with newval. Returns
 * zero if the compare failed, nonzero otherwise.
 */
static __inline int
atomic_cmpset_64(__volatile uint64_t *p, uint64_t cmpval, uint64_t newval)
{
	int ret;

#ifndef __CHERI_PURE_CAPABILITY__
	__asm __volatile (
		"1:\n\t"
		"lld	%0, %1\n\t"		/* load old value */
		"bne	%0, %2, 2f\n\t"		/* compare */
		"move	%0, %3\n\t"		/* value to store */
		"scd	%0, %1\n\t"		/* attempt to store */
		"beqz	%0, 1b\n\t"		/* if it failed, spin */
		"j	3f\n\t"
		"2:\n\t"
		"li	%0, 0\n\t"
		"3:\n"
		: "=&r" (ret), "+m" (*p)
		: "r" (cmpval), "r" (newval)
		: "memory");
#else
	__asm __volatile (
		__INLINE_ASM_PUSH_NOAT
		"1:\n\t"
		QEMU_TLB_WORKAROUND64("%1")
		"clld	%0, %1\n\t"		/* load old value */
		"bne	%0, %2, 2f\n\t"		/* compare */
		"move	%0, %3\n\t"		/* value to store */
		"cscd	%0, %0, %1\n\t"		/* attempt to store */
		"beqz	%0, 1b\n\t"		/* if it failed, spin */
		"j	3f\n\t"
		"2:\n\t"
		"li	%0, 0\n\t"
		"3:\n"
		__INLINE_ASM_POP_NOAT
		: "=&r" (ret), "+C" (p)
		: "r" (cmpval), "r" (newval)
		: "memory");
#endif

	return ret;
}

static __inline int
atomic_fcmpset_64(__volatile uint64_t *p, uint64_t *cmpval, uint64_t newval)
{
        int ret;

#ifndef __CHERI_PURE_CAPABILITY__
        __asm __volatile (
		"lld	%0, %1\n\t"		/* load old value */
                "bne	%0, %4, 1f\n\t"		/* compare */
                "move	%0, %3\n\t"		/* value to store */
                "scd	%0, %1\n\t"		/* attempt to store */
		"j	2f\n\t"			/* exit regardless of success */
		"nop\n\t"			/* avoid delay slot accident */
                "1:\n\t"
                "sd	%0, %2\n\t"		/* save old value */
                "li	%0, 0\n\t"
                "2:\n"
                : "=&r" (ret), "+m" (*p), "=m" (*cmpval)
                : "r" (newval), "r" (*cmpval)
                : "memory");
#else
	uint64_t tmp;
	uint64_t expected = *cmpval;

	__asm __volatile (
		__INLINE_ASM_PUSH_NOAT
		"clld	%[tmp], %[ptr]\n\t"		/* load old value */
		"bne	%[tmp], %[expected], 1f\n\t"	/* compare */
		"nop\n\t"			/* avoid delay slot accident */
		"cscd	%[ret], %[newval], %[ptr]\n\t"	/* attempt to store */
		"j	2f\n\t"			/* exit regardless of success */
		"nop\n\t"			/* avoid delay slot accident */
		"1:\n\t"
		"csd	%[tmp], $0, 0(%[cmpval])\n\t"	/* store loaded value */
		"li	%[ret], 0\n\t"
		"2:\n"
		__INLINE_ASM_POP_NOAT
		: [ret] "=&r" (ret), [tmp] "=&r" (tmp), [ptr]"+C" (p),
		    [cmpval]"+C" (cmpval)
		: [newval] "r" (newval), [expected] "r" (expected)
		: "memory");
#endif
	return ret;
}

/*
 * Atomically compare the value stored at *p with cmpval and if the
 * two values are equal, update the value of *p with newval. Returns
 * zero if the compare failed, nonzero otherwise.
 */
ATOMIC_CMPSET_ACQ_REL(64);
ATOMIC_FCMPSET_ACQ_REL(64);

/*
 * Atomically add the value of v to the integer pointed to by p and return
 * the previous value of *p.
 */
static __inline uint64_t
atomic_fetchadd_64(__volatile uint64_t *p, uint64_t v)
{
	uint64_t value, temp;

#ifndef __CHERI_PURE_CAPABILITY__
	__asm __volatile (
		"1:\n\t"
		"lld	%0, %1\n\t"		/* load old value */
		"daddu	%2, %3, %0\n\t"		/* calculate new value */
		"scd	%2, %1\n\t"		/* attempt to store */
		"beqz	%2, 1b\n\t"		/* spin if failed */
		: "=&r" (value), "+m" (*p), "=&r" (temp)
		: "r" (v));
#else
	__asm __volatile (
		__INLINE_ASM_PUSH_NOAT
		"1:\n\t"
		QEMU_TLB_WORKAROUND64("%1")
		"clld	%0, %1\n\t"		/* load old value */
		"daddu	%2, %3, %0\n\t"		/* calculate new value */
		"cscd	%2, %2, %1\n\t"		/* attempt to store */
		"beqz	%2, 1b\n\t"		/* spin if failed */
		__INLINE_ASM_POP_NOAT
		: "=&r" (value), "+C" (p), "=&r" (temp)
		: "r" (v));
#endif
	return (value);
}
#endif


#ifdef __CHERI_PURE_CAPABILITY__
/*
 * cheri-only variants to perform atomic operations on pointers.
 */

static __inline void
atomic_set_cap(__volatile uintptr_t *p, uintptr_t v)
{
	uintptr_t temp;

	__asm __volatile (
		"1:\n\t"
		"cllc		%0, %1\n\t"	/* load old value */
		"cgetoffset	$t0, %0\n\t"	/* calculate new value */
		"cgetoffset	$t1, %2\n\t"
		"or		$t0, $t1, $t0\n\t"
		"csetoffset	%0, %0, $t0\n\t"
		"cscc		$t0, %0, %1\n\t" /* attempt to store */
		"beqz		$t0, 1b\n\t"	/* spin if failed */
		"nop\n\t"			/* delay slot */
		: "=&r" (temp), "+C" (p)
		: "r" (v)
		: "t0", "t1", "memory");
}

static __inline void
atomic_clear_cap(__volatile uintptr_t *p, uintptr_t v)
{
	uintptr_t temp;
	v = ~v;

	__asm __volatile (
		"1:\n\t"
		"cllc		%0, %1\n\t"	/* load old value */
		"cgetoffset	$t0, %0\n\t"	/* calculate new value */
		"cgetoffset	$t1, %2\n\t"
		"and		$t0, $t1, $t0\n\t"
		"csetoffset	%0, %0, $t0\n\t"
		"cscc		$t0, %0, %1\n\t" /* attempt to store */
		"beqz		$t0, 1b\n\t"	/* spin if failed */
		"nop\n\t"			/* delay slot */
		: "=&r" (temp), "+C" (p)
		: "r" (v)
		: "t0", "t1", "memory");
}

static __inline void
atomic_add_cap(__volatile uintptr_t *p, uintptr_t v)
{
	uintptr_t temp;

	__asm __volatile (
		"1:\n\t"
		"cllc		%0, %1\n\t"	/* load old value */
		"cgetoffset	$t0, %2\n\t"	/* calculate new value */
		"cincoffset	%0, %0, $t0\n\t"
		"cscc		$t0, %0, %1\n\t" /* attempt to store */
		"beqz		$t0, 1b\n\t"	/* spin if failed */
		"nop\n\t"			/* delay slot */
		: "=&r" (temp), "+C" (p)
		: "r" (v)
		: "t0", "memory");
}

static __inline void
atomic_subtract_cap(__volatile uintptr_t *p, uintptr_t v)
{
	uintptr_t temp;

	__asm __volatile (
		"1:\n\t"
		"cllc		%0, %1\n\t"	/* load old value */
		"cgetoffset	$t0, %2\n\t"	/* calculate new value */
		"dsubu		$t0, $zero, $t0\n\t"
		"cincoffset	%0, %0, $t0\n\t"
		"cscc		$t0, %0, %1\n\t" /* attempt to store */
		"beqz		$t0, 1b\n\t"	/* spin if failed */
		"nop\n\t"			/* delay slot */
		: "=&r" (temp), "+C" (p)
		: "r" (v)
		: "t0", "memory");
}

#define ATOMIC_ACQ_REL_CAP(NAME)					\
static __inline  void							\
atomic_##NAME##_acq_cap(__volatile uintptr_t *p, uintptr_t v)		\
{									\
	atomic_##NAME##_cap(p, v);					\
	mips_sync(); 							\
}									\
									\
static __inline  void							\
atomic_##NAME##_rel_cap(__volatile uintptr_t *p, uintptr_t v)		\
{									\
	mips_sync();							\
	atomic_##NAME##_cap(p, v);					\
}

ATOMIC_ACQ_REL_CAP(set)
ATOMIC_ACQ_REL_CAP(clear)
ATOMIC_ACQ_REL_CAP(add)
ATOMIC_ACQ_REL_CAP(subtract)

#undef ATOMIC_ACQ_REL_CAP

static __inline uint64_t
atomic_cmpset_cap(__volatile uintptr_t *p, uintptr_t cmpval, uintptr_t newval)
{
	uint64_t ret;
	uintptr_t temp;

	__asm __volatile (
		"1:\n\t"
		"cllc		%1, %2\n\t"	/* load old value */
		"ceq		%0, %1, %3\n\t" /* compare */
		"beqz		%0, 2f\n\t"
		"cmove		%1, %4\n\t"
		"cscc		%0, %1, %2\n\t" /* attempt to store */
		"beqz		%0, 1b\n\t"	/* spin if failed */
		"nop\n\t"
		"2:\n\t"
		: "=&r" (ret), "=&r" (temp), "+C" (p)
		: "r" (cmpval), "r" (newval)
		: "memory");
	return (ret);
}

static __inline uint64_t
atomic_cmpset_acq_cap(__volatile uintptr_t *p, uintptr_t cmpval, uintptr_t newval)
{
	int retval;

	retval = atomic_cmpset_cap(p, cmpval, newval);
	mips_sync();
	return (retval);
}

static __inline uint64_t
atomic_cmpset_rel_cap(__volatile uintptr_t *p, uintptr_t cmpval, uintptr_t newval)
{
	mips_sync();
	return (atomic_cmpset_cap(p, cmpval, newval));
}

static __inline uint64_t
atomic_fcmpset_cap(__volatile uintptr_t *p, uintptr_t *cmpval, uintptr_t newval)
{
	uint64_t ret;
	uintptr_t tmp, cmp = *cmpval;

	__asm __volatile (
		"1:\n\t"
		"cllc	%[tmp], %[p]\n\t"	/* load old value */
		"ceq	%[ret], %[tmp], %[cmp]\n\t" /* compare */
		"beqz	%[ret], 2f\n\t"
		"cmove	%[tmp], %[newval]\n\t"
		"cscc	%[ret], %[tmp], %[p]\n\t" /* attempt to store */
		"beqz	%[ret], 1b\n\t"	/* spin if failed */
		"j	3f\n\t"
		"2:\n\t"
		"csc	%[tmp], $zero, 0(%[cmpval])\n\t" /* store the loaded value */
		"3:\n\t"
		: [ret] "=&r" (ret), [tmp] "=&r" (tmp), [p] "+C" (p),
			[cmpval] "+C" (cmpval)
		: [newval] "r" (newval), [cmp] "r" (cmp)
		: "memory");
	return ret;
}

static __inline uint64_t
atomic_fcmpset_acq_cap(__volatile uintptr_t *p, uintptr_t *cmpval, uintptr_t newval)
{
	int retval;

	retval = atomic_fcmpset_cap(p, cmpval, newval);
	mips_sync();
	return (retval);
}

static __inline uint64_t
atomic_fcmpset_rel_cap(__volatile uintptr_t *p, uintptr_t *cmpval, uintptr_t newval)
{
	mips_sync();
	return (atomic_fcmpset_cap(p, cmpval, newval));
}

static __inline uintptr_t
atomic_readandclear_cap(__volatile uintptr_t *p)
{
	uintptr_t result, tmp;

	__asm __volatile (
		"1:\n\t"
		"cllc		%0, %1\n\t"	/* load old value */
		"cgetnull	%2\n\t"		/* clear c1 */
		"cscc		$t0, %2, %1\n\t" /* attempt to store */
		"beqz		$t0, 1b\n\t"	/* spin if failed */
		"nop\n\t"			/* delay slot */
		: "=&r" (result), "+C" (p), "=&r" (tmp)
		:
		: "t0", "memory");
	return result;
}

static __inline uintptr_t
atomic_load_acq_cap(__volatile uintptr_t *p)
{
	uintptr_t value;

	value = *p;
	mips_sync();
	return (value);
}

static __inline void
atomic_store_rel_cap(__volatile uintptr_t *p, uintptr_t v)
{
	mips_sync();
	*p = v;
}
#endif /* __CHERI_PURE_CAPABILITY__ */

static __inline void
atomic_thread_fence_acq(void)
{

	mips_sync();
}

static __inline void
atomic_thread_fence_rel(void)
{

	mips_sync();
}

static __inline void
atomic_thread_fence_acq_rel(void)
{

	mips_sync();
}

static __inline void
atomic_thread_fence_seq_cst(void)
{

	mips_sync();
}
#endif /* ATOMIC_NOTYET */

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
#define	atomic_cmpset_char	atomic_cmpset_8
#define	atomic_cmpset_acq_char	atomic_cmpset_acq_8
#define	atomic_cmpset_rel_char	atomic_cmpset_rel_8
#define	atomic_fcmpset_char	atomic_fcmpset_8
#define	atomic_fcmpset_acq_char	atomic_fcmpset_acq_8
#define	atomic_fcmpset_rel_char	atomic_fcmpset_rel_8

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
#define	atomic_cmpset_short	atomic_cmpset_16
#define	atomic_cmpset_acq_short	atomic_cmpset_acq_16
#define	atomic_cmpset_rel_short	atomic_cmpset_rel_16
#define	atomic_fcmpset_short	atomic_fcmpset_16
#define	atomic_fcmpset_acq_short	atomic_fcmpset_acq_16
#define	atomic_fcmpset_rel_short	atomic_fcmpset_rel_16

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

#ifndef CHERI_PURECAP_KERNEL
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
#else /* CHERI_PURECAP_KERNEL */
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
#endif /* CHERI_PURECAP_KERNEL */

static __inline unsigned int
atomic_swap_int(volatile unsigned int *ptr, const unsigned int value)
{
	unsigned int retval;

	retval = *ptr;

	while (!atomic_fcmpset_int(ptr, &retval, value))
		;
	return (retval);
}

static __inline uint32_t
atomic_swap_32(volatile uint32_t *ptr, const uint32_t value)
{
	uint32_t retval;

	retval = *ptr;

	while (!atomic_fcmpset_32(ptr, &retval, value))
		;
	return (retval);
}

#if defined(__mips_n64) || defined(__mips_n32)
static __inline uint64_t
atomic_swap_64(volatile uint64_t *ptr, const uint64_t value)
{
	uint64_t retval;

	retval = *ptr;

	while (!atomic_fcmpset_64(ptr, &retval, value))
		;
	return (retval);
}
#endif

#ifdef __mips_n64
static __inline unsigned long
atomic_swap_long(volatile unsigned long *ptr, const unsigned long value)
{
	unsigned long retval;

	retval = *ptr;

	while (!atomic_fcmpset_64((volatile uint64_t *)ptr,
	    (uint64_t *)&retval, value))
		;
	return (retval);
}
#else
static __inline unsigned long
atomic_swap_long(volatile unsigned long *ptr, const unsigned long value)
{
	unsigned long retval;

	retval = *ptr;

	while (!atomic_fcmpset_32((volatile uint32_t *)ptr,
	    (uint32_t *)&retval, value))
		;
	return (retval);
}
#endif
#define	atomic_swap_ptr(ptr, value) atomic_swap_long((unsigned long *)(ptr), value)

#include <sys/_atomic_subword.h>

#endif /* ! _MACHINE_ATOMIC_H_ */
// CHERI CHANGES START
// {
//   "updated": 20180919,
//   "target_type": "header",
//   "changes": [
//     "support"
//   ],
//   "changes_purecap": [
//     "support"
//   ]
// }
// CHERI CHANGES END
