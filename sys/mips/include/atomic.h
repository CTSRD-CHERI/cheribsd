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

#if !defined(__mips_n64) && !defined(__mips_n32)
#include <sys/_atomic64e.h>
#endif

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

/*
 * Avoid an error if the compiler decides to use $at as one of the registers.
 * This only seems to happen in the CHERI purecap case so far
 */
#define __INLINE_ASM_PUSH_NOAT	".set push\n\t.set noat\n\t"
#define __INLINE_ASM_POP_NOAT	".set pop"

static __inline void
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
#if defined(__mips_n64) || defined(__mips_n32)
ATOMIC_STORE_LOAD(64)
#endif
#undef ATOMIC_STORE_LOAD

/*
 * MIPS n32 is not a LP64 API, so atomic_load_64 isn't defined there. Define it
 * here since n32 is an oddball !LP64 but that can do 64-bit atomics.
 */
#if defined(__mips_n32)
#define	atomic_load_64	atomic_load_acq_64
#endif

/*
 * Atomically compare the value stored at *p with cmpval and if the
 * two values are equal, update the value of *p with newval. Returns
 * zero if the compare failed, nonzero otherwise.
 */
#define	ATOMIC_CMPSET(WIDTH)						\
static __inline int							\
atomic_cmpset_##WIDTH(__volatile uint##WIDTH##_t *p,			\
    uint##WIDTH##_t cmpval, uint##WIDTH##_t newval)			\
{									\
	return (__atomic_compare_exchange_n(p, &cmpval, newval, 0,	\
	    __ATOMIC_RELAXED, __ATOMIC_RELAXED));			\
}

/*
 * Atomically compare the value stored at *p with cmpval and if the
 * two values are equal, update the value of *p with newval. Returns
 * zero if the compare failed, nonzero otherwise.
 */
#define	ATOMIC_FCMPSET(WIDTH)						\
static __inline int							\
atomic_fcmpset_##WIDTH(__volatile uint##WIDTH##_t *p,			\
    uint##WIDTH##_t *cmpval, uint##WIDTH##_t newval)			\
{									\
	return (__atomic_compare_exchange_n(p, cmpval, newval, 1,	\
	    __ATOMIC_RELAXED, __ATOMIC_RELAXED));			\
}

#ifdef __CHERI_PURE_CAPABILITY__
/*
 * In a purecap kernel we cannot use the generic sub-word implementation.
 */
ATOMIC_CMPSET(8)
ATOMIC_FCMPSET(8)
ATOMIC_CMPSET(16)
ATOMIC_FCMPSET(16)
#define	atomic_cmpset_8 atomic_cmpset_8
#define	atomic_fcmpset_8 atomic_fcmpset_8
#define	atomic_cmpset_16 atomic_cmpset_16
#define	atomic_fcmpset_16 atomic_fcmpset_16
#endif

ATOMIC_CMPSET(32)
ATOMIC_FCMPSET(32)

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
ATOMIC_CMPSET(64)
ATOMIC_FCMPSET(64)

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

ATOMIC_CMPSET(ptr);
ATOMIC_FCMPSET(ptr);

#undef ATOMIC_CMPSET
#undef ATOMIC_FCMPSET

#ifdef __CHERI_PURE_CAPABILITY__
/*
 * CHERI-only variants to perform atomic operations on pointers.
 */

static __inline void
atomic_set_ptr(volatile uintptr_t *p, uintptr_t v)
{
	uintptr_t temp;

	__asm __volatile (
		"1:\n\t"
		"cllc		%0, %1\n\t"	/* load old value */
		"cgetaddr	$t0, %0\n\t"	/* calculate new value */
		"cgetaddr	$t1, %2\n\t"
		"or		$t0, $t1, $t0\n\t"
		"csetaddr	%0, %0, $t0\n\t"
		"cscc		$t0, %0, %1\n\t" /* attempt to store */
		"beqz		$t0, 1b\n\t"	/* spin if failed */
		"nop\n\t"			/* delay slot */
		: "=&r" (temp), "+C" (p)
		: "r" (v)
		: "t0", "t1", "memory");
}

static __inline void
atomic_clear_ptr(volatile uintptr_t *p, uintptr_t v)
{
	uintptr_t temp;
	v = ~v;

	__asm __volatile (
		"1:\n\t"
		"cllc		%0, %1\n\t"	/* load old value */
		"cgetaddr	$t0, %0\n\t"	/* calculate new value */
		"cgetaddr	$t1, %2\n\t"
		"and		$t0, $t1, $t0\n\t"
		"csetaddr	%0, %0, $t0\n\t"
		"cscc		$t0, %0, %1\n\t" /* attempt to store */
		"beqz		$t0, 1b\n\t"	/* spin if failed */
		"nop\n\t"			/* delay slot */
		: "=&r" (temp), "+C" (p)
		: "r" (v)
		: "t0", "t1", "memory");
}

static __inline void
atomic_add_ptr(volatile uintptr_t *p, uintptr_t v)
{
	uintptr_t temp;

	__asm __volatile (
		"1:\n\t"
		"cllc		%0, %1\n\t"	/* load old value */
		"cgetaddr	$t0, %2\n\t"	/* calculate new value */
		"cincaddr	%0, %0, $t0\n\t"
		"cscc		$t0, %0, %1\n\t" /* attempt to store */
		"beqz		$t0, 1b\n\t"	/* spin if failed */
		"nop\n\t"			/* delay slot */
		: "=&r" (temp), "+C" (p)
		: "r" (v)
		: "t0", "memory");
}

static __inline void
atomic_subtract_ptr(volatile uintptr_t *p, uintptr_t v)
{
	uintptr_t temp;

	__asm __volatile (
		"1:\n\t"
		"cllc		%0, %1\n\t"	/* load old value */
		"cgetaddr	$t0, %2\n\t"	/* calculate new value */
		"cgetaddr	$t1, %0\n\t"
		"dsubu		$t0, $t1, $t0\n\t"
		"csetaddr	%0, %0, $t0\n\t"
		"cscc		$t0, %0, %1\n\t" /* attempt to store */
		"beqz		$t0, 1b\n\t"	/* spin if failed */
		"nop\n\t"			/* delay slot */
		: "=&r" (temp), "+C" (p)
		: "r" (v)
		: "t0", "memory");
}

#define ATOMIC_ACQ_REL_PTR(NAME)					\
static __inline  void							\
atomic_##NAME##_acq_ptr(volatile uintptr_t *p, uintptr_t v)		\
{									\
	atomic_##NAME##_ptr(p, v);					\
	mips_sync(); 							\
}									\
									\
static __inline  void							\
atomic_##NAME##_rel_ptr(volatile uintptr_t *p, uintptr_t v)		\
{									\
	mips_sync();							\
	atomic_##NAME##_ptr(p, v);					\
}

ATOMIC_ACQ_REL_PTR(set)
ATOMIC_ACQ_REL_PTR(clear)
ATOMIC_ACQ_REL_PTR(add)
ATOMIC_ACQ_REL_PTR(subtract)

#undef ATOMIC_ACQ_REL_PTR

static __inline int
atomic_cmpset_acq_ptr(volatile uintptr_t *p, uintptr_t cmpval, uintptr_t newval)
{
	int retval;

	retval = atomic_cmpset_ptr(p, cmpval, newval);
	mips_sync();
	return (retval);
}

static __inline int
atomic_cmpset_rel_ptr(volatile uintptr_t *p, uintptr_t cmpval, uintptr_t newval)
{
	mips_sync();
	return (atomic_cmpset_ptr(p, cmpval, newval));
}

static __inline int
atomic_fcmpset_acq_ptr(volatile uintptr_t *p, uintptr_t *cmpval, uintptr_t newval)
{
	int retval;

	retval = atomic_fcmpset_ptr(p, cmpval, newval);
	mips_sync();
	return (retval);
}

static __inline int
atomic_fcmpset_rel_ptr(volatile uintptr_t *p, uintptr_t *cmpval, uintptr_t newval)
{
	mips_sync();
	return (atomic_fcmpset_ptr(p, cmpval, newval));
}

static __inline uintptr_t
atomic_readandclear_ptr(volatile uintptr_t *p)
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
atomic_load_acq_ptr(volatile uintptr_t *p)
{
	uintptr_t value;

	value = *p;
	mips_sync();
	return (value);
}

static __inline void
atomic_store_rel_ptr(volatile uintptr_t *p, uintptr_t v)
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

#ifndef __CHERI_PURE_CAPABILITY__
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
#define	atomic_cmpset_acq_ptr	atomic_cmpset_acq_long
#define	atomic_cmpset_rel_ptr	atomic_cmpset_rel_long
#define	atomic_fcmpset_acq_ptr	atomic_fcmpset_acq_long
#define	atomic_fcmpset_rel_ptr	atomic_fcmpset_rel_long
#define	atomic_load_acq_ptr	atomic_load_acq_long
#define	atomic_store_rel_ptr	atomic_store_rel_long
#define	atomic_readandclear_ptr	atomic_readandclear_long
#endif

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

#ifdef __CHERI_PURE_CAPABILITY__
static __inline uintptr_t
atomic_swap_ptr(volatile uintptr_t *ptr, const uintptr_t value)
{
	uintptr_t retval;

	retval = *ptr;

	while (!atomic_fcmpset_ptr(ptr, &retval, value))
		;
	return (retval);
}
#else
#define	atomic_swap_ptr(ptr, value) atomic_swap_long((unsigned long *)(ptr), value)
#endif

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
