/*-
 * Copyright (c) 2010 Isilon Systems, Inc.
 * Copyright (c) 2010 iX Systems, Inc.
 * Copyright (c) 2010 Panasas, Inc.
 * Copyright (c) 2013-2016 Mellanox Technologies, Ltd.
 * Copyright (c) 2015 François Tigeot
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef __DRMCOMPAT_LINUX_COMPILER_H__
#define	__DRMCOMPAT_LINUX_COMPILER_H__

#include <sys/cdefs.h>
#include <linux/bitops.h>
#include <linux/math64.h>

#define __user
#define __kernel
#define __safe
#define __force
#define __nocast
#define __iomem
#define __chk_user_ptr(x)		((void)0)
#define __chk_io_ptr(x)			((void)0)
#define __builtin_warning(x, y...)	(1)
#define __acquires(x)
#define __releases(x)
#define __acquire(x)			do { } while (0)
#define __release(x)			do { } while (0)
#define __cond_lock(x,c)		(c)
#define	__bitwise
#define __devinitdata
#define	__deprecated
#define __init
#define	__initconst
#define	__devinit
#define	__devexit
#define __exit
#define	__rcu
#define	__percpu
#define	__weak __weak_symbol
#define	__malloc
#define	___stringify(...)		#__VA_ARGS__
#define	__stringify(...)		___stringify(__VA_ARGS__)
#define	__attribute_const__		__attribute__((__const__))
#undef __always_inline
#define	__always_inline			inline
#define	noinline			__noinline
#define	____cacheline_aligned		__aligned(CACHE_LINE_SIZE)

#define	likely(x)			__builtin_expect(!!(x), 1)
#define	unlikely(x)			__builtin_expect(!!(x), 0)
#define typeof(x)			__typeof(x)

#define	uninitialized_var(x)		x = x
#define	__maybe_unused			__unused
#define	__always_unused			__unused
#define	__must_check			__result_use_check

#define	__printf(a,b)			__printflike(a,b)

#define	barrier()			__asm__ __volatile__("": : :"memory")

#define	___PASTE(a,b) a##b
#define	__PASTE(a,b) ___PASTE(a,b)

#define	ACCESS_ONCE(x)			(*(volatile __typeof(x) *)&(x))

#define	WRITE_ONCE(x,v) do {		\
	barrier();			\
	ACCESS_ONCE(x) = (v);		\
	barrier();			\
} while (0)

#define	READ_ONCE(x) ({			\
	__typeof(x) __var = ({		\
		barrier();		\
		ACCESS_ONCE(x);		\
	});				\
	barrier();			\
	__var;				\
})

#define	lockless_dereference(p) READ_ONCE(p)

#define	_AT(T,X)	((T)(X))

#ifndef PRINT_UNIMPLEMENTED
#define PRINT_UNIMPLEMENTED 1
#endif

#define	UNIMPLEMENTED_ONCE() do {		\
	static int seen = 0;			\
						\
	if (!seen && PRINT_UNIMPLEMENTED) {	\
		log(LOG_WARNING,		\
		    "%s not implemented -- see your local kernel hacker\n", \
		    __FUNCTION__);		\
		seen = 1;			\
	}					\
} while (0)

#define	DODGY_ONCE() do {			\
	static int seen = 0;			\
						\
	if (!seen && PRINT_UNIMPLEMENTED) {	\
		log(LOG_WARNING,		\
		    "%s is dodgy -- see your local kernel hacker\n", \
		    __FUNCTION__);		\
		seen = 1;			\
	}					\
} while (0)

#undef UNIMPLEMENTED /* is defined to NOP in kernel lkpi */
#define	UNIMPLEMENTED()	UNIMPLEMENTED_ONCE()
#define	WARN_NOT()	UNIMPLEMENTED_ONCE()
#define	DODGY()		DODGY_ONCE()

#define	idr_init_base(idr,base)	idr_init(idr)

static inline uint64_t mul_u64_u32_div(uint64_t a, uint32_t mul, uint32_t divisor)
{
	union {
		uint64_t ll;
		struct {
#ifdef __BIG_ENDIAN
			uint32_t high, low;
#else
			uint32_t low, high;
#endif
		} l;
	} u, rl, rh;

	u.ll = a;
	rl.ll = mul_u32_u32(u.l.low, mul);
	rh.ll = mul_u32_u32(u.l.high, mul) + rl.l.high;

	/* Bits 32-63 of the result will be in rh.l.low. */
	rl.l.high = do_div(rh.ll, divisor);

	/* Bits 0-31 of the result will be in rl.l.low.	*/
	do_div(rl.ll, divisor);

	rl.l.high = rh.l.low;
	return rl.ll;
}

#endif	/* __DRMCOMPAT_LINUX_COMPILER_H__ */
