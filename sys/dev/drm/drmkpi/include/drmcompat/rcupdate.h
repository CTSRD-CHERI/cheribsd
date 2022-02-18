/*-
 * Copyright (c) 2016-2017 Mellanox Technologies, Ltd.
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

#ifndef __DRMCOMPAT_RCUPDATE_H__
#define	__DRMCOMPAT_RCUPDATE_H__

/* BSD specific defines */
#define	RCU_TYPE_REGULAR 0
#define	RCU_TYPE_SLEEPABLE 1
#define	RCU_TYPE_MAX 2

#define	LINUX_KFREE_RCU_OFFSET_MAX	4096	/* exclusive */

struct rcu_head {
};

typedef void (*rcu_callback_t)(struct rcu_head *head);
typedef void (*call_rcu_func_t)(struct rcu_head *head, rcu_callback_t func);

extern struct mtx drmcompat_global_rcu_lock;

static inline void
drmcompat_call_rcu(unsigned type, struct rcu_head *ptr, rcu_callback_t func)
{

	mtx_lock(&drmcompat_global_rcu_lock);
	func(ptr);
	mtx_unlock(&drmcompat_global_rcu_lock);
}

static inline void
drmcompat_rcu_read_lock(unsigned type)
{

	mtx_lock(&drmcompat_global_rcu_lock);
}

static inline void
drmcompat_rcu_read_unlock(unsigned type)
{

	mtx_unlock(&drmcompat_global_rcu_lock);
}

static inline void
drmcompat_rcu_barrier(unsigned type)
{

	mtx_lock(&drmcompat_global_rcu_lock);
	mtx_unlock(&drmcompat_global_rcu_lock);
}

static inline void
drmcompat_synchronize_rcu(unsigned type)
{

	mtx_lock(&drmcompat_global_rcu_lock);
	mtx_unlock(&drmcompat_global_rcu_lock);
}

#endif	/* __DRMCOMPAT_RCUPDATE_H__ */
