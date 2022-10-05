/*	$NetBSD: fence.h,v 1.15 2018/08/27 14:20:41 riastradh Exp $	*/

/*-
 * Copyright (c) 2018 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Taylor R. Campbell.
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __DRMCOMPAT_LINUX_DMA_FENCE_H__
#define	__DRMCOMPAT_LINUX_DMA_FENCE_H__

#include <sys/types.h>
#include <sys/condvar.h>
#include <sys/kernel.h>
#include <sys/sx.h>
#include <sys/queue.h>

#include <linux/kref.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>

struct dma_fence_cb;

struct dma_fence {
	struct kref			refcount;
	spinlock_t			*lock;
	volatile unsigned long		flags;
	unsigned			context;
	unsigned			seqno;
	const struct dma_fence_ops	*ops;
	int				error;

	TAILQ_HEAD(, dma_fence_cb)	f_callbacks;
	struct cv			f_cv;
	struct rcu_head			f_rcu;
};

enum dma_fence_flag_bits {
	DMA_FENCE_FLAG_SIGNALED_BIT,
	DMA_FENCE_FLAG_TIMESTAMP_BIT,
	DMA_FENCE_FLAG_ENABLE_SIGNAL_BIT,
	/* ... */
	DMA_FENCE_FLAG_USER_BITS,
};

struct dma_fence_ops {
	bool		use_64bit_seqno;
	const char	*(*get_driver_name)(struct dma_fence *);
	const char	*(*get_timeline_name)(struct dma_fence *);
	bool		(*enable_signaling)(struct dma_fence *);
	bool		(*signaled)(struct dma_fence *);
	long		(*wait)(struct dma_fence *, bool, long);
	void		(*release)(struct dma_fence *);
};

typedef void (*dma_fence_func_t)(struct dma_fence *, struct dma_fence_cb *);

struct dma_fence_cb {
	dma_fence_func_t		func; /* Linux API name */
	TAILQ_ENTRY(dma_fence_cb)	fcb_entry;
	bool				fcb_onqueue;
};

#define	dma_fence_add_callback		linux_dma_fence_add_callback
#define	dma_fence_context_alloc		linux_dma_fence_context_alloc
#define	dma_fence_default_wait		linux_dma_fence_default_wait
#define	dma_fence_destroy		linux_dma_fence_destroy
#define	dma_fence_enable_sw_signaling	linux_dma_fence_enable_sw_signaling
#define	dma_fence_free			linux_dma_fence_free
#define	dma_fence_get			linux_dma_fence_get
#define	dma_fence_get_rcu		linux_dma_fence_get_rcu
#define	dma_fence_get_rcu_safe		linux_dma_fence_get_rcu_safe
#define	dma_fence_init			linux_dma_fence_init
#define	dma_fence_is_later		linux_dma_fence_is_later
#define	dma_fence_is_signaled		linux_dma_fence_is_signaled
#define	dma_fence_is_signaled_locked	linux_dma_fence_is_signaled_locked
#define	dma_fence_put			linux_dma_fence_put
#define	dma_fence_remove_callback	linux_dma_fence_remove_callback
#define	dma_fence_set_error		linux_dma_fence_set_error
#define	dma_fence_signal		linux_dma_fence_signal
#define	dma_fence_signal_locked		linux_dma_fence_signal_locked
#define	dma_fence_wait			linux_dma_fence_wait
#define	dma_fence_wait_any_timeout	linux_dma_fence_wait_any_timeout
#define	dma_fence_wait_timeout		linux_dma_fence_wait_timeout

extern int linux_dma_fence_trace;

void	dma_fence_init(struct dma_fence *, const struct dma_fence_ops *,
	    spinlock_t *, unsigned, unsigned);
void	dma_fence_destroy(struct dma_fence *);
void	dma_fence_free(struct dma_fence *);

unsigned
	dma_fence_context_alloc(unsigned);
bool	dma_fence_is_later(struct dma_fence *, struct dma_fence *);

struct dma_fence *
	dma_fence_get(struct dma_fence *);
struct dma_fence *
	dma_fence_get_rcu(struct dma_fence *);
struct dma_fence *
	dma_fence_get_rcu_safe(struct dma_fence *volatile const *);
void	dma_fence_put(struct dma_fence *);

int	dma_fence_add_callback(struct dma_fence *, struct dma_fence_cb *,
	    dma_fence_func_t);
bool	dma_fence_remove_callback(struct dma_fence *, struct dma_fence_cb *);
void	dma_fence_enable_sw_signaling(struct dma_fence *);

bool	dma_fence_is_signaled(struct dma_fence *);
bool	dma_fence_is_signaled_locked(struct dma_fence *);
void	dma_fence_set_error(struct dma_fence *, int);
int	dma_fence_signal(struct dma_fence *);
int	dma_fence_signal_locked(struct dma_fence *);
long	dma_fence_default_wait(struct dma_fence *, bool, long);
long	dma_fence_wait(struct dma_fence *, bool);
long	dma_fence_wait_any_timeout(struct dma_fence **, uint32_t, bool, long);
long	dma_fence_wait_timeout(struct dma_fence *, bool, long);
struct dma_fence *dma_fence_get_stub(void);

static inline void
DMA_FENCE_TRACE(struct dma_fence *f, const char *fmt, ...)
{
	va_list va;

	if (__predict_false(linux_dma_fence_trace)) {
		va_start(va, fmt);
		printf("fence %u@%u: ", f->context, f->seqno);
		vprintf(fmt, va);
		va_end(va);
	}
}

#endif	/* __DRMCOMPAT_LINUX_DMA_FENCE_H__ */
