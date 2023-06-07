/*-
 * Copyright (c) 2010 Isilon Systems, Inc.
 * Copyright (c) 2010 iX Systems, Inc.
 * Copyright (c) 2010 Panasas, Inc.
 * Copyright (c) 2013-2017 Mellanox Technologies, Ltd.
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

#ifndef __DRMCOMPAT_WORKQUEUE_H__
#define	__DRMCOMPAT_WORKQUEUE_H__

struct work_struct;
typedef void (*work_func_t)(struct work_struct *);

struct work_exec {
	TAILQ_ENTRY(work_exec) entry;
	struct work_struct *target;
};

struct workqueue_struct {
	struct taskqueue *taskqueue;
	struct mtx exec_mtx;
	TAILQ_HEAD(, work_exec) exec_head;
	atomic_t draining;
};

struct work_struct {
	struct task work_task;
	struct workqueue_struct *work_queue;
	work_func_t func;
	atomic_t state;
};

struct delayed_work {
	struct work_struct work;
	struct {
		struct callout callout;
		struct mtx mtx;
		int	expires;
	} timer;
} __subobject_use_container_bounds;

extern struct workqueue_struct *drmcompat_system_wq;
extern struct workqueue_struct *drmcompat_system_long_wq;
extern struct workqueue_struct *drmcompat_system_unbound_wq;

void drmcompat_init_delayed_work(struct delayed_work *, work_func_t);
void drmcompat_work_fn(void *, int);
void drmcompat_delayed_work_fn(void *, int);
struct workqueue_struct *drmcompat_create_workqueue_common(const char *, int);
void drmcompat_destroy_workqueue(struct workqueue_struct *);
bool drmcompat_queue_work_on(int cpu, struct workqueue_struct *, struct work_struct *);
bool drmcompat_queue_delayed_work_on(int cpu, struct workqueue_struct *,
    struct delayed_work *, unsigned delay);
bool drmcompat_cancel_delayed_work(struct delayed_work *);
bool drmcompat_cancel_work_sync(struct work_struct *);
bool drmcompat_cancel_delayed_work_sync(struct delayed_work *);
bool drmcompat_flush_work(struct work_struct *);
bool drmcompat_flush_delayed_work(struct delayed_work *);
bool drmcompat_work_pending(struct work_struct *);
bool drmcompat_work_busy(struct work_struct *);
struct work_struct *drmcompat_current_work(void);

#endif
