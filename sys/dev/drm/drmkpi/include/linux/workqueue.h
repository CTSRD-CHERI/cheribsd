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

#ifndef	__DRMCOMPAT_LINUX_WORKQUEUE_H__
#define	__DRMCOMPAT_LINUX_WORKQUEUE_H__

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/timer.h>

#include <asm/atomic.h>

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/taskqueue.h>
#include <sys/mutex.h>

#include <drmcompat/workqueue.h>

#define	WORK_CPU_UNBOUND MAXCPU
#define	WQ_UNBOUND (1 << 0)
#define	WQ_HIGHPRI (1 << 1)

#define	DECLARE_WORK(name, fn)						\
	struct work_struct name;					\
	static void name##_init(void *arg)				\
	{								\
		INIT_WORK(&name, fn);					\
	}								\
	SYSINIT(name, SI_SUB_LOCK, SI_ORDER_SECOND, name##_init, NULL)

#define	DECLARE_DELAYED_WORK(name, fn)					\
	struct delayed_work name;					\
	static void name##_init(void *arg)				\
	{								\
		drmcompat_init_delayed_work(&name, fn);			\
	}								\
	SYSINIT(name, SI_SUB_LOCK, SI_ORDER_SECOND, name##_init, NULL)

static inline struct delayed_work *
to_delayed_work(struct work_struct *work)
{
	return (container_of(work, struct delayed_work, work));
}

#define	system_wq			drmcompat_system_wq
#define	system_long_wq			drmcompat_system_long_wq
#define	system_unbound_wq		drmcompat_system_unbound_wq
#define	system_highpri_wq		drmcompat_system_highpri_wq
#define	system_power_efficient_wq	drmcompat_system_power_efficient_wq

#define	INIT_WORK(work, fn)						\
do {									\
	(work)->func = (fn);						\
	(work)->work_queue = NULL;					\
	atomic_set(&(work)->state, 0);					\
	TASK_INIT(&(work)->work_task, 0, drmcompat_work_fn, (work));	\
} while (0)

#define	INIT_WORK_ONSTACK(work, fn) \
	INIT_WORK(work, fn)

#define	INIT_DELAYED_WORK(dwork, fn) \
	drmcompat_init_delayed_work(dwork, fn)

#define	INIT_DELAYED_WORK_ONSTACK(dwork, fn) \
	drmcompat_init_delayed_work(dwork, fn)

#define	INIT_DEFERRABLE_WORK(dwork, fn) \
	INIT_DELAYED_WORK(dwork, fn)

#define	flush_scheduled_work() \
	taskqueue_drain_all(system_wq->taskqueue)

#define	queue_work(wq, work) \
	drmcompat_queue_work_on(WORK_CPU_UNBOUND, wq, work)

#define	schedule_work(work) \
	drmcompat_queue_work_on(WORK_CPU_UNBOUND, system_wq, work)

#define	queue_delayed_work(wq, dwork, delay) \
	drmcompat_queue_delayed_work_on(WORK_CPU_UNBOUND, wq, dwork, delay)

#define	schedule_delayed_work_on(cpu, dwork, delay) \
	drmcompat_queue_delayed_work_on(cpu, system_wq, dwork, delay)

#define	queue_work_on(cpu, wq, work) \
	drmcompat_queue_work_on(cpu, wq, work)

#define	schedule_delayed_work(dwork, delay) \
	drmcompat_queue_delayed_work_on(WORK_CPU_UNBOUND, system_wq, dwork, delay)

#define	queue_delayed_work_on(cpu, wq, dwork, delay) \
	drmcompat_queue_delayed_work_on(cpu, wq, dwork, delay)

#define	create_singlethread_workqueue(name) \
	drmcompat_create_workqueue_common(name, 1)

#define	create_workqueue(name) \
	drmcompat_create_workqueue_common(name, mp_ncpus)

#define	alloc_ordered_workqueue(name, flags) \
	drmcompat_create_workqueue_common(name, 1)

#define	alloc_workqueue(name, flags, max_active) \
	drmcompat_create_workqueue_common(name, max_active)

#define	flush_workqueue(wq) \
	taskqueue_drain_all((wq)->taskqueue)

#define	drain_workqueue(wq) do {		\
	atomic_inc(&(wq)->draining);		\
	taskqueue_drain_all((wq)->taskqueue);	\
	atomic_dec(&(wq)->draining);		\
} while (0)

#define	mod_delayed_work(wq, dwork, delay) ({		\
	bool __retval;					\
	__retval = drmcompat_cancel_delayed_work(dwork);	\
	drmcompat_queue_delayed_work_on(WORK_CPU_UNBOUND,	\
	    wq, dwork, delay);				\
	__retval;					\
})

#define	delayed_work_pending(dwork) \
	drmcompat_work_pending(&(dwork)->work)

#define	cancel_delayed_work(dwork) \
	drmcompat_cancel_delayed_work(dwork)

#define	cancel_work_sync(work) \
	drmcompat_cancel_work_sync(work)

#define	cancel_delayed_work_sync(dwork) \
	drmcompat_cancel_delayed_work_sync(dwork)

#define	flush_work(work) \
	drmcompat_flush_work(work)

#define	flush_delayed_work(dwork) \
	drmcompat_flush_delayed_work(dwork)

#define	work_pending(work) \
	drmcompat_work_pending(work)

#define	work_busy(work) \
	drmcompat_work_busy(work)

#define	destroy_work_on_stack(work) \
	do { } while (0)

#define	destroy_delayed_work_on_stack(dwork) \
	do { } while (0)

#define	destroy_workqueue(wq) \
	drmcompat_destroy_workqueue(wq)

#define	current_work() \
	drmcompat_current_work()

#endif	/* __DRMCOMPAT_LINUX_WORKQUEUE_H__ */
