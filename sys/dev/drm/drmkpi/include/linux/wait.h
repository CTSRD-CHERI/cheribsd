/*-
 * Copyright (c) 2010 Isilon Systems, Inc.
 * Copyright (c) 2010 iX Systems, Inc.
 * Copyright (c) 2010 Panasas, Inc.
 * Copyright (c) 2013, 2014 Mellanox Technologies, Ltd.
 * Copyright (c) 2017 Mark Johnston <markj@FreeBSD.org>
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

#ifndef __DRMCOMPAT_LINUX_WAIT_H__
#define	__DRMCOMPAT_LINUX_WAIT_H__

#include <linux/compiler.h>
#include <linux/list.h>
#include <linux/spinlock.h>

#include <asm/atomic.h>

#include <drmcompat/wait.h>

#include <sys/param.h>
#include <sys/systm.h>

#define	SKIP_SLEEP() (SCHEDULER_STOPPED() || kdb_active)

#define	might_sleep()							\
	WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, NULL, "might_sleep()")

#define	might_sleep_if(cond) do { \
	if (cond) { might_sleep(); } \
} while (0)

#define	DEFINE_WAIT_FUNC(name, function)				\
	wait_queue_entry_t name = {					\
		.private = current,					\
		.func = function,					\
		.entry = LINUX_LIST_HEAD_INIT(name.entry)		\
	}

#define	DEFINE_WAIT(name) \
	DEFINE_WAIT_FUNC(name, drmcompat_autoremove_wake_function)

#define	DECLARE_WAITQUEUE(name, task)					\
	wait_queue_entry_t name = {					\
		.private = task,					\
		.entry = LINUX_LIST_HEAD_INIT(name.entry)		\
	}

#define	DECLARE_WAIT_QUEUE_HEAD(name)					\
	wait_queue_head_t name = {					\
		.entry = LINUX_LIST_HEAD_INIT(name.entry),		\
	};								\
	MTX_SYSINIT(name, &(name).lock.m, spin_lock_name("wqhead"), MTX_DEF)

#define	init_waitqueue_head(wqh) do {					\
	mtx_init(&(wqh)->lock.m, spin_lock_name("wqhead"),		\
	    NULL, MTX_DEF | MTX_NEW | MTX_NOWITNESS);			\
	INIT_LIST_HEAD(&(wqh)->head);					\
} while (0)

#define	wake_up(wqh)							\
	drmcompat_wake_up(wqh, TASK_NORMAL, 1, false)
#define	wake_up_all(wqh)						\
	drmcompat_wake_up(wqh, TASK_NORMAL, 0, false)
#define	wake_up_locked(wqh)						\
	drmcompat_wake_up(wqh, TASK_NORMAL, 1, true)
#define	wake_up_all_locked(wqh)						\
	drmcompat_wake_up(wqh, TASK_NORMAL, 0, true)
#define	wake_up_interruptible(wqh)					\
	drmcompat_wake_up(wqh, TASK_INTERRUPTIBLE, 1, false)
#define	wake_up_interruptible_all(wqh)					\
	drmcompat_wake_up(wqh, TASK_INTERRUPTIBLE, 0, false)

/*
 * Returns -ERESTARTSYS for a signal, 0 if cond is false after timeout, 1 if
 * cond is true after timeout, remaining jiffies (> 0) if cond is true before
 * timeout.
 */
#define	__wait_event_common(wqh, cond, timeout, state, lock) ({	\
	DEFINE_WAIT(__wq);					\
	const int __timeout = ((int)(timeout)) < 1 ? 1 : (timeout);	\
	int __start = ticks;					\
	int __ret = 0;						\
								\
	for (;;) {						\
		drmcompat_prepare_to_wait(&(wqh), &__wq, state);	\
		if (cond)					\
			break;					\
		__ret = drmcompat_wait_event_common(&(wqh), &__wq,	\
		    __timeout, state, lock);			\
		if (__ret != 0)					\
			break;					\
	}							\
	drmcompat_finish_wait(&(wqh), &__wq);			\
	if (__timeout != MAX_SCHEDULE_TIMEOUT) {		\
		if (__ret == -EWOULDBLOCK)			\
			__ret = !!(cond);			\
		else if (__ret != -ERESTARTSYS) {		\
			__ret = __timeout + __start - ticks;	\
			/* range check return value */		\
			if (__ret < 1)				\
				__ret = 1;			\
			else if (__ret > __timeout)		\
				__ret = __timeout;		\
		}						\
	}							\
	__ret;							\
})

#define	wait_event(wqh, cond) do {					\
	(void) __wait_event_common(wqh, cond, MAX_SCHEDULE_TIMEOUT,	\
	    TASK_UNINTERRUPTIBLE, NULL);				\
} while (0)

#define	wait_event_timeout(wqh, cond, timeout) ({			\
	__wait_event_common(wqh, cond, timeout, TASK_UNINTERRUPTIBLE,	\
	    NULL);							\
})

#define	wait_event_killable(wqh, cond) ({				\
	__wait_event_common(wqh, cond, MAX_SCHEDULE_TIMEOUT,		\
	    TASK_INTERRUPTIBLE, NULL);					\
})

#define	wait_event_interruptible(wqh, cond) ({				\
	__wait_event_common(wqh, cond, MAX_SCHEDULE_TIMEOUT,		\
	    TASK_INTERRUPTIBLE, NULL);					\
})

#define	wait_event_interruptible_timeout(wqh, cond, timeout) ({		\
	__wait_event_common(wqh, cond, timeout, TASK_INTERRUPTIBLE,	\
	    NULL);							\
})

#define	prepare_to_wait(wqh, wq, state)	drmcompat_prepare_to_wait(wqh, wq, state)
#define	finish_wait(wqh, wq)		drmcompat_finish_wait(wqh, wq)

/*
 * All existing callers have a cb that just schedule()s. To avoid adding
 * complexity, just emulate that internally. The prototype is different so that
 * callers must be manually modified; a cb that does something other than call
 * schedule() will require special treatment.
 */

#define	wake_up_process_locked(task)	drmcompat_wake_up_task_locked(task)

#endif /* __DRMCOMPAT_LINUX_WAIT_H__ */
