/*-
 * Copyright (c) 2010 Isilon Systems, Inc.
 * Copyright (c) 2010 iX Systems, Inc.
 * Copyright (c) 2010 Panasas, Inc.
 * Copyright (c) 2013-2018 Mellanox Technologies, Ltd.
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

#ifndef __DRMCOMPAT_LINUX_SCHED_H__
#define	__DRMCOMPAT_LINUX_SCHED_H__

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/sleepqueue.h>
#include <sys/time.h>

#include <linux/bitmap.h>
#include <linux/completion.h>
#include <linux/mm_types.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/time.h>

#include <asm/atomic.h>

#include <drmcompat/sched.h>

#define	task_pid_group_leader(task) (task)->td_proc->p_pid
#define	task_pid(task)		((task)->td_tid)
#define	task_pid_nr(task)	((task)->td_tid)
#define	task_pid_vnr(task)	((task)->td_tid)
#define	get_pid(x)		(x)
#define	put_pid(x)		do { } while (0)
#define	current_euid()	(curthread->td_ucred->cr_uid)

#define	set_current_state(x)
#define	__set_current_state(x)

#define	cond_resched()	do { if (!cold) sched_relinquish(curthread); } while (0)

#define	yield()		kern_yield(PRI_UNCHANGED)
#define	sched_yield()	sched_relinquish(curthread)

#define	need_resched() (curthread->td_flags & TDF_NEEDRESCHED)

#define	signal_pending(task)		drmcompat_signal_pending(task)

#define	schedule()					\
	(void)drmcompat_schedule_timeout(MAX_SCHEDULE_TIMEOUT)
#define	schedule_timeout(timeout)			\
	drmcompat_schedule_timeout(timeout)
#define	schedule_timeout_killable(timeout)		\
	schedule_timeout_interruptible(timeout)
#define	schedule_timeout_interruptible(timeout) ({	\
	set_current_state(TASK_INTERRUPTIBLE);		\
	schedule_timeout(timeout);			\
})
#define	schedule_timeout_uninterruptible(timeout) ({	\
	set_current_state(TASK_UNINTERRUPTIBLE);	\
	schedule_timeout(timeout);			\
})

#define	io_schedule()			schedule()
#define	io_schedule_timeout(timeout)	schedule_timeout(timeout)

static inline uint64_t
local_clock(void)
{
	struct timespec ts;

	nanotime(&ts);
	return ((uint64_t)ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec);
}

#endif	/* __DRMCOMPAT_LINUX_SCHED_H__ */
