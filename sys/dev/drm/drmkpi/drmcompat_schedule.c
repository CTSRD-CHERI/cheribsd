/*-
 * Copyright (c) 2017 Mark Johnston <markj@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conds
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conds, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conds and the following disclaimer in the
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/signalvar.h>
#include <sys/sleepqueue.h>

#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/spinlock.h>

#include <drmcompat/completion.h>
#include <drmcompat/sched.h>
#include <drmcompat/wait.h>
#include <drmcompat/ww_mutex.h>

static int
drmcompat_add_to_sleepqueue(void *wchan, struct thread *task,
    const char *wmesg, int timeout, int state)
{
	int flags, ret;

	MPASS((state & ~(TASK_PARKED | TASK_NORMAL)) == 0);

	flags = SLEEPQ_SLEEP | ((state & TASK_INTERRUPTIBLE) != 0 ?
	    SLEEPQ_INTERRUPTIBLE : 0);

	sleepq_add(wchan, NULL, wmesg, flags, 0);
	if (timeout != 0)
		sleepq_set_timeout(wchan, timeout);

	DROP_GIANT();
	if ((state & TASK_INTERRUPTIBLE) != 0) {
		if (timeout == 0)
			ret = -sleepq_wait_sig(wchan, 0);
		else
			ret = -sleepq_timedwait_sig(wchan, 0);
	} else {
		if (timeout == 0) {
			sleepq_wait(wchan, 0);
			ret = 0;
		} else
			ret = -sleepq_timedwait(wchan, 0);
	}
	PICKUP_GIANT();

	/* filter return value */
	if (ret != 0 && ret != -EWOULDBLOCK) {
		ret = -ERESTARTSYS;
	}
	return (ret);
}

void
drmcompat_wake_up_task_locked(struct thread *task)
{
	int wakeup_swapper;

	wakeup_swapper = sleepq_signal(task, SLEEPQ_SLEEP, 0, 0);
	sleepq_release(task);
	if (wakeup_swapper)
		kick_proc0();
}

static int
wake_up_task_by_wq(wait_queue_entry_t *wq, unsigned int state)
{
	int ret, wakeup_swapper;
	struct thread *task;

	task = wq->private;

	ret = wakeup_swapper = 0;
	sleepq_lock(task);
	if ((atomic_load_int(&wq->state) & state) != 0) {
		atomic_store_int(&wq->state, TASK_WAKING);
		wakeup_swapper = sleepq_signal(task, SLEEPQ_SLEEP, 0, 0);
		ret = 1;
	}
	sleepq_release(task);
	if (wakeup_swapper)
		kick_proc0();
	return (ret);
}

bool
drmcompat_signal_pending(struct thread *td)
{
	sigset_t pending;

	PROC_LOCK(td->td_proc);
	pending = td->td_siglist;
	SIGSETOR(pending, td->td_proc->p_siglist);
	SIGSETNAND(pending, td->td_sigmask);
	PROC_UNLOCK(td->td_proc);
	return (!SIGISEMPTY(pending));
}

int
drmcompat_autoremove_wake_function(wait_queue_entry_t *wq, unsigned int state,
    int flags, void *key __unused)
{
	int ret;

	if ((ret = wake_up_task_by_wq(wq, state)) != 0)
		list_del_init(&wq->entry);
	return (ret);
}

void
drmcompat_wake_up(wait_queue_head_t *wqh, unsigned int state, int nr, bool locked)
{
	wait_queue_entry_t *pos, *next;

	if (!locked)
		spin_lock(&wqh->lock);
	list_for_each_entry_safe(pos, next, &wqh->head, entry) {
		if (pos->func == NULL) {
			if (wake_up_task_by_wq(pos, state) != 0 && --nr == 0)
				break;
		} else {
			if (pos->func(pos, state, 0, NULL) != 0 && --nr == 0)
				break;
		}
	}
	if (!locked)
		spin_unlock(&wqh->lock);
}

void
drmcompat_prepare_to_wait(wait_queue_head_t *wqh, wait_queue_entry_t *wq,
    int state)
{

	spin_lock(&wqh->lock);
	if (list_empty(&wq->entry))
		list_add(&wqh->head, &wq->entry);
	atomic_store_int(&wq->state, state);
	spin_unlock(&wqh->lock);
}

void
drmcompat_finish_wait(wait_queue_head_t *wqh, wait_queue_entry_t *wq)
{

	spin_lock(&wqh->lock);
	atomic_store_int(&wq->state, TASK_RUNNING);
	if (!list_empty(&wq->entry)) {
		list_del(&wq->entry);
		INIT_LIST_HEAD(&wq->entry);
	}
	spin_unlock(&wqh->lock);
}

int
drmcompat_wait_event_common(wait_queue_head_t *wqh, wait_queue_entry_t *wq,
    int timeout, unsigned int state, spinlock_t *lock)
{
	struct thread *task;
	int ret;

	if (lock != NULL)
		spin_unlock_irq(lock);

	/* range check timeout */
	if (timeout < 1)
		timeout = 1;
	else if (timeout == MAX_SCHEDULE_TIMEOUT)
		timeout = 0;

	task = current;

	/*
	 * Our wait queue entry is on the stack - make sure it doesn't
	 * get swapped out while we sleep.
	 */
	PHOLD(task->td_proc);
	sleepq_lock(task);
	if (atomic_load_int(&wq->state) != TASK_WAKING) {
		ret = drmcompat_add_to_sleepqueue(task, task, "wevent", timeout,
		    state);
	} else {
		sleepq_release(task);
		ret = 0;
	}
	PRELE(task->td_proc);

	if (lock != NULL)
		spin_lock_irq(lock);
	return (ret);
}

/*
 * Use sleepq_lock(current) before entering this function.
 */
int
drmcompat_schedule_timeout_interruptible(int timeout)
{
	struct thread *task;
	int remainder;
	int ret;

	task = current;

	/* range check timeout */
	if (timeout < 1)
		timeout = 1;
	else if (timeout == MAX_SCHEDULE_TIMEOUT)
		timeout = 0;

	remainder = ticks + timeout;

	ret = drmcompat_add_to_sleepqueue(task, task, "sched", timeout,
	    TASK_INTERRUPTIBLE);

	if (timeout == 0)
		return (MAX_SCHEDULE_TIMEOUT);

	/* range check return value */
	remainder -= ticks;

	/* range check return value */
	if (ret == -ERESTARTSYS && remainder < 1)
		remainder = 1;
	else if (remainder < 0)
		remainder = 0;
	else if (remainder > timeout)
		remainder = timeout;
	return (remainder);
}
