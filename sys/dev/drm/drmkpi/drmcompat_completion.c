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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/mutex.h>
#include <sys/limits.h>
#include <sys/sleepqueue.h>
#include <sys/proc.h>

#include <linux/errno.h>	/* For ERESTARTSYS */

#include <drmcompat/sched.h>
#include <drmcompat/completion.h>

static inline int
drmcompat_timer_jiffies_until(int expires)
{
	int delta = expires - ticks;
	/* guard against already expired values */
	if (delta < 1)
		delta = 1;
	return (delta);
}

void
drmcompat_complete_common(struct completion *c, int all)
{
	int wakeup_swapper;

	sleepq_lock(c);
	if (all) {
		c->done = UINT_MAX;
		wakeup_swapper = sleepq_broadcast(c, SLEEPQ_SLEEP, 0, 0);
	} else {
		if (c->done != UINT_MAX)
			c->done++;
		wakeup_swapper = sleepq_signal(c, SLEEPQ_SLEEP, 0, 0);
	}
	sleepq_release(c);
	if (wakeup_swapper)
		kick_proc0();
}

/*
 * Indefinite wait for done != 0 with or without signals.
 */
int
drmcompat_wait_for_common(struct completion *c, int flags)
{
	int error;

	if (SCHEDULER_STOPPED())
		return (0);

	if (flags != 0)
		flags = SLEEPQ_INTERRUPTIBLE | SLEEPQ_SLEEP;
	else
		flags = SLEEPQ_SLEEP;
	error = 0;
	for (;;) {
		sleepq_lock(c);
		if (c->done)
			break;
		sleepq_add(c, NULL, "completion", flags, 0);
		if (flags & SLEEPQ_INTERRUPTIBLE) {
			DROP_GIANT();
			error = -sleepq_wait_sig(c, 0);
			PICKUP_GIANT();
			if (error != 0) {
				error = -ERESTARTSYS;
				goto intr;
			}
		} else {
			DROP_GIANT();
			sleepq_wait(c, 0);
			PICKUP_GIANT();
		}
	}
	if (c->done != UINT_MAX)
		c->done--;
	sleepq_release(c);

intr:
	return (error);
}

/*
 * Time limited wait for done != 0 with or without signals.
 */
int
drmcompat_wait_for_timeout_common(struct completion *c, int timeout, int flags)
{
	int end = ticks + timeout;
	int error;

	if (SCHEDULER_STOPPED())
		return (0);

	if (flags != 0)
		flags = SLEEPQ_INTERRUPTIBLE | SLEEPQ_SLEEP;
	else
		flags = SLEEPQ_SLEEP;

	for (;;) {
		sleepq_lock(c);
		if (c->done)
			break;
		sleepq_add(c, NULL, "completion", flags, 0);
		sleepq_set_timeout(c, drmcompat_timer_jiffies_until(end));

		DROP_GIANT();
		if (flags & SLEEPQ_INTERRUPTIBLE)
			error = -sleepq_timedwait_sig(c, 0);
		else
			error = -sleepq_timedwait(c, 0);
		PICKUP_GIANT();

		if (error != 0) {
			/* check for timeout */
			if (error == -EWOULDBLOCK) {
				error = 0;	/* timeout */
			} else {
				/* signal happened */
				error = -ERESTARTSYS;
			}
			goto done;
		}
	}
	if (c->done != UINT_MAX)
		c->done--;
	sleepq_release(c);

	/* return how many jiffies are left */
	error = drmcompat_timer_jiffies_until(end);
done:
	return (error);
}

int
drmcompat_try_wait_for_completion(struct completion *c)
{
	int isdone;

	sleepq_lock(c);
	isdone = (c->done != 0);
	if (c->done != 0 && c->done != UINT_MAX)
		c->done--;
	sleepq_release(c);
	return (isdone);
}

int
drmcompat_completion_done(struct completion *c)
{
	int isdone;

	sleepq_lock(c);
	isdone = (c->done != 0);
	sleepq_release(c);
	return (isdone);
}
