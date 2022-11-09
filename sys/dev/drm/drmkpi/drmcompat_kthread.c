/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2021 Ruslan Bukin <br@bsdpad.com>
 *
 * This work was supported by Innovate UK project 105694, "Digital Security
 * by Design (DSbD) Technology Platform Prototype".
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/proc.h>
#include <sys/bus.h>
#include <sys/interrupt.h>
#include <sys/priority.h>

#include <linux/kthread.h>

#define	DRMCOMPAT_SUSPEND_WAIT	2000000

bool
drmcompat_kthread_should_stop_task(struct thread *td)
{

	if (td->td_flags & TDF_KTH_SUSP)
		return (true);

	return (false);
}

bool
drmcompat_kthread_should_stop(void)
{
	struct thread *td;

	td = curthread;

	return (drmcompat_kthread_should_stop_task(td));
}

int
drmcompat_kthread_stop(struct thread *td)
{
	int error;

	error = kthread_suspend(td, DRMCOMPAT_SUSPEND_WAIT);

	return (error);
}

int
drmcompat_kthread_park(struct thread *td)
{
	int error;

	error = kthread_suspend(td, DRMCOMPAT_SUSPEND_WAIT);

	return (error);
}

void
drmcompat_kthread_parkme(void)
{

	kthread_suspend_check();
}

bool
drmcompat_kthread_should_park(void)
{
	struct thread *td;

	td = curthread;

	return (drmcompat_kthread_should_stop_task(td));
}

void
drmcompat_kthread_unpark(struct thread *td)
{

	kthread_resume(td);
}

struct thread *
drmcompat_kthread_setup_and_run(struct thread *td)
{

	thread_lock(td);
	/* make sure the scheduler priority is raised */
	sched_prio(td, PI_SWI(SWI_NET));
	/* put thread into run-queue */
	sched_add(td, SRQ_BORING);

	return (td);
}

void
drmcompat_kthread_fn(void *arg)
{
	struct kthr_wrap *w;

	w = arg;
	w->func(w->arg);

	free(w, M_DRMKMALLOC);

	kthread_exit();
}
