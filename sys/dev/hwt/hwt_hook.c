/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Ruslan Bukin <br@bsdpad.com>
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

/* Hardware Trace (HWT) framework. */

#include <sys/param.h>
#include <sys/eventhandler.h>
#include <sys/ioccom.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/refcount.h>
#include <sys/rwlock.h>
#include <sys/hwt.h>

#include <dev/hwt/hwt_hook.h>
#include <dev/hwt/hwt_context.h>
#include <dev/hwt/hwt_contexthash.h>
#include <dev/hwt/hwt_config.h>
#include <dev/hwt/hwt_thread.h>
#include <dev/hwt/hwt_owner.h>
#include <dev/hwt/hwt_backend.h>
#include <dev/hwt/hwt_record.h>

#define	HWT_DEBUG
#undef	HWT_DEBUG

#ifdef	HWT_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

static void
hwt_switch_in(struct thread *td)
{
	struct hwt_context *ctx;
	struct hwt_thread *thr;
	struct proc *p;
	int cpu_id;

	p = td->td_proc;

	cpu_id = PCPU_GET(cpuid);

	ctx = hwt_contexthash_lookup(p);
	if (ctx == NULL)
		return;

	if (ctx->state != CTX_STATE_RUNNING) {
		HWT_CTX_UNLOCK(ctx);
		return;
	}

	thr = hwt_thread_lookup(ctx, td);
	if (thr == NULL) {
		HWT_CTX_UNLOCK(ctx);
		return;
	}

	dprintf("%s: thr %p index %d tid %d on cpu_id %d\n", __func__, thr,
	    thr->thread_id, td->td_tid, cpu_id);

	hwt_backend_configure(ctx, cpu_id, thr->thread_id);
	hwt_backend_enable(ctx, cpu_id);

	HWT_THR_UNLOCK(thr);
}

static void
hwt_switch_out(struct thread *td)
{
	struct hwt_context *ctx;
	struct hwt_thread *thr;
	struct proc *p;
	int cpu_id;

	p = td->td_proc;

	cpu_id = PCPU_GET(cpuid);

	ctx = hwt_contexthash_lookup(p);
	if (ctx == NULL)
		return;

	if (ctx->state != CTX_STATE_RUNNING) {
		HWT_CTX_UNLOCK(ctx);
		return;
	}
	thr = hwt_thread_lookup(ctx, td);
	if (thr == NULL) {
		HWT_CTX_UNLOCK(ctx);
		return;
	}

	dprintf("%s: thr %p index %d tid %d on cpu_id %d\n", __func__, thr,
	    thr->thread_id, td->td_tid, cpu_id);

	hwt_backend_disable(ctx, cpu_id);
	HWT_THR_UNLOCK(thr);
}

static void
hwt_thread_exit(struct thread *td)
{
	struct hwt_context *ctx;
	struct hwt_thread *thr;
	struct proc *p;
	int cpu_id;

	p = td->td_proc;

	cpu_id = PCPU_GET(cpuid);

	ctx = hwt_contexthash_lookup(p);
	if (ctx == NULL)
		return;

	if (ctx->state != CTX_STATE_RUNNING) {
		HWT_CTX_UNLOCK(ctx);
		return;
	}
	thr = hwt_thread_lookup(ctx, td);
	if (thr == NULL) {
		HWT_CTX_UNLOCK(ctx);
		return;
	}

	thr->state = HWT_THREAD_STATE_EXITED;

	dprintf("%s: thr %p index %d tid %d on cpu_id %d\n", __func__, thr,
	    thr->thread_id, td->td_tid, cpu_id);

	hwt_backend_disable(ctx, cpu_id);
	HWT_THR_UNLOCK(thr);
}

static void
hwt_hook_mmap(struct thread *td)
{
	struct hwt_context *ctx;
	struct hwt_thread *thr;
	struct proc *p;
	int pause;

	p = td->td_proc;

	ctx = hwt_contexthash_lookup(p);
	if (ctx == NULL)
		return;

	/* The ctx state could be any here. */

	pause = ctx->pause_on_mmap ? 1 : 0;

	thr = hwt_thread_lookup(ctx, td);
	if (thr == NULL) {
		HWT_CTX_UNLOCK(ctx);
		return;
	}

	/*
	 * msleep(9) atomically releases the mtx lock, so take refcount
	 * to ensure that thr is not destroyed.
	 */
	refcount_acquire(&thr->refcnt);

	if (pause)
		msleep_spin(thr, &thr->mtx, "hwt-mmap", 0);

	HWT_THR_UNLOCK(thr);

	if (refcount_release(&thr->refcnt))
		hwt_thread_free(thr);
}

static void
hwt_hook_handler(struct thread *td, int func, void *arg)
{
	struct proc *p;

	p = td->td_proc;
	if ((p->p_flag2 & P2_HWT) == 0)
		return;

	switch (func) {
	case HWT_SWITCH_IN:
		hwt_switch_in(td);
		break;
	case HWT_SWITCH_OUT:
		hwt_switch_out(td);
		break;
	case HWT_THREAD_CREATE:
		hwt_thread_create(td);
		break;
	case HWT_THREAD_SET_NAME:
		/* TODO. */
		break;
	case HWT_THREAD_EXIT:
		hwt_thread_exit(td);
		break;
	case HWT_EXEC:
		hwt_record(td, arg);
		hwt_hook_mmap(td);
		break;
	case HWT_MMAP:
		hwt_record(td, arg);
		hwt_hook_mmap(td);
		break;
	case HWT_RECORD:
		hwt_record(td, arg);
		break;
	};
}

void
hwt_hook_load(void)
{

	hwt_hook = hwt_hook_handler;
}

void
hwt_hook_unload(void)
{

	hwt_hook = NULL;
}
