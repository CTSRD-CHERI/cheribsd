/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Ruslan Bukin <br@bsdpad.com>
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

/* Hardware Counting (HWC) framework. */

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/refcount.h>
#include <sys/hwc.h>

#include <dev/hwc/hwc_hook.h>
#if 0
#include <dev/hwc/hwc_context.h>
#include <dev/hwc/hwc_contexthash.h>
#include <dev/hwc/hwc_config.h>
#include <dev/hwc/hwc_thread.h>
#include <dev/hwc/hwc_owner.h>
#include <dev/hwc/hwc_backend.h>
#include <dev/hwc/hwc_record.h>
#include <dev/hwc/hwc_vm.h>
#endif

#define	HWC_DEBUG
#undef	HWC_DEBUG

#ifdef	HWC_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

static void
hwc_switch_in(struct thread *td)
{
#if 0
	struct hwc_context *ctx;
	struct hwc_thread *thr;
	struct proc *p;
	int cpu_id;

	p = td->td_proc;

	cpu_id = PCPU_GET(cpuid);

	ctx = hwc_contexthash_lookup(p);
	if (ctx == NULL)
		return;

	if (ctx->state != CTX_STATE_RUNNING) {
		hwc_ctx_put(ctx);
		return;
	}

	thr = hwc_thread_lookup(ctx, td);
	if (thr == NULL) {
		hwc_ctx_put(ctx);
		return;
	}

	dprintf("%s: thr %p index %d tid %d on cpu_id %d\n", __func__, thr,
	    thr->thread_id, td->td_tid, cpu_id);

	hwc_backend_configure(ctx, cpu_id, thr->thread_id);
	hwc_backend_enable(ctx, cpu_id);

	hwc_ctx_put(ctx);
#endif
}

static void
hwc_switch_out(struct thread *td)
{
#if 0
	struct hwc_context *ctx;
	struct hwc_thread *thr;
	struct proc *p;
	int cpu_id;

	p = td->td_proc;

	cpu_id = PCPU_GET(cpuid);

	ctx = hwc_contexthash_lookup(p);
	if (ctx == NULL)
		return;

	if (ctx->state != CTX_STATE_RUNNING) {
		hwc_ctx_put(ctx);
		return;
	}
	thr = hwc_thread_lookup(ctx, td);
	if (thr == NULL) {
		hwc_ctx_put(ctx);
		return;
	}

	dprintf("%s: thr %p index %d tid %d on cpu_id %d\n", __func__, thr,
	    thr->thread_id, td->td_tid, cpu_id);

	hwc_backend_disable(ctx, cpu_id);

	hwc_ctx_put(ctx);
#endif
}

#if 0
static void
hwc_hook_thread_exit(struct thread *td)
{
	struct hwc_context *ctx;
	struct hwc_thread *thr;
	struct proc *p;
	int cpu_id;

	p = td->td_proc;

	cpu_id = PCPU_GET(cpuid);

	ctx = hwc_contexthash_lookup(p);
	if (ctx == NULL)
		return;

	thr = hwc_thread_lookup(ctx, td);
	if (thr == NULL) {
		hwc_ctx_put(ctx);
		return;
	}

	thr->state = HWC_THREAD_STATE_EXITED;

	dprintf("%s: thr %p index %d tid %d on cpu_id %d\n", __func__, thr,
	    thr->thread_id, td->td_tid, cpu_id);

	if (ctx->state == CTX_STATE_RUNNING)
		hwc_backend_disable(ctx, cpu_id);

	hwc_ctx_put(ctx);
}

static void
hwc_hook_mmap(struct thread *td)
{
	struct hwc_context *ctx;
	struct hwc_thread *thr;
	struct proc *p;
	int pause;

	p = td->td_proc;

	ctx = hwc_contexthash_lookup(p);
	if (ctx == NULL)
		return;

	/* The ctx state could be any here. */

	pause = ctx->pause_on_mmap ? 1 : 0;

	thr = hwc_thread_lookup(ctx, td);
	if (thr == NULL) {
		hwc_ctx_put(ctx);
		return;
	}

	/*
	 * msleep(9) atomically releases the mtx lock, so take refcount
	 * to ensure that thr is not destroyed.
	 * It could not be destroyed prior to this call as we are holding ctx
	 * refcnt.
	 */
	refcount_acquire(&thr->refcnt);
	hwc_ctx_put(ctx);

	if (pause) {
		HWC_THR_LOCK(thr);
		msleep(thr, &thr->mtx, PCATCH, "hwc-mmap", 0);
		HWC_THR_UNLOCK(thr);
	}

	if (refcount_release(&thr->refcnt))
		hwc_thread_free(thr);
}

static int
hwc_hook_thread_create(struct thread *td)
{
	struct hwc_record_entry *entry;
	struct hwc_context *ctx;
	struct hwc_thread *thr;
	char path[MAXPATHLEN];
	size_t bufsize;
	struct proc *p;
	int thread_id, kva_req;
	int error;

	p = td->td_proc;

	/* Step 1. Get CTX and collect information needed. */
	ctx = hwc_contexthash_lookup(p);
	if (ctx == NULL)
		return (ENXIO);
	thread_id = atomic_fetchadd_int(&ctx->thread_counter, 1);
	bufsize = ctx->bufsize;
	kva_req = ctx->hwc_backend->kva_req;
	sprintf(path, "hwc_%d_%d", ctx->ident, thread_id);
	hwc_ctx_put(ctx);

	/* Step 2. Allocate some memory without holding ctx ref. */
	error = hwc_thread_alloc(&thr, path, bufsize, kva_req);
	if (error) {
		printf("%s: could not allocate thread, error %d\n",
		    __func__, error);
		return (error);
	}

	entry = hwc_record_entry_alloc();
	entry->record_type = HWC_RECORD_THREAD_CREATE;
	entry->thread_id = thread_id;

	/* Step 3. Get CTX once again. */
	ctx = hwc_contexthash_lookup(p);
	if (ctx == NULL) {
		hwc_record_entry_free(entry);
		hwc_thread_free(thr);
		/* ctx->thread_counter does not matter. */
		return (ENXIO);
	}
	/* Allocate backend-specific thread data. */
	error = hwc_backend_thread_alloc(ctx, thr);
	if (error != 0) {
		dprintf("%s: failed to allocate backend thread data\n",
			    __func__);
		return (error);
	}

	thr->vm->ctx = ctx;
	thr->ctx = ctx;
	thr->backend = ctx->hwc_backend;
	thr->thread_id = thread_id;
	thr->td = td;

	HWC_CTX_LOCK(ctx);
	hwc_thread_insert(ctx, thr, entry);
	HWC_CTX_UNLOCK(ctx);

	/* Notify userspace. */
	hwc_record_wakeup(ctx);

	hwc_ctx_put(ctx);

	return (0);
}
#endif

static void
hwc_hook_handler(struct thread *td, int func, void *arg)
{
	struct proc *p;

	p = td->td_proc;
	if ((p->p_flag2 & P2_HWC) == 0)
		return;

	switch (func) {
	case HWC_SWITCH_IN:
		hwc_switch_in(td);
		break;
	case HWC_SWITCH_OUT:
		hwc_switch_out(td);
		break;
#if 0
	case HWC_THREAD_CREATE:
		hwc_hook_thread_create(td);
		break;
	case HWC_THREAD_SET_NAME:
		/* TODO. */
		break;
	case HWC_THREAD_EXIT:
		hwc_hook_thread_exit(td);
		break;
	case HWC_EXEC:
	case HWC_MMAP:
		hwc_record_td(td, arg, M_WAITOK | M_ZERO);
		hwc_hook_mmap(td);
		break;
	case HWC_RECORD:
		hwc_record_td(td, arg, M_WAITOK | M_ZERO);
		break;
#endif
	};
}

void
hwc_hook_load(void)
{

	hwc_hook = hwc_hook_handler;
}

void
hwc_hook_unload(void)
{

	hwc_hook = NULL;
}
