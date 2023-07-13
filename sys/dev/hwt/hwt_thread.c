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

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_page.h>
#include <vm/vm_object.h>
#include <vm/vm_pager.h>
#include <vm/vm_pageout.h>
#include <vm/vm_phys.h>

#include <dev/hwt/hwt_hook.h>
#include <dev/hwt/hwt_context.h>
#include <dev/hwt/hwt_contexthash.h>
#include <dev/hwt/hwt_config.h>
#include <dev/hwt/hwt_thread.h>
#include <dev/hwt/hwt_owner.h>
#include <dev/hwt/hwt_ownerhash.h>
#include <dev/hwt/hwt_backend.h>
#include <dev/hwt/hwt_vm.h>

#define	HWT_THREAD_DEBUG
#undef	HWT_THREAD_DEBUG

#ifdef	HWT_THREAD_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

static MALLOC_DEFINE(M_HWT_THREAD, "hwt_thread", "Hardware Trace");

struct hwt_thread *
hwt_thread_first(struct hwt_context *ctx)
{
	struct hwt_thread *thr;

	HWT_CTX_ASSERT_LOCKED(ctx);

	thr = LIST_FIRST(&ctx->threads);

	KASSERT(thr != NULL, ("thr is NULL"));

	return (thr);
}

/*
 * Called by ctx owner only.
 */
struct hwt_thread *
hwt_thread_lookup_by_tid(struct hwt_context *ctx, lwpid_t tid)
{
	struct hwt_thread *thr;

	HWT_CTX_ASSERT_LOCKED(ctx);

	LIST_FOREACH(thr, &ctx->threads, next) {
		if (thr->tid == tid)
			return (thr);
	}

	return (NULL);
}

/*
 * To use by hwt_switch_in/out() only.
 */
struct hwt_thread *
hwt_thread_lookup(struct hwt_context *ctx, struct thread *td)
{
	struct hwt_thread *thr;

	HWT_CTX_ASSERT_LOCKED(ctx);

	LIST_FOREACH(thr, &ctx->threads, next) {
		if (thr->tid == td->td_tid) {
			HWT_THR_LOCK(thr);
			HWT_CTX_UNLOCK(ctx);
			return (thr);
		}
	}

	panic("thread not found");
}

int
hwt_thread_alloc(struct hwt_thread **thr0, size_t bufsize)
{
	struct hwt_thread *thr;
	struct hwt_vm *vm;
	int error;

	thr = malloc(sizeof(struct hwt_thread), M_HWT_THREAD,
	    M_WAITOK | M_ZERO);

	vm = hwt_vm_alloc();
	vm->npages = bufsize / PAGE_SIZE;

	thr->vm = vm;

	mtx_init(&thr->mtx, "thr", NULL, MTX_SPIN);

	refcount_init(&thr->refcnt, 1);

	error = hwt_vm_alloc_buffers(vm);
	if (error)
		return (error);

	*thr0 = thr;

	return (0);
}

void
hwt_thread_free(struct hwt_thread *thr)
{

	hwt_vm_destroy_buffers(thr->vm);

	free(thr, M_HWT_THREAD);
}

void
hwt_thread_insert(struct hwt_context *ctx, struct hwt_thread *thr)
{

	HWT_CTX_ASSERT_LOCKED(ctx);

	LIST_INSERT_HEAD(&ctx->threads, thr, next);
}

int
hwt_thread_create(struct thread *td, struct hwt_thread **thr0)
{
	struct hwt_context *ctx;
	struct hwt_thread *thr;
	struct proc *p;
	size_t bufsize;
	char path[MAXPATHLEN];
	int error;

	p = td->td_proc;

	ctx = hwt_contexthash_lookup(p);
	if (ctx == NULL)
		return (ENXIO);
	bufsize = ctx->bufsize;
	HWT_CTX_UNLOCK(ctx);

	dprintf("%s: NEW thread %p, tid %d\n", __func__, td,
	    td->td_tid);

	error = hwt_thread_alloc(&thr, bufsize);
	if (error) {
		printf("%s: could not allocate thread, error %d\n",
		    __func__, error);
		return (error);
	}

	thr->vm->ctx = ctx;
	thr->tid = td->td_tid;

	sprintf(path, "hwt_%d_%d", ctx->ident, thr->session_id);
	error = hwt_vm_create_cdev(thr->vm, path);
	if (error) {
		printf("%s: could not create cdev, error %d\n",
		    __func__, error);
		return (error);
	}

	ctx = hwt_contexthash_lookup(p);
	if (ctx == NULL) {
		/* TODO: deallocate resources. */
		return (ENXIO);
	}
	thr->ctx = ctx;
	thr->session_id = atomic_fetchadd_int(&ctx->session_counter, 1);
	LIST_INSERT_HEAD(&ctx->threads, thr, next);
	HWT_CTX_UNLOCK(ctx);

	*thr0 = thr;

	return (0);
}
