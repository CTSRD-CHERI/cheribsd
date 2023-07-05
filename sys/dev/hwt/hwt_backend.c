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
#include <sys/rwlock.h>
#include <sys/hwt.h>

#include <dev/hwt/hwt_hook.h>
#include <dev/hwt/hwt_config.h>
#include <dev/hwt/hwt_context.h>
#include <dev/hwt/hwt_thread.h>
#include <dev/hwt/hwt_backend.h>

#define	HWT_BACKEND_DEBUG
#undef	HWT_BACKEND_DEBUG

#ifdef	HWT_BACKEND_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

static struct mtx hwt_backend_mtx;
static LIST_HEAD(, hwt_backend)	hwt_backends;

int
hwt_backend_init(struct hwt_context *ctx)
{

	dprintf("%s\n", __func__);

	ctx->hwt_backend->ops->hwt_backend_init(ctx);

	return (0);
}

int
hwt_backend_deinit(struct hwt_context *ctx)
{

	dprintf("%s\n", __func__);

	ctx->hwt_backend->ops->hwt_backend_deinit();

	return (0);
}

int
hwt_backend_configure(struct hwt_thread *thr, int cpu_id)
{
	struct hwt_context *ctx;

	dprintf("%s\n", __func__);

	ctx = thr->ctx;

	HWT_CTX_ASSERT_LOCKED(ctx);

	ctx->hwt_backend->ops->hwt_backend_configure(thr, cpu_id);

	return (0);
}

int
hwt_backend_enable(struct hwt_thread *thr, int cpu_id)
{
	struct hwt_context *ctx;

	dprintf("%s\n", __func__);

	ctx = thr->ctx;

	HWT_CTX_ASSERT_LOCKED(ctx);

	ctx->hwt_backend->ops->hwt_backend_enable(thr, cpu_id);

	return (0);
}

int
hwt_backend_disable(struct hwt_thread *thr, int cpu_id)
{
	struct hwt_context *ctx;

	dprintf("%s\n", __func__);

	ctx = thr->ctx;

	HWT_CTX_ASSERT_LOCKED(ctx);

	ctx->hwt_backend->ops->hwt_backend_disable(thr, cpu_id);

	return (0);
}

int __unused
hwt_backend_dump(struct hwt_thread *thr, int cpu_id)
{
	struct hwt_context *ctx;

	dprintf("%s\n", __func__);

	ctx = thr->ctx;

	ctx->hwt_backend->ops->hwt_backend_dump(thr, cpu_id);

	return (0);
}

int
hwt_backend_read(struct hwt_thread *thr, int *curpage,
    vm_offset_t *curpage_offset)
{
	struct hwt_context *ctx;
	int error;

	dprintf("%s\n", __func__);

	ctx = thr->ctx;

	error = ctx->hwt_backend->ops->hwt_backend_read(thr, 0, curpage,
	    curpage_offset);

	return (error);
}

struct hwt_backend *
hwt_backend_lookup(const char *name)
{
	struct hwt_backend *backend;

	HWT_BACKEND_LOCK();
	LIST_FOREACH(backend, &hwt_backends, next) {
		if (strcmp(backend->name, name) == 0) {
			HWT_BACKEND_UNLOCK();
			return (backend);
		}
	}
	HWT_BACKEND_UNLOCK();

	return (NULL);
}

int
hwt_register(struct hwt_backend *backend)
{

	if (backend == NULL ||
	    backend->name == NULL ||
	    backend->ops == NULL)
		return (EINVAL);

	HWT_BACKEND_LOCK();
	LIST_INSERT_HEAD(&hwt_backends, backend, next);
	HWT_BACKEND_UNLOCK();

	return (0);
}

void
hwt_backend_load(void)
{

	mtx_init(&hwt_backend_mtx, "hwt backend", NULL, MTX_SPIN);
	LIST_INIT(&hwt_backends);
}
