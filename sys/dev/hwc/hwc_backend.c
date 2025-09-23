/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023-2025 Ruslan Bukin <br@bsdpad.com>
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
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/hwc.h>

#include <dev/hwc/hwc_hook.h>
#include <dev/hwc/hwc_context.h>
#if 0
#include <dev/hwc/hwc_config.h>
#include <dev/hwc/hwc_thread.h>
#endif
#include <dev/hwc/hwc_backend.h>

#define	HWT_BACKEND_DEBUG
#undef	HWT_BACKEND_DEBUG

#ifdef	HWT_BACKEND_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

static struct mtx hwc_backend_mtx;

struct hwc_backend_entry {
	struct hwc_backend *backend;
	LIST_ENTRY(hwc_backend_entry) next;
};

static LIST_HEAD(, hwc_backend_entry)	hwc_backends;

static MALLOC_DEFINE(M_HWT_BACKEND, "hwc_backend", "HWT backend");

int
hwc_backend_init(struct hwc_context *ctx)
{
	int error;

	dprintf("%s\n", __func__);

	error = ctx->hwc_backend->ops->hwc_backend_init(ctx);

	return (error);
}

void
hwc_backend_deinit(struct hwc_context *ctx)
{

	dprintf("%s\n", __func__);

	ctx->hwc_backend->ops->hwc_backend_deinit(ctx);
}

int
hwc_backend_configure(struct hwc_context *ctx, struct hwc_configure *hc)
{
	int error;

	dprintf("%s\n", __func__);

	error = ctx->hwc_backend->ops->hwc_backend_configure(ctx, hc);

	return (error);
}

void
hwc_backend_enable(struct hwc_context *ctx, int cpu_id)
{

	dprintf("%s\n", __func__);

	ctx->hwc_backend->ops->hwc_backend_enable(ctx, cpu_id);
}

void
hwc_backend_disable(struct hwc_context *ctx, int cpu_id)
{

	dprintf("%s\n", __func__);

	ctx->hwc_backend->ops->hwc_backend_disable(ctx, cpu_id);
}

void
hwc_backend_enable_smp(struct hwc_context *ctx)
{

	dprintf("%s\n", __func__);

	ctx->hwc_backend->ops->hwc_backend_enable_smp(ctx);
}

void
hwc_backend_disable_smp(struct hwc_context *ctx)
{

	dprintf("%s\n", __func__);

	ctx->hwc_backend->ops->hwc_backend_disable_smp(ctx);
}

void __unused
hwc_backend_dump(struct hwc_context *ctx, int cpu_id)
{

	dprintf("%s\n", __func__);

	ctx->hwc_backend->ops->hwc_backend_dump(cpu_id);
}

int
hwc_backend_read(struct hwc_context *ctx, struct hwc_vm *vm, int *ident,
    vm_offset_t *offset, uint64_t *data)
{
	int error;

	dprintf("%s\n", __func__);

	error = ctx->hwc_backend->ops->hwc_backend_read(vm, ident,
	    offset, data);

	return (error);
}

struct hwc_backend *
hwc_backend_lookup(const char *name)
{
	struct hwc_backend_entry *entry;
	struct hwc_backend *backend;

	HWT_BACKEND_LOCK();
	LIST_FOREACH(entry, &hwc_backends, next) {
		backend = entry->backend;
		if (strcmp(backend->name, name) == 0) {
			HWT_BACKEND_UNLOCK();
			return (backend);
		}
	}
	HWT_BACKEND_UNLOCK();

	return (NULL);
}

int
hwc_backend_register(struct hwc_backend *backend)
{
	struct hwc_backend_entry *entry;

	if (backend == NULL ||
	    backend->name == NULL ||
	    backend->ops == NULL)
		return (EINVAL);

	entry = malloc(sizeof(struct hwc_backend_entry), M_HWT_BACKEND,
	    M_WAITOK | M_ZERO);
	entry->backend = backend;

	HWT_BACKEND_LOCK();
	LIST_INSERT_HEAD(&hwc_backends, entry, next);
	HWT_BACKEND_UNLOCK();

	return (0);
}

int
hwc_backend_unregister(struct hwc_backend *backend)
{
	struct hwc_backend_entry *entry, *tmp;

	if (backend == NULL)
		return (EINVAL);

	/* TODO: check if not in use */

	HWT_BACKEND_LOCK();
	LIST_FOREACH_SAFE(entry, &hwc_backends, next, tmp) {
		if (entry->backend == backend) {
			LIST_REMOVE(entry, next);
			HWT_BACKEND_UNLOCK();
			free(entry, M_HWT_BACKEND);
			return (0);
		}
	}
	HWT_BACKEND_UNLOCK();

	return (ENOENT);
}

void
hwc_backend_load(void)
{

	mtx_init(&hwc_backend_mtx, "hwc backend", NULL, MTX_DEF);
	LIST_INIT(&hwc_backends);
}

void
hwc_backend_unload(void)
{

	/* TODO: ensure all unregistered */

	mtx_destroy(&hwc_backend_mtx);
}

int
hwc_backend_stop(struct hwc_context *ctx, struct hwc_stop *hs)
{
	int error;

	dprintf("%s\n", __func__);

	error = ctx->hwc_backend->ops->hwc_backend_stop(ctx, hs);

	return (error);
}

int
hwc_backend_start(struct hwc_context *ctx, struct hwc_start *hs)
{
	int error;

	dprintf("%s\n", __func__);

	error = ctx->hwc_backend->ops->hwc_backend_start(ctx, hs);

	return (error);
}

int
hwc_backend_svc_buf(struct hwc_context *ctx, void *data, size_t data_size,
    int data_version)
{
	int error;

	dprintf("%s\n", __func__);

	error = ctx->hwc_backend->ops->hwc_backend_svc_buf(ctx, data, data_size,
	    data_version);

	return (error);
}

#if 0
int
hwc_backend_thread_alloc(struct hwc_context *ctx, struct hwc_thread *thr)
{
	int error;

	dprintf("%s\n", __func__);

	if (ctx->hwc_backend->ops->hwc_backend_thread_alloc == NULL)
		return (0);
	KASSERT(thr->private == NULL,
		    ("%s: thread private data is not NULL\n", __func__));
	error = ctx->hwc_backend->ops->hwc_backend_thread_alloc(thr);

	return (error);
}

void
hwc_backend_thread_free(struct hwc_thread *thr)
{
	dprintf("%s\n", __func__);

	if (thr->backend->ops->hwc_backend_thread_free == NULL)
		return;
	KASSERT(thr->private != NULL,
		    ("%s: thread private data is NULL\n", __func__));
	thr->backend->ops->hwc_backend_thread_free(thr);

	return;
}
#endif
