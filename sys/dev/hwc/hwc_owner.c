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

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/mutex.h>
#include <sys/refcount.h>
#include <sys/rwlock.h>
#include <sys/hwc.h>

#include <dev/hwc/hwc_hook.h>
#include <dev/hwc/hwc_context.h>
#include <dev/hwc/hwc_contexthash.h>
#if 0
#include <dev/hwc/hwc_config.h>
#endif
#include <dev/hwc/hwc_cpu.h>
#if 0
#include <dev/hwc/hwc_thread.h>
#endif
#include <dev/hwc/hwc_owner.h>
#include <dev/hwc/hwc_ownerhash.h>
#include <dev/hwc/hwc_backend.h>
#include <dev/hwc/hwc_vm.h>
#if 0
#include <dev/hwc/hwc_record.h>
#endif

#define	HWT_DEBUG
#undef	HWT_DEBUG

#ifdef	HWT_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

static MALLOC_DEFINE(M_HWT_OWNER, "hwc_owner", "Hardware Trace");

struct hwc_context *
hwc_owner_lookup_ctx(struct hwc_owner *ho, pid_t pid)
{
	struct hwc_context *ctx;

	mtx_lock(&ho->mtx);
	LIST_FOREACH(ctx, &ho->hwcs, next_hwcs) {
		if (ctx->pid == pid) {
			mtx_unlock(&ho->mtx);
			return (ctx);
		}
	}
	mtx_unlock(&ho->mtx);

	return (NULL);
}

#if 0
struct hwc_context *
hwc_owner_lookup_ctx_by_cpu(struct hwc_owner *ho, int cpu)
{
	struct hwc_context *ctx;

	mtx_lock(&ho->mtx);
	LIST_FOREACH(ctx, &ho->hwcs, next_hwcs) {
		if (ctx->cpu == cpu) {
			mtx_unlock(&ho->mtx);
			return (ctx);
		}
	}
	mtx_unlock(&ho->mtx);

	return (NULL);
}
#endif

struct hwc_owner *
hwc_owner_alloc(struct proc *p)
{
	struct hwc_owner *ho;

	ho = malloc(sizeof(struct hwc_owner), M_HWT_OWNER,
	    M_WAITOK | M_ZERO);
	ho->p = p;

	LIST_INIT(&ho->hwcs);
	mtx_init(&ho->mtx, "hwcs", NULL, MTX_DEF);

	return (ho);
}

void
hwc_owner_shutdown(struct hwc_owner *ho)
{
	struct hwc_context *ctx;

	dprintf("%s: stopping hwc owner\n", __func__);

	while (1) {
		mtx_lock(&ho->mtx);
		ctx = LIST_FIRST(&ho->hwcs);
		if (ctx)
			LIST_REMOVE(ctx, next_hwcs);
		mtx_unlock(&ho->mtx);

		if (ctx == NULL)
			break;

		if (ctx->mode == HWC_MODE_THREAD)
			hwc_contexthash_remove(ctx);

		/*
		 * A hook could be still dealing with this ctx right here.
		 */

		HWT_CTX_LOCK(ctx);
		ctx->state = 0;
		HWT_CTX_UNLOCK(ctx);

		/* Ensure hooks invocation is now completed. */
		while (refcount_load(&ctx->refcnt) > 0)
			continue;

		/*
		 * Note that a thread could be still sleeping on msleep(9).
		 */

		hwc_backend_deinit(ctx);
#if 0
		hwc_record_free_all(ctx);
#endif
		hwc_ctx_free(ctx);
	}

	hwc_ownerhash_remove(ho);
	free(ho, M_HWT_OWNER);
}
