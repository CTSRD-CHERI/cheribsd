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
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/refcount.h>
#include <sys/hwc.h>

#include <dev/hwc/hwc_context.h>
#include <dev/hwc/hwc_contexthash.h>
#if 0
#include <dev/hwc/hwc_config.h>
#endif

#define	HWT_DEBUG
#undef	HWT_DEBUG

#ifdef	HWT_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

#define	HWT_CONTEXTHASH_SIZE	1024

static MALLOC_DEFINE(M_HWT_CONTEXTHASH, "hwc_chash", "Hardware Trace");

/*
 * Hash function.  Discard the lower 2 bits of the pointer since
 * these are always zero for our uses.  The hash multiplier is
 * round((2^LONG_BIT) * ((sqrt(5)-1)/2)).
 */

#define	_HWT_HM	11400714819323198486u	/* hash multiplier */
#define	HWT_HASH_PTR(P, M)	((((unsigned long) (P) >> 2) * _HWT_HM) & (M))

static struct mtx hwc_contexthash_mtx;
static u_long hwc_contexthashmask;
static LIST_HEAD(hwc_contexthash, hwc_context)	*hwc_contexthash;

/*
 * To use by hwc_switch_in/out() and hwc_record() only.
 * This function returns with refcnt acquired.
 */
struct hwc_context *
hwc_contexthash_lookup(struct proc *p)
{
	struct hwc_contexthash *hch;
	struct hwc_context *ctx;
	int hindex;

	hindex = HWT_HASH_PTR(p, hwc_contexthashmask);
	hch = &hwc_contexthash[hindex];

	HWT_CTXHASH_LOCK();
	LIST_FOREACH(ctx, hch, next_hch) {
		if (ctx->proc == p) {
			refcount_acquire(&ctx->refcnt);
			HWT_CTXHASH_UNLOCK();
			return (ctx);
		}
	}
	HWT_CTXHASH_UNLOCK();

	return (NULL);
}

void
hwc_contexthash_insert(struct hwc_context *ctx)
{
	struct hwc_contexthash *hch;
	int hindex;

	hindex = HWT_HASH_PTR(ctx->proc, hwc_contexthashmask);
	hch = &hwc_contexthash[hindex];

	HWT_CTXHASH_LOCK();
	LIST_INSERT_HEAD(hch, ctx, next_hch);
	HWT_CTXHASH_UNLOCK();
}

void
hwc_contexthash_remove(struct hwc_context *ctx)
{

	HWT_CTXHASH_LOCK();
	LIST_REMOVE(ctx, next_hch);
	HWT_CTXHASH_UNLOCK();
}

void
hwc_contexthash_load(void)
{

	hwc_contexthash = hashinit(HWT_CONTEXTHASH_SIZE, M_HWT_CONTEXTHASH,
	    &hwc_contexthashmask);
	mtx_init(&hwc_contexthash_mtx, "hwc ctx hash", "hwc ctx", MTX_SPIN);
}

void
hwc_contexthash_unload(void)
{

	mtx_destroy(&hwc_contexthash_mtx);
	hashdestroy(hwc_contexthash, M_HWT_CONTEXTHASH, hwc_contexthashmask);
}
