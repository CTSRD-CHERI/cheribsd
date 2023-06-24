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
#include <sys/rwlock.h>
#include <sys/hwt.h>

#include <dev/hwt/hwt_hook.h>
#include <dev/hwt/hwtvar.h>
#include <dev/hwt/hwt_backend.h>
#include <dev/hwt/hwt_thread.h>
#include <dev/hwt/hwt_context.h>

#define	HWT_DEBUG
#undef	HWT_DEBUG

#ifdef	HWT_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

#define	HWT_PROCHASH_SIZE	1024
#define	HWT_OWNERHASH_SIZE	1024

/*
 * Hash function.  Discard the lower 2 bits of the pointer since
 * these are always zero for our uses.  The hash multiplier is
 * round((2^LONG_BIT) * ((sqrt(5)-1)/2)).
 */

#define	_HWT_HM	11400714819323198486u	/* hash multiplier */
#define	HWT_HASH_PTR(P, M)	((((unsigned long) (P) >> 2) * _HWT_HM) & (M))

static struct mtx hwt_contexthash_mtx;
static u_long hwt_contexthashmask;
static LIST_HEAD(hwt_contexthash, hwt_context)	*hwt_contexthash;

static struct mtx hwt_ownerhash_mtx;
static u_long hwt_ownerhashmask;
static LIST_HEAD(hwt_ownerhash, hwt_owner)	*hwt_ownerhash;

struct hwt_context *
hwt_ctx_lookup_by_owner(struct hwt_owner *ho, pid_t pid)
{
	struct hwt_context *ctx;

	mtx_lock(&ho->mtx);
	LIST_FOREACH(ctx, &ho->hwts, next_hwts) {
		if (ctx->pid == pid) {
			mtx_unlock(&ho->mtx);
			return (ctx);
		}
	}
	mtx_unlock(&ho->mtx);

	return (NULL);
}

struct hwt_owner *
hwt_ctx_lookup_ownerhash(struct proc *p)
{
	struct hwt_ownerhash *hoh;
	struct hwt_owner *ho;
	int hindex;

	hindex = HWT_HASH_PTR(p, hwt_ownerhashmask);
	hoh = &hwt_ownerhash[hindex];

	mtx_lock_spin(&hwt_ownerhash_mtx);
	LIST_FOREACH(ho, hoh, next) {
		if (ho->p == p) {
			mtx_unlock_spin(&hwt_ownerhash_mtx);
			return (ho);
		}
	}
	mtx_unlock_spin(&hwt_ownerhash_mtx);

	return (NULL);
}

struct hwt_context *
hwt_ctx_lookup_by_owner_p(struct proc *owner_p, pid_t pid)
{
	struct hwt_context *ctx;
	struct hwt_owner *ho;

	ho = hwt_ctx_lookup_ownerhash(owner_p);
	if (ho == NULL)
		return (NULL);

	ctx = hwt_ctx_lookup_by_owner(ho, pid);

	return (ctx);
}

struct hwt_context *
hwt_ctx_alloc(void)
{
	struct hwt_context *ctx;

	ctx = malloc(sizeof(struct hwt_context), M_HWT, M_WAITOK | M_ZERO);
	ctx->thread_counter = 1;

	LIST_INIT(&ctx->records);
	mtx_init(&ctx->mtx_records, "hwt records", NULL, MTX_DEF);

	LIST_INIT(&ctx->threads);
	mtx_init(&ctx->mtx_threads, "hwt threads", NULL, MTX_SPIN);

	return (ctx);
}

/*
 * To use by hwt_switch_in/out() and hwt_record() only.
 */
struct hwt_context *
hwt_ctx_lookup_contexthash(struct proc *p)
{
	struct hwt_contexthash *hch;
	struct hwt_context *ctx;
	int hindex;

	hindex = HWT_HASH_PTR(p, hwt_contexthashmask);
	hch = &hwt_contexthash[hindex];

	mtx_lock_spin(&hwt_contexthash_mtx);
	LIST_FOREACH(ctx, hch, next_hch) {
		if (ctx->proc == p) {
			mtx_unlock_spin(&hwt_contexthash_mtx);
			return (ctx);
		}
	}
	mtx_unlock_spin(&hwt_contexthash_mtx);

	panic("no ctx");
}

void
hwt_ctx_insert_contexthash(struct hwt_context *ctx)
{
	struct hwt_contexthash *hch;
	int hindex;

	PROC_LOCK_ASSERT(ctx->proc, MA_OWNED);

	hindex = HWT_HASH_PTR(ctx->proc, hwt_contexthashmask);
	hch = &hwt_contexthash[hindex];

	mtx_lock_spin(&hwt_contexthash_mtx);
	LIST_INSERT_HEAD(hch, ctx, next_hch);
	mtx_unlock_spin(&hwt_contexthash_mtx);
}

/* TODO: create instead of insert */
void
hwt_owner_insert(struct hwt_owner *ho)
{
	struct hwt_ownerhash *hoh;
	int hindex;

	hindex = HWT_HASH_PTR(ho->p, hwt_ownerhashmask);
	hoh = &hwt_ownerhash[hindex];

	mtx_lock_spin(&hwt_ownerhash_mtx);
	LIST_INSERT_HEAD(hoh, ho, next);
	mtx_unlock_spin(&hwt_ownerhash_mtx);
}

void
hwt_owner_destroy(struct hwt_owner *ho)
{

	/* Destroy hwt owner. */
	mtx_lock_spin(&hwt_ownerhash_mtx);
	LIST_REMOVE(ho, next);
	mtx_unlock_spin(&hwt_ownerhash_mtx);

	free(ho, M_HWT);
}

void
hwt_context_load(void)
{

	hwt_contexthash = hashinit(HWT_PROCHASH_SIZE, M_HWT,
	    &hwt_contexthashmask);
        mtx_init(&hwt_contexthash_mtx, "hwt-proc-hash", "hwt-proc", MTX_SPIN);

	hwt_ownerhash = hashinit(HWT_OWNERHASH_SIZE, M_HWT, &hwt_ownerhashmask);
        mtx_init(&hwt_ownerhash_mtx, "hwt-owner-hash", "hwt-owner", MTX_SPIN);
}

void
hwt_ctx_remove(struct hwt_context *ctx)
{
#if 0
	struct hwt_contexthash *hch;
	int hindex;

	hindex = HWT_HASH_PTR(ho->p, hwt_contexthashmask);
	hch = &hwt_contexthash[hindex];
#endif

	mtx_lock_spin(&hwt_contexthash_mtx);
	LIST_REMOVE(ctx, next_hch);
	mtx_unlock_spin(&hwt_contexthash_mtx);
}
