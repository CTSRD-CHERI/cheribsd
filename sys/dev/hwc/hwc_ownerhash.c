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
#include <sys/rwlock.h>
#include <sys/hwc.h>

#include <dev/hwc/hwc_owner.h>
#include <dev/hwc/hwc_ownerhash.h>

#define	HWT_DEBUG
#undef	HWT_DEBUG

#ifdef	HWT_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

#define	HWT_OWNERHASH_SIZE	1024

static MALLOC_DEFINE(M_HWT_OWNERHASH, "hwc_ohash", "Hardware Trace");

/*
 * Hash function.  Discard the lower 2 bits of the pointer since
 * these are always zero for our uses.  The hash multiplier is
 * round((2^LONG_BIT) * ((sqrt(5)-1)/2)).
 */

#define	_HWT_HM	11400714819323198486u	/* hash multiplier */
#define	HWT_HASH_PTR(P, M)	((((unsigned long) (P) >> 2) * _HWT_HM) & (M))

static struct mtx hwc_ownerhash_mtx;
static u_long hwc_ownerhashmask;
static LIST_HEAD(hwc_ownerhash, hwc_owner)	*hwc_ownerhash;

struct hwc_owner *
hwc_ownerhash_lookup(struct proc *p)
{
	struct hwc_ownerhash *hoh;
	struct hwc_owner *ho;
	int hindex;

	hindex = HWT_HASH_PTR(p, hwc_ownerhashmask);
	hoh = &hwc_ownerhash[hindex];

	HWT_OWNERHASH_LOCK();
	LIST_FOREACH(ho, hoh, next) {
		if (ho->p == p) {
			HWT_OWNERHASH_UNLOCK();
			return (ho);
		}
	}
	HWT_OWNERHASH_UNLOCK();

	return (NULL);
}

void
hwc_ownerhash_insert(struct hwc_owner *ho)
{
	struct hwc_ownerhash *hoh;
	int hindex;

	hindex = HWT_HASH_PTR(ho->p, hwc_ownerhashmask);
	hoh = &hwc_ownerhash[hindex];

	HWT_OWNERHASH_LOCK();
	LIST_INSERT_HEAD(hoh, ho, next);
	HWT_OWNERHASH_UNLOCK();
}

void
hwc_ownerhash_remove(struct hwc_owner *ho)
{

	/* Destroy hwc owner. */
	HWT_OWNERHASH_LOCK();
	LIST_REMOVE(ho, next);
	HWT_OWNERHASH_UNLOCK();
}

void
hwc_ownerhash_load(void)
{

	hwc_ownerhash = hashinit(HWT_OWNERHASH_SIZE, M_HWT_OWNERHASH,
	    &hwc_ownerhashmask);
        mtx_init(&hwc_ownerhash_mtx, "hwc-owner-hash", "hwc-owner", MTX_DEF);
}

void
hwc_ownerhash_unload(void)
{
	struct hwc_ownerhash *hoh;
	struct hwc_owner *ho, *tmp;

	HWT_OWNERHASH_LOCK();
	for (hoh = hwc_ownerhash;
	    hoh <= &hwc_ownerhash[hwc_ownerhashmask];
	    hoh++) {
		LIST_FOREACH_SAFE(ho, hoh, next, tmp) {
			/* TODO: module is in use ? */
		}
	}
	HWT_OWNERHASH_UNLOCK();

	mtx_destroy(&hwc_ownerhash_mtx);
	hashdestroy(hwc_ownerhash, M_HWT_OWNERHASH, hwc_ownerhashmask);
}
