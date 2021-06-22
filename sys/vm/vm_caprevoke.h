/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Nathaniel Filardo
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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

#ifndef	_VM_CAPREVOKE_
#define	_VM_CAPREVOKE_
#ifdef CHERI_CAPREVOKE

/**************************** FORWARD DECLARATIONS ***************************/

struct caprevoke_epochs;
struct caprevoke_info_page;
struct caprevoke_stats;
struct file;
struct vm_caprevoke_cookie;
struct vm_map;
struct vm_page;
struct vmspace;

/***************************** REVOCATION ITSELF *****************************/

/* sys/cheri/cheri_otype.c */
uintcap_t cheri_revoke_sealed(uintcap_t);

/*
 * The revoked image of a capability is a *tagged* quantity with zero
 * permissions.
 *
 * If the input is sealed, the revoked image is, at present, the unsealed,
 * zero-permission variant, so that software that uses sealing types for
 * tokens will notice the type mismatch and architectural usage will fail.
 * This is almost certainly a sufficiently subtle point that this is not
 * entirely the right answer, though I hope it's not entirely wrong, either.
 */
static __always_inline inline uintcap_t
cheri_revoke(uintcap_t c)
{
#ifndef CHERI_CAPREVOKE_CLEARTAGS
	if (__builtin_expect(cheri_gettype(c) == -1, 1)) {
		return cheri_andperm(c, 0);
	}
	return cheri_revoke_sealed(c);
#else
	/* No need to handle sealed things specially */
	return cheri_cleartag(c);
#endif
}

/***************************** KERNEL MI LAYER ******************************/

struct vm_caprevoke_cookie {
	const uint8_t * __capability crshadow;
	struct vm_map		*map;
};

int vm_caprevoke_cookie_init(struct vm_map *map,
    struct vm_caprevoke_cookie *baked);
void vm_caprevoke_cookie_rele(struct vm_caprevoke_cookie *cookie);

void vm_caprevoke_info_page(struct vm_map *map,
    struct caprevoke_info_page * __capability *);

enum {
	/* Set externally, checked per page */
	VM_CAPREVOKE_INCREMENTAL = 0x04, /* Scan capdirty, not capstore */
	VM_CAPREVOKE_BARRIERED   = 0x08, /* world is stopped (debug) */
	VM_CAPREVOKE_LOAD_SIDE   = 0x10, /* this is the load-side scan */

	/* Set internally, checked per page */
	VM_CAPREVOKE_QUICK_SUCCESSOR = 0x20,

	/* Set externally, checked per pass */
	VM_CAPREVOKE_TLB_FLUSH   = 0x40, /* shootdown TLBs */
	VM_CAPREVOKE_SYNC_CD     = 0x80, /* pmap capdirty -> MI */
};

int vm_caprevoke_pass(const struct vm_caprevoke_cookie *, int);

/***************************** KERNEL MD LAYER ******************************/

int vm_caprevoke_test(const struct vm_caprevoke_cookie *, uintcap_t);

enum {
	/* If no coarse bits set, VMMAP-bearing caps are imune */
	VM_CAPREVOKE_CF_NO_COARSE_MEM = 0x01,

	/* If no otype bits set, Permit_Seal and _Unseal are imune */
	VM_CAPREVOKE_CF_NO_OTYPES = 0x02,
	VM_CAPREVOKE_CF_NO_CIDS = 0x04,
};
void vm_caprevoke_set_test(struct vm_map *map, int flags);

/*  Shadow region installation into vm map */
int vm_map_install_caprevoke_shadow(struct vm_map *map);

/*  Shadow map capability constructor */
void * __capability vm_caprevoke_shadow_cap(
    int sel, vm_offset_t base, vm_offset_t size, int perm_mask);

/*  Publish epochs to shared page */
void vm_caprevoke_publish_epochs(
    struct caprevoke_info_page * __capability, const struct caprevoke_epochs *);

/*  Walking a particular page */
#define VM_CAPREVOKE_PAGE_HASCAPS 0x01
#define VM_CAPREVOKE_PAGE_DIRTY 0x02
int vm_caprevoke_page_rw(
    const struct vm_caprevoke_cookie *c, struct vm_page *m);
int vm_caprevoke_page_ro(
    const struct vm_caprevoke_cookie *c, struct vm_page *m);

/* callback from MD layer */
enum vm_caprevoke_fault_res {
	VM_CAPREVOKE_FAULT_RESOLVED,	/* Situation averted */
	VM_CAPREVOKE_FAULT_UNRESOLVED,	/* Continue with fault handling */
	VM_CAPREVOKE_FAULT_CAPSTORE,	/* Convert to cap. store fault */
};
enum vm_caprevoke_fault_res vm_caprevoke_fault_visit(
    struct vmspace *, vm_offset_t);

/**************************** STATISTICS COUNTING *****************************/

#ifdef CHERI_CAPREVOKE_STATS
#define CAPREVOKE_STATS_FOR(st, crc) \
	struct caprevoke_stats *st = \
	    (struct caprevoke_stats*)&(crc)->map->vm_caprev_stats
#define CAPREVOKE_STATS_INC(st, ctr, d) \
	do { __atomic_fetch_add(&(st)->ctr, (d), __ATOMIC_RELAXED); } while (0)
#else
#define CAPREVOKE_STATS_FOR(st, crc) do { } while (0)
#define CAPREVOKE_STATS_INC(st, ctr, d) do { } while (0)
#endif
#define CAPREVOKE_STATS_BUMP(st, ctr) CAPREVOKE_STATS_INC(st, ctr, 1)

#endif
#endif
