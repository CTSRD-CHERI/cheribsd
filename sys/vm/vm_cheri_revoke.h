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

#ifndef	_VM_CHERI_REVOKE_
#define	_VM_CHERI_REVOKE_
#ifdef CHERI_CAPREVOKE

/**************************** FORWARD DECLARATIONS ***************************/

struct cheri_revoke_epochs;
struct cheri_revoke_info_page;
struct cheri_revoke_stats;
struct file;
struct sysentvec;
struct vm_cheri_revoke_cookie;
struct vm_map;
struct vm_page;
struct vmspace;

/***************************** REVOCATION ITSELF *****************************/

/* sys/cheri/cheri_otype.c */
uintcap_t cheri_revoke_sealed(uintcap_t);

/*
 * The revoked image of a capability is a *tagged* quantity with zero
 * permissions if CHERI_CAPREVOKE_CLEARTAGS is not set.
 *
 * If the input is sealed, the revoked image is, at present, the unsealed,
 * zero-permission variant, so that software that uses sealing types for
 * tokens will notice the type mismatch and architectural usage will fail.
 * This is almost certainly a sufficiently subtle point that this is not
 * entirely the right answer, though I hope it's not entirely wrong, either.
 */
static __always_inline inline uintcap_t
cheri_revoke_cap(uintcap_t c)
{
#ifndef CHERI_CAPREVOKE_CLEARTAGS
	if (__builtin_expect(cheri_gettype(c) == -1, 1)) {
		return cheri_andperm(c, 0);
	}
	return cheri_revoke_sealed(c);
#else
	/* No need to handle sealed things specially */
	return cheri_cleartag(c);

	/* TODO: Also replace-with-NULL */
#endif
}

/***************************** KERNEL MI LAYER ******************************/

/*
 * XREF constants in cheri/revoke.h; this is here so it's not exposed to
 * userspace (and because it relies on PAGE_SIZE, which is also not exposed).
 */
static const size_t VM_CHERI_REVOKE_GSZ_MEM_MAP = PAGE_SIZE;

struct vm_cheri_revoke_cookie {
	const uint8_t * __capability crshadow;
	struct vm_map		*map;
};

int vm_cheri_revoke_cookie_init(struct vm_map *map,
    struct vm_cheri_revoke_cookie *baked);

void vm_cheri_revoke_info_page(struct vm_map *map, struct sysentvec *,
    struct cheri_revoke_info_page * __capability *);

int vm_cheri_revoke_pass(const struct vm_cheri_revoke_cookie *);
void vm_cheri_revoke_pass_async(struct vmspace *,
    const struct vm_cheri_revoke_cookie *);

void vm_cheri_assert_consistent_clg(struct vm_map *map);

/*  Shadow region installation into vm map */
int vm_map_install_cheri_revoke_shadow(struct vm_map *map, struct sysentvec *);

/*  Shadow map capability constructor */
void * __capability vm_cheri_revoke_shadow_cap(struct sysentvec *,
    int sel, vm_offset_t base, vm_offset_t size, int perm_mask);

/*  Publish epochs to shared page */
void vm_cheri_revoke_publish_epochs(
    struct cheri_revoke_info_page * __capability,
    const struct cheri_revoke_epochs *);

/*  Revoke a single capability if needed */
void vm_cheri_revoke_cap(const struct vm_cheri_revoke_cookie *, uintcap_t *);

/***************************** KERNEL MD LAYER ******************************/

int vm_cheri_revoke_test(const struct vm_cheri_revoke_cookie *, uintcap_t);

enum {
	/* If no coarse bits set */
	VM_CHERI_REVOKE_CF_NO_COARSE_MEM = 0x01,

	/* If no otype bits set, Permit_Seal and _Unseal are imune */
	VM_CHERI_REVOKE_CF_NO_OTYPES = 0x02,
	VM_CHERI_REVOKE_CF_NO_CIDS = 0x04,

	/* If no rev_entry selected in the vm_map */
	VM_CHERI_REVOKE_CF_NO_REV_ENTRY = 0x08,
};
void vm_cheri_revoke_set_test(struct vm_map *map, int flags);

/*  Walking a particular page */
#define VM_CHERI_REVOKE_PAGE_HASCAPS 0x01
#define VM_CHERI_REVOKE_PAGE_DIRTY 0x02
int vm_cheri_revoke_page_rw(
    const struct vm_cheri_revoke_cookie *c, struct vm_page *m);
int vm_cheri_revoke_page_ro(
    const struct vm_cheri_revoke_cookie *c, struct vm_page *m);

/* callback from MD layer */
enum vm_cheri_revoke_fault_res {
	VM_CHERI_REVOKE_FAULT_RESOLVED,	/* Situation averted */
	VM_CHERI_REVOKE_FAULT_UNRESOLVED, /* Continue with fault handling */
	VM_CHERI_REVOKE_FAULT_CAPSTORE,	/* Convert to cap. store fault */
};
enum vm_cheri_revoke_fault_res vm_cheri_revoke_fault_visit(
    struct vmspace *, vm_offset_t);

/**************************** STATISTICS COUNTING *****************************/

#ifdef CHERI_CAPREVOKE_STATS
#define CHERI_REVOKE_STATS_FOR(st, crc) \
	struct cheri_revoke_stats *st = \
	    (struct cheri_revoke_stats*)&(crc)->map->vm_cheri_revoke_stats
#define CHERI_REVOKE_STATS_INC(st, ctr, d) \
	do { __atomic_fetch_add(&(st)->ctr, (d), __ATOMIC_RELAXED); } while (0)
#else
#define CHERI_REVOKE_STATS_FOR(st, crc) do { } while (0)
#define CHERI_REVOKE_STATS_INC(st, ctr, d) do { } while (0)
#endif
#define CHERI_REVOKE_STATS_BUMP(st, ctr) CHERI_REVOKE_STATS_INC(st, ctr, 1)

#endif /* CHERI_CAPREVOKE */
#endif /* !_VM_CHERI_REVOKE_ */
