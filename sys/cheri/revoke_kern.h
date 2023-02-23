/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2018 SRI International
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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


#ifndef __SYS_CHERI_REVOKE_KERN_H__
#define	__SYS_CHERI_REVOKE_KERN_H__

/*
 * The outermost capability revocation state machine.
 *
 *   We begin with no revocation in progress (CAPREVST_NONE).  Userland can
 *   request that we steal the calling thread to carry out an initial pass,
 *   which will begin the next epoch and visit all cap-dirty pages in the
 *   address space, moving us to CAPREVST_INIT_PASS for the duration and to
 *   CAPREVST_INIT_DONE upon completion, before returning to userland.
 *
 *   We are now in the store-side steady state for this epoch: we need only
 *   look at *recently* capdirty pages, kernel hoarders, and register files
 *   to find should-be-revoked pages.  Userland can request additional
 *   passes, which will be *incremental* passes, visiting only capdirty
 *   pages (and keeping us in CAPREVST_STORE_DONE).
 *
 *   Alternatively, userland can request that we finish this epoch,
 *   transitioning us into CAPREVST_LAST_PASS for the duration.  This pass
 *   visits all recently capdirty pages, kernel hoarders, and thread
 *   register files.  It implies at least some brief window of
 *   thread_single'd life.  When this pass finishes, it again increments
 *   the epoch counter, signaling the end of this epoch.
 *
 *     XXX The thread_single window can be reduced by using the "load-side"
 *     strategy, in which we temporarily remove read access to all
 *     recently-capdirty pages and then un-thread_single.  We would continue
 *     to use the calling thread to sweep pages "in the background", but would
 *     also clean pages when taking vm faults.  The epoch must not end
 *     before all pages have been cleaned!
 *
 *   Userland might cause us to jump directly from CAPREVST_NONE to
 *   CAPREVST_LAST_PASS.  This case is *almost* like the above, except that
 *   we have to consider *all* capdirty pages, not just recently-capdirty.
 *
 * The state and epoch counter are stored in the same per-process word,
 * vm_caprev_st.  There is, at present, at most one thread actively engaged
 * in revocation per process.
 */

typedef uint64_t cheri_revoke_state_t;

enum cheri_revoke_state {
	CHERI_REVOKE_ST_NONE       = 0, /* No revocation is in progress */
	CHERI_REVOKE_ST_SS_INITING = 1, /* "store-side" opening now */
	CHERI_REVOKE_ST_SS_INITED  = 2, /* "store-side" open (> 0 opens done) */
	CHERI_REVOKE_ST_SS_LAST    = 3, /* "store-side" closing */
	CHERI_REVOKE_ST_LS_INITING = 4, /* "load-side" opening now */
	CHERI_REVOKE_ST_LS_INITED  = 5, /* "load-side" open (= 1 opens done) */
	CHERI_REVOKE_ST_LS_CLOSING = 6, /* "load-side" background working */
};

#define CHERI_REVOKE_ST_ST_MASK	0x7
#define CHERI_REVOKE_ST_EPOCH_SHIFT	3

static inline enum cheri_revoke_state
cheri_revoke_st_get_state(cheri_revoke_state_t st) {
	return (st & CHERI_REVOKE_ST_ST_MASK);
}

static inline cheri_revoke_epoch_t
cheri_revoke_st_get_epoch(cheri_revoke_state_t st) {
	return (st >> CHERI_REVOKE_ST_EPOCH_SHIFT);
}

static inline void
cheri_revoke_st_set(cheri_revoke_state_t *st, cheri_revoke_epoch_t epoch,
    enum cheri_revoke_state state)
{
	*st = (epoch << CHERI_REVOKE_ST_EPOCH_SHIFT) | state;
}

static inline bool
cheri_revoke_st_is_loadside(cheri_revoke_state_t st) {
	switch (cheri_revoke_st_get_state(st)) {
	case CHERI_REVOKE_ST_LS_INITING:
	case CHERI_REVOKE_ST_LS_INITED:
	case CHERI_REVOKE_ST_LS_CLOSING:
		return true;
	case CHERI_REVOKE_ST_NONE:
	case CHERI_REVOKE_ST_SS_INITING:
	case CHERI_REVOKE_ST_SS_INITED:
	case CHERI_REVOKE_ST_SS_LAST:
		return false;
	}
}

struct cheri_revoke_info_page {
	/* Userland will come to hold RO caps to this bit */
	struct cheri_revoke_info pub;

	/*
	 * The kernel is free to use the rest of this page for
	 * private data that is quite naturally associated with
	 * this VM space.
	 */
};

SYSCTL_DECL(_vm_cheri_revoke);

#endif
