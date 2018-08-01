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

#ifndef __SYS_CAPREVOKE_H__
#define	__SYS_CAPREVOKE_H__

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
 * p_caprev_st.  There is, at present, at most one thread actively engaged
 * in revocation per process.
 */

enum caprevoke_state {
	CAPREVST_NONE      = 0,	/* No revocation is in progress */
	CAPREVST_INIT_PASS = 1,	/* Currently executing a "store-side" pass */
	CAPREVST_INIT_DONE = 2,	/* > 0 store-sides done, no pass running */
	CAPREVST_LAST_PASS = 3,	/* Last, "load-side"/STW pass running */
};

#define CAPREVST_ST_MASK	0x3
#define CAPREVST_EPOCH_SHIFT	2
#define CAPREVST_EPOCH_WIDTH	62

/*
 * Epoch greater than orderings: a > b, a >= b.
 *
 * We use RFC1982 serial number arithmetic to deal with wrap-around.  We
 * assume that there will never be any reason to ask about epochs so far
 * apart that this is problematic.
 *
 * We could probably get away without wraparound handling, given the current
 * width of CAPREVST_EPOCH_WIDTH, but on the chance that it becomes
 * significantly shorter, it doesn't hurt to have this abstracted.
 *
 * XXX this almost surely belongs somewhere else.
 */

static inline int caprevoke_epoch_gt(uint64_t a, uint64_t b) {
	return ((a < b) && ((b - a) > (1ULL << (CAPREVST_EPOCH_WIDTH-1))))
	    || ((b > a) && ((a - b) < (1ULL << (CAPREVST_EPOCH_WIDTH-1))));
}
static inline int caprevoke_epoch_ge(uint64_t a, uint64_t b) {
	return (a == b) || caprevoke_epoch_gt(a, b);
}

	/*
	 * Finish the current revocation epoch this pass.
	 * If there is no current revocation epoch, start one and then
	 * finish it.
	 *
	 * If this flag is not given, then either start an epoch by doing
	 * the first (full) pass or continue an epoch by doing an
	 * incremental pass.
	 */
#define CAPREVOKE_LAST_PASS	0x001

	/*
	 * Some flags indicate that we are to engage in a blocking
	 * capability revocation sweep on a subset of the entire address
	 * space.  If any of these are set, we bypass the above state
	 * machine and visit only the indicated locations.  This is an
	 * expermental feature to see if this kind of mitigation, while
	 * unsound, is still a useful thing to do.
	 */
#define CAPREVOKE_JUST_THE_TIME	0x100	/* Nothing, just report epoch */
#define CAPREVOKE_JUST_MY_REGS  0x200	/* Calling thread register file */
#define CAPREVOKE_JUST_MY_STACK	0x400	/* Calling thread stack */
#define CAPREVOKE_JUST_HOARDERS 0x800	/* Kernel hoarders */
#define CAPREVOKE_JUST_MASK	0xF00

	/*
	 * XXX In a colocated proc model, just the current proc?  Is this a
	 * thing we want?  If so, how do we make it fit with our story?
	 * Does it not alter the epoch clock?  Is there a second clock?
	 */
// #define CAPREVOKE_COLO_JUST_ME		0x1000

/*
 * Information conveyed to userland about a given caprevoke scan.
 */
struct caprevoke_stats {
	uint64_t	epoch;
	uint64_t	pages_scanned;
	uint64_t	pages_faulted_ro;
	uint64_t	pages_faulted_rw;
	uint64_t	pages_fault_skip;
};

#define	CAPREVOKE_SHADOW_NOVMMAP	0x00	/* The ordinary shadow space */
#define CAPREVOKE_SHADOW_OTYPE		0x01	/* The otype shadow space */
/*
 * It is not possible to ask for the _MEM_MAP bitmask, as we intend that one
 * to be used by the kernel internally.  Maybe that's wrong?
 */
#define CAPREVOKE_SHADOW_SPACE_MASK	0x03	/* Flag bits for shadow index */

#ifndef _KERNEL
int caprevoke(int flags, uint64_t start_epoch,
		struct caprevoke_stats *statout);
int caprevoke_shadow(int flags,
	void * __capability arena,
	void * __capability * shadow);
#endif

#endif /* !__SYS_MALIAS_H__ */
