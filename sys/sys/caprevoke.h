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
 * vm_caprev_st.  There is, at present, at most one thread actively engaged
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

typedef uint64_t caprevoke_epoch;

/*
 * Epoch greater than orderings: a > b, a >= b.
 *
 * We use RFC1982 serial number arithmetic to deal with wrap-around.  We
 * assume that there will never be any reason to ask about epochs so far
 * apart that this is problematic.
 *
 * We could probably get away without wraparound handling, given the current
 * value of CAPREVST_EPOCH_WIDTH, but on the chance that it becomes
 * significantly shorter, it doesn't hurt to have this abstracted.
 *
 * XXX this almost surely belongs somewhere else.
 */

static inline int caprevoke_epoch_gt(caprevoke_epoch a, caprevoke_epoch b) {
	return ((a < b) && ((b - a) > (1ULL << (CAPREVST_EPOCH_WIDTH-1))))
	    || ((a > b) && ((a - b) < (1ULL << (CAPREVST_EPOCH_WIDTH-1))));
}
static inline int caprevoke_epoch_ge(caprevoke_epoch a, caprevoke_epoch b) {
	return (a == b) || caprevoke_epoch_gt(a, b);
}

static inline int caprevoke_epoch_clears(caprevoke_epoch now,
                                         caprevoke_epoch then) {
	return caprevoke_epoch_ge(now, then + (then & 1) + 2);
}

/* Returns 1 if cap is revoked, 0 otherwise. */
static inline int caprevoke_is_revoked(const void * __capability cap) {
	return (__builtin_cheri_perms_get(cap) == 0);
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
	 * If this bit is set, the kernel is free to return without making
	 * progress.
	 *
	 * The returned statistics describe any transitions that take place
	 * as a result of this request, but not any that result due to
	 * backgrounded work.
	 *
	 * If set without CAPREVOKE_IGNORE_START, the kernel may treat this
	 * as a hint that background revocation may be useful (XXX but we
	 * don't implement that yet).
	 *
	 */
#define	CAPREVOKE_NO_WAIT_OK	0x002

	/*
	 * Ignore the given epoch argument and always attempt to advance the
	 * epoch clock relative to its value "at the time of the call".
	 */
#define	CAPREVOKE_IGNORE_START	0x004

	/*
	 * Do a pass only if an epoch is open after synchronization.  This
	 * is most useful when we want to get to the end of an epoch as
	 * quickly as possible; if we're already past the end, then we
	 * should just stay there.
	 */
#define	CAPREVOKE_ONLY_IF_OPEN	0x008

	/*
	 * Ordinarily, caprevoke with CAPREVOKE_LAST_PASS attempts to
	 * minimize the amount of work it does with the world held in
	 * single-threaded state.  It will do up to three passes:
	 *
	 *   * an opening/incremental pass with the world running
	 *
	 *   * a pass with the world stopped, which visits kernel hoarders
	 *     and recently-dirty pages (since the above pass)
	 *
	 *   * another pass with the world resumed, again visiting
	 *     recently-dirty pages.  (XXX Not yet!)
	 *
	 * The first and/or last of these may be disabled by passing
	 * CAPREVOKE_LAST_NO_EARLY and/or CAPREVOKE_LAST_NO_LATE flags,
	 * causing more work to be pushed into the world-stopped phase.
	 *
	 * Setting CAPREVOKE_LAST_NO_EARLY when not setting
	 * CAPREVOKE_LAST_PASS will cause no passes to be performed.
	 *
	 * XXX CAPREVOKE_LAST_NO_LATE is currently implied because our VM
	 * does not actually take advantage of the split.  This is
	 * post-ASPLOS work at the earliest.
	 */
#define CAPREVOKE_LAST_NO_EARLY	0x010
#define CAPREVOKE_LAST_NO_LATE	0x020

	/*
	 * Force a synchronization with the PMAP before doing a non-LAST
	 * pass (including the EARLY part of a LAST call).  This should let
	 * us measure the impact of lazily synchronizing with the PMAP
	 * capdirty bits.
	 *
	 * This may also be useful if one were to do intermediate (i.e.,
	 * neither opening nor closing) passes, but at present we do not.
	 *
	 * Meaningless if CAPREVOKE_LAST_NO_EARLY also set.
	 */
#define CAPREVOKE_EARLY_SYNC	0x040

	/*
	 * Some flags indicate that we are to engage in a blocking
	 * capability revocation sweep on a subset of the entire address
	 * space.  If any of these are set, we bypass the above state
	 * machine and visit only the indicated locations.  This is an
	 * expermental feature to see if this kind of mitigation, while
	 * unsound, is still a useful thing to do.
	 */
/* CAPREVOKE_JUST_THE_TIME was 0x100; it is unsafe and superseded */
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

		/*
		 * The synchronized time at the start of the call.  This
		 * value is useful for *enqueueing* objects to quarantine:
		 * all bitmap writes prior to the system call certainly
		 * happened in or before epoch_init, and so waiting for the
		 * epoch to advance sufficiently far relative to epoch_init
		 * will ensure that those objects have been revoked.
		 */
	caprevoke_epoch	epoch_init;

		/*
		 * The synchronized time at the end of the call.  This value
		 * is useful for *dequeueing* objects from quarantine: if
		 * this value clears the recorded epoch_init, then those
		 * objects have been revoked.
		 *
		 * It may be the case that epoch_fini < epoch_init.  This
		 * implies that an epoch transition is in progress but that
		 * the requested "start_epoch" given to caprevoke() has been
		 * cleared by the reported value of epoch_fini, and so there
		 * is no reason to wait for the transition to finish.
		 */
	caprevoke_epoch	epoch_fini;

		/*
		 * The remainder of the fields of this structure are purely
		 * informative; they may be of slight interest to policies,
		 * but shouldn't influence correctness.
		 */

	uint64_t	page_scan_cycles;

	uint32_t	pages_retried;
	uint32_t	pages_scan_ro;
	uint32_t	pages_scan_rw;

	uint32_t	pages_faulted_ro;
	uint32_t	pages_faulted_rw;

	uint32_t	pages_skip_fast;
	uint32_t	pages_skip;

	uint32_t	caps_found;
	uint32_t	caps_found_revoked;

	uint32_t	caps_cleared;

	uint32_t	lines_scan;
	uint32_t	pages_mark_clean;

	uint32_t	__spare[2];
};

#define	CAPREVOKE_SHADOW_NOVMMAP	0x00	/* The ordinary shadow space */
#define CAPREVOKE_SHADOW_OTYPE		0x01	/* The otype shadow space */
/*
 * It is not possible to ask for the _MEM_MAP bitmask, as we intend that one
 * to be used by the kernel internally for munmap().  Maybe that's wrong?
 *
 * XXX Do we want a madvise mode to allow userspace to request revocation
 * of vm objects that we aren't deleting?  They *can* use the NOVMMAP
 * bitmask, but it's 256 times as many bits to flip.
 */
#define CAPREVOKE_SHADOW_SPACE_MASK	0x03	/* Flag bits for shadow index */

#ifndef _KERNEL

	/*
	 * Drive the revocation state machine.
	 *
	 * If the current epoch clock is sufficient to caprvoke_epoch_clears
	 * start_epoch, this call returns immediately, populating
	 * statout->epoch_{init,fini} with the current clock's value.
	 *
	 * XXX if caprevoke_epoch becomes more complex than a scalar type,
	 * this prototype will need to change or we'll need to be more
	 * explicit about it being a hint or something.
	 */
int caprevoke(int flags, caprevoke_epoch start_epoch,
		struct caprevoke_stats *statout);

	/*
	 * Request a capability to the shadow bitmap state for the given
	 * arena.  Flags determine which space is requested; the arena cap
	 * must have appropriate privileges.
	 *
	 * This call must fail if the resulting capability would not be
	 * representable due to alignment constraints.
	 */
int caprevoke_shadow(int flags,
	void * __capability arena,
	void * __capability * shadow);

#endif

#endif /* !__SYS_CAPREVOKE_H__ */
