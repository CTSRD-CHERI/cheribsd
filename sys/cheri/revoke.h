/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2018 SRI International
 * Copyright (c) 2020-2022 Microsoft Corp.
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

#ifndef __SYS_CHERI_REVOKE_H__
#define	__SYS_CHERI_REVOKE_H__

#include <cheri/cherireg.h> /* For CHERI_OTYPE_BITS */

typedef uint64_t cheri_revoke_epoch_t;
#define CHERI_REVOKE_ST_EPOCH_WIDTH	61

/*
 * Epoch greater than orderings: a > b, a >= b.
 *
 * We use RFC1982 serial number arithmetic to deal with wrap-around.  We
 * assume that there will never be any reason to ask about epochs so far
 * apart that this is problematic.
 *
 * We could probably get away without wraparound handling, given the current
 * value of CHERI_REVOKE_ST_EPOCH_WIDTH, but on the chance that it becomes
 * significantly shorter, it doesn't hurt to have this abstracted.
 *
 * XXX Eventually we'd like to switch to using capabilities themselves as epoch
 * "counters" so that it's a small "epoch width" but there's no possibility of
 * confusion because we can revoke very old epoch handles.
 *
 * XXX this almost surely belongs somewhere else.
 */

static inline int cheri_revoke_epoch_gt(cheri_revoke_epoch_t a,
    cheri_revoke_epoch_t b) {
	static const cheri_revoke_epoch_t top =
	    1ULL << (CHERI_REVOKE_ST_EPOCH_WIDTH-1);
	return ((a < b) && ((b - a) > top)) || ((a > b) && ((a - b) < top));
}
static inline int cheri_revoke_epoch_ge(cheri_revoke_epoch_t a,
    cheri_revoke_epoch_t b) {
	return (a == b) || cheri_revoke_epoch_gt(a, b);
}

static inline int cheri_revoke_epoch_clears(cheri_revoke_epoch_t now,
                                         cheri_revoke_epoch_t then) {
	return cheri_revoke_epoch_ge(now, then + (then & 1) + 2);
}

/* Returns 1 if cap is revoked, 0 otherwise. */
static inline int
cheri_revoke_is_revoked(const void * __capability cap)
{
#ifndef CHERI_CAPREVOKE_CLEARTAGS
	return (__builtin_cheri_perms_get(cap) == 0);
#else
	return (__builtin_cheri_tag_get(cap) == 0);
#endif
}

/*************************** SHADOW BITMAP LAYOUT ***************************/

/*
 * The shadow bitmap is defined in a way that allows a single capability to
 * access three "variable"-sized structures in a way that depends only on static
 * features of the architecture rather than dynamic behaviors thereof.
 *
 * In particular, we used to define the shadow as the (padded) concatenation of
 * four structures: the fine-grained memory shadow, the coarse-grained memory
 * shadow, the otype shadow, and the info page.  Unpleasantly, we did so
 * identically for all supporting architectures.  Moreover, while this worked
 * fine so long as each architecture had a fixed size for each of those, it
 * broke as soon as RISC-V supported both RV39 and RV47, because now we needed
 * to know the dynamic-at-boot size of the address space to offset into the
 * amalgamated structure.
 *
 * So instead, we propose a more uniform, more-MI layout that "grows" in two
 * directions and we pass a pointer to the middle of the structure.  This allows
 * the MD tests to use constant offsets even as the AS size grows.  Concretely,
 * the shadow is now the concatenation of
 *
 *  - the coarse-grained memory shadow bitmap (1 bit per page), with the bit
 *    corresponding to the page 0x0...0 at the LSB of the *highest* address in
 *    this region (that is, this region "grows down"),
 *
 *  - the otype memory shadow bitmap (1 bit per otype), with the bit
 *    corresponding to otype 0 at the LSB of the *lowest* address in this
 *    region,
 *
 *  - the fine-grained memory shadow bitmap (1 bit per cap), with the bit
 *    corresponding to the granule at 0x0...0 as the LSB of the *lowest* address
 *    in this region.
 *
 * This amalgam is aligned so that the fine-grained memory shadow within is
 * naturally aligned, and the other structures are packed below, so that it's
 * (relatively) easy to explain the implications for alignment of user address
 * ranges.
 *
 * XXX Note that all of this is somewhat conjecture: we don't actually use the
 * otype or coarse shadows at the moment, the coarse shadow seems like it might
 * go away in favor of some other mechanism, and some architectures additionally
 * have other namespaces, like CIDs, that we might want to track.  There's also
 * the intense desire to have CHERI+MTE simplify this dance enormously, assuming
 * we get there.
 */

static const size_t VM_CHERI_REVOKE_GSZ_MEM_NOMAP = sizeof(void * __capability);
static const size_t VM_CHERI_REVOKE_GSZ_OTYPE = 1;

static const size_t VM_CHERI_REVOKE_BSZ_OTYPE =
  ((1 << CHERI_OTYPE_BITS) / VM_CHERI_REVOKE_GSZ_OTYPE / 8);

/*************************** REVOKER CONTROL FLAGS ***************************/

	/*
	 * Finish the current revocation epoch this pass.
	 * If there is no current revocation epoch, start one and then
	 * finish it.
	 *
	 * If this flag is not given, then either start an epoch by doing
	 * the first (full) pass or continue an epoch by doing an
	 * incremental pass.  (For the load side algorithm, incremental passes
	 * except the opening one are essentially no-ops.)
	 */
#define CHERI_REVOKE_LAST_PASS	0x0001

	/*
	 * If this bit is set, the kernel is free to return without making
	 * progress.
	 */
#define	CHERI_REVOKE_NO_WAIT_OK	0x0002

	/*
	 * Ignore the given epoch argument and always attempt to advance the
	 * epoch clock relative to its value "at the time of the call".
	 */
#define	CHERI_REVOKE_IGNORE_START	0x0004

	/*
	 * Do a pass only if an epoch is open after synchronization.
	 *
	 * XXX This has probably lost any utility it may ever have had.
	 */
#define	CHERI_REVOKE_ONLY_IF_OPEN	0x0008

	/*
	 * Ordinarily, cheri_revoke with CHERI_REVOKE_LAST_PASS attempts to
	 * minimize the amount of work it does with the world held in
	 * single-threaded state.  It will do up to two passes:
	 *
	 *   * an opening/incremental pass with the world running
	 *
	 *   * a pass with the world stopped, which visits kernel hoarders
	 *     and recently-dirty pages (since the above pass)
	 *
	 * The first may be disabled by passing CHERI_REVOKE_LAST_NO_EARLY,
	 * causing more work to be pushed into the world-stopped phase.
	 *
	 * Setting CHERI_REVOKE_LAST_NO_EARLY when not setting
	 * CHERI_REVOKE_LAST_PASS will cause no passes to be performed.
	 *
	 * XXX This has probably lost any utility it may ever have had.
	 */
#define CHERI_REVOKE_LAST_NO_EARLY	0x0010

	/*
	 * Force a synchronization with the PMAP before doing a non-LAST
	 * pass (including the EARLY part of a LAST call).  This should let
	 * us measure the impact of lazily synchronizing with the PMAP
	 * capdirty bits.
	 *
	 * This may also be useful if one were to do intermediate (i.e.,
	 * neither opening nor closing) passes, but at present we do not.
	 *
	 * Meaningless if CHERI_REVOKE_LAST_NO_EARLY also set.
	 *
	 * XXX This has probably lost any utility it may ever have had.
	 */
#define CHERI_REVOKE_EARLY_SYNC	0x0020

	/*
         * If opening a new revocation epoch, ignore the default mode and run
         * this one using the load-side algorithm.
	 */
#define CHERI_REVOKE_FORCE_LOAD_SIDE	0x0040

	/*
         * If opening a new revocation epoch, ignore the default mode and run
         * this one using the store-side algorithm.
	 */
#define CHERI_REVOKE_FORCE_STORE_SIDE	0x0080

	/*
	 * Reset the stats counters to zero "after" reporting
	 */
#define CHERI_REVOKE_TAKE_STATS	0x1000

/*
 * Information conveyed to userland about a given cheri_revoke scan.
 *
 * Given what's being counted, here are some things possibly useful to fitting a
 * linear regression model:
 *
 *  - The average time per fault is approximately fault_cycles / fault_visits.
 *
 *  - The average time *scanning* per page is approximately
 *      page_scan_cycles / (fault_visits + pages_scan_ro + pages_scan_rw)
 *
 *  - The overhead of faulting is approximately the per fault overhead minus the
 *    per page overhead.
 *
 *  - There are different iteration overheads for pages scanned by the iterator
 *    and for pages already found scanned by the CLG fault handler.
 *
 *  - There is some sweeper cost associated with each pages_faulted_{ro,rw}
 *    tick, which comes out of total time spent, not page_scan_cycles or
 *    fault_cycles.
 *
 *  - There is linear sweeper overhead per pages_skip_nofill and pages_skip
 *    tick, but pages_skip_fast has a less clear relationship with time spent.
 *    It is likely worth excluding the latter from modeling.
 */

struct cheri_revoke_stats {
	/*
	 * Total cycles spent inside MD page scan routines; inclusive of sweeps
	 * from CLG fault handler.
	 */
	uint64_t	page_scan_cycles;
	/*
	 * Total cycles spent inside MI CLG handler; includes state machine,
	 * pmap traversal, and page sweeps.
	 */
	uint64_t	fault_cycles;

	uint32_t	__spare[7];

	/*
	 * Pages iterated by the VM iterator, in each of RO and RW states;
	 * exclusive of CLG fault handler invocations.
	 */
	uint32_t	pages_scan_ro;
	uint32_t	pages_scan_rw;

	/*
	 * Calls from the VM iterator to the VM fault handlers, in each of RO
	 * and RW states.  Exclusive of CLG fault handler invocations.
	 */
	uint32_t	pages_faulted_ro;
	uint32_t	pages_faulted_rw;

	/*
	 * Number of invocations of MI CLG fault handler (RO and RW pages
	 * conflated).
	 */
	uint32_t	fault_visits;

	/*
	 * Various fast-out paths of the VM iterator.  _fast is synthesized from
	 * the size of spans skipped, while _nofill and pages_skip itself are
	 * incremented by bailing attempts to find each vm_page_t structure.
	 */
	uint32_t	pages_skip_fast;
	uint32_t	pages_skip_nofill;
	uint32_t	pages_skip;

	/*
	 * Counters incremented during sweeps, inclusive of both the VM iterator
	 * and CLG faults
	 */
	uint32_t	caps_found;
	uint32_t	caps_found_revoked; /* Already revoked */
	uint32_t	caps_cleared;	/* Revoked this time */
	uint32_t	lines_scan;

	/* A holdover from Cornucopia; see vm_cheri_revoke_visit_ro */
	uint32_t	pages_mark_clean;
};

/*
 * XXX The use of two counters is mostly a bug, but it's never been worth
 * fixing.  It originated in response to some error handling paths where it
 * seemed like we might have to "rewind" the epoch counter to back out of a
 * failed revocation pass, but probably a different design would have been
 * better.  Apologies.  Eventually, there will be only one.
 */
struct cheri_revoke_epochs {
	cheri_revoke_epoch_t enqueue; /* Label on entry to quarantine */
	cheri_revoke_epoch_t dequeue; /* Gates removal from quarantine */
};

struct cheri_revoke_info {
        const vaddr_t base_mem_nomap;
        const vaddr_t base_otype;

	struct cheri_revoke_epochs epochs;
};

struct cheri_revoke_syscall_info {
	struct cheri_revoke_epochs epochs;
	struct cheri_revoke_stats stats;
};

#define	CHERI_REVOKE_SHADOW_NOVMMAP	0x00	/* The ordinary shadow space */
#define CHERI_REVOKE_SHADOW_OTYPE	0x01	/* The otype shadow space */
/*
 * It is not possible to ask for the _MEM_MAP bitmask, as we intend that one
 * to be used by the kernel internally for munmap().  Maybe that's wrong?
 *
 * XXX Do we want a madvise mode to allow userspace to request revocation
 * of vm objects that we aren't deleting?  They *can* use the NOVMMAP
 * bitmask, but it's 256 times as many bits to flip.
 */

#define CHERI_REVOKE_SHADOW_INFO_STRUCT	0x03	/* R/O access to shared state */

/*
 * XXX This should go away as soon as we have allocators w/ per-arena shadows
 * or come to depend on CHERI+MTE, whichever happens first.  However, the
 * minimal-bookkeeping version of libmrs uses this, and that's very convenient.
 */
#define CHERI_REVOKE_SHADOW_NOVMMAP_ENTIRE 0x07	/* The entire shadow region */

#define CHERI_REVOKE_SHADOW_SPACE_MASK	0x07	/* Flag bits for shadow index */

#ifndef _KERNEL
	/*
	 * Drive the revocation state machine.
	 *
	 * If the current epoch clock is sufficient to caprvoke_epoch_clears
	 * start_epoch, this call returns immediately, populating
	 * statout->epoch_{init,fini} with the current clock's value.
	 *
	 * XXX if cheri_revoke_epoch becomes more complex than a scalar type,
	 * this prototype will need to change or we'll need to be more
	 * explicit about it being a hint or something.
	 */
int cheri_revoke(int flags, cheri_revoke_epoch_t start_epoch,
		struct cheri_revoke_syscall_info *crsi);

	/*
	 * Request a capability to the shadow bitmap state for the given
	 * arena.  Flags determine which space is requested; the arena cap
	 * must have appropriate privileges.
	 *
	 * This call must fail if the resulting capability would not be
	 * representable due to alignment constraints.
	 */
int cheri_revoke_get_shadow(int flags,
	void * __capability arena,
	void * __capability * shadow);
#endif

#endif /* !__SYS_CHERI_REVOKE_H__ */
