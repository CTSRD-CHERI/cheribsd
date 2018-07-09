/*-
 * SPDX-License-Identifier: (BSD-4-Clause AND MIT-CMU)
 *
 * Copyright (c) 1991 Regents of the University of California.
 * All rights reserved.
 * Copyright (c) 1994 John S. Dyson
 * All rights reserved.
 * Copyright (c) 1994 David Greenman
 * All rights reserved.
 * Copyright (c) 2005 Yahoo! Technologies Norway AS
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * The Mach Operating System project at Carnegie-Mellon University.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from: @(#)vm_pageout.c	7.4 (Berkeley) 5/7/91
 *
 *
 * Copyright (c) 1987, 1990 Carnegie-Mellon University.
 * All rights reserved.
 *
 * Authors: Avadis Tevanian, Jr., Michael Wayne Young
 *
 * Permission to use, copy, modify and distribute this software and
 * its documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND
 * FOR ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie the
 * rights to redistribute these changes.
 */

/*
 *	The proverbial page-out daemon.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_vm.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/eventhandler.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/ktr.h>
#include <sys/mount.h>
#include <sys/racct.h>
#include <sys/resourcevar.h>
#include <sys/sched.h>
#include <sys/sdt.h>
#include <sys/signalvar.h>
#include <sys/smp.h>
#include <sys/time.h>
#include <sys/vnode.h>
#include <sys/vmmeter.h>
#include <sys/rwlock.h>
#include <sys/sx.h>
#include <sys/sysctl.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>
#include <vm/vm_pageout.h>
#include <vm/vm_pager.h>
#include <vm/vm_phys.h>
#include <vm/swap_pager.h>
#include <vm/vm_extern.h>
#include <vm/uma.h>

/*
 * System initialization
 */

/* the kernel process "vm_pageout"*/
static void vm_pageout(void);
static void vm_pageout_init(void);
static int vm_pageout_clean(vm_page_t m, int *numpagedout);
static int vm_pageout_cluster(vm_page_t m);
static bool vm_pageout_scan(struct vm_domain *vmd, int pass);
static void vm_pageout_mightbe_oom(struct vm_domain *vmd, int page_shortage,
    int starting_page_shortage);

SYSINIT(pagedaemon_init, SI_SUB_KTHREAD_PAGE, SI_ORDER_FIRST, vm_pageout_init,
    NULL);

struct proc *pageproc;

static struct kproc_desc page_kp = {
	"pagedaemon",
	vm_pageout,
	&pageproc
};
SYSINIT(pagedaemon, SI_SUB_KTHREAD_PAGE, SI_ORDER_SECOND, kproc_start,
    &page_kp);

SDT_PROVIDER_DEFINE(vm);
SDT_PROBE_DEFINE(vm, , , vm__lowmem_scan);

/* Pagedaemon activity rates, in subdivisions of one second. */
#define	VM_LAUNDER_RATE		10
#define	VM_INACT_SCAN_RATE	2

int vm_pageout_deficit;		/* Estimated number of pages deficit */
u_int vm_pageout_wakeup_thresh;
static int vm_pageout_oom_seq = 12;
static bool vm_pageout_wanted;	/* Event on which pageout daemon sleeps */
bool vm_pages_needed;		/* Are threads waiting for free pages? */

/* Pending request for dirty page laundering. */
static enum {
	VM_LAUNDRY_IDLE,
	VM_LAUNDRY_BACKGROUND,
	VM_LAUNDRY_SHORTFALL
} vm_laundry_request = VM_LAUNDRY_IDLE;
static int vm_inactq_scans;

static int vm_pageout_update_period;
static int disable_swap_pageouts;
static int lowmem_period = 10;
static time_t lowmem_uptime;
static int swapdev_enabled;

static int vm_panic_on_oom = 0;

SYSCTL_INT(_vm, OID_AUTO, panic_on_oom,
	CTLFLAG_RWTUN, &vm_panic_on_oom, 0,
	"panic on out of memory instead of killing the largest process");

SYSCTL_INT(_vm, OID_AUTO, pageout_wakeup_thresh,
	CTLFLAG_RWTUN, &vm_pageout_wakeup_thresh, 0,
	"free page threshold for waking up the pageout daemon");

SYSCTL_INT(_vm, OID_AUTO, pageout_update_period,
	CTLFLAG_RWTUN, &vm_pageout_update_period, 0,
	"Maximum active LRU update period");
  
SYSCTL_INT(_vm, OID_AUTO, lowmem_period, CTLFLAG_RWTUN, &lowmem_period, 0,
	"Low memory callback period");

SYSCTL_INT(_vm, OID_AUTO, disable_swapspace_pageouts,
	CTLFLAG_RWTUN, &disable_swap_pageouts, 0, "Disallow swapout of dirty pages");

static int pageout_lock_miss;
SYSCTL_INT(_vm, OID_AUTO, pageout_lock_miss,
	CTLFLAG_RD, &pageout_lock_miss, 0, "vget() lock misses during pageout");

SYSCTL_INT(_vm, OID_AUTO, pageout_oom_seq,
	CTLFLAG_RWTUN, &vm_pageout_oom_seq, 0,
	"back-to-back calls to oom detector to start OOM");

static int act_scan_laundry_weight = 3;
SYSCTL_INT(_vm, OID_AUTO, act_scan_laundry_weight, CTLFLAG_RWTUN,
    &act_scan_laundry_weight, 0,
    "weight given to clean vs. dirty pages in active queue scans");

static u_int vm_background_launder_target;
SYSCTL_UINT(_vm, OID_AUTO, background_launder_target, CTLFLAG_RWTUN,
    &vm_background_launder_target, 0,
    "background laundering target, in pages");

static u_int vm_background_launder_rate = 4096;
SYSCTL_UINT(_vm, OID_AUTO, background_launder_rate, CTLFLAG_RWTUN,
    &vm_background_launder_rate, 0,
    "background laundering rate, in kilobytes per second");

static u_int vm_background_launder_max = 20 * 1024;
SYSCTL_UINT(_vm, OID_AUTO, background_launder_max, CTLFLAG_RWTUN,
    &vm_background_launder_max, 0, "background laundering cap, in kilobytes");

int vm_pageout_page_count = 32;

int vm_page_max_wired;		/* XXX max # of wired pages system-wide */
SYSCTL_INT(_vm, OID_AUTO, max_wired,
	CTLFLAG_RW, &vm_page_max_wired, 0, "System-wide limit to wired page count");

static u_int isqrt(u_int num);
static boolean_t vm_pageout_fallback_object_lock(vm_page_t, vm_page_t *);
static int vm_pageout_launder(struct vm_domain *vmd, int launder,
    bool in_shortfall);
static void vm_pageout_laundry_worker(void *arg);
static boolean_t vm_pageout_page_lock(vm_page_t, vm_page_t *);

/*
 * Initialize a dummy page for marking the caller's place in the specified
 * paging queue.  In principle, this function only needs to set the flag
 * PG_MARKER.  Nonetheless, it write busies and initializes the hold count
 * to one as safety precautions.
 */ 
static void
vm_pageout_init_marker(vm_page_t marker, u_short queue)
{

	bzero(marker, sizeof(*marker));
	marker->flags = PG_MARKER;
	marker->busy_lock = VPB_SINGLE_EXCLUSIVER;
	marker->queue = queue;
	marker->hold_count = 1;
}

/*
 * vm_pageout_fallback_object_lock:
 * 
 * Lock vm object currently associated with `m'. VM_OBJECT_TRYWLOCK is
 * known to have failed and page queue must be either PQ_ACTIVE or
 * PQ_INACTIVE.  To avoid lock order violation, unlock the page queue
 * while locking the vm object.  Use marker page to detect page queue
 * changes and maintain notion of next page on page queue.  Return
 * TRUE if no changes were detected, FALSE otherwise.  vm object is
 * locked on return.
 * 
 * This function depends on both the lock portion of struct vm_object
 * and normal struct vm_page being type stable.
 */
static boolean_t
vm_pageout_fallback_object_lock(vm_page_t m, vm_page_t *next)
{
	struct vm_page marker;
	struct vm_pagequeue *pq;
	boolean_t unchanged;
	u_short queue;
	vm_object_t object;

	queue = m->queue;
	vm_pageout_init_marker(&marker, queue);
	pq = vm_page_pagequeue(m);
	object = m->object;
	
	TAILQ_INSERT_AFTER(&pq->pq_pl, m, &marker, plinks.q);
	vm_pagequeue_unlock(pq);
	vm_page_unlock(m);
	VM_OBJECT_WLOCK(object);
	vm_page_lock(m);
	vm_pagequeue_lock(pq);

	/*
	 * The page's object might have changed, and/or the page might
	 * have moved from its original position in the queue.  If the
	 * page's object has changed, then the caller should abandon
	 * processing the page because the wrong object lock was
	 * acquired.  Use the marker's plinks.q, not the page's, to
	 * determine if the page has been moved.  The state of the
	 * page's plinks.q can be indeterminate; whereas, the marker's
	 * plinks.q must be valid.
	 */
	*next = TAILQ_NEXT(&marker, plinks.q);
	unchanged = m->object == object &&
	    m == TAILQ_PREV(&marker, pglist, plinks.q);
	KASSERT(!unchanged || m->queue == queue,
	    ("page %p queue %d %d", m, queue, m->queue));
	TAILQ_REMOVE(&pq->pq_pl, &marker, plinks.q);
	return (unchanged);
}

/*
 * Lock the page while holding the page queue lock.  Use marker page
 * to detect page queue changes and maintain notion of next page on
 * page queue.  Return TRUE if no changes were detected, FALSE
 * otherwise.  The page is locked on return. The page queue lock might
 * be dropped and reacquired.
 *
 * This function depends on normal struct vm_page being type stable.
 */
static boolean_t
vm_pageout_page_lock(vm_page_t m, vm_page_t *next)
{
	struct vm_page marker;
	struct vm_pagequeue *pq;
	boolean_t unchanged;
	u_short queue;

	vm_page_lock_assert(m, MA_NOTOWNED);
	if (vm_page_trylock(m))
		return (TRUE);

	queue = m->queue;
	vm_pageout_init_marker(&marker, queue);
	pq = vm_page_pagequeue(m);

	TAILQ_INSERT_AFTER(&pq->pq_pl, m, &marker, plinks.q);
	vm_pagequeue_unlock(pq);
	vm_page_lock(m);
	vm_pagequeue_lock(pq);

	/* Page queue might have changed. */
	*next = TAILQ_NEXT(&marker, plinks.q);
	unchanged = m == TAILQ_PREV(&marker, pglist, plinks.q);
	KASSERT(!unchanged || m->queue == queue,
	    ("page %p queue %d %d", m, queue, m->queue));
	TAILQ_REMOVE(&pq->pq_pl, &marker, plinks.q);
	return (unchanged);
}

/*
 * Scan for pages at adjacent offsets within the given page's object that are
 * eligible for laundering, form a cluster of these pages and the given page,
 * and launder that cluster.
 */
static int
vm_pageout_cluster(vm_page_t m)
{
	vm_object_t object;
	vm_page_t mc[2 * vm_pageout_page_count], p, pb, ps;
	vm_pindex_t pindex;
	int ib, is, page_base, pageout_count;

	vm_page_assert_locked(m);
	object = m->object;
	VM_OBJECT_ASSERT_WLOCKED(object);
	pindex = m->pindex;

	/*
	 * We can't clean the page if it is busy or held.
	 */
	vm_page_assert_unbusied(m);
	KASSERT(m->hold_count == 0, ("page %p is held", m));

	pmap_remove_write(m);
	vm_page_unlock(m);

	mc[vm_pageout_page_count] = pb = ps = m;
	pageout_count = 1;
	page_base = vm_pageout_page_count;
	ib = 1;
	is = 1;

	/*
	 * We can cluster only if the page is not clean, busy, or held, and
	 * the page is in the laundry queue.
	 *
	 * During heavy mmap/modification loads the pageout
	 * daemon can really fragment the underlying file
	 * due to flushing pages out of order and not trying to
	 * align the clusters (which leaves sporadic out-of-order
	 * holes).  To solve this problem we do the reverse scan
	 * first and attempt to align our cluster, then do a 
	 * forward scan if room remains.
	 */
more:
	while (ib != 0 && pageout_count < vm_pageout_page_count) {
		if (ib > pindex) {
			ib = 0;
			break;
		}
		if ((p = vm_page_prev(pb)) == NULL || vm_page_busied(p)) {
			ib = 0;
			break;
		}
		vm_page_test_dirty(p);
		if (p->dirty == 0) {
			ib = 0;
			break;
		}
		vm_page_lock(p);
		if (!vm_page_in_laundry(p) ||
		    p->hold_count != 0) {	/* may be undergoing I/O */
			vm_page_unlock(p);
			ib = 0;
			break;
		}
		pmap_remove_write(p);
		vm_page_unlock(p);
		mc[--page_base] = pb = p;
		++pageout_count;
		++ib;

		/*
		 * We are at an alignment boundary.  Stop here, and switch
		 * directions.  Do not clear ib.
		 */
		if ((pindex - (ib - 1)) % vm_pageout_page_count == 0)
			break;
	}
	while (pageout_count < vm_pageout_page_count && 
	    pindex + is < object->size) {
		if ((p = vm_page_next(ps)) == NULL || vm_page_busied(p))
			break;
		vm_page_test_dirty(p);
		if (p->dirty == 0)
			break;
		vm_page_lock(p);
		if (!vm_page_in_laundry(p) ||
		    p->hold_count != 0) {	/* may be undergoing I/O */
			vm_page_unlock(p);
			break;
		}
		pmap_remove_write(p);
		vm_page_unlock(p);
		mc[page_base + pageout_count] = ps = p;
		++pageout_count;
		++is;
	}

	/*
	 * If we exhausted our forward scan, continue with the reverse scan
	 * when possible, even past an alignment boundary.  This catches
	 * boundary conditions.
	 */
	if (ib != 0 && pageout_count < vm_pageout_page_count)
		goto more;

	return (vm_pageout_flush(&mc[page_base], pageout_count,
	    VM_PAGER_PUT_NOREUSE, 0, NULL, NULL));
}

/*
 * vm_pageout_flush() - launder the given pages
 *
 *	The given pages are laundered.  Note that we setup for the start of
 *	I/O ( i.e. busy the page ), mark it read-only, and bump the object
 *	reference count all in here rather then in the parent.  If we want
 *	the parent to do more sophisticated things we may have to change
 *	the ordering.
 *
 *	Returned runlen is the count of pages between mreq and first
 *	page after mreq with status VM_PAGER_AGAIN.
 *	*eio is set to TRUE if pager returned VM_PAGER_ERROR or VM_PAGER_FAIL
 *	for any page in runlen set.
 */
int
vm_pageout_flush(vm_page_t *mc, int count, int flags, int mreq, int *prunlen,
    boolean_t *eio)
{
	vm_object_t object = mc[0]->object;
	int pageout_status[count];
	int numpagedout = 0;
	int i, runlen;

	VM_OBJECT_ASSERT_WLOCKED(object);

	/*
	 * Initiate I/O.  Mark the pages busy and verify that they're valid
	 * and read-only.
	 *
	 * We do not have to fixup the clean/dirty bits here... we can
	 * allow the pager to do it after the I/O completes.
	 *
	 * NOTE! mc[i]->dirty may be partial or fragmented due to an
	 * edge case with file fragments.
	 */
	for (i = 0; i < count; i++) {
		KASSERT(mc[i]->valid == VM_PAGE_BITS_ALL,
		    ("vm_pageout_flush: partially invalid page %p index %d/%d",
			mc[i], i, count));
		KASSERT((mc[i]->aflags & PGA_WRITEABLE) == 0,
		    ("vm_pageout_flush: writeable page %p", mc[i]));
		vm_page_sbusy(mc[i]);
	}
	vm_object_pip_add(object, count);

	vm_pager_put_pages(object, mc, count, flags, pageout_status);

	runlen = count - mreq;
	if (eio != NULL)
		*eio = FALSE;
	for (i = 0; i < count; i++) {
		vm_page_t mt = mc[i];

		KASSERT(pageout_status[i] == VM_PAGER_PEND ||
		    !pmap_page_is_write_mapped(mt),
		    ("vm_pageout_flush: page %p is not write protected", mt));
		switch (pageout_status[i]) {
		case VM_PAGER_OK:
			vm_page_lock(mt);
			if (vm_page_in_laundry(mt))
				vm_page_deactivate_noreuse(mt);
			vm_page_unlock(mt);
			/* FALLTHROUGH */
		case VM_PAGER_PEND:
			numpagedout++;
			break;
		case VM_PAGER_BAD:
			/*
			 * The page is outside the object's range.  We pretend
			 * that the page out worked and clean the page, so the
			 * changes will be lost if the page is reclaimed by
			 * the page daemon.
			 */
			vm_page_undirty(mt);
			vm_page_lock(mt);
			if (vm_page_in_laundry(mt))
				vm_page_deactivate_noreuse(mt);
			vm_page_unlock(mt);
			break;
		case VM_PAGER_ERROR:
		case VM_PAGER_FAIL:
			/*
			 * If the page couldn't be paged out to swap because the
			 * pager wasn't able to find space, place the page in
			 * the PQ_UNSWAPPABLE holding queue.  This is an
			 * optimization that prevents the page daemon from
			 * wasting CPU cycles on pages that cannot be reclaimed
			 * becase no swap device is configured.
			 *
			 * Otherwise, reactivate the page so that it doesn't
			 * clog the laundry and inactive queues.  (We will try
			 * paging it out again later.)
			 */
			vm_page_lock(mt);
			if (object->type == OBJT_SWAP &&
			    pageout_status[i] == VM_PAGER_FAIL) {
				vm_page_unswappable(mt);
				numpagedout++;
			} else
				vm_page_activate(mt);
			vm_page_unlock(mt);
			if (eio != NULL && i >= mreq && i - mreq < runlen)
				*eio = TRUE;
			break;
		case VM_PAGER_AGAIN:
			if (i >= mreq && i - mreq < runlen)
				runlen = i - mreq;
			break;
		}

		/*
		 * If the operation is still going, leave the page busy to
		 * block all other accesses. Also, leave the paging in
		 * progress indicator set so that we don't attempt an object
		 * collapse.
		 */
		if (pageout_status[i] != VM_PAGER_PEND) {
			vm_object_pip_wakeup(object);
			vm_page_sunbusy(mt);
		}
	}
	if (prunlen != NULL)
		*prunlen = runlen;
	return (numpagedout);
}

static void
vm_pageout_swapon(void *arg __unused, struct swdevt *sp __unused)
{

	atomic_store_rel_int(&swapdev_enabled, 1);
}

static void
vm_pageout_swapoff(void *arg __unused, struct swdevt *sp __unused)
{

	if (swap_pager_nswapdev() == 1)
		atomic_store_rel_int(&swapdev_enabled, 0);
}

/*
 * Attempt to acquire all of the necessary locks to launder a page and
 * then call through the clustering layer to PUTPAGES.  Wait a short
 * time for a vnode lock.
 *
 * Requires the page and object lock on entry, releases both before return.
 * Returns 0 on success and an errno otherwise.
 */
static int
vm_pageout_clean(vm_page_t m, int *numpagedout)
{
	struct vnode *vp;
	struct mount *mp;
	vm_object_t object;
	vm_pindex_t pindex;
	int error, lockmode;

	vm_page_assert_locked(m);
	object = m->object;
	VM_OBJECT_ASSERT_WLOCKED(object);
	error = 0;
	vp = NULL;
	mp = NULL;

	/*
	 * The object is already known NOT to be dead.   It
	 * is possible for the vget() to block the whole
	 * pageout daemon, but the new low-memory handling
	 * code should prevent it.
	 *
	 * We can't wait forever for the vnode lock, we might
	 * deadlock due to a vn_read() getting stuck in
	 * vm_wait while holding this vnode.  We skip the 
	 * vnode if we can't get it in a reasonable amount
	 * of time.
	 */
	if (object->type == OBJT_VNODE) {
		vm_page_unlock(m);
		vp = object->handle;
		if (vp->v_type == VREG &&
		    vn_start_write(vp, &mp, V_NOWAIT) != 0) {
			mp = NULL;
			error = EDEADLK;
			goto unlock_all;
		}
		KASSERT(mp != NULL,
		    ("vp %p with NULL v_mount", vp));
		vm_object_reference_locked(object);
		pindex = m->pindex;
		VM_OBJECT_WUNLOCK(object);
		lockmode = MNT_SHARED_WRITES(vp->v_mount) ?
		    LK_SHARED : LK_EXCLUSIVE;
		if (vget(vp, lockmode | LK_TIMELOCK, curthread)) {
			vp = NULL;
			error = EDEADLK;
			goto unlock_mp;
		}
		VM_OBJECT_WLOCK(object);

		/*
		 * Ensure that the object and vnode were not disassociated
		 * while locks were dropped.
		 */
		if (vp->v_object != object) {
			error = ENOENT;
			goto unlock_all;
		}
		vm_page_lock(m);

		/*
		 * While the object and page were unlocked, the page
		 * may have been:
		 * (1) moved to a different queue,
		 * (2) reallocated to a different object,
		 * (3) reallocated to a different offset, or
		 * (4) cleaned.
		 */
		if (!vm_page_in_laundry(m) || m->object != object ||
		    m->pindex != pindex || m->dirty == 0) {
			vm_page_unlock(m);
			error = ENXIO;
			goto unlock_all;
		}

		/*
		 * The page may have been busied or held while the object
		 * and page locks were released.
		 */
		if (vm_page_busied(m) || m->hold_count != 0) {
			vm_page_unlock(m);
			error = EBUSY;
			goto unlock_all;
		}
	}

	/*
	 * If a page is dirty, then it is either being washed
	 * (but not yet cleaned) or it is still in the
	 * laundry.  If it is still in the laundry, then we
	 * start the cleaning operation. 
	 */
	if ((*numpagedout = vm_pageout_cluster(m)) == 0)
		error = EIO;

unlock_all:
	VM_OBJECT_WUNLOCK(object);

unlock_mp:
	vm_page_lock_assert(m, MA_NOTOWNED);
	if (mp != NULL) {
		if (vp != NULL)
			vput(vp);
		vm_object_deallocate(object);
		vn_finished_write(mp);
	}

	return (error);
}

/*
 * Attempt to launder the specified number of pages.
 *
 * Returns the number of pages successfully laundered.
 */
static int
vm_pageout_launder(struct vm_domain *vmd, int launder, bool in_shortfall)
{
	struct vm_pagequeue *pq;
	vm_object_t object;
	vm_page_t m, next;
	int act_delta, error, maxscan, numpagedout, starting_target;
	int vnodes_skipped;
	bool pageout_ok, queue_locked;

	starting_target = launder;
	vnodes_skipped = 0;

	/*
	 * Scan the laundry queues for pages eligible to be laundered.  We stop
	 * once the target number of dirty pages have been laundered, or once
	 * we've reached the end of the queue.  A single iteration of this loop
	 * may cause more than one page to be laundered because of clustering.
	 *
	 * maxscan ensures that we don't re-examine requeued pages.  Any
	 * additional pages written as part of a cluster are subtracted from
	 * maxscan since they must be taken from the laundry queue.
	 *
	 * As an optimization, we avoid laundering from PQ_UNSWAPPABLE when no
	 * swap devices are configured.
	 */
	if (atomic_load_acq_int(&swapdev_enabled))
		pq = &vmd->vmd_pagequeues[PQ_UNSWAPPABLE];
	else
		pq = &vmd->vmd_pagequeues[PQ_LAUNDRY];

scan:
	vm_pagequeue_lock(pq);
	maxscan = pq->pq_cnt;
	queue_locked = true;
	for (m = TAILQ_FIRST(&pq->pq_pl);
	    m != NULL && maxscan-- > 0 && launder > 0;
	    m = next) {
		vm_pagequeue_assert_locked(pq);
		KASSERT(queue_locked, ("unlocked laundry queue"));
		KASSERT(vm_page_in_laundry(m),
		    ("page %p has an inconsistent queue", m));
		next = TAILQ_NEXT(m, plinks.q);
		if ((m->flags & PG_MARKER) != 0)
			continue;
		KASSERT((m->flags & PG_FICTITIOUS) == 0,
		    ("PG_FICTITIOUS page %p cannot be in laundry queue", m));
		KASSERT((m->oflags & VPO_UNMANAGED) == 0,
		    ("VPO_UNMANAGED page %p cannot be in laundry queue", m));
		if (!vm_pageout_page_lock(m, &next) || m->hold_count != 0) {
			vm_page_unlock(m);
			continue;
		}
		object = m->object;
		if ((!VM_OBJECT_TRYWLOCK(object) &&
		    (!vm_pageout_fallback_object_lock(m, &next) ||
		    m->hold_count != 0)) || vm_page_busied(m)) {
			VM_OBJECT_WUNLOCK(object);
			vm_page_unlock(m);
			continue;
		}

		/*
		 * Unlock the laundry queue, invalidating the 'next' pointer.
		 * Use a marker to remember our place in the laundry queue.
		 */
		TAILQ_INSERT_AFTER(&pq->pq_pl, m, &vmd->vmd_laundry_marker,
		    plinks.q);
		vm_pagequeue_unlock(pq);
		queue_locked = false;

		/*
		 * Invalid pages can be easily freed.  They cannot be
		 * mapped; vm_page_free() asserts this.
		 */
		if (m->valid == 0)
			goto free_page;

		/*
		 * If the page has been referenced and the object is not dead,
		 * reactivate or requeue the page depending on whether the
		 * object is mapped.
		 */
		if ((m->aflags & PGA_REFERENCED) != 0) {
			vm_page_aflag_clear(m, PGA_REFERENCED);
			act_delta = 1;
		} else
			act_delta = 0;
		if (object->ref_count != 0)
			act_delta += pmap_ts_referenced(m);
		else {
			KASSERT(!pmap_page_is_mapped(m),
			    ("page %p is mapped", m));
		}
		if (act_delta != 0) {
			if (object->ref_count != 0) {
				VM_CNT_INC(v_reactivated);
				vm_page_activate(m);

				/*
				 * Increase the activation count if the page
				 * was referenced while in the laundry queue.
				 * This makes it less likely that the page will
				 * be returned prematurely to the inactive
				 * queue.
 				 */
				m->act_count += act_delta + ACT_ADVANCE;

				/*
				 * If this was a background laundering, count
				 * activated pages towards our target.  The
				 * purpose of background laundering is to ensure
				 * that pages are eventually cycled through the
				 * laundry queue, and an activation is a valid
				 * way out.
				 */
				if (!in_shortfall)
					launder--;
				goto drop_page;
			} else if ((object->flags & OBJ_DEAD) == 0)
				goto requeue_page;
		}

		/*
		 * If the page appears to be clean at the machine-independent
		 * layer, then remove all of its mappings from the pmap in
		 * anticipation of freeing it.  If, however, any of the page's
		 * mappings allow write access, then the page may still be
		 * modified until the last of those mappings are removed.
		 */
		if (object->ref_count != 0) {
			vm_page_test_dirty(m);
			if (m->dirty == 0)
				pmap_remove_all(m);
		}

		/*
		 * Clean pages are freed, and dirty pages are paged out unless
		 * they belong to a dead object.  Requeueing dirty pages from
		 * dead objects is pointless, as they are being paged out and
		 * freed by the thread that destroyed the object.
		 */
		if (m->dirty == 0) {
free_page:
			vm_page_free(m);
			VM_CNT_INC(v_dfree);
		} else if ((object->flags & OBJ_DEAD) == 0) {
			if (object->type != OBJT_SWAP &&
			    object->type != OBJT_DEFAULT)
				pageout_ok = true;
			else if (disable_swap_pageouts)
				pageout_ok = false;
			else
				pageout_ok = true;
			if (!pageout_ok) {
requeue_page:
				vm_pagequeue_lock(pq);
				queue_locked = true;
				vm_page_requeue_locked(m);
				goto drop_page;
			}

			/*
			 * Form a cluster with adjacent, dirty pages from the
			 * same object, and page out that entire cluster.
			 *
			 * The adjacent, dirty pages must also be in the
			 * laundry.  However, their mappings are not checked
			 * for new references.  Consequently, a recently
			 * referenced page may be paged out.  However, that
			 * page will not be prematurely reclaimed.  After page
			 * out, the page will be placed in the inactive queue,
			 * where any new references will be detected and the
			 * page reactivated.
			 */
			error = vm_pageout_clean(m, &numpagedout);
			if (error == 0) {
				launder -= numpagedout;
				maxscan -= numpagedout - 1;
			} else if (error == EDEADLK) {
				pageout_lock_miss++;
				vnodes_skipped++;
			}
			goto relock_queue;
		}
drop_page:
		vm_page_unlock(m);
		VM_OBJECT_WUNLOCK(object);
relock_queue:
		if (!queue_locked) {
			vm_pagequeue_lock(pq);
			queue_locked = true;
		}
		next = TAILQ_NEXT(&vmd->vmd_laundry_marker, plinks.q);
		TAILQ_REMOVE(&pq->pq_pl, &vmd->vmd_laundry_marker, plinks.q);
	}
	vm_pagequeue_unlock(pq);

	if (launder > 0 && pq == &vmd->vmd_pagequeues[PQ_UNSWAPPABLE]) {
		pq = &vmd->vmd_pagequeues[PQ_LAUNDRY];
		goto scan;
	}

	/*
	 * Wakeup the sync daemon if we skipped a vnode in a writeable object
	 * and we didn't launder enough pages.
	 */
	if (vnodes_skipped > 0 && launder > 0)
		(void)speedup_syncer();

	return (starting_target - launder);
}

/*
 * Compute the integer square root.
 */
static u_int
isqrt(u_int num)
{
	u_int bit, root, tmp;

	bit = 1u << ((NBBY * sizeof(u_int)) - 2);
	while (bit > num)
		bit >>= 2;
	root = 0;
	while (bit != 0) {
		tmp = root + bit;
		root >>= 1;
		if (num >= tmp) {
			num -= tmp;
			root += bit;
		}
		bit >>= 2;
	}
	return (root);
}

/*
 * Perform the work of the laundry thread: periodically wake up and determine
 * whether any pages need to be laundered.  If so, determine the number of pages
 * that need to be laundered, and launder them.
 */
static void
vm_pageout_laundry_worker(void *arg)
{
	struct vm_domain *domain;
	struct vm_pagequeue *pq;
	uint64_t nclean, ndirty;
	u_int inactq_scans, last_launder;
	int domidx, last_target, launder, shortfall, shortfall_cycle, target;
	bool in_shortfall;

	domidx = (uintptr_t)arg;
	domain = &vm_dom[domidx];
	pq = &domain->vmd_pagequeues[PQ_LAUNDRY];
	KASSERT(domain->vmd_segs != 0, ("domain without segments"));
	vm_pageout_init_marker(&domain->vmd_laundry_marker, PQ_LAUNDRY);

	shortfall = 0;
	in_shortfall = false;
	shortfall_cycle = 0;
	target = 0;
	inactq_scans = 0;
	last_launder = 0;

	/*
	 * Calls to these handlers are serialized by the swap syscall lock.
	 */
	(void)EVENTHANDLER_REGISTER(swapon, vm_pageout_swapon, domain,
	    EVENTHANDLER_PRI_ANY);
	(void)EVENTHANDLER_REGISTER(swapoff, vm_pageout_swapoff, domain,
	    EVENTHANDLER_PRI_ANY);

	/*
	 * The pageout laundry worker is never done, so loop forever.
	 */
	for (;;) {
		KASSERT(target >= 0, ("negative target %d", target));
		KASSERT(shortfall_cycle >= 0,
		    ("negative cycle %d", shortfall_cycle));
		launder = 0;

		/*
		 * First determine whether we need to launder pages to meet a
		 * shortage of free pages.
		 */
		if (shortfall > 0) {
			in_shortfall = true;
			shortfall_cycle = VM_LAUNDER_RATE / VM_INACT_SCAN_RATE;
			target = shortfall;
		} else if (!in_shortfall)
			goto trybackground;
		else if (shortfall_cycle == 0 || vm_laundry_target() <= 0) {
			/*
			 * We recently entered shortfall and began laundering
			 * pages.  If we have completed that laundering run
			 * (and we are no longer in shortfall) or we have met
			 * our laundry target through other activity, then we
			 * can stop laundering pages.
			 */
			in_shortfall = false;
			target = 0;
			goto trybackground;
		}
		last_launder = inactq_scans;
		launder = target / shortfall_cycle--;
		goto dolaundry;

		/*
		 * There's no immediate need to launder any pages; see if we
		 * meet the conditions to perform background laundering:
		 *
		 * 1. The ratio of dirty to clean inactive pages exceeds the
		 *    background laundering threshold and the pagedaemon has
		 *    been woken up to reclaim pages since our last
		 *    laundering, or
		 * 2. we haven't yet reached the target of the current
		 *    background laundering run.
		 *
		 * The background laundering threshold is not a constant.
		 * Instead, it is a slowly growing function of the number of
		 * page daemon scans since the last laundering.  Thus, as the
		 * ratio of dirty to clean inactive pages grows, the amount of
		 * memory pressure required to trigger laundering decreases.
		 */
trybackground:
		nclean = vm_cnt.v_inactive_count + vm_cnt.v_free_count;
		ndirty = vm_cnt.v_laundry_count;
		if (target == 0 && inactq_scans != last_launder &&
		    ndirty * isqrt(inactq_scans - last_launder) >= nclean) {
			target = vm_background_launder_target;
		}

		/*
		 * We have a non-zero background laundering target.  If we've
		 * laundered up to our maximum without observing a page daemon
		 * request, just stop.  This is a safety belt that ensures we
		 * don't launder an excessive amount if memory pressure is low
		 * and the ratio of dirty to clean pages is large.  Otherwise,
		 * proceed at the background laundering rate.
		 */
		if (target > 0) {
			if (inactq_scans != last_launder) {
				last_launder = inactq_scans;
				last_target = target;
			} else if (last_target - target >=
			    vm_background_launder_max * PAGE_SIZE / 1024) {
				target = 0;
			}
			launder = vm_background_launder_rate * PAGE_SIZE / 1024;
			launder /= VM_LAUNDER_RATE;
			if (launder > target)
				launder = target;
		}

dolaundry:
		if (launder > 0) {
			/*
			 * Because of I/O clustering, the number of laundered
			 * pages could exceed "target" by the maximum size of
			 * a cluster minus one. 
			 */
			target -= min(vm_pageout_launder(domain, launder,
			    in_shortfall), target);
			pause("laundp", hz / VM_LAUNDER_RATE);
		}

		/*
		 * If we're not currently laundering pages and the page daemon
		 * hasn't posted a new request, sleep until the page daemon
		 * kicks us.
		 */
		vm_pagequeue_lock(pq);
		if (target == 0 && vm_laundry_request == VM_LAUNDRY_IDLE)
			(void)mtx_sleep(&vm_laundry_request,
			    vm_pagequeue_lockptr(pq), PVM, "launds", 0);

		/*
		 * If the pagedaemon has indicated that it's in shortfall, start
		 * a shortfall laundering unless we're already in the middle of
		 * one.  This may preempt a background laundering.
		 */
		if (vm_laundry_request == VM_LAUNDRY_SHORTFALL &&
		    (!in_shortfall || shortfall_cycle == 0)) {
			shortfall = vm_laundry_target() + vm_pageout_deficit;
			target = 0;
		} else
			shortfall = 0;

		if (target == 0)
			vm_laundry_request = VM_LAUNDRY_IDLE;
		inactq_scans = vm_inactq_scans;
		vm_pagequeue_unlock(pq);
	}
}

/*
 *	vm_pageout_scan does the dirty work for the pageout daemon.
 *
 *	pass == 0: Update active LRU/deactivate pages
 *	pass >= 1: Free inactive pages
 *
 * Returns true if pass was zero or enough pages were freed by the inactive
 * queue scan to meet the target.
 */
static bool
vm_pageout_scan(struct vm_domain *vmd, int pass)
{
	vm_page_t m, next;
	struct vm_pagequeue *pq;
	vm_object_t object;
	long min_scan;
	int act_delta, addl_page_shortage, deficit, inactq_shortage, maxscan;
	int page_shortage, scan_tick, scanned, starting_page_shortage;
	boolean_t queue_locked;

	/*
	 * If we need to reclaim memory ask kernel caches to return
	 * some.  We rate limit to avoid thrashing.
	 */
	if (vmd == &vm_dom[0] && pass > 0 &&
	    (time_uptime - lowmem_uptime) >= lowmem_period) {
		/*
		 * Decrease registered cache sizes.
		 */
		SDT_PROBE0(vm, , , vm__lowmem_scan);
		EVENTHANDLER_INVOKE(vm_lowmem, VM_LOW_PAGES);
		/*
		 * We do this explicitly after the caches have been
		 * drained above.
		 */
		uma_reclaim();
		lowmem_uptime = time_uptime;
	}

	/*
	 * The addl_page_shortage is the number of temporarily
	 * stuck pages in the inactive queue.  In other words, the
	 * number of pages from the inactive count that should be
	 * discounted in setting the target for the active queue scan.
	 */
	addl_page_shortage = 0;

	/*
	 * Calculate the number of pages that we want to free.  This number
	 * can be negative if many pages are freed between the wakeup call to
	 * the page daemon and this calculation.
	 */
	if (pass > 0) {
		deficit = atomic_readandclear_int(&vm_pageout_deficit);
		page_shortage = vm_paging_target() + deficit;
	} else
		page_shortage = deficit = 0;
	starting_page_shortage = page_shortage;

	/*
	 * Start scanning the inactive queue for pages that we can free.  The
	 * scan will stop when we reach the target or we have scanned the
	 * entire queue.  (Note that m->act_count is not used to make
	 * decisions for the inactive queue, only for the active queue.)
	 */
	pq = &vmd->vmd_pagequeues[PQ_INACTIVE];
	maxscan = pq->pq_cnt;
	vm_pagequeue_lock(pq);
	queue_locked = TRUE;
	for (m = TAILQ_FIRST(&pq->pq_pl);
	     m != NULL && maxscan-- > 0 && page_shortage > 0;
	     m = next) {
		vm_pagequeue_assert_locked(pq);
		KASSERT(queue_locked, ("unlocked inactive queue"));
		KASSERT(vm_page_inactive(m), ("Inactive queue %p", m));

		VM_CNT_INC(v_pdpages);
		next = TAILQ_NEXT(m, plinks.q);

		/*
		 * skip marker pages
		 */
		if (m->flags & PG_MARKER)
			continue;

		KASSERT((m->flags & PG_FICTITIOUS) == 0,
		    ("Fictitious page %p cannot be in inactive queue", m));
		KASSERT((m->oflags & VPO_UNMANAGED) == 0,
		    ("Unmanaged page %p cannot be in inactive queue", m));

		/*
		 * The page or object lock acquisitions fail if the
		 * page was removed from the queue or moved to a
		 * different position within the queue.  In either
		 * case, addl_page_shortage should not be incremented.
		 */
		if (!vm_pageout_page_lock(m, &next))
			goto unlock_page;
		else if (m->hold_count != 0) {
			/*
			 * Held pages are essentially stuck in the
			 * queue.  So, they ought to be discounted
			 * from the inactive count.  See the
			 * calculation of inactq_shortage before the
			 * loop over the active queue below.
			 */
			addl_page_shortage++;
			goto unlock_page;
		}
		object = m->object;
		if (!VM_OBJECT_TRYWLOCK(object)) {
			if (!vm_pageout_fallback_object_lock(m, &next))
				goto unlock_object;
			else if (m->hold_count != 0) {
				addl_page_shortage++;
				goto unlock_object;
			}
		}
		if (vm_page_busied(m)) {
			/*
			 * Don't mess with busy pages.  Leave them at
			 * the front of the queue.  Most likely, they
			 * are being paged out and will leave the
			 * queue shortly after the scan finishes.  So,
			 * they ought to be discounted from the
			 * inactive count.
			 */
			addl_page_shortage++;
unlock_object:
			VM_OBJECT_WUNLOCK(object);
unlock_page:
			vm_page_unlock(m);
			continue;
		}
		KASSERT(m->hold_count == 0, ("Held page %p", m));

		/*
		 * Dequeue the inactive page and unlock the inactive page
		 * queue, invalidating the 'next' pointer.  Dequeueing the
		 * page here avoids a later reacquisition (and release) of
		 * the inactive page queue lock when vm_page_activate(),
		 * vm_page_free(), or vm_page_launder() is called.  Use a
		 * marker to remember our place in the inactive queue.
		 */
		TAILQ_INSERT_AFTER(&pq->pq_pl, m, &vmd->vmd_marker, plinks.q);
		vm_page_dequeue_locked(m);
		vm_pagequeue_unlock(pq);
		queue_locked = FALSE;

		/*
		 * Invalid pages can be easily freed. They cannot be
		 * mapped, vm_page_free() asserts this.
		 */
		if (m->valid == 0)
			goto free_page;

		/*
		 * If the page has been referenced and the object is not dead,
		 * reactivate or requeue the page depending on whether the
		 * object is mapped.
		 */
		if ((m->aflags & PGA_REFERENCED) != 0) {
			vm_page_aflag_clear(m, PGA_REFERENCED);
			act_delta = 1;
		} else
			act_delta = 0;
		if (object->ref_count != 0) {
			act_delta += pmap_ts_referenced(m);
		} else {
			KASSERT(!pmap_page_is_mapped(m),
			    ("vm_pageout_scan: page %p is mapped", m));
		}
		if (act_delta != 0) {
			if (object->ref_count != 0) {
				VM_CNT_INC(v_reactivated);
				vm_page_activate(m);

				/*
				 * Increase the activation count if the page
				 * was referenced while in the inactive queue.
				 * This makes it less likely that the page will
				 * be returned prematurely to the inactive
				 * queue.
 				 */
				m->act_count += act_delta + ACT_ADVANCE;
				goto drop_page;
			} else if ((object->flags & OBJ_DEAD) == 0) {
				vm_pagequeue_lock(pq);
				queue_locked = TRUE;
				m->queue = PQ_INACTIVE;
				TAILQ_INSERT_TAIL(&pq->pq_pl, m, plinks.q);
				vm_pagequeue_cnt_inc(pq);
				goto drop_page;
			}
		}

		/*
		 * If the page appears to be clean at the machine-independent
		 * layer, then remove all of its mappings from the pmap in
		 * anticipation of freeing it.  If, however, any of the page's
		 * mappings allow write access, then the page may still be
		 * modified until the last of those mappings are removed.
		 */
		if (object->ref_count != 0) {
			vm_page_test_dirty(m);
			if (m->dirty == 0)
				pmap_remove_all(m);
		}

		/*
		 * Clean pages can be freed, but dirty pages must be sent back
		 * to the laundry, unless they belong to a dead object.
		 * Requeueing dirty pages from dead objects is pointless, as
		 * they are being paged out and freed by the thread that
		 * destroyed the object.
		 */
		if (m->dirty == 0) {
free_page:
			vm_page_free(m);
			VM_CNT_INC(v_dfree);
			--page_shortage;
		} else if ((object->flags & OBJ_DEAD) == 0)
			vm_page_launder(m);
drop_page:
		vm_page_unlock(m);
		VM_OBJECT_WUNLOCK(object);
		if (!queue_locked) {
			vm_pagequeue_lock(pq);
			queue_locked = TRUE;
		}
		next = TAILQ_NEXT(&vmd->vmd_marker, plinks.q);
		TAILQ_REMOVE(&pq->pq_pl, &vmd->vmd_marker, plinks.q);
	}
	vm_pagequeue_unlock(pq);

	/*
	 * Wake up the laundry thread so that it can perform any needed
	 * laundering.  If we didn't meet our target, we're in shortfall and
	 * need to launder more aggressively.  If PQ_LAUNDRY is empty and no
	 * swap devices are configured, the laundry thread has no work to do, so
	 * don't bother waking it up.
	 *
	 * The laundry thread uses the number of inactive queue scans elapsed
	 * since the last laundering to determine whether to launder again, so
	 * keep count.
	 */
	if (starting_page_shortage > 0) {
		pq = &vm_dom[0].vmd_pagequeues[PQ_LAUNDRY];
		vm_pagequeue_lock(pq);
		if (vm_laundry_request == VM_LAUNDRY_IDLE &&
		    (pq->pq_cnt > 0 || atomic_load_acq_int(&swapdev_enabled))) {
			if (page_shortage > 0) {
				vm_laundry_request = VM_LAUNDRY_SHORTFALL;
				VM_CNT_INC(v_pdshortfalls);
			} else if (vm_laundry_request != VM_LAUNDRY_SHORTFALL)
				vm_laundry_request = VM_LAUNDRY_BACKGROUND;
			wakeup(&vm_laundry_request);
		}
		vm_inactq_scans++;
		vm_pagequeue_unlock(pq);
	}

	/*
	 * Wakeup the swapout daemon if we didn't free the targeted number of
	 * pages.
	 */
	if (page_shortage > 0)
		vm_swapout_run();

	/*
	 * If the inactive queue scan fails repeatedly to meet its
	 * target, kill the largest process.
	 */
	vm_pageout_mightbe_oom(vmd, page_shortage, starting_page_shortage);

	/*
	 * Compute the number of pages we want to try to move from the
	 * active queue to either the inactive or laundry queue.
	 *
	 * When scanning active pages, we make clean pages count more heavily
	 * towards the page shortage than dirty pages.  This is because dirty
	 * pages must be laundered before they can be reused and thus have less
	 * utility when attempting to quickly alleviate a shortage.  However,
	 * this weighting also causes the scan to deactivate dirty pages more
	 * more aggressively, improving the effectiveness of clustering and
	 * ensuring that they can eventually be reused.
	 */
	inactq_shortage = vm_cnt.v_inactive_target - (vm_cnt.v_inactive_count +
	    vm_cnt.v_laundry_count / act_scan_laundry_weight) +
	    vm_paging_target() + deficit + addl_page_shortage;
	inactq_shortage *= act_scan_laundry_weight;

	pq = &vmd->vmd_pagequeues[PQ_ACTIVE];
	vm_pagequeue_lock(pq);
	maxscan = pq->pq_cnt;

	/*
	 * If we're just idle polling attempt to visit every
	 * active page within 'update_period' seconds.
	 */
	scan_tick = ticks;
	if (vm_pageout_update_period != 0) {
		min_scan = pq->pq_cnt;
		min_scan *= scan_tick - vmd->vmd_last_active_scan;
		min_scan /= hz * vm_pageout_update_period;
	} else
		min_scan = 0;
	if (min_scan > 0 || (inactq_shortage > 0 && maxscan > 0))
		vmd->vmd_last_active_scan = scan_tick;

	/*
	 * Scan the active queue for pages that can be deactivated.  Update
	 * the per-page activity counter and use it to identify deactivation
	 * candidates.  Held pages may be deactivated.
	 */
	for (m = TAILQ_FIRST(&pq->pq_pl), scanned = 0; m != NULL && (scanned <
	    min_scan || (inactq_shortage > 0 && scanned < maxscan)); m = next,
	    scanned++) {
		KASSERT(m->queue == PQ_ACTIVE,
		    ("vm_pageout_scan: page %p isn't active", m));
		next = TAILQ_NEXT(m, plinks.q);
		if ((m->flags & PG_MARKER) != 0)
			continue;
		KASSERT((m->flags & PG_FICTITIOUS) == 0,
		    ("Fictitious page %p cannot be in active queue", m));
		KASSERT((m->oflags & VPO_UNMANAGED) == 0,
		    ("Unmanaged page %p cannot be in active queue", m));
		if (!vm_pageout_page_lock(m, &next)) {
			vm_page_unlock(m);
			continue;
		}

		/*
		 * The count for page daemon pages is updated after checking
		 * the page for eligibility.
		 */
		VM_CNT_INC(v_pdpages);

		/*
		 * Check to see "how much" the page has been used.
		 */
		if ((m->aflags & PGA_REFERENCED) != 0) {
			vm_page_aflag_clear(m, PGA_REFERENCED);
			act_delta = 1;
		} else
			act_delta = 0;

		/*
		 * Perform an unsynchronized object ref count check.  While
		 * the page lock ensures that the page is not reallocated to
		 * another object, in particular, one with unmanaged mappings
		 * that cannot support pmap_ts_referenced(), two races are,
		 * nonetheless, possible:
		 * 1) The count was transitioning to zero, but we saw a non-
		 *    zero value.  pmap_ts_referenced() will return zero
		 *    because the page is not mapped.
		 * 2) The count was transitioning to one, but we saw zero. 
		 *    This race delays the detection of a new reference.  At
		 *    worst, we will deactivate and reactivate the page.
		 */
		if (m->object->ref_count != 0)
			act_delta += pmap_ts_referenced(m);

		/*
		 * Advance or decay the act_count based on recent usage.
		 */
		if (act_delta != 0) {
			m->act_count += ACT_ADVANCE + act_delta;
			if (m->act_count > ACT_MAX)
				m->act_count = ACT_MAX;
		} else
			m->act_count -= min(m->act_count, ACT_DECLINE);

		/*
		 * Move this page to the tail of the active, inactive or laundry
		 * queue depending on usage.
		 */
		if (m->act_count == 0) {
			/* Dequeue to avoid later lock recursion. */
			vm_page_dequeue_locked(m);

			/*
			 * When not short for inactive pages, let dirty pages go
			 * through the inactive queue before moving to the
			 * laundry queues.  This gives them some extra time to
			 * be reactivated, potentially avoiding an expensive
			 * pageout.  During a page shortage, the inactive queue
			 * is necessarily small, so we may move dirty pages
			 * directly to the laundry queue.
			 */
			if (inactq_shortage <= 0)
				vm_page_deactivate(m);
			else {
				/*
				 * Calling vm_page_test_dirty() here would
				 * require acquisition of the object's write
				 * lock.  However, during a page shortage,
				 * directing dirty pages into the laundry
				 * queue is only an optimization and not a
				 * requirement.  Therefore, we simply rely on
				 * the opportunistic updates to the page's
				 * dirty field by the pmap.
				 */
				if (m->dirty == 0) {
					vm_page_deactivate(m);
					inactq_shortage -=
					    act_scan_laundry_weight;
				} else {
					vm_page_launder(m);
					inactq_shortage--;
				}
			}
		} else
			vm_page_requeue_locked(m);
		vm_page_unlock(m);
	}
	vm_pagequeue_unlock(pq);
	if (pass > 0)
		vm_swapout_run_idle();
	return (page_shortage <= 0);
}

static int vm_pageout_oom_vote;

/*
 * The pagedaemon threads randlomly select one to perform the
 * OOM.  Trying to kill processes before all pagedaemons
 * failed to reach free target is premature.
 */
static void
vm_pageout_mightbe_oom(struct vm_domain *vmd, int page_shortage,
    int starting_page_shortage)
{
	int old_vote;

	if (starting_page_shortage <= 0 || starting_page_shortage !=
	    page_shortage)
		vmd->vmd_oom_seq = 0;
	else
		vmd->vmd_oom_seq++;
	if (vmd->vmd_oom_seq < vm_pageout_oom_seq) {
		if (vmd->vmd_oom) {
			vmd->vmd_oom = FALSE;
			atomic_subtract_int(&vm_pageout_oom_vote, 1);
		}
		return;
	}

	/*
	 * Do not follow the call sequence until OOM condition is
	 * cleared.
	 */
	vmd->vmd_oom_seq = 0;

	if (vmd->vmd_oom)
		return;

	vmd->vmd_oom = TRUE;
	old_vote = atomic_fetchadd_int(&vm_pageout_oom_vote, 1);
	if (old_vote != vm_ndomains - 1)
		return;

	/*
	 * The current pagedaemon thread is the last in the quorum to
	 * start OOM.  Initiate the selection and signaling of the
	 * victim.
	 */
	vm_pageout_oom(VM_OOM_MEM);

	/*
	 * After one round of OOM terror, recall our vote.  On the
	 * next pass, current pagedaemon would vote again if the low
	 * memory condition is still there, due to vmd_oom being
	 * false.
	 */
	vmd->vmd_oom = FALSE;
	atomic_subtract_int(&vm_pageout_oom_vote, 1);
}

/*
 * The OOM killer is the page daemon's action of last resort when
 * memory allocation requests have been stalled for a prolonged period
 * of time because it cannot reclaim memory.  This function computes
 * the approximate number of physical pages that could be reclaimed if
 * the specified address space is destroyed.
 *
 * Private, anonymous memory owned by the address space is the
 * principal resource that we expect to recover after an OOM kill.
 * Since the physical pages mapped by the address space's COW entries
 * are typically shared pages, they are unlikely to be released and so
 * they are not counted.
 *
 * To get to the point where the page daemon runs the OOM killer, its
 * efforts to write-back vnode-backed pages may have stalled.  This
 * could be caused by a memory allocation deadlock in the write path
 * that might be resolved by an OOM kill.  Therefore, physical pages
 * belonging to vnode-backed objects are counted, because they might
 * be freed without being written out first if the address space holds
 * the last reference to an unlinked vnode.
 *
 * Similarly, physical pages belonging to OBJT_PHYS objects are
 * counted because the address space might hold the last reference to
 * the object.
 */
static long
vm_pageout_oom_pagecount(struct vmspace *vmspace)
{
	vm_map_t map;
	vm_map_entry_t entry;
	vm_object_t obj;
	long res;

	map = &vmspace->vm_map;
	KASSERT(!map->system_map, ("system map"));
	sx_assert(&map->lock, SA_LOCKED);
	res = 0;
	for (entry = map->header.next; entry != &map->header;
	    entry = entry->next) {
		if ((entry->eflags & MAP_ENTRY_IS_SUB_MAP) != 0)
			continue;
		obj = entry->object.vm_object;
		if (obj == NULL)
			continue;
		if ((entry->eflags & MAP_ENTRY_NEEDS_COPY) != 0 &&
		    obj->ref_count != 1)
			continue;
		switch (obj->type) {
		case OBJT_DEFAULT:
		case OBJT_SWAP:
		case OBJT_PHYS:
		case OBJT_VNODE:
			res += obj->resident_page_count;
			break;
		}
	}
	return (res);
}

void
vm_pageout_oom(int shortage)
{
	struct proc *p, *bigproc;
	vm_offset_t size, bigsize;
	struct thread *td;
	struct vmspace *vm;
	bool breakout;

	/*
	 * We keep the process bigproc locked once we find it to keep anyone
	 * from messing with it; however, there is a possibility of
	 * deadlock if process B is bigproc and one of its child processes
	 * attempts to propagate a signal to B while we are waiting for A's
	 * lock while walking this list.  To avoid this, we don't block on
	 * the process lock but just skip a process if it is already locked.
	 */
	bigproc = NULL;
	bigsize = 0;
	sx_slock(&allproc_lock);
	FOREACH_PROC_IN_SYSTEM(p) {
		PROC_LOCK(p);

		/*
		 * If this is a system, protected or killed process, skip it.
		 */
		if (p->p_state != PRS_NORMAL || (p->p_flag & (P_INEXEC |
		    P_PROTECTED | P_SYSTEM | P_WEXIT)) != 0 ||
		    p->p_pid == 1 || P_KILLED(p) ||
		    (p->p_pid < 48 && swap_pager_avail != 0)) {
			PROC_UNLOCK(p);
			continue;
		}
		/*
		 * If the process is in a non-running type state,
		 * don't touch it.  Check all the threads individually.
		 */
		breakout = false;
		FOREACH_THREAD_IN_PROC(p, td) {
			thread_lock(td);
			if (!TD_ON_RUNQ(td) &&
			    !TD_IS_RUNNING(td) &&
			    !TD_IS_SLEEPING(td) &&
			    !TD_IS_SUSPENDED(td) &&
			    !TD_IS_SWAPPED(td)) {
				thread_unlock(td);
				breakout = true;
				break;
			}
			thread_unlock(td);
		}
		if (breakout) {
			PROC_UNLOCK(p);
			continue;
		}
		/*
		 * get the process size
		 */
		vm = vmspace_acquire_ref(p);
		if (vm == NULL) {
			PROC_UNLOCK(p);
			continue;
		}
		_PHOLD_LITE(p);
		PROC_UNLOCK(p);
		sx_sunlock(&allproc_lock);
		if (!vm_map_trylock_read(&vm->vm_map)) {
			vmspace_free(vm);
			sx_slock(&allproc_lock);
			PRELE(p);
			continue;
		}
		size = vmspace_swap_count(vm);
		if (shortage == VM_OOM_MEM)
			size += vm_pageout_oom_pagecount(vm);
		vm_map_unlock_read(&vm->vm_map);
		vmspace_free(vm);
		sx_slock(&allproc_lock);

		/*
		 * If this process is bigger than the biggest one,
		 * remember it.
		 */
		if (size > bigsize) {
			if (bigproc != NULL)
				PRELE(bigproc);
			bigproc = p;
			bigsize = size;
		} else {
			PRELE(p);
		}
	}
	sx_sunlock(&allproc_lock);
	if (bigproc != NULL) {
		if (vm_panic_on_oom != 0)
			panic("out of swap space");
		PROC_LOCK(bigproc);
		killproc(bigproc, "out of swap space");
		sched_nice(bigproc, PRIO_MIN);
		_PRELE(bigproc);
		PROC_UNLOCK(bigproc);
		wakeup(&vm_cnt.v_free_count);
	}
}

static void
vm_pageout_worker(void *arg)
{
	struct vm_domain *domain;
	int domidx, pass;
	bool target_met;

	domidx = (uintptr_t)arg;
	domain = &vm_dom[domidx];
	pass = 0;
	target_met = true;

	/*
	 * XXXKIB It could be useful to bind pageout daemon threads to
	 * the cores belonging to the domain, from which vm_page_array
	 * is allocated.
	 */

	KASSERT(domain->vmd_segs != 0, ("domain without segments"));
	domain->vmd_last_active_scan = ticks;
	vm_pageout_init_marker(&domain->vmd_marker, PQ_INACTIVE);
	vm_pageout_init_marker(&domain->vmd_inacthead, PQ_INACTIVE);
	TAILQ_INSERT_HEAD(&domain->vmd_pagequeues[PQ_INACTIVE].pq_pl,
	    &domain->vmd_inacthead, plinks.q);

	/*
	 * The pageout daemon worker is never done, so loop forever.
	 */
	while (TRUE) {
		mtx_lock(&vm_page_queue_free_mtx);

		/*
		 * Generally, after a level >= 1 scan, if there are enough
		 * free pages to wakeup the waiters, then they are already
		 * awake.  A call to vm_page_free() during the scan awakened
		 * them.  However, in the following case, this wakeup serves
		 * to bound the amount of time that a thread might wait.
		 * Suppose a thread's call to vm_page_alloc() fails, but
		 * before that thread calls VM_WAIT, enough pages are freed by
		 * other threads to alleviate the free page shortage.  The
		 * thread will, nonetheless, wait until another page is freed
		 * or this wakeup is performed.
		 */
		if (vm_pages_needed && !vm_page_count_min()) {
			vm_pages_needed = false;
			wakeup(&vm_cnt.v_free_count);
		}

		/*
		 * Do not clear vm_pageout_wanted until we reach our free page
		 * target.  Otherwise, we may be awakened over and over again,
		 * wasting CPU time.
		 */
		if (vm_pageout_wanted && target_met)
			vm_pageout_wanted = false;

		/*
		 * Might the page daemon receive a wakeup call?
		 */
		if (vm_pageout_wanted) {
			/*
			 * No.  Either vm_pageout_wanted was set by another
			 * thread during the previous scan, which must have
			 * been a level 0 scan, or vm_pageout_wanted was
			 * already set and the scan failed to free enough
			 * pages.  If we haven't yet performed a level >= 1
			 * (page reclamation) scan, then increase the level
			 * and scan again now.  Otherwise, sleep a bit and
			 * try again later.
			 */
			mtx_unlock(&vm_page_queue_free_mtx);
			if (pass >= 1)
				pause("pwait", hz / VM_INACT_SCAN_RATE);
			pass++;
		} else {
			/*
			 * Yes.  If threads are still sleeping in VM_WAIT
			 * then we immediately start a new scan.  Otherwise,
			 * sleep until the next wakeup or until pages need to
			 * have their reference stats updated.
			 */
			if (vm_pages_needed) {
				mtx_unlock(&vm_page_queue_free_mtx);
				if (pass == 0)
					pass++;
			} else if (mtx_sleep(&vm_pageout_wanted,
			    &vm_page_queue_free_mtx, PDROP | PVM, "psleep",
			    hz) == 0) {
				VM_CNT_INC(v_pdwakeups);
				pass = 1;
			} else
				pass = 0;
		}

		target_met = vm_pageout_scan(domain, pass);
	}
}

/*
 *	vm_pageout_init initialises basic pageout daemon settings.
 */
static void
vm_pageout_init(void)
{
	/*
	 * Initialize some paging parameters.
	 */
	vm_cnt.v_interrupt_free_min = 2;
	if (vm_cnt.v_page_count < 2000)
		vm_pageout_page_count = 8;

	/*
	 * v_free_reserved needs to include enough for the largest
	 * swap pager structures plus enough for any pv_entry structs
	 * when paging. 
	 */
	if (vm_cnt.v_page_count > 1024)
		vm_cnt.v_free_min = 4 + (vm_cnt.v_page_count - 1024) / 200;
	else
		vm_cnt.v_free_min = 4;
	vm_cnt.v_pageout_free_min = (2*MAXBSIZE)/PAGE_SIZE +
	    vm_cnt.v_interrupt_free_min;
	vm_cnt.v_free_reserved = vm_pageout_page_count +
	    vm_cnt.v_pageout_free_min + (vm_cnt.v_page_count / 768);
	vm_cnt.v_free_severe = vm_cnt.v_free_min / 2;
	vm_cnt.v_free_target = 4 * vm_cnt.v_free_min + vm_cnt.v_free_reserved;
	vm_cnt.v_free_min += vm_cnt.v_free_reserved;
	vm_cnt.v_free_severe += vm_cnt.v_free_reserved;
	vm_cnt.v_inactive_target = (3 * vm_cnt.v_free_target) / 2;
	if (vm_cnt.v_inactive_target > vm_cnt.v_free_count / 3)
		vm_cnt.v_inactive_target = vm_cnt.v_free_count / 3;

	/*
	 * Set the default wakeup threshold to be 10% above the minimum
	 * page limit.  This keeps the steady state out of shortfall.
	 */
	vm_pageout_wakeup_thresh = (vm_cnt.v_free_min / 10) * 11;

	/*
	 * Set interval in seconds for active scan.  We want to visit each
	 * page at least once every ten minutes.  This is to prevent worst
	 * case paging behaviors with stale active LRU.
	 */
	if (vm_pageout_update_period == 0)
		vm_pageout_update_period = 600;

	/* XXX does not really belong here */
	if (vm_page_max_wired == 0)
		vm_page_max_wired = vm_cnt.v_free_count / 3;

	/*
	 * Target amount of memory to move out of the laundry queue during a
	 * background laundering.  This is proportional to the amount of system
	 * memory.
	 */
	vm_background_launder_target = (vm_cnt.v_free_target -
	    vm_cnt.v_free_min) / 10;
}

/*
 *     vm_pageout is the high level pageout daemon.
 */
static void
vm_pageout(void)
{
	int error;
	int i;

	swap_pager_swap_init();
	error = kthread_add(vm_pageout_laundry_worker, NULL, curproc, NULL,
	    0, 0, "laundry: dom0");
	if (error != 0)
		panic("starting laundry for domain 0, error %d", error);
	for (i = 1; i < vm_ndomains; i++) {
		error = kthread_add(vm_pageout_worker, (void *)(uintptr_t)i,
		    curproc, NULL, 0, 0, "dom%d", i);
		if (error != 0) {
			panic("starting pageout for domain %d, error %d\n",
			    i, error);
		}
	}
	error = kthread_add(uma_reclaim_worker, NULL, curproc, NULL,
	    0, 0, "uma");
	if (error != 0)
		panic("starting uma_reclaim helper, error %d\n", error);
	vm_pageout_worker((void *)(uintptr_t)0);
}

/*
 * Perform an advisory wakeup of the page daemon.
 */
void
pagedaemon_wakeup(void)
{

	mtx_assert(&vm_page_queue_free_mtx, MA_NOTOWNED);

	if (!vm_pageout_wanted && curthread->td_proc != pageproc) {
		vm_pageout_wanted = true;
		wakeup(&vm_pageout_wanted);
	}
}

/*
 * Wake up the page daemon and wait for it to reclaim free pages.
 *
 * This function returns with the free queues mutex unlocked.
 */
void
pagedaemon_wait(int pri, const char *wmesg)
{

	mtx_assert(&vm_page_queue_free_mtx, MA_OWNED);

	/*
	 * vm_pageout_wanted may have been set by an advisory wakeup, but if the
	 * page daemon is running on a CPU, the wakeup will have been lost.
	 * Thus, deliver a potentially spurious wakeup to ensure that the page
	 * daemon has been notified of the shortage.
	 */
	if (!vm_pageout_wanted || !vm_pages_needed) {
		vm_pageout_wanted = true;
		wakeup(&vm_pageout_wanted);
	}
	vm_pages_needed = true;
	msleep(&vm_cnt.v_free_count, &vm_page_queue_free_mtx, PDROP | pri,
	    wmesg, 0);
}
