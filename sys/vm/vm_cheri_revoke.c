#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_vm.h"
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/sched.h>
#include <sys/sysent.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_extern.h>
#include <vm/vm_page.h>

#include <cheri/cheric.h>
#include <cheri/revoke.h>
#include <cheri/revoke_kern.h>
#include <vm/vm_cheri_revoke.h>

// XXX This is very much a work in progress!

/***************************** PAGE VISITS ******************************/

static inline int
vm_cheri_revoke_should_visit_page(vm_page_t m, int flags)
{
	vm_page_astate_t mas = vm_page_astate_load(m);

	/*
	 * If a page is capdirty, visit this page.  On incremental passes,
	 * this should catch a superset of the pages we need to visit.
	 */
	if (mas.flags & PGA_CAPDIRTY)
		return 1;

	/*
	 * If this is an incremental scan, we only care about
	 * recently-capdirty pages, so can stop here.
	 */
	if (flags & VM_CHERI_REVOKE_INCREMENTAL)
		return 0;

	/*
	 * On the other hand, for full scans, we want to visit all pages
	 * that may have had capabilities, not just recently.
	 */
	if (mas.flags & PGA_CAPSTORE)
		return 1;

	return 0;
}

enum vm_cro_visit {
	VM_CHERI_REVOKE_VIS_DONE  = 0,
	VM_CHERI_REVOKE_VIS_DIRTY = 1,
};

/*
 * Given a writable, xbusy page, visit it as part of the background scan, RW.
 */
static void
vm_cheri_revoke_visit_rw(
    const struct vm_cheri_revoke_cookie *crc, int flags, vm_page_t m, bool *cap)
{
	int hascaps;
	CHERI_REVOKE_STATS_FOR(crst, crc);

	CHERI_REVOKE_STATS_BUMP(crst, pages_scan_rw);

	/*
	 * In the Cornucopia story, we want to consider the page no longer dirty
	 * just before we visit it.  We're interlocked against ourselves here,
	 * in that there's just one revoker thread either running concurrently
	 * or with the world stopped, so there's no risk of two of us getting
	 * confused.
	 *
	 * In the load-side story, that's less true.  If there were just one
	 * revoker and just one alias of this page, we could safely consume
	 * PGA_CAPDIRTY before scanning the page: any racing store would cause
	 * the PTE to become capdirty and any reclaim would push that back up to
	 * PGA_CAPDIRTY.  Because there are aliases, though, we risk racing CLG
	 * faults through this or another PTE (which, recall, merely wire, and
	 * not xbusy the page under study).  In particular, if CLG faults could
	 * transition to IDLE, we would risk this race:
	 *
	 *   T1                   T2                         T3
	 *   --------------------|--------------------------|----------------
	 *                        wire m for CLG
	 *                        visit page, see no caps
	 *   hold m for bg scan
	 *                                                   create new PTE
	 *   xbusy
	 *                                                   write a cap to m
	 *                                                   evict PTE, set
	 *                                                    PGA_CAPDIRTY
	 *   clear PGA_CAPDIRTY
	 *                        observe all PTEs clean,
	 *                         and PGA_CAPDIRTY zero:
	 *                          move to IDLE!
	 *   visit, see cap
	 *   bounce off PTE CLG
	 *   xunbusy
	 *
	 * At this point we would have an IDLE page bearing a capability.  But
	 * there are two ways around this: we could accept the transient of an
	 * IDLE xbusy page as a kind of "not really IDLE" state and have the
	 * background revoker put it back (by re-asserting PGA_CAPSTORE), or we
	 * could restrict the transition to IDLE to the background scan.  We
	 * choose the latter for the moment.  Thus, even though the CLG faults
	 * might see a zero for PGA_CAPDIRTY where they shouldn't, nothing
	 * fundamentally depends on that result, so it's fine.  (XXX yes?)
	 */
	vm_page_aflag_clear(m, PGA_CAPDIRTY);

	hascaps = vm_cheri_revoke_page_rw(crc, m);

	if (hascaps & VM_CHERI_REVOKE_PAGE_DIRTY) {
		/*
		 * Load-side visits might see new capabilities being written
		 * concurrently, but by construction any such must have already
		 * been scanned for revocation.  Exposing this capdirtiness to
		 * the MI layer is too cheap to worry about.
		 *
		 * Store-side visits might see new caps during the concurrent
		 * phase and these pages need to be revisited.  Hopefully the
		 * PTE is capdirty in such a scenario, but it does't hurt to
		 * promote the dirtiness to the MI layer here.  During the
		 * world-stopped phase, we shouldn't be seeing new
		 * capabilities...  But, because it's possible that userspace
		 * has aliased pages across address spaces and this whole
		 * revocation thing mooted, we don't assert here lest userspace
		 * be able to panic the kernel.
		 */
		vm_page_capdirty(m);
	}

	*cap = !!(hascaps & VM_CHERI_REVOKE_PAGE_HASCAPS);
}

/*
 * The same thing, but for a *readable*, wired page.  The page is not busied
 * herein and there's no need for the caller to hold it busy either; the page's
 * vm_object should be unlocked prior to calling.
 *
 * Returns VIS_DIRTY if the page must be visited read-write, or VIS_DONE if it
 * is clear to advance and carry on.
 */
static enum vm_cro_visit
vm_cheri_revoke_visit_ro(
    const struct vm_cheri_revoke_cookie *crc, int flags, vm_page_t m, bool *cap)
{
	CHERI_REVOKE_STATS_FOR(crst, crc);
	int hascaps;

#ifdef INVARIANTS
	vm_page_astate_t mas = vm_page_astate_load(m);
#endif

	CHERI_REVOKE_STATS_BUMP(crst, pages_scan_ro);

	/*
	 * As above, it's safe to clear this flag here on either the load or
	 * store side, regardless of aliasing.  On the store side, we don't
	 * need to visit this page again and on the load side we won't IDLE the
	 * page in any racing CLG fault handler.
	 */
	vm_page_aflag_clear(m, PGA_CAPDIRTY);
	hascaps = vm_cheri_revoke_page_ro(crc, m);

	KASSERT(!(hascaps & VM_CHERI_REVOKE_PAGE_HASCAPS) ||
		((mas.flags & PGA_CAPSTORE) || (mas.flags & PGA_CAPDIRTY)),
	    ("cap-bearing RO page without h/r capdirty?"
	     " hc=%x m=%p, m->of=%x, m->af=%x",
		hascaps, m, m->oflags, vm_page_astate_load(m).flags));

	if (hascaps & VM_CHERI_REVOKE_PAGE_DIRTY) {
		return VM_CHERI_REVOKE_VIS_DIRTY;
	}

	*cap = !!(hascaps & VM_CHERI_REVOKE_PAGE_HASCAPS);
	return VM_CHERI_REVOKE_VIS_DONE;
}

enum vm_cheri_revoke_fault_res
vm_cheri_revoke_fault_visit(struct vmspace *uvms, vm_offset_t va)
{
#ifdef CHERI_CAPREVOKE_STATS
	uint64_t cyc_start = get_cyclecount();
#endif
	enum vm_cheri_revoke_fault_res res;
	enum pmap_caploadgen_res pres;
	int vres;
	struct vm_cheri_revoke_cookie crc;
	vm_page_t m = NULL;
	bool hascap = false;
	bool xbusied = false;

	/*
	 * Since faults may be spurious, avoid looking at VM data structures
	 * unless we have to.  This seems wrong, somehow. XXX
	 */
	bool hascookie = false;

	pmap_t upmap = vmspace_pmap(uvms);

again:
	pres = pmap_caploadgen_update(upmap, va, &m,
	    PMAP_CAPLOADGEN_UPDATETLB
	    | (xbusied ? PMAP_CAPLOADGEN_XBUSIED : 0)
	    | (hascap ? PMAP_CAPLOADGEN_HASCAPS : 0));

	switch (pres) {
	case PMAP_CAPLOADGEN_OK:
	case PMAP_CAPLOADGEN_ALREADY:
	case PMAP_CAPLOADGEN_CLEAN:
		res = VM_CHERI_REVOKE_FAULT_RESOLVED;
		goto out;

	case PMAP_CAPLOADGEN_UNABLE:
	case PMAP_CAPLOADGEN_TEARDOWN:
		res = VM_CHERI_REVOKE_FAULT_UNRESOLVED;
		goto out;

	case PMAP_CAPLOADGEN_SCAN_RO_WIRED:
		xbusied = false;
		break;

	case PMAP_CAPLOADGEN_SCAN_RO_XBUSIED:
	case PMAP_CAPLOADGEN_SCAN_RW_XBUSIED:
		xbusied = true;
		break;

	default:
		panic("Bad pmap_caploadgen_fault_user return");
	}

	if (!hascookie) {
		vres = vm_cheri_revoke_cookie_init(&uvms->vm_map, &crc);
		KASSERT(vres == 0,
		    ("vm_cheri_revoke_cooke_init failure in fault_visit"));
		hascookie = true;
	}

	/*
	 * The following cases have the page wired so we can inspect it.  It's
	 * therefore important that we always end with "goto again" (which drops
	 * the wiring) or that we call vm_page_unwire() ourselves.  The page's
	 * identity is not stable across the scan, but because it is wired we
	 * know it won't be repurposed (through pageout or laundry), but it may
	 * be removed from the pmap where we were looking.
	 */
	switch (pres) {
	default:
		panic("impossible");

	case PMAP_CAPLOADGEN_SCAN_RO_WIRED:
	case PMAP_CAPLOADGEN_SCAN_RO_XBUSIED:
		vres = vm_cheri_revoke_page_ro(&crc, m);
		if (vres & VM_CHERI_REVOKE_PAGE_DIRTY) {
			/*
			 * Need to write but can't to current mapping.  We can't
			 * use PGA_WRITEABLE because the page isn't busy, just
			 * wired down.  Fall out and synchronize with the VM.
			 */
			if (xbusied) {
				vm_page_xunbusy(m);
			} else {
				vm_page_unwire(m, PQ_ACTIVE);
			}
			res = VM_CHERI_REVOKE_FAULT_CAPSTORE;
			goto out;
		}
		hascap = vres & VM_CHERI_REVOKE_PAGE_HASCAPS;
		break;

	case PMAP_CAPLOADGEN_SCAN_RW_XBUSIED:
		vres = vm_cheri_revoke_page_rw(&crc, m);

		/*
		 * Discard VM_CHERI_REVOKE_PAGE_DIRTY: losing a load-side CAS
		 * race is perfectly fine, as anything stored over top of it
		 * must have already been checked.
		 */

		hascap = vres & VM_CHERI_REVOKE_PAGE_HASCAPS;
		break;
	}

	goto again;

out:

#ifdef CHERI_CAPREVOKE_STATS
	/*
	 * This might, very rarely, get credited to the next epoch, if we have
	 * raced the close. (XXX?)
	 */

	if (!hascookie) {
		vres = vm_cheri_revoke_cookie_init(&uvms->vm_map, &crc);
		KASSERT(vres == 0,
		    ("vm_caprevoke_cooke_init failure in fault_visit"));
		hascookie = true;
	}

	
	uint64_t cyc_end = get_cyclecount();
	sx_slock(&uvms->vm_map.vm_cheri_revoke_stats_sx);
	{
		CHERI_REVOKE_STATS_FOR(crst, &crc);
		CHERI_REVOKE_STATS_BUMP(crst, fault_visits);
		CHERI_REVOKE_STATS_INC(crst, fault_cycles, cyc_end - cyc_start);
	}
	sx_sunlock(&uvms->vm_map.vm_cheri_revoke_stats_sx);
#endif

	if (hascookie)
		vm_cheri_revoke_cookie_rele(&crc);

	return res;
}

/******************************* VM ITERATION *******************************/

static bool cheri_revoke_avoid_faults = 1;
SYSCTL_BOOL(_vm, OID_AUTO, cheri_revoke_avoid_faults, CTLFLAG_RW,
    &cheri_revoke_avoid_faults, 0,
    "XXX");

enum vm_cro_at {
	VM_CHERI_REVOKE_AT_OK    = 0,
	VM_CHERI_REVOKE_AT_TICK  = 1,
	VM_CHERI_REVOKE_AT_VMERR = 2
};

/*
 * Given a map, map entry, and page index within that entry, visit that page
 * for revocation.  The entry must have an object.
 *
 * The map must be read-locked on entry and will be read-locked on return,
 * but this lock may be dropped in the interim.
 *
 * The entry's object must be wlocked on entry and will be returned
 * wlocked on success and unlocked on failure.  Even on success, the lock
 * may have been dropped and reacquired.
 *
 * On success, *ooff will be updated to the next offset to probe (which may
 * be past the end of the object; the caller should test).  This next offset
 * may equal ioff if the world has shifted; this is probably fine as the
 * caller should just repeat the call.  On failure, *ooff will not be modified.
 */
static enum vm_cro_at
vm_cheri_revoke_object_at(const struct vm_cheri_revoke_cookie *crc, int flags,
    vm_map_entry_t entry, vm_offset_t ioff, vm_offset_t *ooff, int *vmres)
{
#ifdef INVARIANTS
	vm_page_astate_t mas;
#endif
	CHERI_REVOKE_STATS_FOR(crst, crc);
	vm_map_t map = crc->map;
	vm_object_t obj = entry->object.vm_object;
	vm_pindex_t ipi = OFF_TO_IDX(ioff);
	vm_offset_t addr = ioff - entry->offset + entry->start;
	vm_page_t m = NULL;
	bool mwired = false;
	bool mxbusy = false;
	bool mdidvm = false;
	bool viscap = false;

	VM_OBJECT_ASSERT_WLOCKED(obj);

	/*
	 * If we're on the load side, we can ask the pmap to help us out.  This
	 * will have one of the following outcomes:
	 *
	 *  * fast out if LCLG == GCLG (PMAP_CAPLOADGEN_ALREADY, i.e., if this
	 *    mapping has already been visited by vm_cheri_revoke_fault_visit)
	 *    or if m->a.flags has PGA_CAPSTORE clear (PMAP_CAPLOADGEN_CLEAN).
	 *
	 *  * returning an xbusied writeable page
	 *
	 *  * returning a wired page that may be either RO or RW but that we
	 *    must scan as if it were RO, falling back to vm_fault() if we must
	 *    mutate it.
	 *
	 *  * slow out if neither of the above are possible, triggering
	 *    immediate fallback to the VM (vm_page_grab_valid or vm_fault).
	 *
	 */
	if (flags & VM_CHERI_REVOKE_LOAD_SIDE) {
		int pmres;

		pmres = pmap_caploadgen_update(crc->map->pmap, addr, &m, 0);

		switch (pmres) {
		default:
		case PMAP_CAPLOADGEN_OK:
		case PMAP_CAPLOADGEN_TEARDOWN:
			panic("Bad first return from pmap_caploadgen_update");

		case PMAP_CAPLOADGEN_ALREADY:
		case PMAP_CAPLOADGEN_CLEAN:
			*ooff = ioff + PAGE_SIZE;
			return VM_CHERI_REVOKE_AT_OK;

		case PMAP_CAPLOADGEN_UNABLE:
			/*
			 * Fall back to VM lookup.  We either could not resolve
			 * the page at this address (perhaps because there isn't
			 * one) or we couldn't wire something being torn down.
			 *
			 * XXX In some eventuality it might be nice to have the
			 * pmap able to definitely answer "there isn't a page
			 * here even if you go ask the VM", a sort of analogy
			 * to skipping to the next VM map entry.
			 */
			break;

		case PMAP_CAPLOADGEN_SCAN_RO_WIRED:
			VM_OBJECT_WUNLOCK(obj);
			mwired = true;
			goto visit_ro;

		case PMAP_CAPLOADGEN_SCAN_RO_XBUSIED:
			VM_OBJECT_WUNLOCK(obj);
			mxbusy = true;
			goto visit_ro;

		case PMAP_CAPLOADGEN_SCAN_RW_XBUSIED:
			VM_OBJECT_WUNLOCK(obj);
			mxbusy = true;
			goto visit_rw;
		}
	}
	// XXX else pmap_extract_and_hold?

	KASSERT(m == NULL, ("Load side bad state arc"));
	/*
	 * Try to grab the page out of the VM, walking the shadow chain to find
	 * the source of CoW, if any.  Do not materialize a (CoW or otherwise)
	 * zero page that isn't already in some object.
	 *
	 * This routine internally xbusies the page regardless of what we ask,
	 * so it's quite natural to let it return the page to us in that state,
	 * as if we had gotten SCAN_R[OW]_XBUSIED above.
	 */
	/*
	 * XXXMJ as VM_ALLOC_NOZERO is currently implemented, this can return an
	 * invalid page, and in this case we fail to check the shadow chain.
	 *
	 * XXXNWF 20220802 is that still true?
	 */
	(void)vm_page_grab_valid(&m, obj, ipi, VM_ALLOC_NOZERO);

	if (m == NULL) {
		if (flags & VM_CHERI_REVOKE_QUICK_SUCCESSOR) {
			/* Look forward in the object's collection of pages */
			vm_page_t obj_next_pg = vm_page_find_least(obj, ipi);

			vm_offset_t lastoff =
			    entry->end - entry->start + entry->offset;

			if ((obj_next_pg == NULL) ||
			    (obj_next_pg->pindex >= OFF_TO_IDX(lastoff))) {
				CHERI_REVOKE_STATS_INC(crst, pages_skip_fast,
				    (entry->end - addr) >> PAGE_SHIFT);
				*ooff = lastoff;
			} else {
				KASSERT(obj_next_pg->object == obj,
				    ("Fast find page in bad object?"));

				*ooff = IDX_TO_OFF(obj_next_pg->pindex);
				CHERI_REVOKE_STATS_INC(crst, pages_skip_fast,
				    obj_next_pg->pindex - ipi);
			}
			return VM_CHERI_REVOKE_AT_OK;
		}

		CHERI_REVOKE_STATS_BUMP(crst, pages_faulted_ro);

		int res;
		unsigned int last_timestamp = map->timestamp;

		VM_OBJECT_WUNLOCK(obj);

		vm_map_unlock_read(map);
		res = vm_fault(map, addr, VM_PROT_READ | VM_PROT_READ_CAP,
		    VM_FAULT_NOFILL, &m);
		vm_map_lock_read(map);

		if (res == KERN_PAGE_NOT_FILLED) {
			/*
			 * NOFILL did its thing, and, as far as we know, there
			 * is no pmap entry to update.  Just get out of here.
			 */
			CHERI_REVOKE_STATS_BUMP(crst, pages_skip_nofill);
			*ooff = ioff + PAGE_SIZE;
			VM_OBJECT_WLOCK(obj);
			return VM_CHERI_REVOKE_AT_OK;
		}
		if (res != KERN_SUCCESS) {
			*vmres = res;
			return VM_CHERI_REVOKE_AT_VMERR;
		}
		if (last_timestamp != map->timestamp) {
			/*
			 * The map has changed out from under us; bail and
			 * the caller will look up the new map entry.
			 */
			return VM_CHERI_REVOKE_AT_TICK;
		}

		/*
		 * vm_fault will have scanned this page for us, so we're good
		 * to jump out.  The pmap will have been updated by vm_fault.
		 */
		mdidvm = true;
		mwired = true;
		goto ok;
	}

	KASSERT(m->object == obj, ("Page lookup bad object?"));
	mxbusy = true;
	VM_OBJECT_WUNLOCK(obj);

	if (!vm_cheri_revoke_should_visit_page(m, flags)) {
		CHERI_REVOKE_STATS_BUMP(crst, pages_skip);
		goto ok;
	}

	/*
	 * Because we hold the page xbusy, we can let PGA_WRITEABLE tell us if
	 * there are any writeable mappings, and so the page is OK to mutate,
	 * or not.
	 */
	if (pmap_page_is_write_mapped(m)) {
visit_rw:
		KASSERT(vm_page_all_valid(m), ("Page grab valid invalid?"));
		vm_page_assert_xbusied(m);

		if (m->object == obj) {
			/* Visit the page RW in place */
			vm_cheri_revoke_visit_rw(crc, flags, m, &viscap);
			goto ok;
		}

		/*
		 * The page may have changed identity while we were xbusying it
		 * and in that case; something funny is going on, so just bail
		 * out to the fault path.
		 */
		goto visit_rw_fault;
	}

visit_ro:
	KASSERT(mxbusy || mwired, ("RO visit !busy !wired?"));

	switch (vm_cheri_revoke_visit_ro(crc, flags, m, &viscap)) {
	case VM_CHERI_REVOKE_VIS_DONE:
		/* We were able to conclude that the page was clean while RO*/
		goto ok;
	case VM_CHERI_REVOKE_VIS_DIRTY:
		/* Dirty here means we need to upgrade to RW now */
		break;
	default:
		panic("bad result from vm_cheri_revoke_visit_ro");
	}

visit_rw_fault:
	CHERI_REVOKE_STATS_BUMP(crst, pages_faulted_rw);

	int res;
	unsigned int last_timestamp = map->timestamp;

	if (mwired) {
		mwired = false;
		vm_page_unwire_in_situ(m);
	}
	if (mxbusy) {
		mxbusy = false;
		vm_page_xunbusy(m);
	}

	vm_map_unlock_read(map);
	VM_OBJECT_ASSERT_UNLOCKED(obj);
	m = NULL;

	res = vm_fault(map, addr, VM_PROT_WRITE | VM_PROT_WRITE_CAP,
	    VM_FAULT_NORMAL, &m);
	vm_map_lock_read(map);
	if (res != KERN_SUCCESS) {
		*vmres = res;
		VM_OBJECT_ASSERT_UNLOCKED(obj);
		return VM_CHERI_REVOKE_AT_VMERR;
	}
	if (last_timestamp != map->timestamp) {
		vm_page_unwire(m, PQ_INACTIVE);
		VM_OBJECT_ASSERT_UNLOCKED(obj);
		return VM_CHERI_REVOKE_AT_TICK;
	}

	mwired = true;
	mdidvm = true;

ok:
	VM_OBJECT_ASSERT_UNLOCKED(obj);
	KASSERT(mxbusy || mwired, ("caprevoke !xbusy !wired?"));

	/*
	 * If this is the load side and we hit the VM, then the LCLG bit should
	 * already be up to date (if present; see the above INVARIANTS test).
	 * Otherwise, the load side should update the LCLG bit now.
	 */
	if (!mdidvm && (flags & VM_CHERI_REVOKE_LOAD_SIDE)) {
		vm_page_t m2 = m;
		int pmres;

		pmres = pmap_caploadgen_update(crc->map->pmap, addr, &m2,
		    (mxbusy ? PMAP_CAPLOADGEN_XBUSIED : 0) |
		    (mxbusy ? PMAP_CAPLOADGEN_NONEWMAPS : 0) |
		    (viscap ? PMAP_CAPLOADGEN_HASCAPS : 0));

		switch (pmres) {
		case PMAP_CAPLOADGEN_OK:
			/* Update applied */
			break;
		case PMAP_CAPLOADGEN_ALREADY:
		case PMAP_CAPLOADGEN_CLEAN:
			/* We lost a narrow race & visited the page twice */
			break;
		case PMAP_CAPLOADGEN_UNABLE:
			/* Page not installed in the pmap; that's fine */
			break;

		default:
			panic("Bad second return from caploadgen update: %d",
			    pmres);
		}

		/* pmap_caploadgen_page will have unwired for us */
		KASSERT(m2 == NULL, ("LS !didvm upd !NULL?"));
		mwired = false;
		mxbusy = false;
	}
#ifdef INVARIANTS
	/*
	 * Even if the page has been replaced, it must have been by another act
	 * of the VM, and so the CLG should be absent or up to date.
	 */
	if (mdidvm && (flags & VM_CHERI_REVOKE_LOAD_SIDE)) {
		int pmres;
		vm_page_t m2 = m;

		pmres = pmap_caploadgen_update(crc->map->pmap, addr, &m2,
		    (mxbusy ? PMAP_CAPLOADGEN_XBUSIED : 0));
		switch(pmres) {
		case PMAP_CAPLOADGEN_UNABLE:
		case PMAP_CAPLOADGEN_ALREADY:
			break;

		default:
			panic("Bad return from didvm caploadgen update: %d",
			    pmres);
		}

		/* pmap_caploadgen_page will have unwired/unbusied for us */
		KASSERT(m2 == NULL, ("LS didvm upd !NULL?"));
		mwired = false;
		mxbusy = false;
	}

	/*
	 * XXX In all the excitement for load-side, we've neglected store-side's
	 * ability to ever clear PGA_CAPSTORE.  That needs some attention for
	 * fair comparison!
	 */

	mas = vm_page_astate_load(m);
	KASSERT(((mas.flags & PGA_CAPDIRTY) == 0) ||
		!(flags & VM_CHERI_REVOKE_BARRIERED),
	    ("Capdirty page after visit with world stopped?"));
#endif

	*ooff = ioff + PAGE_SIZE;
	if (mwired)
		vm_page_unwire_in_situ(m);
	if (mxbusy)
		vm_page_xunbusy(m);

	VM_OBJECT_WLOCK(obj);

	return VM_CHERI_REVOKE_AT_OK;
}

/*
 * Do a sweep through a given map entry, starting at a given va.  Update the
 * va with how far we got.
 *
 * The map must be read-locked on entry and will be read-locked on exit, but
 * the lock may be dropped internally.  The map must, therefore, also be
 * held across invocation.
 */
static int
vm_cheri_revoke_map_entry(const struct vm_cheri_revoke_cookie *crc, int flags,
    vm_map_entry_t entry, vm_offset_t *addr)
{
	int res;
	vm_offset_t ooffset;
	vm_object_t obj;
	vm_object_t objlocked = NULL;

	KASSERT(!(entry->eflags & MAP_ENTRY_IS_SUB_MAP),
	    ("cheri_revoke SUB_MAP"));

	obj = entry->object.vm_object;

	/* No backing object?  Just a bunch of zeros, so skip it */
	if (!obj)
		goto fini;

	/* Skip entire mappings that do not permit capability reads */
	if ((entry->max_protection & VM_PROT_READ_CAP) == 0)
		goto fini;

	if (cheri_revoke_avoid_faults) {
		if ((obj->type == OBJT_DEFAULT) &&
		    ((obj->backing_object == NULL) ||
		     ((obj->backing_object->flags & OBJ_HASCAP) == 0)))
			flags |= VM_CHERI_REVOKE_QUICK_SUCCESSOR;

		/*
		 * XXX How do to QUICK_SUCCESSOR for OBJT_SWAP?
		 * MJ: this could be extended to swap objects by additionally
		 * querying the pager for a copy of non-resident pages.
		 * swap_pager_find_least() would be the main vehicle for that.
		 */
	}

	objlocked = obj;
	VM_OBJECT_WLOCK(obj);

	while (*addr < entry->end) {
		int vmres;
#ifdef INVARIANTS
		vm_offset_t oaddr = *addr;
#endif

		/* Find ourselves in this object */
		ooffset = *addr - entry->start + entry->offset;

		res = vm_cheri_revoke_object_at(
		    crc, flags, entry, ooffset, &ooffset, &vmres);

		/* How far did we get? */
		*addr = ooffset - entry->offset + entry->start;
		KASSERT(*addr <= entry->end,
		    ("vm_cheri_revoke post past entry end: %lx > %lx (was %lx)",
			entry->end, *addr, oaddr));

		switch (res) {
		case VM_CHERI_REVOKE_AT_VMERR:
			return vmres;
		case VM_CHERI_REVOKE_AT_TICK:
			/* Have the caller retranslate the map */
			return KERN_SUCCESS;
		case VM_CHERI_REVOKE_AT_OK:
			break;
		}
	}

fini:
	if (objlocked)
		VM_OBJECT_WUNLOCK(objlocked);

	*addr = entry->end;
	return KERN_SUCCESS;
}

/*
 * Do a sweep through all mapped objects, hunting for revoked capabilities,
 * as defined by the machdep vm_cheri_revoke_page.
 *
 * For simplicity, the proc must be held on entry and will be held
 * throughout.  XXX Would we rather do something else?
 */
int
vm_cheri_revoke_pass(const struct vm_cheri_revoke_cookie *crc, int flags)
{
	int res = KERN_SUCCESS;
	const vm_map_t map = crc->map;
	vm_map_entry_t entry;
	vm_offset_t addr;

	addr = 0;

	/* Acquire the address space map write-locked and not busy */
	vm_map_lock(map);
	if (map->busy)
		vm_map_wait_busy(map);

	/* Stay on this core for the duration */
	sched_pin();

	if (flags & VM_CHERI_REVOKE_SYNC_CD) {
		/* Flush out all the MD capdirty bits to the MI layer. */
		pmap_sync_capdirty(map->pmap);
	}

	/*
	 * Downgrade VM map locks to read-locked but busy to guard against
	 * a racing fork (see vmspace_fork).
	 */
	vm_map_busy(map);
	vm_map_lock_downgrade(map);

	entry = vm_map_entry_first(map);

	if (entry != &map->header)
		addr = entry->start;

	while (entry != &map->header) {
		/*
		 * XXX Somewhere around here we should be resetting
		 * MPROT_QUARANTINE'd map entries to be usable again, yes?
		 */

		res = vm_cheri_revoke_map_entry(crc, flags, entry, &addr);

		/*
		 * We might be bailing out because a page fault failed for
		 * catastrophic reasons (or polite ones like ptrace()).
		 */
		if (res != KERN_SUCCESS) {
			printf("CHERI revoke bail va=%lx res=%d\n", addr, res);
			goto out;
		}

		if (!vm_map_lookup_entry(map, addr, &entry)) {
			entry = vm_map_entry_succ(entry);
			if (entry != &map->header)
				addr = entry->start;
		}
	}

	/*
	 * We could do this to ensure that the TLB has no stale CLG entries,
	 * but that's not really requisite: they'll either get pushed out,
	 * we'll either trap on them belatedly and fix them up
	 * (PMAP_CAPLOADGEN_ALREADY), or they'll get shot down when we
	 * increment the CLG for the *next* pass (while we've got the world
	 * stopped.)
	 *
	if (flags & VM_CHERI_REVOKE_LOAD_SIDE)
		pmap_invalidate_all(pmap);
	 */

out:
	vm_map_unlock_read(map);

	sched_unpin();

	vm_map_lock(map);
	vm_map_unbusy(map);
	vm_map_unlock(map);

	return res;
}

/*
 * XXX Should this encapsulate a barrier around epochs and stat collection and
 * all that?  I don't think there are any meaningful races around epoch close,
 * but maybe it'd be better to be a little more structured.
 */
int
vm_cheri_revoke_cookie_init(vm_map_t map, struct vm_cheri_revoke_cookie *crc)
{
	KASSERT(map == &curproc->p_vmspace->vm_map,
	    ("cheri revoke does not support foreign maps (yet)"));

	if (!SV_CURPROC_FLAG(SV_CHERI))
		return KERN_INVALID_ARGUMENT;

	crc->map = map;

	/*
	 * Build the capability to the shadow bitmap that we will use for probes
	 * during this revocation pass or fault.  We are holding the map xlocked
	 * at this point, so we cannot use any of the checked constructors,
	 * which, with INVARIANTS, try to validate that the cap does not span
	 * reservations and, so, slock the map; WITNESS sensibly objects.
	 *
	 * TODO:
	 * For foreign maps, we should take advantage of map->vm_cheri_revoke_sh
	 * and construct a mapping in the local address space to manipulate
	 * the remote one!
	 */
	crc->crshadow = cheri_capability_build_user_rwx_unchecked(
	    CHERI_PERM_LOAD | CHERI_PERM_GLOBAL,
	    curproc->p_sysent->sv_cheri_revoke_shadow_base,
	    curproc->p_sysent->sv_cheri_revoke_shadow_length,
	    curproc->p_sysent->sv_cheri_revoke_shadow_offset);

	return KERN_SUCCESS;
}

void
vm_cheri_revoke_cookie_rele(struct vm_cheri_revoke_cookie *crc)
{
	(void)crc;
	return;
}

/******************************* VM & SHADOW *******************************/

static bool cheri_revoke_core_shadow = 0;
SYSCTL_BOOL(_vm, OID_AUTO, cheri_revoke_core_shadow, CTLFLAG_RW,
    &cheri_revoke_core_shadow, 0,
    "Include the cheri_revoke shadow in core dumps");

/*
 * Map a capability revocation shadow
 */
int
vm_map_install_cheri_revoke_shadow(struct vm_map *map, struct sysentvec *sv)
{
	int cow = cheri_revoke_core_shadow ? 0 : MAP_DISABLE_COREDUMP;
	int error = KERN_SUCCESS;
	bool reserved_shadow = false;
	bool reserved_info = false;
	vm_object_t vmo_shadow, vmo_info;
	vm_pointer_t start;

	vm_offset_t start_addr = sv->sv_cheri_revoke_shadow_base;
	vm_offset_t end_addr = start_addr + sv->sv_cheri_revoke_shadow_length;

	vmo_shadow = vm_object_allocate(OBJT_DEFAULT, end_addr - start_addr);
	vmo_info = vm_object_allocate(OBJT_DEFAULT, PAGE_SIZE);

	vm_map_lock(map);

	start = start_addr; /* upcast to NULL-derived cap */

	error = vm_map_reservation_create_locked(map, &start,
		    end_addr - start_addr,
		    VM_PROT_READ | VM_PROT_WRITE);

	KASSERT((ptraddr_t)start == start_addr,
		("vm_map_reservation_create_locked moved revocation's cheese"));

	if (error != KERN_SUCCESS) {
		goto out;
	}
	reserved_shadow = true;

	error = vm_map_insert(map, vmo_shadow, 0, start, end_addr,
				VM_PROT_READ | VM_PROT_WRITE,
				VM_PROT_READ | VM_PROT_WRITE,
				cow, start_addr);

	if (error != KERN_SUCCESS) {
		goto out;
	}

	/* Now do the same thing for the info page */
	start_addr = start = sv->sv_cheri_revoke_info_page;
	end_addr = sv->sv_cheri_revoke_info_page + PAGE_SIZE;

	error = vm_map_reservation_create_locked(map, &start,
		    end_addr - start_addr,
		    VM_PROT_READ | VM_PROT_WRITE);
	reserved_info = true;

	KASSERT((ptraddr_t)start == start_addr,
		("vm_map_reservation_create_locked moved revocation's cheese"));

	if (error != KERN_SUCCESS) {
		goto out;
	}

	error = vm_map_insert(map, vmo_info, 0, start, end_addr,
				VM_PROT_READ | VM_PROT_WRITE,
				VM_PROT_READ | VM_PROT_WRITE,
				cow, start_addr);

	if (error != KERN_SUCCESS) {
		goto out;
	}
	
	/*
	 * XXX We should probably be tracking the shadow object in the map,
	 * but what to do in fork()?
	 */

out:
	if (error != KERN_SUCCESS) {
		int error2;

		if (reserved_info) {
			error2 = vm_map_reservation_delete_locked(map,
			    sv->sv_cheri_revoke_info_page);
			KASSERT(error2 == KERN_SUCCESS,
			    ("vm_map_install_cheri_revoke_shadow can't undo"));
		}
		if (reserved_shadow) {
			error2 = vm_map_reservation_delete_locked(map,
			    sv->sv_cheri_revoke_shadow_base);
			KASSERT(error2 == KERN_SUCCESS,
			    ("vm_map_install_cheri_revoke_shadow can't undo"));
		}

		(void) error2; /* Placate !INVARIANTS build */
	}

	vm_map_unlock(map);

	if (error == KERN_SUCCESS) {
		/* Initialize cheri_revoke info (map unlocked for copyout) */
		struct cheri_revoke_info initinfo = {
			.base_mem_nomap =
			    sv->sv_cheri_revoke_shadow_base +
			    sv->sv_cheri_revoke_shadow_offset,
			.base_otype =
			    sv->sv_cheri_revoke_shadow_base +
			    sv->sv_cheri_revoke_shadow_offset -
			    VM_CHERI_REVOKE_BSZ_OTYPE,
			{0, 0}
		};
		struct cheri_revoke_info_page * __capability infopage;
		vm_cheri_revoke_info_page(map, sv, &infopage);

		error = copyout(&initinfo, infopage, sizeof(initinfo));
		KASSERT(error == 0,
			("vm_map_install_cheri_revoke_shadow copyout"));
	} else {
		vm_object_deallocate(vmo_shadow);
		vm_object_deallocate(vmo_info);
	}
	return error;
}

void
vm_cheri_revoke_publish_epochs(
    struct cheri_revoke_info_page * __capability info_page,
    const struct cheri_revoke_epochs *ip)
{
	struct cheri_revoke_epochs * __capability target =
	    &info_page->pub.epochs;
	int res = copyoutcap(ip, target, sizeof(*target));
	KASSERT(res == 0, ("vm_cheri_revoke_publish: bad copyout %d\n", res));
	(void)res;
}

/*
 * Grant access to a capability shadow
 */
void * __capability
vm_cheri_revoke_shadow_cap(struct sysentvec *sv, int sel, vm_offset_t base,
    vm_offset_t size, int pmask)
{
	switch(sel) {
	/* Accessible to userspace */
	case CHERI_REVOKE_SHADOW_NOVMMAP: {
		vm_offset_t shadow_base, shadow_size;

		/* Require at least byte granularity in the shadow space */
		if ((base & ((VM_CHERI_REVOKE_GSZ_MEM_NOMAP * 8) - 1)) != 0)
			return (void * __capability)(uintptr_t)EINVAL;
		if ((size & ((VM_CHERI_REVOKE_GSZ_MEM_NOMAP * 8) - 1)) != 0)
			return (void * __capability)(uintptr_t)EINVAL;

		shadow_base = sv->sv_cheri_revoke_shadow_base
		            + sv->sv_cheri_revoke_shadow_offset
		            + (base / VM_CHERI_REVOKE_GSZ_MEM_NOMAP / 8);
		shadow_size = size / VM_CHERI_REVOKE_GSZ_MEM_NOMAP / 8;

		return cheri_capability_build_user_data(
			(pmask & (CHERI_PERM_LOAD | CHERI_PERM_STORE)) |
			    CHERI_PERM_GLOBAL,
			shadow_base, shadow_size, 0);
	}
	case CHERI_REVOKE_SHADOW_OTYPE: {
		vm_offset_t shadow_base, shadow_size;

		/* Require at least byte granularity in the shadow space */
		if ((base & ((VM_CHERI_REVOKE_GSZ_OTYPE * 8) - 1)) != 0)
			return (void * __capability)(uintptr_t)EINVAL;
		if ((size & ((VM_CHERI_REVOKE_GSZ_OTYPE * 8) - 1)) != 0)
			return (void * __capability)(uintptr_t)EINVAL;

		shadow_base = sv->sv_cheri_revoke_shadow_base
		            + sv->sv_cheri_revoke_shadow_offset
		            - VM_CHERI_REVOKE_BSZ_OTYPE
		            + (base / VM_CHERI_REVOKE_GSZ_OTYPE / 8);
		shadow_size = size / VM_CHERI_REVOKE_GSZ_OTYPE / 8;

		return cheri_capability_build_user_data(
			CHERI_PERM_LOAD | CHERI_PERM_STORE | CHERI_PERM_GLOBAL,
			shadow_base, shadow_size, 0);
	}
	case CHERI_REVOKE_SHADOW_INFO_STRUCT: {
		return cheri_capability_build_user_data(
			CHERI_PERM_LOAD
			| CHERI_PERM_LOAD_CAP
			| CHERI_PERM_GLOBAL,
			sv->sv_cheri_revoke_info_page,
			sizeof(struct cheri_revoke_info),
			0);
	}
	case CHERI_REVOKE_SHADOW_NOVMMAP_ENTIRE: {
		vm_offset_t shadow_base, shadow_size;

		shadow_base = sv->sv_cheri_revoke_shadow_base
		            + sv->sv_cheri_revoke_shadow_offset;
		shadow_size = sv->sv_cheri_revoke_shadow_length
		            - sv->sv_cheri_revoke_shadow_offset;

		return cheri_capability_build_user_data(
		    CHERI_PERM_LOAD | CHERI_PERM_STORE | CHERI_PERM_GLOBAL,
		    shadow_base, shadow_size, 0);
	}
	/* Kernel-only */
	// XXX CHERI_REVOKE_SHADOW_MAP:
	//
	default:
		return (void * __capability)(uintptr_t)EINVAL;
	}
}

void
vm_cheri_revoke_info_page(struct vm_map *map, struct sysentvec *sv,
    struct cheri_revoke_info_page * __capability *ifp)
{
	/* XXX In prinicple, it could work cross-process, but not yet */
	KASSERT(map == &curthread->td_proc->p_vmspace->vm_map,
		("vm_cheri_revoke_page_info req. intraprocess work right now"));

	*ifp = cheri_capability_build_user_data(CHERI_PERM_LOAD |
	    CHERI_PERM_LOAD_CAP | CHERI_PERM_STORE | CHERI_PERM_STORE_CAP |
	    CHERI_PERM_GLOBAL,
	    sv->sv_cheri_revoke_info_page, PAGE_SIZE, 0);
}
