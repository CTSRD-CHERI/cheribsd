#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_vm.h"
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/rwlock.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_extern.h>
#include <vm/vm_page.h>

#include <cheri/cheric.h>
#include <cheri/revoke.h>
#include <vm/vm_cheri_revoke.h>

// XXX This is very much a work in progress!

static bool cheri_revoke_avoid_faults = 1;
SYSCTL_BOOL(_vm, OID_AUTO, cheri_revoke_avoid_faults, CTLFLAG_RW,
    &cheri_revoke_avoid_faults, 0,
    "XXX");

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
	VM_CHERI_REVOKE_VIS_BUSY  = 2
};

/*
 * Given a writable, wired page in a wlocked object, visit it.
 */
static enum vm_cro_visit
vm_cheri_revoke_visit_rw(
    const struct vm_cheri_revoke_cookie *crc, int flags, vm_page_t m, bool *cap)
{
	int hascaps;
	CHERI_REVOKE_STATS_FOR(crst, crc);

	if (vm_page_sleep_if_busy(m, "CHERI revoke"))
		return VM_CHERI_REVOKE_VIS_BUSY;
		
	vm_page_xbusy(m);
	VM_OBJECT_WUNLOCK(m->object);

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

	/*
	 * m->object cannot have changed: the busy lock protects both the page's
	 * contents (against pageout, not concurrent mutation) but also its
	 * identity.
	 */
	VM_OBJECT_WLOCK(m->object);
	vm_page_xunbusy(m);

	*cap = !!(hascaps & VM_CHERI_REVOKE_PAGE_HASCAPS);
	return VM_CHERI_REVOKE_VIS_DONE;
}

/*
 * The same thing, but for a *readable*, wired page.
 *
 * Returns 1 if the page must be visited read-write, 0 if it is clear to
 * advance and carry on.
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

	if (vm_page_sleep_if_busy(m, "CHERI revoke"))
		return VM_CHERI_REVOKE_VIS_BUSY;
	vm_page_xbusy(m);
	VM_OBJECT_WUNLOCK(m->object);

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

	VM_OBJECT_WLOCK(m->object);
	vm_page_xunbusy(m);

	if (hascaps & VM_CHERI_REVOKE_PAGE_DIRTY) {
		return VM_CHERI_REVOKE_VIS_DIRTY;
	}

	*cap = !!(hascaps & VM_CHERI_REVOKE_PAGE_HASCAPS);
	return VM_CHERI_REVOKE_VIS_DONE;
}

static void
vm_cheri_revoke_unwire_in_situ(vm_page_t m)
{
	vm_page_lock(m);
	vm_page_unwire(m, vm_page_active(m) ? PQ_ACTIVE : PQ_INACTIVE);
	vm_page_unlock(m);
}

// XXX stats
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
	pmap_t upmap = vmspace_pmap(uvms);

	vres = vm_cheri_revoke_cookie_init(&uvms->vm_map, &crc);
	KASSERT(vres == 0,
	    ("vm_cheri_revoke_cooke_init failure in fault_visit"));

again:
	pres = pmap_caploadgen_update(upmap, va, &m,
	    PMAP_CAPLOADGEN_UPDATETLB | PMAP_CAPLOADGEN_WIRE |
	    (hascap ? PMAP_CAPLOADGEN_HASCAPS : 0));

	switch(pres) {
	case PMAP_CAPLOADGEN_UNABLE:
	case PMAP_CAPLOADGEN_TEARDOWN:
		res = VM_CHERI_REVOKE_FAULT_UNRESOLVED;
		break;

	case PMAP_CAPLOADGEN_ALREADY:
	case PMAP_CAPLOADGEN_CLEAN:
	case PMAP_CAPLOADGEN_OK:
		res = VM_CHERI_REVOKE_FAULT_RESOLVED;
		break;

	default:
		panic("Bad pmap_caploadgen_fault_user return");

	/*
	 * The following cases have the page wired so we can inspect it.  It's
	 * therefore important that we always end with "goto again" (which
	 * drops the wiring and possibly acquires a new one) or that we call
	 * vm_page_unwire() ourselves.
	 */
	case PMAP_CAPLOADGEN_SCAN_CLEAN_RO:
		/*
		 * This is a somewhat unexpected result but might happen if the
		 * fault is tag-independent or there are aliased mappings.
		 * This mapping has both cap-dirty and cap-dirtyable clear.
		 */

		/* FALLTHROUGH */
	case PMAP_CAPLOADGEN_SCAN_RO:
		vres = vm_cheri_revoke_page_ro(&crc, m);
		if (vres & VM_CHERI_REVOKE_PAGE_DIRTY) {
			vm_page_unwire(m, PQ_ACTIVE);
			res = VM_CHERI_REVOKE_FAULT_CAPSTORE;
			break;
		}
		hascap = vres & VM_CHERI_REVOKE_PAGE_HASCAPS;
		goto again;

	case PMAP_CAPLOADGEN_SCAN_CLEAN_RW:
		/*
		 * Like PMAP_CAPLOADGEN_SCAN_CLEAN_RO, this mapping believes
		 * itself clean (but writable).
		 */

		/* FALLTHROUGH */
	case PMAP_CAPLOADGEN_SCAN_RW:
		vres = vm_cheri_revoke_page_rw(&crc, m);

		/*
		 * Discard VM_CHERI_REVOKE_PAGE_DIRTY: losing a load-side CAS
		 * race is perfectly fine, as anything stored over top of it
		 * must have already been checked.
		 */

		hascap = vres & VM_CHERI_REVOKE_PAGE_HASCAPS;
		goto again;
	}

#ifdef CHERI_CAPREVOKE_STATS
	/*
	 * This might, very rarely, get credited to the next epoch, if we have
	 * raced the close. (XXX?)
	 */
	
	uint64_t cyc_end = get_cyclecount();
	sx_slock(&uvms->vm_map.vm_cheri_revoke_stats_sx);
	{
		CHERI_REVOKE_STATS_FOR(crst, &crc);
		CHERI_REVOKE_STATS_BUMP(crst, fault_visits);
		CHERI_REVOKE_STATS_INC(crst, fault_cycles, cyc_end - cyc_start);
	}
	sx_sunlock(&uvms->vm_map.vm_cheri_revoke_stats_sx);
#endif

	vm_cheri_revoke_cookie_rele(&crc);

	return res;
}

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
	vm_page_astate_t mas;
	CHERI_REVOKE_STATS_FOR(crst, crc);
	vm_map_t map = crc->map;
	vm_object_t obj = entry->object.vm_object;
	vm_pindex_t ipi = OFF_TO_IDX(ioff);
	vm_offset_t addr = ioff - entry->offset + entry->start;
	vm_page_t m = NULL;
	bool mwired = false;
	bool mdidvm = false;
	bool viscap = false;

	VM_OBJECT_ASSERT_WLOCKED(obj);

	/*
	 * If we're on the load side, we can ask the pmap to help us out.  This
	 * is functionally equivalent to pmap_extract_and_hold, but with a fast
	 * out if LCLG == GCLG (PMAP_CAPLOADGEN_ALREADY, i.e., if this mapping
	 * has already been visited by vm_cheri_revoke_fault_visit) or if
	 * m->a.flags has PGA_CAPSTORE clear (PMAP_CAPLOADGEN_CLEAN).
	 */
	if (flags & VM_CHERI_REVOKE_LOAD_SIDE) {
		int pmres;

		pmres = pmap_caploadgen_update(crc->map->pmap, addr, &m, 0);

		switch (pmres) {
		case PMAP_CAPLOADGEN_OK:
		case PMAP_CAPLOADGEN_TEARDOWN:
			panic("Bad first return from pmap_caploadgen_update");
		case PMAP_CAPLOADGEN_ALREADY:
		case PMAP_CAPLOADGEN_CLEAN:
			*ooff = ioff + PAGE_SIZE;
			return VM_CHERI_REVOKE_AT_OK;
		case PMAP_CAPLOADGEN_UNABLE:
			break;
		case PMAP_CAPLOADGEN_SCAN_RO:
		case PMAP_CAPLOADGEN_SCAN_CLEAN_RO:
			if (m->object != obj) {
				VM_OBJECT_WUNLOCK(obj);
				VM_OBJECT_WLOCK(m->object);
			}
			goto visit_ro;
		case PMAP_CAPLOADGEN_SCAN_RW:
		case PMAP_CAPLOADGEN_SCAN_CLEAN_RW:
			if (m->object != obj) {
				VM_OBJECT_WUNLOCK(obj);
				VM_OBJECT_WLOCK(m->object);
			}
			goto visit_rw;
		}
	}
	// XXX else pmap_extract_and_hold?

	KASSERT(m == NULL, ("Load side bad state arc"));
	vm_page_grab_valid(&m, obj, ipi,
	    VM_ALLOC_WIRED | VM_ALLOC_NOBUSY | VM_ALLOC_NOZERO);

	if (m == NULL) {
		if (flags & VM_CHERI_REVOKE_QUICK_SUCCESSOR) {
			/* Look forward in the object map */
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
		res = vm_fault(map, addr, VM_PROT_READ, VM_FAULT_NOFILL, &m);
		vm_map_lock_read(map);

		if (res == KERN_NOT_RECEIVER) {
			/* NOFILL did its thing */
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

		VM_OBJECT_WLOCK(m->object);
		mdidvm = true;

		/* vm_fault has handled it all for us */
		goto ok;
	} else {
		KASSERT(m->object == obj, ("Page lookup bad object?"));
		KASSERT(vm_page_all_valid(m), ("Page grab valid invalid?"));
		mwired = true;
	}

	VM_OBJECT_ASSERT_WLOCKED(m->object);
	KASSERT(vm_page_all_valid(m), ("Revocation invalid page"));

	if (!vm_cheri_revoke_should_visit_page(m, flags)) {
		CHERI_REVOKE_STATS_BUMP(crst, pages_skip);
		goto ok;
	}

visit_ro:
	if (pmap_page_is_write_mapped(m)) {
visit_rw:
		if (m->object == obj) {
			/* Visit the page RW in place */
			switch (vm_cheri_revoke_visit_rw(crc, flags, m,
			    &viscap)) {
			case VM_CHERI_REVOKE_VIS_DONE:
				goto ok;

			case VM_CHERI_REVOKE_VIS_BUSY:
				if (mwired)
					vm_cheri_revoke_unwire_in_situ(m);
				VM_OBJECT_WUNLOCK(obj);
				return VM_CHERI_REVOKE_AT_TICK;
			default:
				panic(
				    "bad result from vm_cheri_revoke_visit_rw");
			}
		}

		/*
		 * XXX I don't quite understand how this is
		 * possible, but something seems fishy about
		 * this situation.  Just go force a RW fault
		 * to copy up the page
		 */
		goto visit_rw_fault;
	}

	switch (vm_cheri_revoke_visit_ro(crc, flags, m, &viscap)) {
	case VM_CHERI_REVOKE_VIS_DONE:
		/* We were able to conclude that the page was clean */
		goto ok;
	case VM_CHERI_REVOKE_VIS_BUSY:
		/*
		 * This is kind of awkward; the page is busy and it's
		 * not clear by whom.  But whoever it is needs our
		 * object lock to unbusy.  So handle this like the
		 * map stepping forward.
		 */
		if (mwired)
			vm_cheri_revoke_unwire_in_situ(m);
		VM_OBJECT_WUNLOCK(obj);
		return VM_CHERI_REVOKE_AT_TICK;
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
		vm_cheri_revoke_unwire_in_situ(m);
	}
	VM_OBJECT_WUNLOCK(m->object);
	vm_map_unlock_read(map);
	res = vm_fault(map, addr, VM_PROT_WRITE | VM_PROT_WRITE_CAP,
	    VM_FAULT_NORMAL, &m);
	vm_map_lock_read(map);
	if (res != KERN_SUCCESS) {
		*vmres = res;
		VM_OBJECT_ASSERT_UNLOCKED(obj);
		return VM_CHERI_REVOKE_AT_VMERR;
	}
	if (last_timestamp != map->timestamp) {
		VM_OBJECT_ASSERT_UNLOCKED(obj);
		return VM_CHERI_REVOKE_AT_TICK;
	}

	KASSERT(m->object == obj, ("Bad page object after FAULT WRITE"));

	mdidvm = true;
	VM_OBJECT_WLOCK(m->object);

ok:
	/*
	 * If this is the load side and we hit the VM, then the LCLG bit should
	 * already be up to date (if present).  Otherwise, the load side needs
	 * to update the LCLG bit now.
	 */
	if (!mdidvm && (flags & VM_CHERI_REVOKE_LOAD_SIDE)) {
		vm_page_t m2 = m;
		int pmres;

		pmres = pmap_caploadgen_update(crc->map->pmap, addr, &m2,
		    PMAP_CAPLOADGEN_EXCLUSIVE /* object locked */ |
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
		case PMAP_CAPLOADGEN_TEARDOWN:
		case PMAP_CAPLOADGEN_SCAN_RO:
		case PMAP_CAPLOADGEN_SCAN_CLEAN_RO:
		case PMAP_CAPLOADGEN_SCAN_RW:
		case PMAP_CAPLOADGEN_SCAN_CLEAN_RW:
			panic("Bad second return from pmap_caploadgen_update");
		}
	}
#ifdef INVARIANTS
	/*
	 * Even if the page has been replaced, it must have been by another act
	 * of the VM, and so the CLG should be absent or up to date.
	 */
	if (mdidvm && (flags & VM_CHERI_REVOKE_LOAD_SIDE)) {
		int pmres;
		vm_page_t m2 = NULL;

		pmres = pmap_caploadgen_update(crc->map->pmap, addr, &m2,
		    PMAP_CAPLOADGEN_EXCLUSIVE /* object locked */ |
		    (viscap ? PMAP_CAPLOADGEN_HASCAPS : 0));
		switch(pmres) {
		case PMAP_CAPLOADGEN_UNABLE:
		case PMAP_CAPLOADGEN_ALREADY:
			break;
		default:
			panic("Bad return from didvm caploadgen update: %d",
			    pmres);
		}
	}
#endif

	/*
	 * XXX In all the excitement for load-side, we've neglected store-side's
	 * ability to ever clear PGA_CAPSTORE.  That needs some attention for
	 * fair comparison!
	 */

	mas = vm_page_astate_load(m);
	KASSERT(((mas.flags & PGA_CAPDIRTY) == 0) ||
		!(flags & VM_CHERI_REVOKE_BARRIERED),
	    ("Capdirty page after visit with world stopped?"));

	*ooff = ioff + PAGE_SIZE;
	if (mwired)
		vm_cheri_revoke_unwire_in_situ(m);
	if (m->object != obj) {
		VM_OBJECT_WUNLOCK(m->object);
		VM_OBJECT_WLOCK(obj);
	}
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

		/* XXX How do to QUICK_SUCCESSOR for OBJT_SWAP? */
	}

	objlocked = obj;
	VM_OBJECT_WLOCK(obj);

	while (*addr < entry->end) {
		int vmres;
		vm_offset_t oaddr;

		/* Find ourselves in this object */
		ooffset = *addr - entry->start + entry->offset;
		oaddr = *addr;

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
		if (res != KERN_SUCCESS)
			goto out;

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

	vm_map_lock(map);
	vm_map_unbusy(map);
	vm_map_unlock(map);

	return res;
}

_Static_assert(VM_CHERI_REVOKE_PAD_SIZE >=
	(VM_CHERI_REVOKE_BSZ_MEM_NOMAP + VM_CHERI_REVOKE_BSZ_MEM_MAP +
	    VM_CHERI_REVOKE_BSZ_OTYPE + PAGE_SIZE),
    "VM_CHERI_REVOKE_PAD_SIZE too small");
_Static_assert(
    (VM_CHERI_REVOKE_BM_BASE + VM_CHERI_REVOKE_PAD_SIZE) <= VM_MAXUSER_ADDRESS,
    "VM_CHERI_REVOKE shadow exceeds max size");

/*
 * XXX Should this encapsulate a barrier around epochs and stat collectio and
 * all that?  I don't think there are any meaningful races around epoch close,
 * but maybe it'd be better to be a little more structured.
 */
int
vm_cheri_revoke_cookie_init(vm_map_t map, struct vm_cheri_revoke_cookie *crc)
{
	KASSERT(map == &curproc->p_vmspace->vm_map,
	    ("cheri revoke does not support foreign maps (yet)"));
	KASSERT(map->vm_cheri_revoke_shva == VM_CHERI_REVOKE_BM_BASE,
	    ("cheri revoke shadow does not match definition"));

	if (map->vm_cheri_revoke_sh == NULL)
		return KERN_INVALID_ARGUMENT;

	crc->map = map;

	/*
	 * For foreign maps, we should take advantage of map->vm_cheri_revoke_sh
	 * and construct a mapping in the local address space to manipulate
	 * the remote one!
	 */
	crc->crshadow = cheri_capability_build_user_data(
	    CHERI_PERM_LOAD | CHERI_PERM_GLOBAL, VM_CHERI_REVOKE_BM_BASE,
	    VM_CHERI_REVOKE_PAD_SIZE, 0);

	return KERN_SUCCESS;
}

void
vm_cheri_revoke_cookie_rele(struct vm_cheri_revoke_cookie *crc)
{
	(void)crc;
	return;
}
