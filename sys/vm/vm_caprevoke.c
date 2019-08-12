#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_vm.h"
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/cheriabi.h>
#include <sys/caprevoke.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_extern.h>
#include <vm/vm_page.h>

// XXX This is very much a work in progress!

static bool caprevoke_avoid_faults = 1;
SYSCTL_BOOL(_vm, OID_AUTO, caprevoke_avoid_faults, CTLFLAG_RW,
    &caprevoke_avoid_faults, 0,
    "XXX");

static bool caprevoke_last_redirty = 1;
SYSCTL_BOOL(_vm, OID_AUTO, caprevoke_last_redirty, CTLFLAG_RW,
    &caprevoke_last_redirty, 0,
    "XXX");

static int
vm_caprevoke_should_visit_page(vm_page_t m, int flags)
{
	/*
	 * Always visit recently-capdirty pages.  As a side effect,
	 * clear the PGA_CAPSTORED flag on this page.
	 */
	if (vm_page_aflag_xclear_acq(m, PGA_CAPSTORED) & PGA_CAPSTORED)
		return 1;

	/*
	 * If this is an incremental scan, we only care about
	 * recently-capdirty pages, so can stop here.
	 */
	if (flags & VM_CAPREVOKE_INCREMENTAL)
		return 0;

	/*
	 * On the other hand, for full scans, we want to visit all pages
	 * that may have had capabilities, not just recently.
	 */
	if (m->oflags & VPO_PASTCAPSTORE)
		return 1;

	return 0;
}

enum vm_cro_visit {
	VM_CAPREVOKE_VIS_DONE  = 0,
	VM_CAPREVOKE_VIS_DIRTY = 1,
	VM_CAPREVOKE_VIS_BUSY  = 2
};

/*
 * Given a writable, wired page in a wlocked object, visit it.
 */
static int
vm_caprevoke_visit_rw(vm_object_t obj, vm_page_t m, int flags,
			struct caprevoke_stats *stat)
{
	int hascaps;

	if (!vm_page_tryxbusy(m))
		return VM_CAPREVOKE_VIS_BUSY;
	VM_OBJECT_WUNLOCK(obj);

retry:
	stat->pages_scanned++;
	hascaps = vm_caprevoke_page(m, flags, stat);

	/* CAS failures cause us to revisit */
	if (hascaps & VM_CAPREVOKE_PAGE_DIRTY) {
		/* If the world is stopped, do that now */
		if (flags & VM_CAPREVOKE_LAST_FINI) {
			stat->pages_retried++;
			goto retry;
		}
		vm_page_capdirty(m);
	}

	VM_OBJECT_WLOCK(obj);
	vm_page_xunbusy(m);

	/*
	 * Update VPO_PASTCAPSTORE to record the results of
	 * this sweep.  Even if we clear it here, it's
	 * entirely possible that PGA_CAPSTORED has become
	 * set again in the interim.
	 */
	if (hascaps & VM_CAPREVOKE_PAGE_HASCAPS) {
		m->oflags |= VPO_PASTCAPSTORE;
	} else {
		m->oflags &= ~VPO_PASTCAPSTORE;
	}

	return VM_CAPREVOKE_VIS_DONE;
}

/*
 * The same thing, but for a *readable*, wired page.
 *
 * Returns 1 if the page must be visited read-write, 0 if it is clear to
 * advance and carry on.
 */
static int
vm_caprevoke_visit_ro(vm_object_t obj, vm_page_t m, int flags,
			struct caprevoke_stats *stat)
{
	int hascaps;

	if (!vm_page_tryxbusy(m))
		return VM_CAPREVOKE_VIS_BUSY;
	VM_OBJECT_WUNLOCK(obj);

	stat->pages_scanned++;
	hascaps = vm_caprevoke_page_ro(m, flags, stat);

	VM_OBJECT_WLOCK(obj);
	vm_page_xunbusy(m);

	if (hascaps & VM_CAPREVOKE_PAGE_DIRTY) {
		return VM_CAPREVOKE_VIS_DIRTY;
	}

	if (hascaps & VM_CAPREVOKE_PAGE_HASCAPS) {
		m->oflags |= VPO_PASTCAPSTORE;
	} else {
		m->oflags &= ~VPO_PASTCAPSTORE;
	}

	return VM_CAPREVOKE_VIS_DONE;
}

static void
vm_caprevoke_unwire_in_situ(vm_page_t m)
{
	vm_page_lock(m);
	vm_page_unwire(m, vm_page_active(m) ? PQ_ACTIVE : PQ_INACTIVE);
	vm_page_unlock(m);
}

enum vm_cro_at {
	VM_CAPREVOKE_AT_OK    = 0,
	VM_CAPREVOKE_AT_TICK  = 1,
	VM_CAPREVOKE_AT_VMERR = 2
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
 * If gaze_shadows is false, we restrict our attention to this object's own
 * pages, while if it is set we will fault around in the shadow hierarchy to
 * find and copy deeper pages.
 *
 * On success, *ooff will be updated to the next offset to probe (which may
 * be past the end of the object; the caller should test).  This next offset
 * may equal ioff if the world has shifted; this is probably fine as the
 * caller should just repeat the call.  On failure, *ooff will not be modified.
 */
static enum vm_cro_at
vm_caprevoke_object_at(vm_map_t map, vm_map_entry_t entry, vm_offset_t ioff,
			bool gaze_shadows, int flags, vm_offset_t *ooff,
			struct caprevoke_stats *stat, int *vmres)
{
	vm_object_t obj = entry->object.vm_object;
	vm_pindex_t ipi = OFF_TO_IDX(ioff);

	vm_page_t m = vm_page_lookup(obj, ipi);

	KASSERT((m == NULL) || (m->valid == VM_PAGE_BITS_ALL),
		("Revocation invalid page"));

	if (m == NULL) {
		vm_offset_t addr = ioff - entry->offset + entry->start;

		if (!gaze_shadows) {
			/* Look forward in the object map */
			vm_page_t obj_next_pg = vm_page_find_least(obj, ipi);

			if (obj_next_pg == NULL) {
				stat->pages_fault_skip += (entry->end - addr) >> PAGE_SHIFT;
				*ooff = entry->end - entry->start + entry->offset;
			} else {
				*ooff = IDX_TO_OFF(obj_next_pg->pindex);
			}
			return VM_CAPREVOKE_AT_OK;
		}

		stat->pages_faulted_ro++;

		int res;
		unsigned int last_timestamp = map->timestamp;

		VM_OBJECT_WUNLOCK(obj);

		vm_map_unlock_read(map);
		res = vm_fault_hold(map, addr, VM_PROT_READ, VM_FAULT_NORMAL,
				    &m);
		vm_map_lock_read(map);

		if (res != KERN_SUCCESS) {
			*vmres = res;
			return VM_CAPREVOKE_AT_VMERR;
		}
		if (last_timestamp != map->timestamp) {
			/*
			 * The map has changed out from under us; bail and
			 * the caller will look up the new map entry.
			 * First, though, it's important to release the page
			 * we're holding!
			 *
			 * If we're the sole wiring holder, consider this
			 * page active because we're most likely about to
			 * come right back.
			 */
			vm_page_lock(m);
			vm_page_unwire(m, PQ_ACTIVE);
			vm_page_unlock(m);
			return VM_CAPREVOKE_AT_TICK;
		}

		VM_OBJECT_WLOCK(obj);
		vm_caprevoke_unwire_in_situ(m);
	}

	if (!vm_caprevoke_should_visit_page(m, flags)) {
		*ooff = ioff + pagesizes[m->psind];
		return VM_CAPREVOKE_AT_OK;
	}

	if (pmap_page_is_write_mapped(m)) {
		/* The page is writable; just go do the revocation in place */
		vm_caprevoke_visit_rw(obj, m, flags, stat);
		*ooff = ioff + pagesizes[m->psind];
		return VM_CAPREVOKE_AT_OK;
	}

	switch(vm_caprevoke_visit_ro(obj, m, flags, stat))
	{
	case VM_CAPREVOKE_VIS_DONE:
		/* We were able to conclude that the page was clean */
		*ooff = ioff + pagesizes[m->psind];
		return VM_CAPREVOKE_AT_OK;
	case VM_CAPREVOKE_VIS_BUSY:
		/*
		 * This is kind of awkward; the page is busy and it's
		 * not clear by whom.  But whoever it is needs our
		 * object lock to unbusy.  So handle this like the
		 * map stepping forward.
		 */
		VM_OBJECT_WUNLOCK(obj);
		return VM_CAPREVOKE_AT_TICK;
	case VM_CAPREVOKE_VIS_DIRTY:
		break;
	default:
		panic("bad result from vm_caprevoke_visit_ro");
	}

	stat->pages_faulted_rw++;

	int res;
	unsigned int last_timestamp = map->timestamp;

	vm_offset_t addr = ioff - entry->offset + entry->start;

	VM_OBJECT_WUNLOCK(obj);
	vm_map_unlock_read(map);
	res = vm_fault_hold(map, addr, VM_PROT_WRITE, VM_FAULT_NORMAL, &m);
	vm_map_lock_read(map);
	if (res != KERN_SUCCESS) {
		*vmres = res;
		return VM_CAPREVOKE_AT_VMERR;
	}
	if (last_timestamp != map->timestamp) {
		vm_page_lock(m);
		vm_page_unwire(m, PQ_ACTIVE);
		vm_page_unlock(m);
		return VM_CAPREVOKE_AT_TICK;
	}

	VM_OBJECT_WLOCK(obj);
	vm_caprevoke_unwire_in_situ(m);
	switch(vm_caprevoke_visit_rw(obj, m, flags, stat))
	{
	case VM_CAPREVOKE_VIS_DONE:
		*ooff = ioff + pagesizes[m->psind];
		return VM_CAPREVOKE_AT_OK;
	case VM_CAPREVOKE_VIS_BUSY:
		VM_OBJECT_WUNLOCK(obj);
		return VM_CAPREVOKE_AT_TICK;
	default:
		panic("bad result from vm_caprevoke_visit_rw");
	}
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
vm_caprevoke_map_entry(vm_map_t map, vm_map_entry_t entry, const int flags,
			vm_offset_t *addr, struct caprevoke_stats *stat)
{
	int res;
	vm_offset_t ooffset;
	vm_object_t obj;
	bool obj_has_backing_caps;

	// XXX NWF ?
	if (entry->eflags & MAP_ENTRY_IS_SUB_MAP)
		goto fini;

	obj = entry->object.vm_object;

	/* No backing object?  Just a bunch of zeros, so skip it */
	if (!obj)
		goto fini;

	/* Skip entire objects that cannot store tags */
	if ((obj->flags & (OBJ_NOLOADTAGS | OBJ_NOSTORETAGS)) ==
	    (OBJ_NOLOADTAGS | OBJ_NOSTORETAGS))
		goto fini;

	VM_OBJECT_WLOCK(obj);

	if (caprevoke_avoid_faults) {
		/*
		 * Look to see if this object's backing stores are not tag-capable.
		 * If so, this allows us to immediately advance to the next page
		 * in this object whenever we find something unmapped.
		 *
		 * XXX There is an intermediate "faster" path we haven't yet
		 * explored, which is to have a "next possible tag-capable pindex"
		 * operation on the stack of vm objects that we might find we need.
		 *
		 * XXX Do we really have to look recursively like this or is
		 * it enough to just glance at the immediate backing object?
		 */

		vm_object_t tobj;

		obj_has_backing_caps = false;

		for (tobj = obj->backing_object; tobj != NULL;
		    tobj = tobj->backing_object) {
			if ((tobj->flags & OBJ_NOLOADTAGS) == 0 ||
			    (tobj->flags & OBJ_NOSTORETAGS) == 0) {
				obj_has_backing_caps = true;
				break;
			}
		}
	} else {
		obj_has_backing_caps = true;
	}

	while (*addr < entry->end) {
		int vmres;

		/* Find ourselves in this object */
		ooffset = *addr      - entry->start + entry->offset;

		res = vm_caprevoke_object_at(map, entry, ooffset,
						obj_has_backing_caps, flags,
						&ooffset, stat, &vmres);

		/* How far did we get? */
		*addr = ooffset - entry->offset + entry->start;
		KASSERT(*addr <= entry->end, ("vm_caprevoke post past entry end"));

		switch (res) {
		case VM_CAPREVOKE_AT_VMERR:
			return vmres;
		case VM_CAPREVOKE_AT_TICK:
			/* Have the caller retranslate the map */
			return KERN_SUCCESS;
		case VM_CAPREVOKE_AT_OK:
			break;
		}

	}

	VM_OBJECT_WUNLOCK(obj);

fini:
	*addr = entry->end;
	return KERN_SUCCESS;
}

/*
 * Do a sweep through all mapped objects, hunting for revoked capabilities,
 * as defined by the machdep vm_caprevoke_page.
 *
 * For simplicity, the proc must be held on entry and will be held
 * throughout.  XXX Would we rather do something else?
 *
 * XXX Right now, CAPREVOKE_LAST_INIT and _FINI are probably not correctly
 * used.  We should, instead, take the flags to imply...
 *
 *   LAST_INIT by itself: enter into the load-side story
 *   LAST_FINI by itself: clean pages in the background
 *   both: as now, a world-stopped cleaning pass
 */
int
vm_caprevoke(struct proc *p, int flags, struct caprevoke_stats *st)
{
	int res = KERN_SUCCESS;
	struct vmspace *vm;
	vm_map_t map;
	vm_map_entry_t entry;
	vm_offset_t addr;

	if ((flags & (VM_CAPREVOKE_LAST_INIT|VM_CAPREVOKE_LAST_FINI))
	    == VM_CAPREVOKE_LAST_FINI) {
		/*
		 * XXX We don't do the load-side story; instead, we do all our work
		 * in LAST_INIT.  There's nothing to do in this second pass.
		 */
		return KERN_SUCCESS;
	}

	/*
	 * XXX Right now, we know that there are no coarse-grain bits
	 * getting set, since we don't do MPROT_QUARANTINE or anything of
	 * that sort.  So we just always assert VM_CAPREVOKE_NO_COARSE.
	 * In the future, we should count the number of pages held in
	 * MPROT_QUARANTINE or munmap()'s quarantine or other such to decide
	 * whether to set this!
	 */
	flags |= VM_CAPREVOKE_NO_COARSE;

	PROC_ASSERT_HELD(p);
	vm = vmspace_acquire_ref(p);

	addr = 0;
	map = &vm->vm_map;

	/* Acquire the address space map write-locked and not busy */
	vm_map_lock(map);
	if(map->busy)
		vm_map_wait_busy(map);

	if (flags & VM_CAPREVOKE_LAST_INIT) {
		/*
		 * The world is thread-singled; now is a great time to go
		 * flush out all the MD capdirty bits to the MI layer.
		 *
		 * XXX Do we really want to do this only in LAST_INIT?
		 * Should we have a separate flag to optionally do this for
		 * incremental passes or something?  The world might not be
		 * single-threaded for those, but maybe that's OK?
		 */
		pmap_sync_capdirty(map->pmap);
	}

	/*
	 * Downgrade VM map locks to read-locked but busy to guard against
	 * a racing fork (see vmspace_fork).
	 */
	vm_map_busy(map);
	vm_map_lock_downgrade(map);

	entry = map->header.next;

	if (entry != &map->header)
		addr = entry->start;

	while (entry != &map->header) {
		/*
		 * XXX Somewhere around here we should be resetting
		 * MPROT_QUARANTINE'd map entries to be usable again, yes?
		 */

		res = vm_caprevoke_map_entry(map, entry, flags, &addr, st);

		/*
		 * We might be bailing out because a page fault failed for
		 * catastrophic reasons (or polite ones like ptrace()).
		 */
		if (res != KERN_SUCCESS)
			goto out;

		if (!vm_map_lookup_entry(map, addr, &entry)) {
			entry = entry->next;
			if (entry != &map->header)
				addr = entry->start;
		}
	}

out:
	vm_map_unlock_read(map);
	vm_map_lock(map);
	vm_map_unbusy(map);
	vm_map_unlock(map);
	vmspace_free(vm);

	return res;
}

/*
 * Do a sweep across the single map entry containing the given address.
 */
int
vm_caprevoke_one(struct proc *p, int flags, vm_offset_t oneaddr,
		 struct caprevoke_stats *st)
{
	int res = KERN_SUCCESS;
	struct vmspace *vm;
	vm_map_t map;
	vm_map_entry_t entry;
	vm_offset_t addr;

	KASSERT(!!(flags & VM_CAPREVOKE_LAST_INIT)
		 == !!(flags & VM_CAPREVOKE_LAST_FINI),
			("vm_caprevoke_one bad LAST flags"));

	PROC_ASSERT_HELD(p);
	vm = vmspace_acquire_ref(p);
	map = &vm->vm_map;
	vm_map_lock_read(map);

	if (!vm_map_lookup_entry(map, oneaddr, &entry))
		goto out;

	addr = entry->start;
	while (addr < entry->end) {
		res = vm_caprevoke_map_entry(map, entry, flags, &addr, st);

		if (res != KERN_SUCCESS)
			goto out;

		if (!vm_map_lookup_entry(map, addr, &entry))
			break;
		if (oneaddr < entry->start)
			break;
	}

out:
	vm_map_unlock_read(map);
	vmspace_free(vm);
	return res;
}
