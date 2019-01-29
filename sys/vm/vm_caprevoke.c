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
#include <sys/caprevoke.h>
#include <vm/vm_caprevoke.h>

// XXX This is very much a work in progress!

static bool caprevoke_avoid_faults = 1;
SYSCTL_BOOL(_vm, OID_AUTO, caprevoke_avoid_faults, CTLFLAG_RW,
    &caprevoke_avoid_faults, 0,
    "XXX");

static bool caprevoke_last_redirty = 1;
SYSCTL_BOOL(_vm, OID_AUTO, caprevoke_last_redirty, CTLFLAG_RW,
    &caprevoke_last_redirty, 0,
    "XXX");

static inline int
vm_caprevoke_should_visit_page(vm_page_t m, int flags)
{
	/*
	 * If a page is capdirty, visit this page.  On incremental passes,
	 * this should catch a superset of the pages we need to visit.
	 */
	if (vm_page_astate_load(m).flags & PGA_CAPDIRTY)
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
	if (m->oflags & VPO_CAPSTORE)
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
vm_caprevoke_visit_rw(
    const struct vm_caprevoke_cookie *crc, int flags, vm_page_t m)
{
	int hascaps;
	CAPREVOKE_STATS_FOR(crst, crc);

	if (!vm_page_tryxbusy(m))
		return VM_CAPREVOKE_VIS_BUSY;
	VM_OBJECT_WUNLOCK(m->object);

retry:
	CAPREVOKE_STATS_BUMP(crst, pages_scan_rw);
	hascaps = vm_caprevoke_page(crc, m);

	/* CAS failures cause us to revisit */
	if (hascaps & VM_CAPREVOKE_PAGE_DIRTY) {
		/* If the world is stopped, do that now */
		if (flags & VM_CAPREVOKE_LAST_FINI) {
			CAPREVOKE_STATS_BUMP(crst, pages_retried);
			goto retry;
		}
		vm_page_capdirty(m);
	}

	VM_OBJECT_WLOCK(m->object);
	vm_page_xunbusy(m);

	/*
	 * XXX Not yet: we are still relying on VPO_CAPSTORE to capture
	 * page permissions, so doing this will trip an assert that we
	 * are failing to set PMAP_ENTER_NOSTORETAGS when/if we re-insert
	 * this page
	 */
#ifdef notyet_capstore_permissions
	/*
	 * Update VPO_CAPSTORE to record the results of
	 * this sweep.  Even though we cleared PGA_CAPDIRTY before
	 * calling this function, it's entirely possible that it
	 * has become set again in the interim.
	 */
	if (hascaps & VM_CAPREVOKE_PAGE_HASCAPS) {
		m->oflags |= VPO_CAPSTORE;
	} else {
		m->oflags &= ~VPO_CAPSTORE;
		CAPREVOKE_STATS_BUMP(crst, pages_mark_clean);
	}
#endif

	return VM_CAPREVOKE_VIS_DONE;
}

/*
 * The same thing, but for a *readable*, wired page.
 *
 * Returns 1 if the page must be visited read-write, 0 if it is clear to
 * advance and carry on.
 */
static int
vm_caprevoke_visit_ro(
    const struct vm_caprevoke_cookie *crc, int flags, vm_page_t m)
{
	CAPREVOKE_STATS_FOR(crst, crc);
	int hascaps;

	if (!vm_page_tryxbusy(m))
		return VM_CAPREVOKE_VIS_BUSY;
	VM_OBJECT_WUNLOCK(m->object);

	CAPREVOKE_STATS_BUMP(crst, pages_scan_ro);
	hascaps = vm_caprevoke_page_ro(crc, m);

	KASSERT(!(hascaps & VM_CAPREVOKE_PAGE_HASCAPS) ||
		((m->oflags & VPO_CAPSTORE) ||
		    (vm_page_astate_load(m).flags & PGA_CAPDIRTY)),
	    ("cap-bearing RO page without h/r capdirty?"
	     " hc=%x m=%p, m->of=%x, m->af=%x",
		hascaps, m, m->oflags, vm_page_astate_load(m).flags));

	VM_OBJECT_WLOCK(m->object);
	vm_page_xunbusy(m);

	if ((hascaps & VM_CAPREVOKE_PAGE_HASCAPS) == 0) {
		/*
		 * This can only be true if we scanned the entire page and
		 * found no tagged, permission-bearing things.  In that case,
		 * even though the page is possibly shared, it's safe to mark
		 * it as clean for subsequent revocation passes!
		 */
		vm_page_aflag_clear(m, PGA_CAPDIRTY);
#ifdef notyet_capstore_permissions
		m->oflags &= ~VPO_CAPSTORE;
#endif

		CAPREVOKE_STATS_BUMP(crst, pages_mark_clean);
	} else if (m->a.flags & PGA_CAPDIRTY) {
		/*
		 * Even if we have capabilities here, it's sufficient to
		 * visit only in the opening pass.  While RW pages would
		 * rely on PGA_CAPDIRTY to be revisited, for RO pages,
		 * VIS_DIRTY causes us to upgrade to RW now, so this is
		 * a fine shuffling of capdirty bits.
		 */
		vm_page_aflag_clear(m, PGA_CAPDIRTY);
		m->oflags |= VPO_CAPSTORE;
	}

	if (hascaps & VM_CAPREVOKE_PAGE_DIRTY) {
		return VM_CAPREVOKE_VIS_DIRTY;
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
 * On success, *ooff will be updated to the next offset to probe (which may
 * be past the end of the object; the caller should test).  This next offset
 * may equal ioff if the world has shifted; this is probably fine as the
 * caller should just repeat the call.  On failure, *ooff will not be modified.
 */
static enum vm_cro_at
vm_caprevoke_object_at(const struct vm_caprevoke_cookie *crc, int flags,
    vm_map_entry_t entry, vm_offset_t ioff, vm_offset_t *ooff, int *vmres)
{
	CAPREVOKE_STATS_FOR(crst, crc);
	vm_map_t map = crc->map;
	vm_object_t obj = entry->object.vm_object;
	vm_pindex_t ipi = OFF_TO_IDX(ioff);

	vm_page_t m = vm_page_lookup(obj, ipi);

	KASSERT((m == NULL) || (m->valid == VM_PAGE_BITS_ALL),
	    ("Revocation invalid page"));

	if (m == NULL) {
		vm_offset_t addr = ioff - entry->offset + entry->start;

		if (flags & VM_CAPREVOKE_QUICK_SUCCESSOR) {
			/* Look forward in the object map */
			vm_page_t obj_next_pg = vm_page_find_least(obj, ipi);

			vm_offset_t lastoff =
			    entry->end - entry->start + entry->offset;

			if ((obj_next_pg == NULL) ||
			    (obj_next_pg->pindex >= OFF_TO_IDX(lastoff))) {
				CAPREVOKE_STATS_INC(crst, pages_skip_fast,
				    (entry->end - addr) >> PAGE_SHIFT);
				*ooff = lastoff;
			} else {

				KASSERT(obj_next_pg->object == obj,
				    ("Fast find page in bad object?"));

				*ooff = IDX_TO_OFF(obj_next_pg->pindex);
				CAPREVOKE_STATS_INC(crst, pages_skip_fast,
				    obj_next_pg->pindex - ipi);
			}
			return VM_CAPREVOKE_AT_OK;
		}

		CAPREVOKE_STATS_BUMP(crst, pages_faulted_ro);

		int res;
		unsigned int last_timestamp = map->timestamp;

		VM_OBJECT_WUNLOCK(obj);

		vm_map_unlock_read(map);
		res = vm_fault(map, addr, VM_PROT_READ, VM_FAULT_NORMAL, &m);
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

		VM_OBJECT_WLOCK(m->object);
		vm_caprevoke_unwire_in_situ(m);
	} else {
		KASSERT(m->object == obj, ("Page lookup bad object?"));
	}

	VM_OBJECT_ASSERT_WLOCKED(m->object);

	if (pmap_page_is_write_mapped(m)) {
		if (!vm_caprevoke_should_visit_page(m, flags)) {
			CAPREVOKE_STATS_BUMP(crst, pages_skip);
			goto visit_rw_ok;
		}

		if (m->object == obj) {
			/* Go visit the page RW in place */
			goto visit_rw;
		}

		/*
		 * XXX I don't quite understand how this is
		 * possible, but something seems fishy about
		 * this situation.  Just go force a RW fault
		 * to copy up the page
		 */
		goto visit_rw_fault;
	}

	if (!vm_caprevoke_should_visit_page(m, flags)) {
		*ooff = ioff + pagesizes[m->psind];
		CAPREVOKE_STATS_BUMP(crst, pages_skip);
		if (m->object != obj) {
			VM_OBJECT_WUNLOCK(m->object);
			VM_OBJECT_WLOCK(obj);
		}
		return VM_CAPREVOKE_AT_OK;
	}

	switch (vm_caprevoke_visit_ro(crc, flags, m)) {
	case VM_CAPREVOKE_VIS_DONE:
		/* We were able to conclude that the page was clean */
		*ooff = ioff + pagesizes[m->psind];
		if (m->object != obj) {
			VM_OBJECT_WUNLOCK(m->object);
			VM_OBJECT_WLOCK(obj);
		}
		return VM_CAPREVOKE_AT_OK;
	case VM_CAPREVOKE_VIS_BUSY:
		/*
		 * This is kind of awkward; the page is busy and it's
		 * not clear by whom.  But whoever it is needs our
		 * object lock to unbusy.  So handle this like the
		 * map stepping forward.
		 */
		if (m->object != obj) {
			VM_OBJECT_WUNLOCK(m->object);
		}
		VM_OBJECT_ASSERT_UNLOCKED(obj);
		return VM_CAPREVOKE_AT_TICK;
	case VM_CAPREVOKE_VIS_DIRTY:
		/* Dirty here means we need to upgrade to RW now */
		break;
	default:
		panic("bad result from vm_caprevoke_visit_ro");
	}

visit_rw_fault:
	CAPREVOKE_STATS_BUMP(crst, pages_faulted_rw);

	int res;
	unsigned int last_timestamp = map->timestamp;

	vm_offset_t addr = ioff - entry->offset + entry->start;

	VM_OBJECT_WUNLOCK(m->object);
	vm_map_unlock_read(map);
	res = vm_fault(map, addr, VM_PROT_WRITE, VM_FAULT_NORMAL, &m);
	vm_map_lock_read(map);
	if (res != KERN_SUCCESS) {
		*vmres = res;
		VM_OBJECT_ASSERT_UNLOCKED(obj);
		return VM_CAPREVOKE_AT_VMERR;
	}
	if (last_timestamp != map->timestamp) {
		vm_page_lock(m);
		vm_page_unwire(m, PQ_ACTIVE);
		vm_page_unlock(m);
		VM_OBJECT_ASSERT_UNLOCKED(obj);
		return VM_CAPREVOKE_AT_TICK;
	}

	KASSERT(m->object == obj, ("Bad page object after FAULT WRITE"));

	VM_OBJECT_WLOCK(m->object);
	vm_caprevoke_unwire_in_situ(m);

visit_rw:
	vm_page_aflag_clear(m, PGA_CAPDIRTY);
	switch (vm_caprevoke_visit_rw(crc, flags, m)) {
	case VM_CAPREVOKE_VIS_DONE:
visit_rw_ok:

		KASSERT(((vm_page_astate_load(m).flags & PGA_CAPDIRTY) == 0) ||
			!(flags & VM_CAPREVOKE_LAST_INIT),
		    ("Capdirty page after visit with world stopped?"));

		/*
		 * When we are closing a revocation epoch, we transfer
		 * VPO_CAPSTORE to PGA_CAPDIRTY so that we don't take
		 * as many faults in the inter-epoch period.  We know that
		 * we're going to visit all the VPO_CAPSTORE-bearing
		 * pages when we open the next epoch anyway, so there's no
		 * point in lazily setting their PGA_CAPDIRTY flags.
		 */
		if (caprevoke_last_redirty &&
		    (flags & VM_CAPREVOKE_LAST_INIT)) {
			if (m->oflags & VPO_CAPSTORE) {
				vm_page_capdirty(m);
			}
		}

		*ooff = ioff + pagesizes[m->psind];
		if (m->object != obj) {
			VM_OBJECT_WUNLOCK(m->object);
			VM_OBJECT_WLOCK(obj);
		}
		return VM_CAPREVOKE_AT_OK;
	case VM_CAPREVOKE_VIS_BUSY:
		VM_OBJECT_WUNLOCK(m->object);
		VM_OBJECT_ASSERT_UNLOCKED(obj);
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
vm_caprevoke_map_entry(const struct vm_caprevoke_cookie *crc, int flags,
    vm_map_entry_t entry, vm_offset_t *addr)
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
		 * Look to see if this object's backing stores are not
		 * tag-capable. If so, this allows us to immediately advance to
		 * the next page in this object whenever we find something
		 * unmapped.  Credit goes to Edward Napierala for demonstrating
		 * that this was viable.
		 *
		 * XXX There is an intermediate "faster" path we haven't yet
		 * explored, which is to have a "next possible tag-capable
		 * pindex" operation on the stack of vm objects that we might
		 * find we need.
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
	if (!obj_has_backing_caps)
		flags |= VM_CAPREVOKE_QUICK_SUCCESSOR;

	while (*addr < entry->end) {
		int vmres;

		/* Find ourselves in this object */
		ooffset = *addr - entry->start + entry->offset;

		res = vm_caprevoke_object_at(
		    crc, flags, entry, ooffset, &ooffset, &vmres);

		/* How far did we get? */
		*addr = ooffset - entry->offset + entry->start;
		KASSERT(
		    *addr <= entry->end, ("vm_caprevoke post past entry end"));

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
vm_caprevoke(const struct vm_caprevoke_cookie *crc, int flags)
{
	int res = KERN_SUCCESS;
	const vm_map_t map = crc->map;
	vm_map_entry_t entry;
	vm_offset_t addr;

	if ((flags & (VM_CAPREVOKE_LAST_INIT | VM_CAPREVOKE_LAST_FINI)) ==
	    VM_CAPREVOKE_LAST_FINI) {
		/*
		 * XXX We don't do the load-side story; instead, we do all our
		 * work in LAST_INIT.  There's nothing to do in this second
		 * pass.
		 */
		return KERN_SUCCESS;
	}

	addr = 0;

	/* Acquire the address space map write-locked and not busy */
	vm_map_lock(map);
	if (map->busy)
		vm_map_wait_busy(map);

	if (flags & VM_CAPREVOKE_PMAP_SYNC) {
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

		res = vm_caprevoke_map_entry(crc, flags, entry, &addr);

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

out:
	vm_map_unlock_read(map);
	vm_map_lock(map);
	vm_map_unbusy(map);
	vm_map_unlock(map);

	return res;
}

/*
 * Do a sweep across the single map entry containing the given address.
 */
int
vm_caprevoke_one(
    const struct vm_caprevoke_cookie *crc, int flags, vm_offset_t oneaddr)
{
	int res = KERN_SUCCESS;
	const vm_map_t map = crc->map;
	vm_map_entry_t entry;
	vm_offset_t addr;

	KASSERT(!!(flags & VM_CAPREVOKE_LAST_INIT) ==
		!!(flags & VM_CAPREVOKE_LAST_FINI),
	    ("vm_caprevoke_one bad LAST flags"));

	vm_map_lock_read(map);

	if (!vm_map_lookup_entry(map, oneaddr, &entry))
		goto out;

	addr = entry->start;
	while (addr < entry->end) {
		res = vm_caprevoke_map_entry(crc, flags, entry, &addr);

		if (res != KERN_SUCCESS)
			goto out;

		if (!vm_map_lookup_entry(map, addr, &entry))
			break;
		if (oneaddr < entry->start)
			break;
	}

out:
	vm_map_unlock_read(map);
	return res;
}

_Static_assert(VM_CAPREVOKE_PAD_SIZE >=
	(VM_CAPREVOKE_BSZ_MEM_NOMAP + VM_CAPREVOKE_BSZ_MEM_MAP +
	    VM_CAPREVOKE_BSZ_OTYPE + PAGE_SIZE),
    "VM_CAPREVOKE_PAD_SIZE too small");
_Static_assert(
    (VM_CAPREVOKE_BM_BASE + VM_CAPREVOKE_PAD_SIZE) <= VM_MAXUSER_ADDRESS,
    "VM_CAPREVOKE shadow exceeds max size");

int
vm_caprevoke_cookie_init(vm_map_t map, struct caprevoke_stats *stats,
    struct vm_caprevoke_cookie *crc)
{
	KASSERT(map == &curproc->p_vmspace->vm_map,
	    ("caprev does not support foreign maps (yet)"));
	KASSERT(map->vm_caprev_shva == VM_CAPREVOKE_BM_BASE,
	    ("caprev shadow does not match definition"));

	if (map->vm_caprev_sh == NULL)
		return KERN_INVALID_ARGUMENT;

	crc->map = map;
#ifdef CHERI_CAPREVOKE_STATS
	crc->stats = stats;
#endif

	/*
	 * XXX Right now, we know that there are no coarse-grain bits
	 * getting set, nor otypes nor anything else, since we don't do
	 * MPROT_QUARANTINE or anything of that sort.
	 *
	 * In the future, we should count the number of pages held in
	 * MPROT_QUARANTINE or munmap()'s quarantine or other such to decide
	 * whether to set _NO_COARSE.  Similary for the others.
	 */
	vm_caprevoke_set_test(crc,
	    VM_CAPREVOKE_CF_NO_COARSE_MEM | VM_CAPREVOKE_CF_NO_OTYPES |
		VM_CAPREVOKE_CF_NO_CIDS);

	/*
	 * For foreign maps, we should take advantage of map->vm_caprev_sh
	 * and construct a mapping in the local address space to manipulate
	 * the remote one!
	 */
	crc->crshadow = cheri_capability_build_user_data(
	    CHERI_PERM_LOAD | CHERI_PERM_GLOBAL, VM_CAPREVOKE_BM_BASE,
	    VM_CAPREVOKE_PAD_SIZE, 0);

	crc->info_page = cheri_capability_build_user_data(CHERI_PERM_LOAD |
		CHERI_PERM_LOAD_CAP | CHERI_PERM_STORE | CHERI_PERM_STORE_CAP |
		CHERI_PERM_GLOBAL,
	    VM_CAPREVOKE_INFO_PAGE, PAGE_SIZE, 0);

	return KERN_SUCCESS;
}

void
vm_caprevoke_cookie_rele(struct vm_caprevoke_cookie *crc)
{
	(void)crc;
	return;
}
