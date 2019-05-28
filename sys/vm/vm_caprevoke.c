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

#define VM_CROBJ_DONE		0
#define VM_CROBJ_ROMAPPED	1
#define VM_CROBJ_UNMAPPED	2

/*
 * Sweep through a subset of a particular object, from `*oo` to `eo`.
 * Return how far we got before failing in `oo`.  Pages between the initial
 * value of `*oo` and the value of `*oo` at return will have had their
 * PGA_CAPSTORED bits updated to reflect the true measured presence of
 * capabilities on this page, and will have had `pmap_tc_capdirty` called on
 * them prior to revocation; as such, a page will only become
 * `pmap_is_capdirty` after this function if a capstore happened after the
 * start of revocation.
 *
 * `obj` must be unlocked at entry, but the map containing the entry whence
 * it came must be held read-locked across the duration of this call.  At
 * points internally, `obj` will be locked.
 *
 * `flags` adjust the behavior of this function:
 *
 *   VM_CAPREVOKE_INCREMENTAL: examine only pages which the pmap considers
 *   "recently" capability dirty.  In the typical use case of the capdirty
 *   logic, that will mean "since the last invocation of this function".
 *
 *   VM_CAPREVOKE_STOPTHEWORLD: the world is stopped for our attention, so
 *   we can more aggressively assert.
 *
 * Result codes are
 *
 *   VM_CROBJ_DONE     - finished and *oo == eo.
 *
 *   VM_CROBJ_ROMAPPED - just past *oo, a page we intend to visit is RO
 *                       mapped; fault handling is required to upgrade to a
 *                       writable mapping, but the caller can skip any
 *                       fast-path testing
 *
 *   VM_CROBJ_UNMAPPED - just past *oo, a page is in swap and fault handling
 *                       is required.
 */
static int
vm_caprevoke_object(vm_object_t obj, vm_offset_t eo, int flags,
		    vm_offset_t *oo, struct caprevoke_stats *stat)
{
	vm_offset_t co = *oo;

	VM_OBJECT_WLOCK(obj);

	while (co < eo) {
		vm_page_t m;
		vm_pindex_t pindex;

		/* Find the page for this offset within the object. */
		pindex = OFF_TO_IDX(co);
		m = vm_page_lookup(obj, pindex);
		KASSERT((m == NULL) || (m->valid == VM_PAGE_BITS_ALL),
			("Revocation invalid page"));
		if ((m == NULL) || !pmap_page_is_write_mapped(m)) {
			VM_OBJECT_WUNLOCK(obj);
			*oo = co;
			return (m == NULL) ? VM_CROBJ_UNMAPPED
			                   : VM_CROBJ_ROMAPPED;
		}

		if (vm_caprevoke_should_visit_page(m, flags)) {
			int hascaps;

			/*
			 * Exclusive busy the page and, soon, drop the object lock
			 * around the actual revocation.  This lets the world make
			 * progress, but prevents concurrent revocation of this
			 * page, in particular, so our dance with PGA_CAPSTORED
			 * below is reasonable.
			 */
			vm_page_xbusy(m);
			VM_OBJECT_WUNLOCK(obj);

retry:
			stat->pages_scanned++;
			hascaps = vm_caprevoke_page(m);

			/* CAS failures cause us to revisit */
			if (hascaps & VM_CAPREVOKE_PAGE_DIRTY) {
				/* If the world is stopped, do that now */
				if (flags & VM_CAPREVOKE_LAST_FINI) {
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
		} else {
			/* Incremental scans cannot update VPO_PASTCAPSTORE */
		}

		co += pagesizes[m->psind];

		/*
		 * If this is a stop the world pass, there should be
		 * absolutely no way for this page to be capdirty again.
		 */
		KASSERT(((flags & VM_CAPREVOKE_LAST_FINI) == 0) ||
				((m->aflags & PGA_CAPSTORED) == 0),
			("Capdirty page in STW revocation pass"));
	}

	VM_OBJECT_WUNLOCK(obj);

	*oo = eo;
	return VM_CROBJ_DONE;
}

/*
 * Do a sweep through a given map entry, starting at a given va.  Update the
 * va with how far we got.
 *
 * The map must be read-locked on entry and will be read-locked on exit, but
 * the lock may be dropped internally.  The map must, therefore, also be
 * held across invocation.
 */
static void
vm_caprevoke_map_entry(vm_map_t map, vm_map_entry_t entry, const int flags,
			vm_offset_t *addr, struct caprevoke_stats *stat)
{
	int res;
	vm_offset_t eoffset;
	vm_offset_t ooffset;
	vm_object_t obj;

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

	KASSERT(*addr < entry->end, ("vm_caprevoke at=%lx past entry end=%lx", *addr, entry->end));

	eoffset = entry->end - entry->start + entry->offset;

again:	
	/* Find ourselves in this object */
	ooffset = *addr      - entry->start + entry->offset;

	/* Make some progress */
	res = vm_caprevoke_object(obj, eoffset, flags, &ooffset, stat);

	/* How far did we get? */
	*addr = ooffset - entry->offset + entry->start;

	KASSERT(*addr <= entry->end, ("vm_caprevoke post past entry end"));

	switch(res) {
	case VM_CROBJ_ROMAPPED :
	case VM_CROBJ_UNMAPPED : {

		/*
		 * Missing page; fault it back in and go again.  We drop our
		 * read lock on the map (but not our ref to it) to take the
		 * fault.  This means that it could be quite different by
		 * the time we get back, but the timestamp guides the way.
		 *
		 * In fact, we do this dance twice(ish).  We drop the lock
		 * to take a *read* fault, holding the resulting page, so
		 * that we can look at it.  If the page doesn't merit
		 * visiting, then skip it.  Otherwise, go take a write fault
		 * and re-enter vm_caprevoke_object.
		 *
		 * XXX deferred revocation?
		 */

		unsigned int last_timestamp;
		vm_page_t mh = NULL;

		last_timestamp = map->timestamp;
		vm_map_unlock_read(map);

		if (res == VM_CROBJ_UNMAPPED) {
			/*
			 * XXX This is more expensive, but probably faster
			 * and less memory intensive, than just immediately
			 * leaping to the write fault.  We'll still force
			 * the ZFOD mappings, the first time through, but
			 * won't actually upgrade them to writagble here.
			 * We won't necessarily dirty swapped pages, even if
			 * we haul them back in, either.
			 *
			 * XXX We'd much rather ask a relatively complex
			 * question: what is the pindex of the next page in
			 * the shadow chain that plausibly contains a
			 * capability?  Consider the case where we've got a
			 * .data with only some pages copied up: the
			 * OBJT_DEFAULT shadowing the OBJT_VNODE contains
			 * all the pages we care about, but page faults will
			 * dive deeper and pull the inherently-tagless pages
			 * up into core, which is pointless.
			 *
			 * Unfortunately, to answer that question I think
			 * requires knowledge of various OBJT_*-associated
			 * internals, since the pages do not exist for
			 * paged-out regions of OBJT_SWAP and perhaps also
			 * for OBJT_VNODE?
			 */

			res = vm_fault_hold(map, *addr, VM_PROT_READ,
						VM_FAULT_TAGCAPABLE, &mh);
			vm_map_lock_read(map);
			if ((res != KERN_SUCCESS) && (res != KERN_NO_ACCESS)) {
				KASSERT(mh == NULL, ("Failure yet page held?"));
				return;
			}
			if (last_timestamp != map->timestamp) {
				/*
				 * The map has changed out from under us;
				 * bail and the caller will look up the new
				 * map entry.  First, though, it's important
				 * to release the page we're holding!
				 */
				vm_page_lock(mh);
				vm_page_unhold(mh);
				vm_page_unlock(mh);
				return;
			}
			if (res == KERN_NO_ACCESS) {
				/*
				 * This address is not backed by an object
				 * that can store tags.  Bump up by the
				 * baseline page size and try again.
				 *
				 * XXX We'd much rather find out the next
				 * possible tag-capable address rather than
				 * probe like this...
				 */
				KASSERT(mh == NULL, ("KERN_NO_ACCESS page held?"));
				*addr += PAGE_SIZE;
				stat->pages_fault_skip++;
				goto again;
			}

			/*
			 * This page might belong to a shadowed object and
			 * not be installed in our obj until we write fault!
			 * Lock this object, not ours!  We don't hold our
			 * obj locked at this point, so there's no risk of
			 * deadlock in object acquisition order.
			 */
			VM_OBJECT_RLOCK(mh->object);

			if (!vm_caprevoke_should_visit_page(mh, flags)) {
				VM_OBJECT_RUNLOCK(mh->object);
				*addr += pagesizes[mh->psind];
				vm_page_lock(mh);
				vm_page_unhold(mh);
				vm_page_unlock(mh);
				mh = NULL;
				stat->pages_faulted_ro++;
				if (*addr == entry->end)
					return;
				goto again;
			} else {
				VM_OBJECT_RUNLOCK(mh->object);
			}

			vm_map_unlock_read(map);
		}

		res = vm_fault_hold(map, *addr, VM_PROT_WRITE,
					VM_FAULT_NORMAL, NULL);

		if (mh) {
			vm_page_lock(mh);
			vm_page_unhold(mh);
			vm_page_unlock(mh);
			mh = NULL;
		}

		stat->pages_faulted_rw++;

		vm_map_lock_read(map);
		if ((res != KERN_SUCCESS)
		    || (last_timestamp != map->timestamp)) {
			/*
			 * The map has changed out from under us; bail and
			 * the caller will look up the new map entry.
			 */
			return;
		}

		/*
		 * Avoid a lookup in the map since we know the current entry
		 * has not changed.
		 */
		goto again;
	}
	case VM_CROBJ_DONE :
		KASSERT(*addr == entry->end, ("caprevoke obj not done? %lx vs %lx", *addr, entry->end));
		return;
	default :
		panic("vm_caprevoke_object bad return %d\n", res);
	}

fini:
	/* We make it here only if the entire object is done */
	*addr = entry->end;
}

/*
 * Do a sweep through all mapped objects, hunting for revoked capabilities,
 * as defined by the machdep vm_caprevoke_page.
 *
 * For simplicity, the proc must be held on entry and will be held
 * throughout.  XXX Would we rather do something else?
 *
 * XXX Right now, CAPREVOKE_LAST_INIT is ignored.  We should, instead,
 * take the flags to imply...
 *
 *   LAST_INIT by itself: enter into the load-side story
 *   LAST_FINI by itself: clean pages in the background
 *   both: as now, a world-stopped cleaning pass
 */
int
vm_caprevoke(struct proc *p, int flags, struct caprevoke_stats *st)
{
	struct vmspace *vm;
	vm_map_t map;
	vm_map_entry_t entry;
	vm_offset_t addr;

	KASSERT(!!(flags & VM_CAPREVOKE_LAST_INIT)
		 == !!(flags & VM_CAPREVOKE_LAST_FINI),
			("vm_caprevoke_one bad LAST flags"));

	PROC_ASSERT_HELD(p);
	vm = vmspace_acquire_ref(p);

	addr = 0;
	map = &vm->vm_map;

	/*
	 * Acquire the address space map in read-locked and busy state, to
	 * fence against a concurrent fork (in vmspace_fork, in particular).
	 */
	vm_map_lock(map);
	if(map->busy)
		vm_map_wait_busy(map);
	vm_map_busy(map);

	if (flags & VM_CAPREVOKE_LAST_INIT) {
		/*
		 * The world is thread-singled; now is a great time to go
		 * flush out all the MD capdirty bits to the MI layer.
		 */
		pmap_sync_capdirty(map->pmap);
	}

	/* XXX The rest of this is LAST_FINI-style work */

	vm_map_lock_downgrade(map);

	entry = map->header.next;

	if (entry != &map->header)
		addr = entry->start;

	while (entry != &map->header) {
		vm_caprevoke_map_entry(map, entry, flags, &addr, st);

		if (!vm_map_lookup_entry(map, addr, &entry)) {
			entry = entry->next;
			if (entry != &map->header)
				addr = entry->start;
		}
	}

	vm_map_unlock_read(map);
	vm_map_lock(map);
	vm_map_unbusy(map);
	vm_map_unlock(map);
	vmspace_free(vm);

	return 0;
}

/*
 * Do a sweep across the single map entry containing the given address.
 */
int
vm_caprevoke_one(struct proc *p, int flags, vm_offset_t oneaddr,
		 struct caprevoke_stats *st)
{
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
		vm_caprevoke_map_entry(map, entry, flags, &addr, st);
		if (!vm_map_lookup_entry(map, addr, &entry))
			break;
		if (oneaddr < entry->start)
			break;
	}

out:
	vm_map_unlock_read(map);
	vmspace_free(vm);
	return 0;
}
