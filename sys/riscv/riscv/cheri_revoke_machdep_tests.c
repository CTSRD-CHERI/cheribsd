/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Nathaniel Filardo
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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

#include <sys/param.h>
#include <sys/systm.h>

#include <machine/_inttypes.h>
#include <cheri/cheri.h>
#include <cheri/cheric.h>
#include <cheri/revoke.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_param.h>
#include <vm/vm_map.h>
#include <vm/vm_cheri_revoke.h>

/* Check the coarse-grained MAP bitmap */
static inline unsigned long
vm_cheri_revoke_test_mem_map(const uint8_t * __capability crshadow,
    uintcap_t cut)
{
	uint8_t bmbits;
	const uint8_t * __capability bmloc;

	ptraddr_t va = cheri_getbase(cut);

	bmloc = crshadow - VM_CHERI_REVOKE_BSZ_OTYPE -
	    (va / VM_CHERI_REVOKE_GSZ_MEM_MAP / 8);

#ifdef CHERI_CAPREVOKE_FAST_COPYIN
	/* XXX This is terribly, terribly unsafe and should go away. */
	bmbits = *bmloc;
#else
	{
		int bmbits_ext = fubyte(bmloc);
		if (bmbits_ext == -1) {
			printf("%s: failed to read shadow for %#.16lp"
			    "(s=%#.16lp); assuming not revoked!\n",
			    __func__, (void * __capability)cut, crshadow);
			return (0);
		}
		bmbits = bmbits_ext & 0xFF;
	}
#endif

	/* Fast path: often these are all zeros */

	if (bmbits == 0) {
		return (0);
	}

	return (bmbits & (1 << ((va / VM_CHERI_REVOKE_GSZ_MEM_MAP) % 8)));
}

/* Check the fine-grained NOMAP bitmap */
static inline unsigned long
vm_cheri_revoke_test_mem_nomap(const uint8_t * __capability crshadow,
    uintcap_t cut)
{
	uint8_t bmbits;
	const uint8_t * __capability bmloc;

	ptraddr_t va = cheri_getbase(cut);

	bmloc = crshadow + (va / VM_CHERI_REVOKE_GSZ_MEM_NOMAP / 8);

#ifdef CHERI_CAPREVOKE_FAST_COPYIN
	/* XXX This is terribly, terribly unsafe and should go away. */
	bmbits = *bmloc;
#else
	{
		int bmbits_ext = fubyte(bmloc);
		if (bmbits_ext == -1) {
			printf("%s: failed to read shadow for %#.16lp"
			    "(s=%#.16lp); assuming not revoked!\n",
			    __func__, (void * __capability)cut, crshadow);
			return (0);
		}
		bmbits = bmbits_ext & 0xFF;
	}
#endif

	if (bmbits == 0) {
		return (0);
	}

	return bmbits & (1 << ((va / VM_CHERI_REVOKE_GSZ_MEM_NOMAP) % 8));
}

static inline unsigned
vm_cheri_revoke_test_range(vm_offset_t start, vm_offset_t end, uintcap_t cut)
{
	ptraddr_t va = cheri_getbase(cut);

	return (va >= start && va < end);
}

// TODO: if ((perms & CHERI_PERMS_HWALL_OTYPE) != 0)
// TODO: if ((perms & CHERI_PERMS_HWALL_CID) != 0)

static unsigned long
vm_cheri_revoke_test_just_mem(const uint8_t * __capability crshadow,
    uintcap_t cut, unsigned long perms, vm_offset_t start, vm_offset_t end)
{
	if ((perms & (CHERI_PERMS_HWALL_MEMORY | CHERI_PERM_SW_VMEM)) != 0) {
		if (vm_cheri_revoke_test_mem_map(crshadow, cut))
			return (1);

		if ((perms & CHERI_PERM_SW_VMEM) == 0)
			return (vm_cheri_revoke_test_mem_nomap(crshadow, cut));
	}

	return (0);
}

static unsigned long
vm_cheri_revoke_test_just_mem_fine(const uint8_t * __capability crshadow,
    uintcap_t cut, unsigned long perms, vm_offset_t start, vm_offset_t end)
{
	/*
	 * Most capabilities are memory capabilities, most are unrevoked,
	 * and comparatively few are VMMAP-bearing.... so do the load
	 * first and only then do the permissions checks.
	 */

	if (vm_cheri_revoke_test_mem_nomap(crshadow, cut)) {
		if (__builtin_expect(perms & CHERI_PERM_SW_VMEM,0)) {
			return (0);
		}

		return ((perms & CHERI_PERMS_HWALL_MEMORY) != 0);
	}

	return (0);
}

static unsigned long
vm_cheri_revoke_test_mem_fine_range(const uint8_t * __capability crshadow,
    uintcap_t cut, unsigned long perms, vm_offset_t start, vm_offset_t end)
{
	/*
	 * Only check the capability if it has some memory permissions.
	 */
	if ((perms & CHERI_PERMS_HWALL_MEMORY) != 0) {
		if (vm_cheri_revoke_test_range(start, end, cut))
			return (1);

		if ((perms & CHERI_PERM_SW_VMEM) == 0) {
			return vm_cheri_revoke_test_mem_nomap(crshadow, cut);
		}
	}

	return (0);
}

#ifdef CHERI_CAPREVOKE_POISON
static unsigned long
vm_cheri_revoke_test_poison(const uint8_t * __capability crshadow __unused,
    uintcap_t cut, unsigned long perms, vm_offset_t start __unused,
    vm_offset_t end __unused)
{
	void * __capability rw_cut;
	uintcap_t poison;

	/*
	 * In principle we should look for poison capabilities anywhere in
	 * the [base(cut), top(cut)), but we rely on the following:
	 * 1. If `cut` is quarantined, then the full range [base, top) is
	 * poisoned
	 * 2. If `cut` is an allocator capability that is not quarantined,
	 * but happens to have the first word containing poison, then
	 * it will bear both PERM_SW_VMEM and PERM_POISON and we will leave
	 * it alone regardless.
	 * 3. Loading a poison capability does not cause a CRG load trap
	 *  (not currently the case), or probing for poison does not cause
	 *  a CRG load trap.
	 *
	 * As a result, we can only check the first capability at the base
	 * of the allocation for poison.
	 */
	if ((perms & CHERI_PERM_SW_VMEM) == 0) {
		KASSERT(cheri_gettag(cut),
		    ("Attempt to check poison on invalid cap %#lp",
			(void * __capability)cut));
		KASSERT(cheri_is_poison(cut) == 0,
		    ("Attempt to check poison on poison cap %#lp",
			(void * __capability)cut));
		/*
		 * We must tolerate page faults at this stage.
		 * These are user page faults coming from kernel space.
		 * To do this we either need CAPREVOKE_FAST_COPYIN to
		 * install a custom pcb_onfault, or we have to fuecap.
		 * Both a quite expensive if we get a page fault, and
		 * this also means that we may get a recursive
		 * page scan because the revoker needs to observe
		 * that page.
		 * The recursive page scan can occur regardless of
		 * FAST_COPYIN and MUST be avoided, because the poison
		 * lookup needs to be computationally bounded.
		 * The page scan can be triggered in multiple ways:
		 * 1. recursive CRG fault due to the capability load.
		 * 2. recursive page scan due to mapping a CAPDIRTY page.
		 */

		/*
		 * Note: we need to re-derive the cut capability,
		 * because we will try to load poison from it, so:
		 * - It can not be sealed
		 * - It must permit LOAD_CAP
		 * - It must be valid
		 *
		 * XXX-AM: We should use cheri_capability_build_user_rwx, but
		 * it will lock the curthread map and lookup the mapping to
		 * check that the reservation layout is sensible.
		 * We use the userspace root cap here to avoid doing
		 * this in the revoker loop.
		 *
		 * XXX-AM: It is unclear what to do if the original capability
		 * has length < sizeof(uintcap_t).
		 * This may occur due to delegation of an allocation sub-object,
		 * and therefore it should be revoked.
		 * At the same time, accessing outside the bounds means that
		 * we are potentially doing an OOB access from the kernel and
		 * violating monotonicity.
		 * Similarly, we need to round the address to a capability
		 * boundary.
		 */
		rw_cut = cheri_setoffset(userspace_root_cap, cheri_getbase(cut));
		rw_cut = rounddown2(rw_cut, sizeof(uintcap_t));
		rw_cut = cheri_setbounds(rw_cut, sizeof(uintcap_t));

		/*
		 * The poison probe can fail legitimately in some
		 * cases.
		 * - The page is not mapped (e.g. stack guard page)
		 * In these cases, we accept that the capability
		 * can not be poisoned, because poisoning requires
		 * that the memory has been mapped to write poison into.
		 *
		 * XXX-AM: It is unclear whether this failure mode
		 * can cause invalid poison detection in corner
		 * cases.
		 * Currently this is indistinguishable from no-poison
		 * in the fupoison return value.
		 */
		poison = fupoison(rw_cut);

		KASSERT((void * __capability)poison == NULL ||
		    cheri_gettag(poison),
		    ("Unexpected fupoison result %#lp",
			(void * __capability)poison));

		/*
		 * Now check poison bounds for nested allocations.
		 */
		if (cheri_gettag(poison) &&
		    cheri_getbase(poison) <= cheri_getbase(cut) &&
		    cheri_gettop(poison) >= cheri_gettop(cut)) {
			return (1);
		}
	}

	return (0);
}
#endif

void
vm_cheri_revoke_set_test(vm_map_t map, int flags)
{
	switch(flags) {
	case VM_CHERI_REVOKE_CF_NO_COARSE_MEM |
	    VM_CHERI_REVOKE_CF_NO_OTYPES |
	    VM_CHERI_REVOKE_CF_NO_CIDS:

		map->vm_cheri_revoke_test = vm_cheri_revoke_test_mem_fine_range;
		break;

	case VM_CHERI_REVOKE_CF_NO_COARSE_MEM |
	    VM_CHERI_REVOKE_CF_NO_OTYPES |
	    VM_CHERI_REVOKE_CF_NO_CIDS |
	    VM_CHERI_REVOKE_CF_NO_REV_ENTRY:

		map->vm_cheri_revoke_test = vm_cheri_revoke_test_just_mem_fine;
		break;

	case VM_CHERI_REVOKE_CF_NO_OTYPES |
	    VM_CHERI_REVOKE_CF_NO_CIDS |
	    VM_CHERI_REVOKE_CF_NO_REV_ENTRY:

		map->vm_cheri_revoke_test = vm_cheri_revoke_test_just_mem;
		break;

#ifdef CHERI_CAPREVOKE_POISON
	case VM_CHERI_REVOKE_CF_POISON:
	case VM_CHERI_REVOKE_CF_POISON | VM_CHERI_REVOKE_CF_NO_REV_ENTRY:

		map->vm_cheri_revoke_test = vm_cheri_revoke_test_poison;
		break;
#endif

	default:
		panic("Bad cheri_revoke cookie flags 0x%x\n", flags);
	}
}
