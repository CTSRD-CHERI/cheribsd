/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020-2021 Ruslan Bukin <br@bsdpad.com>
 * Copyright (c) 2014-2021 Andrew Turner
 * Copyright (c) 2014-2016 The FreeBSD Foundation
 * All rights reserved.
 *
 * This work was supported by Innovate UK project 105694, "Digital Security
 * by Design (DSbD) Technology Platform Prototype".
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

/*
 *	Manages physical address maps for IOMMU.
 */

#include <sys/param.h>
#include <sys/ktr.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/systm.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_pageout.h>
#include <vm/vm_radix.h>

#include <machine/machdep.h>

#include <riscv/iommu/iommu_pmap.h>
#include <riscv/iommu/iommu_pte.h>

#define	IOMMU_PAGE_SIZE		4096
#define	IOMMU_PAGE_SHIFT	12

#define	NUL1E		(IOMMU_Ln_ENTRIES * IOMMU_Ln_ENTRIES)
#define	NUL2E		(IOMMU_Ln_ENTRIES * NUL1E)

#define	pmap_l2_pindex(v)	((v) >> IOMMU_L2_SHIFT)

#define	pmap_clear(pte)			pmap_store(pte, 0)
#define	pmap_clear_bits(pte, bits)	atomic_clear_64(pte, bits)
#define	pmap_load_store(pte, entry)	atomic_swap_64(pte, entry)
#define	pmap_load_clear(pte)		pmap_load_store(pte, 0)
#define	pmap_load(pte)			atomic_load_64(pte)
#define	pmap_store(pte, entry)		atomic_store_64(pte, entry)
#define	pmap_store_bits(pte, bits)	atomic_set_64(pte, bits)

#define	PTE_TO_PHYS(pte) \
    ((((pte) & ~PTE_HI_MASK) >> PTE_PPN0_S) * IOMMU_PAGE_SIZE)
#define	L2PTE_TO_PHYS(l2) \
    ((((l2) & ~PTE_HI_MASK) >> PTE_PPN1_S) << IOMMU_L2_SHIFT)

/********************/
/* Inline functions */
/********************/

static __inline void
pagezero(void *p)
{

	bzero(p, IOMMU_PAGE_SIZE);
}

static __inline pd_entry_t *
pmap_l1(pmap_t pmap, vm_offset_t va)
{

	return (&pmap->pm_top[iommu_l1_index(va)]);
}

static __inline pd_entry_t *
pmap_l1_to_l2(pd_entry_t *l1, vm_offset_t va)
{
	vm_paddr_t phys;
	pd_entry_t *l2;

	phys = PTE_TO_PHYS(pmap_load(l1));
	l2 = (pd_entry_t *)PHYS_TO_DMAP(phys);

	return (&l2[iommu_l2_index(va)]);
}

static __inline pd_entry_t *
pmap_l2(pmap_t pmap, vm_offset_t va)
{
	pd_entry_t *l1;

	l1 = pmap_l1(pmap, va);
	if ((pmap_load(l1) & PTE_V) == 0)
		return (NULL);
	if ((pmap_load(l1) & PTE_RX) != 0)
		return (NULL);

	return (pmap_l1_to_l2(l1, va));
}

static __inline pt_entry_t *
pmap_l2_to_l3(pd_entry_t *l2, vm_offset_t va)
{
	vm_paddr_t phys;
	pt_entry_t *l3;

	phys = PTE_TO_PHYS(pmap_load(l2));
	l3 = (pd_entry_t *)PHYS_TO_DMAP(phys);

	return (&l3[iommu_l3_index(va)]);
}

static __inline pt_entry_t *
pmap_l3(pmap_t pmap, vm_offset_t va)
{
	pd_entry_t *l2;

	l2 = pmap_l2(pmap, va);
	if (l2 == NULL)
		return (NULL);
	if ((pmap_load(l2) & PTE_V) == 0)
		return (NULL);
	if ((pmap_load(l2) & PTE_RX) != 0)
		return (NULL);

	return (pmap_l2_to_l3(l2, va));
}

static __inline void
pmap_resident_count_inc(pmap_t pmap, int count)
{

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	pmap->pm_stats.resident_count += count;
}

static __inline void
pmap_resident_count_dec(pmap_t pmap, int count)
{

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	KASSERT(pmap->pm_stats.resident_count >= count,
	    ("pmap %p resident count underflow %ld %d", pmap,
	    pmap->pm_stats.resident_count, count));
	pmap->pm_stats.resident_count -= count;
}

static __inline int
pmap_l3_valid(pt_entry_t l3)
{

	return ((l3 & PTE_V) != 0);
}

/***************************************************
 * Pmap allocation/deallocation routines.
 ***************************************************/

/*
 * Release any resources held by the given physical map.
 * Called when a pmap initialized by pmap_pinit is being released.
 * Should only be called if the map contains no valid mappings.
 */
void
iommu_pmap_release(pmap_t pmap)
{
	vm_page_t m;

	KASSERT(pmap->pm_stats.resident_count == 0,
	    ("pmap_release: pmap resident count %ld != 0",
	    pmap->pm_stats.resident_count));

	m = PHYS_TO_VM_PAGE(DMAP_TO_PHYS((vm_offset_t)pmap->pm_top));
	vm_page_unwire_noq(m);
	vm_page_free(m);
}

int
iommu_pmap_pinit(pmap_t pmap)
{
	vm_paddr_t l1phys;
	vm_page_t l1pt;

	/*
	 * allocate the l1 page
	 */
	while ((l1pt = vm_page_alloc(NULL, 0xdeadbeef, VM_ALLOC_NORMAL |
	    VM_ALLOC_WIRED | VM_ALLOC_ZERO)) == NULL)
		vm_wait(NULL);

	l1phys = VM_PAGE_TO_PHYS(l1pt);
	pmap->pm_top = (pd_entry_t *)PHYS_TO_DMAP(l1phys);
	pmap->pm_satp = SATP_MODE_SV39 | (l1phys >> IOMMU_PAGE_SHIFT);

	if ((l1pt->flags & PG_ZERO) == 0)
		pagezero(pmap->pm_top);

	bzero(&pmap->pm_stats, sizeof(pmap->pm_stats));

	return (1);
}

/***************************************************
 * Page table page management routines.....
 ***************************************************/

/*
 * This routine is called if the desired page table page does not exist.
 *
 * If page table page allocation fails, this routine may sleep before
 * returning NULL.  It sleeps only if a lock pointer was given.
 *
 * Note: If a page allocation fails at page table level two or three,
 * one or two pages may be held during the wait, only to be released
 * afterwards.  This conservative approach is easily argued to avoid
 * race conditions.
 */
static vm_page_t
_pmap_alloc_l3(pmap_t pmap, vm_pindex_t ptepindex)
{
	vm_page_t m, /*pdppg, */pdpg;
	pt_entry_t entry;
	vm_paddr_t phys;
	pn_t pn;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);

	/*
	 * Allocate a page table page.
	 */
	if ((m = vm_page_alloc(NULL, ptepindex, 
	    VM_ALLOC_WIRED | VM_ALLOC_ZERO)) == NULL) {
		/*
		 * Indicate the need to retry.  While waiting, the page table
		 * page may have been allocated.
		 */
		return (NULL);
	}

	if ((m->flags & PG_ZERO) == 0)
		pmap_zero_page(m);

	/*
	 * Map the pagetable page into the process address space, if
	 * it isn't already there.
	 */

	if (ptepindex >= NUL1E) {
		pd_entry_t *l1;
		vm_pindex_t l1index;

		l1index = ptepindex - NUL1E;
		l1 = &pmap->pm_top[l1index];

		pn = (VM_PAGE_TO_PHYS(m) / IOMMU_PAGE_SIZE);
		entry = (PTE_V);
		entry |= (pn << PTE_PPN0_S);
		pmap_store(l1, entry);
	} else {
		vm_pindex_t l1index;
		pd_entry_t *l1, *l2;

		l1index = ptepindex >> (IOMMU_L1_SHIFT - IOMMU_L2_SHIFT);
		l1 = &pmap->pm_top[l1index];
		if (pmap_load(l1) == 0) {
			/* recurse for allocating page dir */
			if (_pmap_alloc_l3(pmap, NUL1E + l1index) == NULL) {
				vm_page_unwire_noq(m);
				vm_page_free_zero(m);
				return (NULL);
			}
		} else {
			phys = PTE_TO_PHYS(pmap_load(l1));
			pdpg = PHYS_TO_VM_PAGE(phys);
			pdpg->ref_count++;
		}

		phys = PTE_TO_PHYS(pmap_load(l1));
		l2 = (pd_entry_t *)PHYS_TO_DMAP(phys);
		l2 = &l2[ptepindex & IOMMU_Ln_ADDR_MASK];

		pn = (VM_PAGE_TO_PHYS(m) / IOMMU_PAGE_SIZE);
		entry = (PTE_V);
		entry |= (pn << PTE_PPN0_S);
		pmap_store(l2, entry);
	}

	pmap_resident_count_inc(pmap, 1);

	return (m);
}

/*
 * Add a single Device-Model entry. This function does not sleep.
 */
int
pmap_dm_enter(pmap_t pmap, vm_offset_t va, vm_paddr_t pa, vm_prot_t prot)
{
	pd_entry_t *l2, *l3;
	pt_entry_t new_l3, orig_l3;
	pn_t pn;
	int rv;
	vm_pindex_t l2pindex;
	vm_page_t l2pg;

	va = trunc_page(va);
	pn = (pa / IOMMU_PAGE_SIZE);

	new_l3 = PTE_V | PTE_R | PTE_A;
	if (prot & VM_PROT_EXECUTE)
		new_l3 |= PTE_X;
	if (prot & VM_PROT_WRITE)
		new_l3 |= PTE_W;
	if (va < VM_MAX_USER_ADDRESS)
		new_l3 |= PTE_U;
#if __has_feature(capabilities)
	if (prot & VM_PROT_READ_CAP)
		new_l3 |= PTE_CR;
	if (prot & VM_PROT_WRITE_CAP)
		new_l3 |= PTE_CW | PTE_CD;
#endif

	new_l3 |= (pn << PTE_PPN0_S);

	CTR2(KTR_PMAP, "pmap_dm_enter: %.16lx -> %.16lx", va, pa);

	PMAP_LOCK(pmap);

retry:
	l2 = pmap_l2(pmap, va);
	if (l2 != NULL && pmap_load(l2) != 0) {
		l3 = pmap_l2_to_l3(l2, va);
	} else {
		/* Allocate a L2 page. */
		l2pindex = pmap_l2_pindex(va);
		l2pg = _pmap_alloc_l3(pmap, l2pindex);
		if (l2pg == NULL) {
			CTR0(KTR_PMAP, "pmap_enter: l2pg == NULL");
			rv = KERN_RESOURCE_SHORTAGE;
			goto out;
		}
		goto retry;
	}

	orig_l3 = pmap_load(l3);
	KASSERT(!pmap_l3_valid(orig_l3), ("l3 is valid"));

	/* New mapping */
	pmap_store(l3, new_l3);
	pmap_resident_count_inc(pmap, 1);

	rv = KERN_SUCCESS;
out:
	PMAP_UNLOCK(pmap);

	return (rv);
}

/*
 * Remove a single Device-Model entry.
 */
int
pmap_dm_remove(pmap_t pmap, vm_offset_t va)
{
	pd_entry_t *l3;
	int rv;

	PMAP_LOCK(pmap);

	l3 = pmap_l3(pmap, va);
	if (l3 != NULL) {
		pmap_resident_count_dec(pmap, 1);
		pmap_clear(l3);
		rv = KERN_SUCCESS;
	} else
		rv = KERN_FAILURE;

	PMAP_UNLOCK(pmap);

	return (rv);
}

/*
 * Remove all the allocated L1, L2 pages from iommu pmap.
 * All the L3 entires must be cleared in advance, otherwise
 * this function panics.
 */
void
iommu_pmap_remove_pages(pmap_t pmap)
{
	pd_entry_t l1e, *l2, l2e;
	pt_entry_t *l3, l3e;
	vm_page_t m, m1;
	vm_offset_t sva;
	vm_paddr_t pa;
	vm_paddr_t pa1;
	int i, j, k;

	PMAP_LOCK(pmap);

	for (sva = VM_MINUSER_ADDRESS, i = iommu_l1_index(sva);
	    (i < IOMMU_Ln_ENTRIES && sva < VM_MAXUSER_ADDRESS); i++) {
		l1e = pmap->pm_top[i];
		if ((l1e & PTE_V) == 0) {
			sva += IOMMU_L1_SIZE;
			continue;
		}
		if ((l1e & PTE_RWX) != 0) {
			sva += IOMMU_L1_SIZE;
			continue;
		}
		pa1 = PTE_TO_PHYS(l1e);
		m1 = PHYS_TO_VM_PAGE(pa1);
		l2 = (pd_entry_t *)PHYS_TO_DMAP(pa);

		for (j = iommu_l2_index(sva); j < IOMMU_Ln_ENTRIES; j++) {
			l2e = l2[j];
			if ((l2e & PTE_V) == 0) {
				sva += IOMMU_L2_SIZE;
				continue;
			}
			pa = PTE_TO_PHYS(l2e);
			m = PHYS_TO_VM_PAGE(pa);
			l3 = (pd_entry_t *)PHYS_TO_DMAP(pa);

			for (k = iommu_l3_index(sva); k < IOMMU_Ln_ENTRIES; k++,
			    sva += IOMMU_L3_SIZE) {
				l3e = l3[k];
				if ((l3e & PTE_V) == 0)
					continue;
				panic("%s: l3e found for va %jx\n",
				    __func__, sva);
			}

			vm_page_unwire_noq(m1);
			vm_page_unwire_noq(m);
			pmap_resident_count_dec(pmap, 1);
			vm_page_free(m);
			pmap_clear(&l2[j]);
		}

		pmap_resident_count_dec(pmap, 1);
		vm_page_free(m1);
		pmap_clear(&pmap->pm_top[i]);
	}

	KASSERT(pmap->pm_stats.resident_count == 0,
	    ("Invalid resident count %jd", pmap->pm_stats.resident_count));

	PMAP_UNLOCK(pmap);
}
