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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/unistd.h>
#include <sys/proc.h>

#include <machine/_inttypes.h>
#include <cheri/cheri.h>
#include <cheri/cheric.h>
#include <cheri/revoke.h>
#include <machine/pcb.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_param.h>
#include <vm/vm_cheri_revoke.h>

/*
 * Revocation test predicates
 */

/*
 * Here's a wildly dangerous thing to do: we know the shadow is inside a
 * completely valid map... so even if this faults, the usual ZFOD handling
 * will kick in.
 *
 * We can therefore install this somewhat dubious function as the fault
 * handler before we sweep a page, which we do physically, so that we can
 * access the virtual pages of the shadow bitmap.  YIKES!
 *
 * Why do this?  Because it beats installing and uninstalling the
 * ->pcb_onfault for every capability we find in the page.
 *
 * Why only for each page?  Because a large amount of kernel code runs
 * between each page scanned and while, in principle, none of that should be
 * accessing user maps... I would much rather a performance hit than
 * accidentally leave an onfault handler registered when we went back to
 * userland!
 */
static void
vm_cheri_revoke_tlb_fault(void)
{
	panic("%s; try rebuilding without CHERI_CAPREVOKE_FAST_COPYIN",
		__FUNCTION__);
}

/*
 * VM internal support for revocation
 */

static int
vm_do_cheri_revoke(int *res,
		const struct vm_cheri_revoke_cookie *crc,
		const uint8_t * __capability crshadow,
		vm_cheri_revoke_test_fn ctp,
		uintcap_t * __capability cutp,
		uintcap_t cut)
{
	int perms = cheri_getperm(cut);
	CHERI_REVOKE_STATS_FOR(crst, crc);

	if (perms == 0) {
		/* For revoked or permissionless caps, do nothing. */

		/*
		 * XXX technically, a sealed permissionless thing is a
		 * bearer token, but that's not really something we use.  We
		 * should probably insist that people don't; keep one sw bit
		 * set or something.
		 */

		CHERI_REVOKE_STATS_BUMP(crst, caps_found_revoked);
	} else if (cheri_gettag(cut) && ctp(crshadow, cut, perms)) {
		void * __capability cscratch;
		int stxr_status;

		uintcap_t cutr = cheri_revoke_cap(cut);

		CHERI_REVOKE_STATS_BUMP(crst, caps_found);

		/*
		 * Load-link the position under test; verify that it matches
		 * our previous load; store conditionally the revoked
		 * version back.  If the verification fails, don't try
		 * anything fancy, just modify the return value to flag the
		 * page as dirty.
		 *
		 * It's possible that this CAS will fail because the pointer
		 * has changed during our test.  That's fine, if this is not
		 * a stop-the-world scan; we'll catch it in the next go
		 * around.  However, because CAS can fail for reasons other
		 * than an actual data failure, return an indicator that the
		 * page should not be considered clean.
		 *
		 * Because revoked capabilities are still tagged, one might
		 * worry that this would reset the capdirty bits.  That's
		 * not true, tho', because we're storing via the direct
		 * mapping of physical memory.
		 */
again:
		/*
		 * stxr returns 0 or 1, so use a value of 2
		 * to indicate that it was not executed.
		 */
		stxr_status = 2;

		__asm__ __volatile__ (
#ifndef __CHERI_PURE_CAPABILITY__
			"bx #4\n\t"
			".arch_extension c64\n\t"
#endif
			"ldxr %[cscratch], [%[cutp]]\n\t"
			"cmp %[cscratch], %[cut]\n\t"
			"bne 1f\n\t"
			"stxr %w[stxr_status], %[cutr], [%[cutp]]\n\t"
			"1:\n\t"
#ifndef __CHERI_PURE_CAPABILITY__
			"bx #4\n\t"
			".arch_extension noc64\n\t"
			".arch_extension a64c\n\t"
#endif
		  : [stxr_status] "=r" (stxr_status),
		    [cscratch] "=&C" (cscratch), [cutr] "+C" (cutr)
		  : [cut] "C" (cut), [cutp] "C" (cutp)
		  : "memory");

		/* stxr returns 0 on success */
		if (__builtin_expect(stxr_status == 0, 1)) {
			CHERI_REVOKE_STATS_BUMP(crst, caps_cleared);
			/* Don't count a revoked cap as HASCAPS */
		} else if (!cheri_gettag(cscratch)) {
			/* Data; don't sweat it */
		} else if (cheri_revoke_is_revoked(cscratch)) {
			/* Revoked cap; don't worry about it */
		} else if (__builtin_expect(stxr_status == 1, 1)) {
			/* stxr returns 1 on failure */
			goto again;
		} else {
			/*
			 * An unexpected capability - stxr_status was neither 0
			 * nor 1, which means that the stxr wasn't executed and
			 * so the capability at cutp has changed.
			 */
			*res |= VM_CHERI_REVOKE_PAGE_DIRTY
				| VM_CHERI_REVOKE_PAGE_HASCAPS ;
		}
	} else {
		CHERI_REVOKE_STATS_BUMP(crst, caps_found);

		/*
		 * Even though it might actually be un-tagged, that's a very
		 * narrow race and this a very common case, so don't bother
		 * testing.  We'll find it clear next time, maybe.
		 */
		*res |= VM_CHERI_REVOKE_PAGE_HASCAPS;
	}

	return 0;
}

static inline void
enable_user_memory_access()
{
	/* Set PSTATE.PAN to 0 */
	__asm __volatile("msr pan, #0");
}

static inline void
disable_user_memory_access()
{
	/* Set PSTATE.PAN to 1 */
	__asm __volatile("msr pan, #1");
}

// TODO: cloadtags stride (copy from mips)

// TODO: CPREFETCH()

static inline int
vm_cheri_revoke_page_iter(const struct vm_cheri_revoke_cookie *crc,
		       int (*cb)(int *, const struct vm_cheri_revoke_cookie *,
				 const uint8_t * __capability,
				 vm_cheri_revoke_test_fn,
				 uintcap_t * __capability,
				 uintcap_t),
		       uintcap_t * __capability mvu,
		       vm_offset_t mve)
{
	int res = 0;

	/* Load once up front, which is almost as good as const */
	vm_cheri_revoke_test_fn ctp = crc->map->vm_cheri_revoke_test;
	const uint8_t * __capability crshadow = crc->crshadow;

#ifdef CHERI_CAPREVOKE_FAST_COPYIN
	curthread->td_pcb->pcb_onfault = (vm_offset_t)vm_cheri_revoke_tlb_fault;
	enable_user_memory_access();
#endif

	for (; cheri_getaddress(mvu) < mve; mvu++) {
		uintcap_t cut = *mvu;
		if (cheri_gettag(cut)) {
			if (cb(&res, crc, crshadow, ctp, mvu, cut))
				goto out;
		}
	}

out:
#ifdef CHERI_CAPREVOKE_FAST_COPYIN
	disable_user_memory_access();
	curthread->td_pcb->pcb_onfault = 0;
#endif
	return res;
}

int
vm_cheri_revoke_test(const struct vm_cheri_revoke_cookie *crc, uintcap_t cut)
{
	if (cheri_gettag(cut)) {
		int res;
#ifdef CHERI_CAPREVOKE_FAST_COPYIN
		curthread->td_pcb->pcb_onfault =
		    (vm_offset_t)vm_cheri_revoke_tlb_fault;
		enable_user_memory_access();
#endif
		res = crc->map->vm_cheri_revoke_test(crc->crshadow, cut,
		    cheri_getperm(cut));
#ifdef CHERI_CAPREVOKE_FAST_COPYIN
		disable_user_memory_access();
		curthread->td_pcb->pcb_onfault = 0;
#endif
		return res;
	}

	return 0;
}

int
vm_cheri_revoke_page_rw(const struct vm_cheri_revoke_cookie *crc, vm_page_t m)
{
#ifdef CHERI_CAPREVOKE_STATS
	CHERI_REVOKE_STATS_FOR(crst, crc);
	uint32_t cyc_start = get_cyclecount();
#endif

	vm_offset_t mva;
	vm_offset_t mve;
	uintcap_t * __capability mvu;

	/*
	 * XXX NWF
	 * This isn't what we really want, but we want to be able to fake up a
	 * a capability to the DMAP area somehow.  (Right now, the kernel's
	 * hybrid so we could use the integer+DDC-authorized capability
	 * atomics, but probably best not.)
	 */
	void * __capability kdc = swap_restore_cap;

	int res = 0;

	/*
	 * XXX NWF
	 * Hopefully m being xbusy'd means it's not about to go away on us.
	 * I don't yet understand all the interlocks in the vm subsystem.
	 */
	mva = PHYS_TO_DMAP(VM_PAGE_TO_PHYS(m));
	mve = mva + pagesizes[0];

	mvu = cheri_setbounds(cheri_setaddress(kdc, mva), pagesizes[0]);

	res = vm_cheri_revoke_page_iter(crc, vm_do_cheri_revoke, mvu, mve);

	/*
	 * stxr in vm_do_cheri_revoke is always a relaxed atomic.
	 * Flush our store buffer before we update anything about this page
	 */
	wmb();

#ifdef CHERI_CAPREVOKE_STATS
	uint32_t cyc_end = get_cyclecount();
	CHERI_REVOKE_STATS_INC(crst, page_scan_cycles, cyc_end - cyc_start);
#endif

	return res;
}

static inline int
vm_cheri_revoke_page_ro_adapt(int *res,
			   const struct vm_cheri_revoke_cookie *vmcrc,
		           const uint8_t * __capability crshadow,
			   vm_cheri_revoke_test_fn ctp,
			   uintcap_t * __capability cutp,
			   uintcap_t cut)
{
	(void)cutp;

	/*
	 * Being untagged would imply mutation, but we're visiting this page
	 * under the assumption that it's read-only.
	 */
	KASSERT(cheri_gettag(cut), ("vm_cheri_revoke_page_ro_adapt untagged"));

	/* If the thing has no permissions, we don't need to scan it later */
	if ((cheri_gettag(cut) == 0) || (cheri_getperm(cut) == 0))
		return 0;

	*res |= VM_CHERI_REVOKE_PAGE_HASCAPS;

	if (ctp(crshadow, cut, cheri_getperm(cut))) {
		*res |= VM_CHERI_REVOKE_PAGE_DIRTY;

		/* One dirty answer is as good as any other; stop eary */
		return 1;
	}

	return 0;
}

/*
 * Like vm_cheri_revoke_page, but does not write to the page in question
 *
 * VM_CHERI_REVOKE_PAGE_DIRTY in the result means that we would like to store
 * back, but can't, rather than that we lost a LL/SC race.  We will return
 * early if this becomes set: there's no reason to continue probing once we
 * know the answer.
 *
 * VM_CHERI_REVOKE_PAGE_HASCAPS continues to mean what it meant before: we
 * saw at least one, permission-bearing capability on this page.
 */
int
vm_cheri_revoke_page_ro(const struct vm_cheri_revoke_cookie *crc, vm_page_t m)
{
#ifdef CHERI_CAPREVOKE_STATS
	uint32_t cyc_start = get_cyclecount();
	CHERI_REVOKE_STATS_FOR(crst, crc);
#endif

	vm_offset_t mva;
	vm_offset_t mve;
	uintcap_t * __capability mvu;
	void * __capability kdc = swap_restore_cap;
	int res = 0;

	mva = PHYS_TO_DMAP(VM_PAGE_TO_PHYS(m));
	mve = mva + pagesizes[0];

	mvu = cheri_setbounds(cheri_setaddress(kdc, mva), pagesizes[0]);

	res = vm_cheri_revoke_page_iter(crc, vm_cheri_revoke_page_ro_adapt, mvu,
	    mve);

	/*
	 * Unlike vm_cheri_revoke_page, we don't need to do a fence here: either
	 * we haven't written to the page, and so there's nothing relevant in
	 * our store buffer, or we're bailing out to upgrade the page to
	 * writeable status.
	 */

#ifdef CHERI_CAPREVOKE_STATS
	uint32_t cyc_end = get_cyclecount();
	crst->page_scan_cycles += cyc_end - cyc_start;
#endif

	return res;
}
