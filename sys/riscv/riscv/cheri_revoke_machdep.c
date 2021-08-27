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
#include <sys/sysent.h>
#include <cheri/revoke.h>

#include <machine/_inttypes.h>
#include <cheri/cheri.h>
#include <cheri/cheric.h>
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
	panic("%s; try rebuilding without CHERI_REVOKE_FAST_COPYIN",
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
		int ok;

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
		 * than an actual data failure, we might loop.
		 *
		 * Because revoked capabilities are still tagged, one might
		 * worry that this would reset the capdirty bits.  That's
		 * not true, tho', because we're storing via the direct
		 * mapping of physical memory.
		 */
again:
		__asm__ __volatile__ (
			"lr.c.cap %[cscratch], (%[cutp])\n\t"
			"cseqx %[ok], %[cscratch], %[cut]\n\t"
			"beq x0, %[ok], 1f\n\t"
			"sc.c.cap %[cutr], (%[cutp])\n\t"
			"1:\n\t"
		  : [ok] "=r" (ok), [cscratch] "=&C" (cscratch),
		    [cutr] "+C" (cutr)
		  : [cut] "C" (cut), [cutp] "C" (cutp)
		  : "memory");

		/* sc.c.cap clobbers its value operand with 0 on success */
		if (__builtin_expect((uintcap_t)cutr == 0, 1)) {
			CHERI_REVOKE_STATS_BUMP(crst, caps_cleared);
			/* Don't count a revoked cap as HASCAPS */
		} else if (!cheri_gettag(cscratch)) {
			/* Data; don't sweat it */
		} else if (cheri_revoke_is_revoked(cscratch)) {
			/* Revoked cap; don't worry about it */
		} else if (__builtin_expect(ok, 1)) {
			/* Spurious CAS failure */
			goto again;
		} else {
			/* An unexpected capability */
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
	uint64_t tmp;

	__asm __volatile (
		"li %[tmp], %[sum]\n\t"
		"csrs sstatus, %[tmp]\n\t"
	: // outputs
		[tmp] "=&r" (tmp)
	: // inputs
		[sum] "i" (SSTATUS_SUM)
	: // clobbers
		"memory"
	);
}

static inline void
disable_user_memory_access()
{
	uint64_t tmp;

	__asm __volatile (
		"li %[tmp], %[sum]\n\t"
		"csrc sstatus, %[tmp]\n\t"
	: // outputs
		[tmp] "=&r" (tmp)
	: // inputs
		[sum] "i" (SSTATUS_SUM)
	: // clobbers
		"memory"
	);
}

#ifdef CHERI_CAPREVOKE_CLOADTAGS
uint8_t cloadtags_stride;
SYSCTL_U8(_vm, OID_AUTO, cloadtags_stride, 0, &cloadtags_stride, 0, "XXX");

static void
measure_cloadtags_stride(void *ignored)
{
	(void)ignored;

	/* A 256-byte cache-line is probably beyond the pale, so use that */
	void * __capability buf[16] __attribute__((aligned(256)));
	int i;

	/* Fill with capabilities */
	for (i = 0; i < sizeof(buf)/sizeof(buf[0]); i++) {
		buf[i] = userspace_root_cap;
	}

	uint64_t tags = __builtin_cheri_cap_load_tags(buf);
	switch (tags) {
	case 0x0001:
		cloadtags_stride = 1;
		break;
	case 0x0003:
		cloadtags_stride = 2;
		break;
	case 0x000F:
		cloadtags_stride = 4;
		break;
	case 0x00FF:
		cloadtags_stride = 8;
		break;
	case 0xFFFF:
		cloadtags_stride = 16;
		break;
	default:
		panic("Bad cloadtags result 0x%" PRIx64, tags);
	}
}
SYSINIT(
    cloadtags_stride, SI_SUB_VM, SI_ORDER_ANY, measure_cloadtags_stride, NULL);
#endif

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
#ifdef CHERI_CAPREVOKE_CLOADTAGS
	CHERI_REVOKE_STATS_FOR(crst, crc);
#endif
	int res = 0;

	/* Load once up front, which is almost as good as const */
	vm_cheri_revoke_test_fn ctp = crc->map->vm_cheri_revoke_test;
	const uint8_t * __capability crshadow = crc->crshadow;
#ifdef CHERI_CAPREVOKE_CLOADTAGS
	uint8_t _cloadtags_stride = cloadtags_stride;
	uint64_t tags, nexttags;
#endif

#ifdef CHERI_CAPREVOKE_FAST_COPYIN
	curthread->td_pcb->pcb_onfault = (vm_offset_t)vm_cheri_revoke_tlb_fault;
	enable_user_memory_access();
#endif

#ifdef CHERI_CAPREVOKE_CLOADTAGS
	tags = __builtin_cheri_cap_load_tags(mvu);

	mve -= _cloadtags_stride * sizeof(void * __capability);

#ifdef CHERI_CAPREVOKE_STATS
	if (tags) {
		CHERI_REVOKE_STATS_BUMP(crst, lines_scan);
	}
#endif

	for (; cheri_getaddress(mvu) < mve; mvu += _cloadtags_stride) {
		uintcap_t * __capability mvt = mvu;

		nexttags =
		    __builtin_cheri_cap_load_tags(mvu + _cloadtags_stride);
		if (nexttags != 0) {
			/* TODO? CPREFETCH(mvu + _cloadtags_stride); */
			CHERI_REVOKE_STATS_BUMP(crst, lines_scan);
		}

		for (; tags != 0; (tags >>= 1), mvt += 1) {
			if (!(tags & 1))
				continue;

			if (cb(&res, crc, crshadow, ctp, mvt, *mvt))
				goto out;
		}

		tags = nexttags;
	}

	/* And the last line */
	{
		uintcap_t * __capability mvt = mvu;
		for (; tags != 0; (tags >>= 1), mvt += 1) {
			if (!(tags & 1))
				continue;

			if (cb(&res, crc, crshadow, ctp, mvt, *mvt))
				goto out;
		}
	}

#else /* no CLOADTAGS */
	/* TODO: lines_scan approximation for CHERI_REVOKE_STATS? */

	for (; cheri_getaddress(mvu) < mve; mvu++) {
		uintcap_t cut = *mvu;
		if (cheri_gettag(cut)) {
			if (cb(&res, crc, crshadow, ctp, mvu, cut))
				goto out;
		}
	}
#endif

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
	 * m is xbusy, which means it's not about to be reclaimed under us.  Go
	 * sweep via the DMAP.
	 */
	mva = PHYS_TO_DMAP(VM_PAGE_TO_PHYS(m));
	mve = mva + PAGE_SIZE;

	mvu = cheri_setbounds(cheri_setaddress(kdc, mva), PAGE_SIZE);

	res = vm_cheri_revoke_page_iter(crc, vm_do_cheri_revoke, mvu, mve);

	/*
	 * sc.c.cap in vm_do_cheri_revoke is always a relaxed atomic.
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
 * Like vm_cheri_revoke_page, but does not write to the page in question.  The
 * page may be in any state that prevents it from going away: xbusy or wired
 * (or, in principle, sbusy, but we don't use that right now).
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

	/*
	 * We have to be a little careful here: just because we're visiting the
	 * page R/O doesn't mean that it has *no* R/W mappings, just that we
	 * are trying to be "gentle" towards the VM and hoping that the page
	 * doesn't have to be modified for revocation.  Don't assert on page
	 * contents, for example!
	 */

	mva = PHYS_TO_DMAP(VM_PAGE_TO_PHYS(m));
	mve = mva + PAGE_SIZE;

	mvu = cheri_setbounds(cheri_setaddress(kdc, mva), PAGE_SIZE);

	res = vm_cheri_revoke_page_iter(crc, vm_cheri_revoke_page_ro_adapt, mvu,
	    mve);

	/*
	 * Unlike vm_cheri_revoke_page_rw, we don't need to do a fence here: we
	 * have not written anything to the page (either because we swept it
	 * successfully without needing to revoke anything or because we would
	 * have and we're headed towards upgrading the page to writable status.)
	 */

#ifdef CHERI_CAPREVOKE_STATS
	uint32_t cyc_end = get_cyclecount();
	crst->page_scan_cycles += cyc_end - cyc_start;
#endif

	return res;
}
