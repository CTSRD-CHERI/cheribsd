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
#include <sys/caprevoke.h>

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
#include <vm/vm_caprevoke.h>

/*
 * Map a capability revocation shadow
 */
int
vm_map_install_caprevoke_shadow(vm_map_t map)
{
	int error = KERN_SUCCESS;
	vm_object_t vmo;
	vm_offset_t start = VM_CAPREVOKE_BM_BASE;
	vm_offset_t end = VM_CAPREVOKE_BM_TOP;

	vmo = vm_object_allocate(OBJT_DEFAULT, end - start);

	vm_map_lock(map);

	if (map->vm_caprev_sh != NULL) {
		error = KERN_PROTECTION_FAILURE;
		goto out;
	}

	error = vm_map_insert(map, vmo, 0, start, end,
				VM_PROT_READ | VM_PROT_WRITE,
				VM_PROT_READ | VM_PROT_WRITE,
				0, start);

	if (error != KERN_SUCCESS) {
		goto out;
	}

	map->vm_caprev_sh = vmo;
	map->vm_caprev_shva = start;

out:
	vm_map_unlock(map);

	if (error) {
		vm_object_deallocate(vmo);
	}
	return error;
}

void
vm_caprevoke_publish(struct caprevoke_info_page * __capability info_page,
    const struct caprevoke_info *ip)
{
	int res = copyoutcap(ip, &info_page->pub, sizeof(*ip));
	KASSERT(res == 0, ("vm_caprevoke_publish: bad copyout %d\n", res));
	(void)res;
}

/*
 * Grant access to a capability shadow
 */
void * __capability
vm_caprevoke_shadow_cap(int sel, vm_offset_t base, vm_offset_t size, int pmask)
{
	switch (sel) {
	/* Accessible to userspace */
	case CAPREVOKE_SHADOW_NOVMMAP: {
		vm_offset_t shadow_base, shadow_size;

		/* Require at least byte granularity in the shadow space */
		if ((base & ((VM_CAPREVOKE_GSZ_MEM_NOMAP * 8) - 1)) != 0)
			return (void * __capability)(uintptr_t)EINVAL;
		if ((size & ((VM_CAPREVOKE_GSZ_MEM_NOMAP * 8) - 1)) != 0)
			return (void * __capability)(uintptr_t)EINVAL;

		shadow_base = VM_CAPREVOKE_BM_MEM_NOMAP +
		    (base / VM_CAPREVOKE_GSZ_MEM_NOMAP / 8);
		shadow_size = size / VM_CAPREVOKE_GSZ_MEM_NOMAP / 8;

		return cheri_capability_build_user_data(
		    (pmask & (CHERI_PERM_LOAD | CHERI_PERM_STORE)) |
			CHERI_PERM_GLOBAL,
		    shadow_base, shadow_size, 0);
	}
	case CAPREVOKE_SHADOW_OTYPE: {
		vm_offset_t shadow_base, shadow_size;

		shadow_base =
		    VM_CAPREVOKE_BM_OTYPE + (base / VM_CAPREVOKE_GSZ_OTYPE / 8);
		shadow_size = size / VM_CAPREVOKE_GSZ_OTYPE / 8;

		/* Require at least byte granularity in the shadow space */
		if ((base & ((VM_CAPREVOKE_GSZ_OTYPE * 8) - 1)) != 0)
			return (void * __capability)(uintptr_t)EINVAL;
		if ((size & ((VM_CAPREVOKE_GSZ_OTYPE * 8) - 1)) != 0)
			return (void * __capability)(uintptr_t)EINVAL;

		return cheri_capability_build_user_data(
		    CHERI_PERM_LOAD | CHERI_PERM_STORE | CHERI_PERM_GLOBAL,
		    shadow_base, shadow_size, 0);
	}
	case CAPREVOKE_SHADOW_INFO_STRUCT: {
		return cheri_capability_build_user_data(
		    CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP | CHERI_PERM_GLOBAL,
		    VM_CAPREVOKE_INFO_PAGE, sizeof(struct caprevoke_info), 0);
	}
	case CAPREVOKE_SHADOW_NOVMMAP_ENTIRE: {
		return cheri_capability_build_user_data(
		    CHERI_PERM_LOAD | CHERI_PERM_STORE | CHERI_PERM_GLOBAL,
		    VM_CAPREVOKE_BM_MEM_NOMAP, VM_CAPREVOKE_BSZ_MEM_NOMAP, 0);
	}
	/* Kernel-only */
	// XXX CAPREVOKE_SHADOW_MAP:
	//
	default:
		return (void * __capability)(uintptr_t)EINVAL;
	}
}

void
vm_caprevoke_info_page(struct vm_map *map,
    struct caprevoke_info_page * __capability *ifp)
{
	/* XXX In prinicple, it could work cross-process, but not yet */
	KASSERT(map == &curthread->td_proc->p_vmspace->vm_map,
		("vm_caprevoke_page_info req. intraprocess work right now"));

	*ifp = cheri_capability_build_user_data(CHERI_PERM_LOAD |
		CHERI_PERM_LOAD_CAP | CHERI_PERM_STORE | CHERI_PERM_STORE_CAP |
		CHERI_PERM_GLOBAL,
	    VM_CAPREVOKE_INFO_PAGE, PAGE_SIZE, 0);
}

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
vm_caprevoke_tlb_fault(void)
{
	panic(__FUNCTION__);
}

/*
 * VM internal support for revocation
 */

/*
 * The Capability Under Test Pointer needs to be a capability because we
 * don't have a LLC instruction, just a CLLC one.
 */
static int
vm_do_caprevoke(int *res, const struct vm_caprevoke_cookie *crc,
    const uint8_t * __capability crshadow, vm_caprevoke_test_fn ctp,
    uintcap_t * __capability cutp, uintcap_t cut)
{
	int perms = cheri_getperm(cut);
	CAPREVOKE_STATS_FOR(crst, crc);

	if (perms == 0) {
		/* For revoked or permissionless caps, do nothing. */

		/*
		 * XXX technically, a sealed permissionless thing is a
		 * bearer token, but that's not really something we use.  We
		 * should probably insist that people don't; keep one sw bit
		 * set or something.
		 */

		CAPREVOKE_STATS_BUMP(crst, caps_found_revoked);
	} else if (cheri_gettag(cut) && ctp(crshadow, cut, perms)) {
		void * __capability cscratch;
		int ok;

		uintcap_t cutr = cheri_revoke(cut);

		CAPREVOKE_STATS_BUMP(crst, caps_found);

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
		__asm__ __volatile__ (
			".set push\n\t"
			".set noreorder\n\t"
			"cllc %[cscratch], %[cutp]\n\t"
			"cexeq %[ok], %[cscratch], %[cut]\n\t"
			"beqz %[ok], 1f\n\t"
			"nop\n\t"
			"cscc %[ok], %[cutr], %[cutp]\n\t"
			"1:\n\t"
			".set pop\n\t"
		  : [ok] "=r" (ok), [cscratch] "=&C" (cscratch)
		  : [cut] "C" (cut), [cutp] "C" (cutp), [cutr] "C" (cutr)
		  : "memory");

		if (__builtin_expect(ok, 1)) {
			CAPREVOKE_STATS_BUMP(crst, caps_cleared);
			/* Don't count a revoked cap as HASCAPS */
		} else if (!cheri_gettag(cscratch)) {
			/* Data; don't sweat it */
		} else if (caprevoke_is_revoked(cscratch)) {
			/* Revoked cap; don't worry about it */
		} else if ((uintcap_t)cscratch == cut) {
			/*
			 * Spurious CAS failure; go again.
			 *
			 * XXX It's a little sad that we have to repeat the test
			 * that the assembler just performed.  Is there a better
			 * way?
			 */
			goto again;
		} else {
			/* An unexpected capability!  Flag us as dirty */
			*res |= VM_CAPREVOKE_PAGE_DIRTY |
			     VM_CAPREVOKE_PAGE_HASCAPS;
		}
	} else {
		CAPREVOKE_STATS_BUMP(crst, caps_found);

		/*
		 * Even though it might actually be un-tagged, that's a very
		 * narrow race and this a very common case, so don't bother
		 * testing.  We'll find it clear next time, maybe.
		 */
		*res |= VM_CAPREVOKE_PAGE_HASCAPS;
	}

	return 0;
}

#ifdef CHERI_CAPREVOKE_CLOADTAGS
uint8_t cloadtags_stride;
SYSCTL_U8(_vm, OID_AUTO, cloadtags_stride, 0, &cloadtags_stride, 0, "XXX");

static void
measure_cloadtags_stride(void *ignored)
{
	(void)ignored;

	void * __capability buf[64] __attribute__((aligned(PAGE_SIZE)));
	int i;

	/* Fill with capabilities */
	for (i = 0; i < 64; i++) {
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

#if 0
/* We expect loads and no stores, thus hint 4 */
#define CPREFETCH(c)                                           \
	__asm__ __volatile__("pref 4, 0(%[addr])\n\t"          \
			     : /* no out */                    \
			     : [addr] "r"(cheri_getaddress(c)) \
			     : /* no clobber */)
#else
#define CPREFETCH(c) do {} while(0)
#endif

static inline int
vm_caprevoke_page_iter(const struct vm_caprevoke_cookie *crc,
    int (*cb)(int *, const struct vm_caprevoke_cookie *,
	const uint8_t * __capability, vm_caprevoke_test_fn,
	uintcap_t * __capability, uintcap_t),
    uintcap_t * __capability mvu, vm_offset_t mve)
{
	CAPREVOKE_STATS_FOR(crst, crc);

	int res = 0;

	/* Load once up front, which is almost as good as const */
#ifdef CHERI_CAPREVOKE_CLOADTAGS
	uint8_t _cloadtags_stride = cloadtags_stride;
#endif
	vm_caprevoke_test_fn ctp = crc->map->vm_caprev_test;
	const uint8_t * __capability crshadow = crc->crshadow;

	curthread->td_pcb->pcb_onfault = vm_caprevoke_tlb_fault;

#ifdef CHERI_CAPREVOKE_CLOADTAGS
	uint64_t tags, nexttags;

	tags = __builtin_cheri_cap_load_tags(mvu);

	mve -= _cloadtags_stride * sizeof(void * __capability);

#ifdef CHERI_CAPREVOKE_STATS
	if (tags) {
		CAPREVOKE_STATS_BUMP(crst, lines_scan);
	}
#endif

	for (; cheri_getaddress(mvu) < mve; mvu += _cloadtags_stride) {
		uintcap_t * __capability mvt = mvu;

		nexttags =
		    __builtin_cheri_cap_load_tags(mvu + _cloadtags_stride);
		if (nexttags != 0) {
			CPREFETCH(mvu + _cloadtags_stride);
			CAPREVOKE_STATS_BUMP(crst, lines_scan);
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
#else
#ifdef CHERI_CAPREVOKE_STATS
	int seentag = 0;
#endif
	for (; cheri_getaddress(mvu) < mve; mvu += 8) {
		void * __capability * __capability mvt = mvu;

		for (int i = 0; i < 8; i++, mvt++) {
			void * __capability cut = *mvt;
			if (cheri_gettag(cut)) {
#ifdef CHERI_CAPREVOKE_STATS
				seentag++;
#endif
				if (cb(&res, crc, crshadow, ctp, mvt, cut))
					goto out;
			}
		}
	}
#ifdef CHERI_CAPREVOKE_STATS
	if (seentag) {
		CAPREVOKE_STATS_BUMP(crst, lines_scan);
	}
#endif
#endif

out:
	curthread->td_pcb->pcb_onfault = NULL;
	return res;
}

int
vm_caprevoke_test(const struct vm_caprevoke_cookie *crc, uintcap_t cut)
{
	if (cheri_gettag(cut)) {
		int res;
		curthread->td_pcb->pcb_onfault = vm_caprevoke_tlb_fault;
		res = crc->map->vm_caprev_test(crc->crshadow, cut,
		    cheri_getperm(cut));
		curthread->td_pcb->pcb_onfault = NULL;
		return res;
	}

	return 0;
}

int
vm_caprevoke_page_rw(const struct vm_caprevoke_cookie *crc, vm_page_t m)
{
#ifdef CHERI_CAPREVOKE_STATS
	CAPREVOKE_STATS_FOR(crst, crc);
	uint32_t cyc_start = get_cyclecount();
#endif

	vm_paddr_t mpa = VM_PAGE_TO_PHYS(m);
	vm_offset_t mva;
	vm_offset_t mve;
	uintcap_t * __capability mvu;
	/* XXX NWF Is this what we want? */
	void * __capability kdc = cheri_getkdc();
	int res = 0;

	/*
	 * XXX NWF
	 * Hopefully m being xbusy'd means it's not about to go away on us.
	 * I don't yet understand all the interlocks in the vm subsystem.
	 */
	KASSERT(
	    MIPS_DIRECT_MAPPABLE(mpa), ("Revoke not directly map swept page?"));
	mva = MIPS_PHYS_TO_DIRECT(mpa);
	mve = mva + pagesizes[m->psind];

	mvu = cheri_setbounds(cheri_setaddress(kdc, mva), pagesizes[m->psind]);

	res = vm_caprevoke_page_iter(crc, vm_do_caprevoke, mvu, mve);

#ifdef CHERI_CAPREVOKE_STATS
	uint32_t cyc_end = get_cyclecount();
	CAPREVOKE_STATS_INC(crst, page_scan_cycles, cyc_end - cyc_start);
#endif

	return res;
}

static inline int
vm_caprevoke_page_ro_adapt(int *res, const struct vm_caprevoke_cookie *vmcrc,
    const uint8_t * __capability crshadow, vm_caprevoke_test_fn ctp,
    uintcap_t * __capability cutp, uintcap_t cut)
{
	(void)cutp;

	/*
	 * Being untagged would imply mutation, but we're visiting this page
	 * under the assumption that it's read-only.
	 */
	KASSERT(cheri_gettag(cut), ("vm_caprevoke_page_ro_adapt untagged"));

	/* If the thing has no permissions, we don't need to scan it later */
	if (cheri_getperm(cut) == 0)
		return 0;

	*res |= VM_CAPREVOKE_PAGE_HASCAPS;

	if (ctp(crshadow, cut, cheri_getperm(cut))) {
		*res |= VM_CAPREVOKE_PAGE_DIRTY;

		/* One dirty answer is as good as any other; stop eary */
		return 1;
	}

	return 0;
}

/*
 * Like vm_caprevoke_page, but does not write to the page in question
 *
 * VM_CAPREVOKE_PAGE_DIRTY in the result means that we would like to store
 * back, but can't, rather than that we lost a LL/SC race.  We will return
 * early if this becomes set: there's no reason to continue probing once we
 * know the answer.
 *
 * VM_CAPREVOKE_PAGE_HASCAPS continues to mean what it meant before: we
 * saw at least one, permission-bearing capability on this page.
 */
int
vm_caprevoke_page_ro(const struct vm_caprevoke_cookie *crc, vm_page_t m)
{
#ifdef CHERI_CAPREVOKE_STATS
	uint32_t cyc_start = get_cyclecount();
	CAPREVOKE_STATS_FOR(crst, crc);
#endif

	vm_paddr_t mpa = VM_PAGE_TO_PHYS(m);
	vm_offset_t mva;
	vm_offset_t mve;
	uintcap_t * __capability mvu;
	void * __capability kdc = cheri_getkdc();
	int res = 0;

	KASSERT(
	    MIPS_DIRECT_MAPPABLE(mpa), ("Revoke not directly map swept page?"));
	mva = MIPS_PHYS_TO_DIRECT(mpa);
	mve = mva + pagesizes[m->psind];

	mvu = cheri_setbounds(cheri_setaddress(kdc, mva), pagesizes[m->psind]);

	res = vm_caprevoke_page_iter(crc, vm_caprevoke_page_ro_adapt, mvu, mve);

#ifdef CHERI_CAPREVOKE_STATS
	uint32_t cyc_end = get_cyclecount();
	CAPREVOKE_STATS_INC(crst, page_scan_cycles, cyc_end - cyc_start);
#endif

	return res;
}
