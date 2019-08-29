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
#include <sys/caprevoke.h>

#include <machine/_inttypes.h>
#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_param.h>
#include <vm/vm_caprevoke.h>

static inline int
vm_test_caprevoke_mem(const struct vm_caprevoke_cookie *crc,
		      const void * __capability cut)
{
	/*
	 * Find appropriate bitmap bits.  We use the base so that even if
	 * the cursor is out of bounds, we find the true status of the
	 * allocation under test.
	 */

	vm_offset_t va = cheri_getbase(cut);

	/*
	 * All capabilities are checked against the coarse MAP bitmap, unless
	 * we're instructed not to, as we might be if we know that there are
	 * no bits set anywhere in that map.  Since this map is under the
	 * kernel's control, this is a reasonable possibility.
	 */
	if ((crc->flags & VM_CAPREVOKE_CF_NO_COARSE) == 0)
	{
		uint8_t bmbits;
		const uint8_t * __capability bmloc;

		bmloc = crc->crshadow
			+ (VM_CAPREVOKE_BM_MEM_MAP - VM_CAPREVOKE_BM_BASE)
			+ (va / VM_CAPREVOKE_GSZ_MEM_MAP / 8);

		bmbits = fubyte_c(bmloc);

		if (bmbits & (1 << ((va / VM_CAPREVOKE_GSZ_MEM_MAP) % 8))) {
			return 1;
		}
	}

	if ((cheri_getperm(cut) & CHERI_PERM_CHERIABI_VMMAP) == 0) {
		/*
		 * This is a non-VMMAP-bearing capability.  Also check the
		 * NOMAP bitmap
		 */

		uint8_t bmbits;
		const uint8_t * __capability bmloc;

		bmloc = crc->crshadow
			+ (VM_CAPREVOKE_BM_MEM_NOMAP - VM_CAPREVOKE_BM_BASE)
			+ (va / VM_CAPREVOKE_GSZ_MEM_NOMAP / 8);

		bmbits = fubyte_c(bmloc);

		if (bmbits & (1 << ((va / VM_CAPREVOKE_GSZ_MEM_NOMAP) % 8))) {
			return 1;
		}
	}

	return 0;
}

int
vm_test_caprevoke(const struct vm_caprevoke_cookie *crc,
		  const void * __capability cut)
{
	int res = 0;
	int perms = cheri_getperm(cut);

	if ((perms & (CHERI_PERMS_HWALL_MEMORY | CHERI_PERM_CHERIABI_VMMAP))
	    != 0) {
		res |= vm_test_caprevoke_mem(crc, cut);
	}

	// TODO: if ((perms & CHERI_PERMS_HWALL_OTYPE) != 0)

	// TODO: if ((perms & CHERI_PERMS_HWALL_CID) != 0)

	return res;
}

/*
 * The Capability Under Test Pointer needs to be a capability because we
 * don't have a LLC instruction, just a CLLC one.
 */
static int
vm_do_caprevoke(const struct vm_caprevoke_cookie *crc,
		void * __capability * __capability cutp,
		void * __capability cut)
{
	CAPREVOKE_STATS_FOR(crst, crc);
	int res = 0;

	KASSERT(cheri_gettag(cut), ("untagged in vm_do_caprevoke"));

	if (vm_test_caprevoke(crc, cut)) {
		void * __capability cscratch;
		int ok;

		void * __capability cutr = cheri_revoke(cut);

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
		__asm__ __volatile__ (
			"cllc %[cscratch], %[cutp]\n\t"
			"cexeq %[ok], %[cscratch], %[cut]\n\t"
			"beqz %[ok], 1f\n\t"
			"nop\n\t"
			"cscc %[ok], %[cutr], %[cutp]\n\t"
			"1:\n\t"
		  : [ok] "=r" (ok), [cscratch] "=&C" (cscratch)
		  : [cut] "C" (cut), [cutp] "C" (cutp), [cutr] "C" (cutr)
		  : "memory");

		if (__builtin_expect(ok,1)) {
			CAPREVOKE_STATS_BUMP(crst, caps_cleared);
			/* Don't count a revoked cap as HASCAPS */
		} else {
			res = VM_CAPREVOKE_PAGE_DIRTY
				| VM_CAPREVOKE_PAGE_HASCAPS ;
		}
	} else {
		/* Again, don't count a revoked cap as HASCAPS */
		if ((cheri_getperm(cut) != 0) || (cheri_getsealed(cut) != 0)) {
			CAPREVOKE_STATS_BUMP(crst, caps_found);
			res = VM_CAPREVOKE_PAGE_HASCAPS;
		}
		// XXX else crc->stats->caps_found_revoked++;
	}

	return res;
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
	        buf[i] = cheri_getkdc();
	}

	uint64_t tags = __builtin_cheri_cap_load_tags(buf);
	switch(tags) {
	case 0x0001:  cloadtags_stride = 1;  break;
	case 0x0003:  cloadtags_stride = 2;  break;
	case 0x000F:  cloadtags_stride = 4;  break;
	case 0x00FF:  cloadtags_stride = 8;  break;
	case 0xFFFF:  cloadtags_stride = 16; break;
	default:
		panic("Bad cloadtags result 0x%" PRIx64, tags);
	}
}
SYSINIT(cloadtags_stride, SI_SUB_VM, SI_ORDER_ANY,
        measure_cloadtags_stride, NULL);
#endif

static inline int
vm_caprevoke_page_iter(const struct vm_caprevoke_cookie *crc,
		       int (*cb)(const struct vm_caprevoke_cookie *,
				 void * __capability * __capability,
				 void * __capability),
		       void * __capability * __capability mvu,
		       vm_offset_t mve)
{
	int res = 0;

#ifdef CHERI_CAPREVOKE_CLOADTAGS
	for( ; cheri_getaddress(mvu) < mve; mvu += cloadtags_stride ) {
		void * __capability * __capability mvt = mvu;
		uint64_t tags;

		tags = __builtin_cheri_cap_load_tags(mvt);

		for(; tags != 0; (tags >>= 1), mvt += 1) {
			if (!(tags & 1))
				continue;

			res |= cb(crc, mvt, *mvt);
			if (res & VM_CAPREVOKE_PAGE_EARLY_OUT)
				return res;
		}
	}
#else
	for( ; cheri_getaddress(mvu) < mve; mvu++) {
		void * __capability cut = *mvu;
		if (cheri_gettag(cut)) {
			res |= cb(crc, mvu, cut);
			if (res & VM_CAPREVOKE_PAGE_EARLY_OUT)
				return res;
		}
	}
#endif

	return res;
}

int
vm_caprevoke_page(const struct vm_caprevoke_cookie *crc, vm_page_t m)
{
#ifdef CHERI_CAPREVOKE_STATS
	CAPREVOKE_STATS_FOR(crst, crc);
	uint32_t cyc_start = cheri_get_cyclecount();
#endif

	vm_paddr_t mpa = VM_PAGE_TO_PHYS(m);
	vm_offset_t mva;
	vm_offset_t mve;
	void * __capability * __capability mvu;
	/* XXX NWF Is this what we want? */
	void * __capability kdc = cheri_getkdc();
	int res = 0;

	/*
	 * XXX NWF
	 * Hopefully m being xbusy'd means it's not about to go away on us.
	 * I don't yet understand all the interlocks in the vm subsystem.
	 */
	KASSERT(MIPS_DIRECT_MAPPABLE(mpa),
		("Revoke not directly map swept page?"));
	mva = MIPS_PHYS_TO_DIRECT(mpa);
	mve = mva + pagesizes[m->psind];

	mvu = cheri_csetbounds(cheri_setaddress(kdc, mva), pagesizes[m->psind]);

	res = vm_caprevoke_page_iter(crc, vm_do_caprevoke, mvu, mve);

#ifdef CHERI_CAPREVOKE_STATS
	uint32_t cyc_end = cheri_get_cyclecount();
	CAPREVOKE_STATS_INC(crst, page_scan_cycles, cyc_end - cyc_start);
#endif

	return res;
}

static inline int
vm_caprevoke_page_ro_adapt(const struct vm_caprevoke_cookie *vmcrc,
			   void * __capability * __capability cutp,
			   void * __capability cut)
{
	(void)cutp;

	int res = vm_test_caprevoke(vmcrc, cut);

	if (res & VM_CAPREVOKE_PAGE_DIRTY)
		return res | VM_CAPREVOKE_PAGE_EARLY_OUT;

	return res;
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
 * saw at least one capability on this page.
 */
int
vm_caprevoke_page_ro(const struct vm_caprevoke_cookie *crc, vm_page_t m)
{
#ifdef CHERI_CAPREVOKE_STATS
	uint32_t cyc_start = cheri_get_cyclecount();
	CAPREVOKE_STATS_FOR(crst, crc);
#endif

	vm_paddr_t mpa = VM_PAGE_TO_PHYS(m);
	vm_offset_t mva;
	vm_offset_t mve;
	void * __capability * __capability mvu;
	void * __capability kdc = cheri_getkdc();
	int res = 0;

	KASSERT(MIPS_DIRECT_MAPPABLE(mpa),
		("Revoke not directly map swept page?"));
	mva = MIPS_PHYS_TO_DIRECT(mpa);
	mve = mva + pagesizes[m->psind];

	mvu = cheri_csetbounds(cheri_setaddress(kdc, mva), pagesizes[m->psind]);

	res = vm_caprevoke_page_iter(crc, vm_caprevoke_page_ro_adapt, mvu, mve);

#ifdef CHERI_CAPREVOKE_STATS
	uint32_t cyc_end = cheri_get_cyclecount();
	crst->page_scan_cycles += cyc_end - cyc_start;
#endif

	return res;
}

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
	vmo->flags |= OBJ_NOLOADTAGS | OBJ_NOSTORETAGS;

	vm_map_lock(map);

	if (map->vm_caprev_sh != NULL) {
		error = KERN_PROTECTION_FAILURE;
		goto out;
	}

	error = vm_map_insert(map, vmo, 0, start, end,
				VM_PROT_READ | VM_PROT_WRITE,
				VM_PROT_READ | VM_PROT_WRITE,
				0);

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

#define ERRNO_CAP(v) ((void * __capability)(__intptr_t)(v))

/*
 * Grant access to a capability shadow
 */
void * __capability
vm_caprevoke_shadow_cap(int sel, vm_offset_t base, vm_offset_t size, int pmask)
{
	switch(sel) {
	/* Accessible to userspace */
	case CAPREVOKE_SHADOW_NOVMMAP: {
		vm_offset_t shadow_base, shadow_size;

		/* Require at least byte granularity in the shadow space */
		if ((base & ((VM_CAPREVOKE_GSZ_MEM_NOMAP * 8) - 1)) != 0)
			return ERRNO_CAP(EINVAL);
		if ((size & ((VM_CAPREVOKE_GSZ_MEM_NOMAP * 8) - 1)) != 0)
			return ERRNO_CAP(EINVAL);

		shadow_base = VM_CAPREVOKE_BM_MEM_NOMAP
		            + (base / VM_CAPREVOKE_GSZ_MEM_NOMAP / 8);
		shadow_size = size / VM_CAPREVOKE_GSZ_MEM_NOMAP / 8;

		return cheri_capability_build_user_data(
			pmask & (CHERI_PERM_LOAD | CHERI_PERM_STORE)
				| CHERI_PERM_GLOBAL,
			shadow_base, shadow_size, 0);
	}	
	case CAPREVOKE_SHADOW_OTYPE: {
		vm_offset_t shadow_base, shadow_size;

		shadow_base = VM_CAPREVOKE_BM_OTYPE
		            + (base / VM_CAPREVOKE_GSZ_OTYPE / 8);
		shadow_size = size / VM_CAPREVOKE_GSZ_OTYPE / 8;

		/* Require at least byte granularity in the shadow space */
		if ((base & ((VM_CAPREVOKE_GSZ_OTYPE * 8) - 1)) != 0)
			return ERRNO_CAP(EINVAL);
		if ((size & ((VM_CAPREVOKE_GSZ_OTYPE * 8) - 1)) != 0)
			return ERRNO_CAP(EINVAL);

		return cheri_capability_build_user_data(
			CHERI_PERM_LOAD | CHERI_PERM_STORE | CHERI_PERM_GLOBAL,
			shadow_base, shadow_size, 0);
	}
	case CAPREVOKE_SHADOW_INFO_STRUCT: {
		return cheri_capability_build_user_data(
			CHERI_PERM_LOAD
			| CHERI_PERM_LOAD_CAP
			| CHERI_PERM_GLOBAL,
			VM_CAPREVOKE_INFO_PAGE,
			sizeof(struct caprevoke_info),
			0);
	}
	/* Kernel-only */
	// XXX CAPREVOKE_SHADOW_MAP:
	//
	default:
		return ERRNO_CAP(EINVAL);
	}
}

void
vm_caprevoke_publish(const struct vm_caprevoke_cookie *vmcrc,
			 const struct caprevoke_info *ip)
{
	int res = copyout_c(ip, &vmcrc->info_page->pub, sizeof(*ip));
	KASSERT(res == 0, ("vm_caprevoke_publish: bad copyout %d\n", res));
	(void)res;
}
