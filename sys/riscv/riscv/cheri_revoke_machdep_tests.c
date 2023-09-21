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

	bmloc = crshadow
	    - VM_CHERI_REVOKE_BSZ_OTYPE
	    - (va / VM_CHERI_REVOKE_GSZ_MEM_MAP / 8);

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
		      uintcap_t cut, unsigned long perms,
		      vm_offset_t start, vm_offset_t end)
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

/*
 *
 */
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

	default:
		panic("Bad cheri_revoke cookie flags 0x%x\n", flags);
	}
}


