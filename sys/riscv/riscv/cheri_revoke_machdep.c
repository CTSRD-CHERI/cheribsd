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

static bool cheri_revoke_core_shadow = 0;
SYSCTL_BOOL(_vm, OID_AUTO, cheri_revoke_core_shadow, CTLFLAG_RW,
    &cheri_revoke_core_shadow, 0,
    "Include the cheri_revoke shadow in core dumps");

/*
 * Map a capability revocation shadow
 */
int
vm_map_install_cheri_revoke_shadow(vm_map_t map)
{
	int cow;
	int error = KERN_SUCCESS;
	vm_object_t vmo;
	vm_pointer_t start;
	vm_offset_t start_addr = VM_CHERI_REVOKE_BM_BASE;
	vm_offset_t end_addr = VM_CHERI_REVOKE_BM_TOP;

	vmo = vm_object_allocate(OBJT_DEFAULT, end_addr - start_addr);

	vm_map_lock(map);

	if (map->vm_cheri_revoke_sh != NULL) {
		error = KERN_PROTECTION_FAILURE;
		goto out;
	}

	start = start_addr; /* upcast to NULL-derived cap */

	error = vm_map_reservation_create_locked(map, &start,
		    end_addr - start_addr,
		    VM_PROT_READ | VM_PROT_WRITE);

	KASSERT((ptraddr_t)start == start_addr,
		("vm_map_reservation_create_locked moved revocation's cheese"));

	if (error != KERN_SUCCESS) {
		goto out;
	}

	cow = cheri_revoke_core_shadow ? 0 : MAP_DISABLE_COREDUMP;

	error = vm_map_insert(map, vmo, 0, start, end_addr,
				VM_PROT_READ | VM_PROT_WRITE,
				VM_PROT_READ | VM_PROT_WRITE,
				cow, start_addr);

	if (error != KERN_SUCCESS) {
		int error2;

		error2 = vm_map_reservation_delete_locked(map, start);
		KASSERT(error2 == KERN_SUCCESS,
			("vm_map_install_cheri_revoke_shadow failed twice!"));

		goto out;
	}

	map->vm_cheri_revoke_sh = vmo;
	map->vm_cheri_revoke_shva = start;
	/* XXX NWF That might want to be vm_cheri_revoke_shcap? */

out:
	vm_map_unlock(map);

	if (error == KERN_SUCCESS) {
		/* Initialize cheri_revoke info (map unlocked for copyout) */
		struct cheri_revoke_info initinfo = {
			.base_mem_nomap = VM_CHERI_REVOKE_BM_MEM_NOMAP,
			.base_otype = VM_CHERI_REVOKE_BM_OTYPE,
			{0, 0}
		};
		struct cheri_revoke_info_page * __capability infopage;
		vm_cheri_revoke_info_page(map, &infopage);

		error = copyout(&initinfo, infopage, sizeof(initinfo));
		KASSERT(error == 0,
			("vm_map_install_cheri_revoke_shadow copyout"));
	} else {
		vm_object_deallocate(vmo);
	}
	return error;
}

void
vm_cheri_revoke_publish_epochs(
    struct cheri_revoke_info_page * __capability info_page,
    const struct cheri_revoke_epochs *ip)
{
	struct cheri_revoke_epochs * __capability target =
	    &info_page->pub.epochs;
	int res = copyoutcap(ip, target, sizeof(*target));
	KASSERT(res == 0, ("vm_cheri_revoke_publish: bad copyout %d\n", res));
	(void)res;
}

/*
 * Grant access to a capability shadow
 */
void * __capability
vm_cheri_revoke_shadow_cap(int sel, vm_offset_t base, vm_offset_t size,
    int pmask)
{
	switch(sel) {
	/* Accessible to userspace */
	case CHERI_REVOKE_SHADOW_NOVMMAP: {
		vm_offset_t shadow_base, shadow_size;

		/* Require at least byte granularity in the shadow space */
		if ((base & ((VM_CHERI_REVOKE_GSZ_MEM_NOMAP * 8) - 1)) != 0)
			return (void * __capability)(uintptr_t)EINVAL;
		if ((size & ((VM_CHERI_REVOKE_GSZ_MEM_NOMAP * 8) - 1)) != 0)
			return (void * __capability)(uintptr_t)EINVAL;

		shadow_base = VM_CHERI_REVOKE_BM_MEM_NOMAP
		            + (base / VM_CHERI_REVOKE_GSZ_MEM_NOMAP / 8);
		shadow_size = size / VM_CHERI_REVOKE_GSZ_MEM_NOMAP / 8;

		return cheri_capability_build_user_data(
			(pmask & (CHERI_PERM_LOAD | CHERI_PERM_STORE)) |
			    CHERI_PERM_GLOBAL,
			shadow_base, shadow_size, 0);
	}
	case CHERI_REVOKE_SHADOW_OTYPE: {
		vm_offset_t shadow_base, shadow_size;

		shadow_base = VM_CHERI_REVOKE_BM_OTYPE
		            + (base / VM_CHERI_REVOKE_GSZ_OTYPE / 8);
		shadow_size = size / VM_CHERI_REVOKE_GSZ_OTYPE / 8;

		/* Require at least byte granularity in the shadow space */
		if ((base & ((VM_CHERI_REVOKE_GSZ_OTYPE * 8) - 1)) != 0)
			return (void * __capability)(uintptr_t)EINVAL;
		if ((size & ((VM_CHERI_REVOKE_GSZ_OTYPE * 8) - 1)) != 0)
			return (void * __capability)(uintptr_t)EINVAL;

		return cheri_capability_build_user_data(
			CHERI_PERM_LOAD | CHERI_PERM_STORE | CHERI_PERM_GLOBAL,
			shadow_base, shadow_size, 0);
	}
	case CHERI_REVOKE_SHADOW_INFO_STRUCT: {
		return cheri_capability_build_user_data(
			CHERI_PERM_LOAD
			| CHERI_PERM_LOAD_CAP
			| CHERI_PERM_GLOBAL,
			VM_CHERI_REVOKE_INFO_PAGE,
			sizeof(struct cheri_revoke_info),
			0);
	}
	case CHERI_REVOKE_SHADOW_NOVMMAP_ENTIRE: {
		return cheri_capability_build_user_data(
		    CHERI_PERM_LOAD | CHERI_PERM_STORE | CHERI_PERM_GLOBAL,
		    VM_CHERI_REVOKE_BM_MEM_NOMAP, VM_CHERI_REVOKE_BSZ_MEM_NOMAP,
		    0);
	}
	/* Kernel-only */
	// XXX CHERI_REVOKE_SHADOW_MAP:
	//
	default:
		return (void * __capability)(uintptr_t)EINVAL;
	}
}

void
vm_cheri_revoke_info_page(struct vm_map *map,
    struct cheri_revoke_info_page * __capability *ifp)
{
	/* XXX In prinicple, it could work cross-process, but not yet */
	KASSERT(map == &curthread->td_proc->p_vmspace->vm_map,
		("vm_cheri_revoke_page_info req. intraprocess work right now"));

	*ifp = cheri_capability_build_user_data(CHERI_PERM_LOAD |
		CHERI_PERM_LOAD_CAP | CHERI_PERM_STORE | CHERI_PERM_STORE_CAP |
		CHERI_PERM_GLOBAL,
	    VM_CHERI_REVOKE_INFO_PAGE, PAGE_SIZE, 0);
}
