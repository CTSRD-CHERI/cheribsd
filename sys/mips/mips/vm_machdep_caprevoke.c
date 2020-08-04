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
