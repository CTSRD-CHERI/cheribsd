/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Alfredo Mazzinghi.
 * Copyright (c) 2025 Capabilities Limited.
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
#include "opt_vm.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mutex.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_object.h>
#include <vm/vm_extern.h>
#include <vm/vm_page.h>

#include <cheri/cheric.h>
#include <cheri/revoke.h>
#include <cheri/revoke_kern.h>
#include <vm/vm_cheri_revoke.h>

_Static_assert((CHERI_REVOKE_KSHADOW_MAX - CHERI_REVOKE_KSHADOW_MIN) ==
    ((VM_MAX_KERNEL_ADDRESS - VM_MIN_KERNEL_ADDRESS) / 8 / sizeof(void *)),
	"Invalid kernel revoke shadow bitmap size");

/*
 * Kernel revocation info context.
 * This is a statically allocated version of the user info page.
 *
 * XXX I think only the epochs are used here, we should simplify this.
 */
struct cheri_revoke_info kernel_revoke_info_store;

/*
 * Initialize revocation structures for the kernel map.
 *
 * This must be called after the kernel_map is initialized, so that the
 * revocation structures in the kernel_map are properly initialized.
 *
 * Before kmem_cheri_revoke_init(), kernel memory revocation is impossible,
 * any early memory freed (e.g. by UMA) will be marked as quarantined but
 * no revocation is possible until after this call.
 *
 * In practice, this is close to uma_startup2() in kmem_init(), so it will
 * enable revocation for most of the boot sequence.
 *
 * The kernel shadow bitmap is allocated using a kernel shadow vm_object,
 * similarly to the user shadow map.
 * This means that the kernel allocators will paint the bitmap via kernel
 * virtual memory.
 * However, we need to ensure that the shadow bitmap is available via the DMAP
 * when we fault.
 */
void
kmem_cheri_revoke_init(void)
{
	/* int error; */
	/* int cow = MAP_CREATE_SHADOW; */

	/* // XXX how do I map this? It is outside of the kernel map... */
	/* error = vm_map_reservation_create_locked(kernel_map, &start, */
	/*     CHERI_REVOKE_KSHADOW_MAX - CHERI_REVOKE_KSHADOW_MIN, */
	/*     VM_PROT_READ | VM_PROT_WRITE); */
	/* /\* */
	/*  * XXX-AM in principle we could still boot here, we just can't revoke? */
	/*  *\/ */
	/* if (error != KERN_SUCCESS) */
	/* 	panic("Failed to reserve kernel shadow bitmap error: %d", error); */

	/* error = vm_map_insert(kernel_map, kernel_shadow_object, 0, start, */
	/*     start + shadow_size, VM_PROT_READ | VM_PROT_WRITE, */
	/*     VM_PROT_READ | VM_PROT_WRITE, cow, start); */
	/* if (error != KERN_SUCCESS) */
	/* 	panic("Failed to map kernel shadow bitmap error: %d", error); */

	vm_map_lock(kernel_map);

	kernel_map->vm_cheri_async_revoke_shadow = kernel_shadow_root_cap;

	struct cheri_revoke_info init = {
		.base_mem_nomap = CHERI_REVOKE_KSHADOW_MIN,
		/*
		 * Note: we are not using the otype shadow map in the kernel
		 * and space for it is not allocated.
		 */
		.base_otype = -1,
		.epochs = {0, 0}
	};
	memcpy(kernel_revoke_info, &init, sizeof(*kernel_revoke_info));

	vm_map_unlock(kernel_map);
}
