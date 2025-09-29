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

static vm_offset_t
kmem_shadow_granule_offset(ptraddr_t addr)
{
	/* Exclude the DMAP for now */
	KASSERT(addr >= VM_MIN_KERNEL_ADDRESS && addr < VM_MAX_KERNEL_ADDRESS,
	    ("Invalid kernel address to quarantine %lx", addr));

	return ((addr - VM_MIN_KERNEL_ADDRESS) / CHERI_REVOKE_KSHADOW_GRANULE);
}

static vm_offset_t
kmem_shadow_word_offset(ptraddr_t addr)
{
	vm_offset_t offset;

	offset = rounddown2(kmem_shadow_granule_offset(addr) / NBBY,
	    sizeof(uint64_t));

	return (offset);
}

static vm_offset_t
kmem_shadow_last_word_offset(ptraddr_t addr, size_t size)
{
	if (size > 0)
		return kmem_shadow_word_offset(addr + size - 1);
	else
		return kmem_shadow_word_offset(addr);
}

static uint64_t
kmem_shadow_first_word_mask(ptraddr_t addr, size_t size)
{
	const size_t shadow_size = size / CHERI_REVOKE_KSHADOW_GRANULE;
	size_t lsb_offset;
	uint64_t mask;

	lsb_offset = kmem_shadow_granule_offset(addr) %
	    (NBBY * sizeof(uint64_t));
	mask = ~((1ULL << lsb_offset) - 1);

	if (kmem_shadow_word_offset(addr) ==
	    kmem_shadow_last_word_offset(addr, size) &&
	    lsb_offset + size != 64) {
		/* Shadow region is entirely within the first word */
		mask ^= ~((1ULL << (lsb_offset + shadow_size)) - 1);
	}

	return (htole64(mask));
}

static uint64_t
kmem_shadow_last_word_mask(ptraddr_t addr, size_t size)
{
	size_t msb_offset;
	uint64_t mask;

	msb_offset = kmem_shadow_granule_offset(addr + size - 1) %
	    (NBBY * sizeof(uint64_t));
	mask = (1ULL << msb_offset) - 1;

	return (htole64(mask));
}

/*
 * Paint the kernel shadow bitmap corresponding to the given memory region.
 *
 * It is interesting how we deal with double-free, because these can occur
 * across threads.
 * This currently should protect against malicious races where the quarantine
 * is painted concurrently from two different threads 0 and 1 and
 * thread 1 is stopped until the revocation pass is done and quarantine
 * cleared from thread 0, leading to thread 1 painting the quarantine for
 * a no-longer-revoked capability.
 *
 * Note that the capability must have the PERM_SW_VMEM bit set to authorize
 * this operation.
 * XXX-AM: This must be adapted to work before kmem_init().
 *
 * XXX-AM: See userspace caprev_shadow_nomap_set_len() in libcheri_caprevoke,
 * perhaps there is a way to reuse the same code, but it is unclear
 * at this point.
 *
 * Return 0 if the quarantine is painted normally. 1 if this was detected as
 * a double-free or the quarantine was already partially painted.
 */
int
kmem_quarantine(void *mem, size_t size)
{
	uint64_t *shadow_mem;
	vm_offset_t fwo, lwo;
	vm_offset_t mask;
	const ptraddr_t shadow_base = (ptraddr_t)kernel_shadow_root_cap;
	ptraddr_t addr = (ptraddr_t)mem;

	if (__predict_false(cheri_getsealed(mem)))
		panic("Quarantine sealed capability %#p", mem);
	if (__predict_false(!cheri_gettag(mem)))
		panic("Quarantine invalid capability %#p", mem);
	if (__predict_false(cheri_gettop(mem) < (ptraddr_t)mem + size))
		panic("Quarantine invalid bounds %#p", mem);

	KASSERT(cheri_gettag(kernel_shadow_root_cap),
	    ("Invalid kernel shadow root %#p", kernel_shadow_root_cap));

	fwo = kmem_shadow_word_offset(addr);
	lwo = kmem_shadow_last_word_offset(addr, size);
	shadow_mem = cheri_setaddress(kernel_shadow_root_cap,
	    shadow_base + fwo);

	/* Insert a KTR/Dtrace probe here? */

	/*
	 * Follow userland approach of using the first word to synchronize
	 * concurrent quarantine requests.
	 */
	mask = kmem_shadow_first_word_mask(addr, size);
	if (!kmem_shadow_set_first_word(shadow_mem, mem, mask)) {
		return (1);
	}
	shadow_mem = shadow_mem + 1;

	/* Paint words [1, N - 2] of the bitmap, excluding both the first and last */
	if (lwo - fwo > sizeof(uint64_t)) {
		memset(shadow_mem, 1, lwo - fwo - sizeof(uint64_t));
	}

	/* Paint the last word, this may race with another partial painting */
	if (lwo != fwo) {
		shadow_mem = cheri_setaddress(kernel_shadow_root_cap,
		    shadow_base + lwo);
		mask = kmem_shadow_last_word_mask(addr, size);
		atomic_set_64(shadow_mem, mask);
	}

	return (0);
}

/*
 * Extend the shadow bitmap to the given memory region.
 *
 * This ensures that the shadow bitmap will cover the
 * given region. The MD pmap implementation is free to map
 * additional shadow bitmap space, if necessary.
 * Notionally, this is similar to kasan shadow mappings.
 */
void
kmem_shadow_map(vm_offset_t addr, size_t size)
{
	vm_offset_t shadow_start;
	vm_offset_t shadow_end;
	int i;

	mtx_assert(&kernel_map->system_mtx, MA_OWNED);

	size = roundup2(size, CHERI_REVOKE_KSHADOW_GRANULE);
	shadow_start = rounddown2(kmem_shadow_word_offset(addr), PAGE_SIZE);
	shadow_end = roundup2(kmem_shadow_word_offset(addr + size), PAGE_SIZE);

	for (i = 0; i < howmany(shadow_end - shadow_start, PAGE_SIZE); i++) {
		pmap_krevoke_shadow_enter(CHERI_REVOKE_KSHADOW_MIN +
		    shadow_start + ptoa(i));
	}
}


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
