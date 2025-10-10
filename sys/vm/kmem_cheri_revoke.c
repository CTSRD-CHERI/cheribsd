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
#include <sys/kthread.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/unistd.h>

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

static struct mtx krevoke_mtx;
MTX_SYSINIT(krevoke_mtx, &krevoke_mtx, "kmem async revoker", MTX_DEF);

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
 * Kernel map background revoker thread.
 */
static void
kmem_revoke_kproc(void *arg __unused)
{
	cheri_revoke_epoch_t epoch;
	enum cheri_revoke_state asyncst;

	for (;;) {
		/* Check if we are scheduled to advance to the next epoch */
		mtx_lock(&krevoke_mtx);
		vm_map_lock(kernel_map);
		asyncst = cheri_revoke_st_get_state(
		    kernel_map->vm_cheri_async_revoke_st);
		epoch = cheri_revoke_st_get_epoch(
		    kernel_map->vm_cheri_async_revoke_st);
		if (asyncst == CHERI_REVOKE_ST_NONE) {
			vm_map_unlock(kernel_map);

			msleep(&kernel_map->vm_cheri_async_revoke_st,
			    &krevoke_mtx, PDROP, "krevoker", 0);
			continue;
		}
		KASSERT(asyncst == CHERI_REVOKE_ST_INITING,
		    ("kmem_revoke_kproc !ST_INITING"));

		/* Barrier phase */
		printf("XXX-AM: barrier phase %#lx\n", epoch);

		/* Revocation pass */
		printf("XXX-AM: revocation phase %#lx\n", epoch);

		vm_map_unlock(kernel_map);

		/* Wakeup any sleepers waiting for the revoker to finish */
		cv_broadcast(&kernel_map->vm_cheri_revoke_cv);
		printf("XXX-AM: krevoke kproc done\n");
	}

	kproc_exit(0);
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
	if (__predict_false((cheri_getperm(mem) & CHERI_PERM_SW_KMEM) == 0))
		panic("Quarantine operation requires PERM_SW_KMEM %#p", mem);
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
 * Trigger a revocation pass on kernel_map.
 *
 * The kernel revocation is inherently asynchronous. This manages the epochs
 * based on the kernel_map revoker async state. The synchronous state is unused.
 *
 * We don't use the user-space async revoker work queue, because the revocation
 * loop diverges for kernel revocation.
 *
 * XXX-AM: This is the moral equivalent of kern_cheri_revoke that operates on
 * the kernel_map. Since this is not a system call, this only operates
 * asynchronously to avoid blocking.
 *
 * In principle, we should be able to merge this code and the kern_cheri_revoke
 * state machine, however we don't necessarily have a thread structure here from
 * which to grab the vmspace and vm_map, instead we use the kernel map
 * and kernel_pmap directly. Note that locking is also slightly different.
 *
 * XXX-AM: do we need authorization to start a revocation pass?
 */
void
kmem_revoke(void)
{
	cheri_revoke_epoch_t epoch;
	enum cheri_revoke_state entryst;

	KASSERT((curthread)->td_critnest == 0,
	    ("kmem_revoke in critical section"));

	vm_map_lock(kernel_map);
	epoch = cheri_revoke_st_get_epoch(kernel_map->vm_cheri_async_revoke_st);
	entryst = cheri_revoke_st_get_state(
	    kernel_map->vm_cheri_async_revoke_st);

	if (entryst == CHERI_REVOKE_ST_NONE) {
		/*
		 * Advance state and wakeup the kernel revoker loop.
		 * Note that the epoch does not change yet, we will
		 * do that in the async worker when we are sure that
		 * the epoch is fully open.
		 */
		KASSERT((epoch & 1) == 0, ("Odd epoch NONE"));
		cheri_revoke_st_set(&kernel_map->vm_cheri_async_revoke_st, epoch,
		    CHERI_REVOKE_ST_INITING);
		vm_map_unlock(kernel_map);

		mtx_lock(&krevoke_mtx);
		wakeup_one(&kernel_map->vm_cheri_async_revoke_st);
		mtx_unlock(&krevoke_mtx);
	} else {
		/* Pending kernel revoker run, schedule next pass? */
		/* TODO unimplemented */
		vm_map_unlock(kernel_map);
	}
}

/*
 * Sleep until the current epoch clears the given start_epoch.
 */
/* void */
/* kmem_wait_epoch_clears(cheri_revoke_epoch_t start_epoch) */
/* { */
/* 	/\* cv_wait(kernel_map->vm_cheri_revoke_cv); *\/ */
/* } */

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
	vm_map_lock(kernel_map);

	/* Not sure if this is useless, since vmem never releases kva */
	/* kernel_map->vm_cheri_revoke_quarantining = true; */
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

static void
kmem_revoke_kproc_init(void *arg __unused)
{
	int error;

	error = kproc_create(kmem_revoke_kproc, NULL, NULL, RFNOWAIT,
	    0, "cheri_krevoke");
	if (error != 0)
		panic("%s: failed to create worker process", __func__);
}
SYSINIT(kmem_revoke_kproc, SI_SUB_KTHREAD_INIT, SI_ORDER_ANY,
    kmem_revoke_kproc_init, NULL);
