/*-
 * Copyright (c) 2010 Isilon Systems, Inc.
 * Copyright (c) 2016 Matthew Macy (mmacy@mattmacy.io)
 * Copyright (c) 2017 Mellanox Technologies, Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/proc.h>
#include <sys/sched.h>

#include <machine/bus.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_object.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/vm_pager.h>
#include <vm/vm_radix.h>
#include <vm/vm_reserv.h>
#include <vm/vm_extern.h>

#include <vm/uma.h>
#include <vm/uma_int.h>

#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/preempt.h>
#include <linux/fs.h>
#include <linux/shmem_fs.h>

void
si_meminfo(struct sysinfo *si)
{
	si->totalram = physmem;
	si->totalhigh = 0;
	si->mem_unit = PAGE_SIZE;
}

void *
linux_page_address(struct page *page)
{

	if (page->object != kmem_object && page->object != kernel_object) {
		return (PMAP_HAS_DMAP ?
		    ((void *)(uintptr_t)PHYS_TO_DMAP(VM_PAGE_TO_PHYS(page))) :
		    NULL);
	}
	return ((void *)(uintptr_t)(VM_MIN_KERNEL_ADDRESS +
	    IDX_TO_OFF(page->pindex)));
}

vm_page_t
linux_alloc_pages(gfp_t flags, unsigned int order)
{
	vm_page_t page;

	if (PMAP_HAS_DMAP) {
		unsigned long npages = 1UL << order;
		int req = VM_ALLOC_NOOBJ | VM_ALLOC_WIRED | VM_ALLOC_NORMAL;

		if ((flags & M_ZERO) != 0)
			req |= VM_ALLOC_ZERO;
		if (order == 0 && (flags & GFP_DMA32) == 0) {
			page = vm_page_alloc(NULL, 0, req);
			if (page == NULL)
				return (NULL);
		} else {
			vm_paddr_t pmax = (flags & GFP_DMA32) ?
			    BUS_SPACE_MAXADDR_32BIT : BUS_SPACE_MAXADDR;
		retry:
			page = vm_page_alloc_contig(NULL, 0, req,
			    npages, 0, pmax, PAGE_SIZE, 0, VM_MEMATTR_DEFAULT);

			if (page == NULL) {
				if (flags & M_WAITOK) {
					if (!vm_page_reclaim_contig(req,
					    npages, 0, pmax, PAGE_SIZE, 0)) {
						vm_wait(NULL);
					}
					flags &= ~M_WAITOK;
					goto retry;
				}
				return (NULL);
			}
		}
		if (flags & M_ZERO) {
			unsigned long x;

			for (x = 0; x != npages; x++) {
				vm_page_t pgo = page + x;

				if ((pgo->flags & PG_ZERO) == 0)
					pmap_zero_page(pgo);
			}
		}
	} else {
		vm_offset_t vaddr;

		vaddr = linux_alloc_kmem(flags, order);
		if (vaddr == 0)
			return (NULL);

		page = PHYS_TO_VM_PAGE(vtophys((void *)vaddr));

		KASSERT(vaddr == (vm_offset_t)page_address(page),
		    ("Page address mismatch"));
	}

	return (page);
}

void
linux_free_pages(vm_page_t page, unsigned int order)
{
	if (PMAP_HAS_DMAP) {
		unsigned long npages = 1UL << order;
		unsigned long x;

		for (x = 0; x != npages; x++) {
			vm_page_t pgo = page + x;

			if (vm_page_unwire_noq(pgo))
				vm_page_free(pgo);
		}
	} else {
		vm_offset_t vaddr;

		vaddr = (vm_offset_t)page_address(page);

		linux_free_kmem(vaddr, order);
	}
}

vm_offset_t
linux_alloc_kmem(gfp_t flags, unsigned int order)
{
	size_t size = ((size_t)PAGE_SIZE) << order;
	vm_offset_t addr;

	if ((flags & GFP_DMA32) == 0) {
		addr = kmem_malloc(size, flags & GFP_NATIVE_MASK);
	} else {
		addr = kmem_alloc_contig(size, flags & GFP_NATIVE_MASK, 0,
		    BUS_SPACE_MAXADDR_32BIT, PAGE_SIZE, 0, VM_MEMATTR_DEFAULT);
	}
	return (addr);
}

void
linux_free_kmem(vm_offset_t addr, unsigned int order)
{
	size_t size = ((size_t)PAGE_SIZE) << order;

	kmem_free(addr, size);
}

static int
linux_get_user_pages_internal(vm_map_t map, unsigned long start, int nr_pages,
    int write, struct page **pages)
{
	vm_prot_t prot;
	size_t len;
	int count;

	prot = write ? (VM_PROT_READ | VM_PROT_WRITE) : VM_PROT_READ;
	len = ((size_t)nr_pages) << PAGE_SHIFT;
	count = vm_fault_quick_hold_pages(map, start, len, prot, pages, nr_pages);
	return (count == -1 ? -EFAULT : nr_pages);
}

int
__get_user_pages_fast(unsigned long start, int nr_pages, int write,
    struct page **pages)
{
	vm_map_t map;
	vm_page_t *mp;
	vm_offset_t va;
	vm_offset_t end;
	vm_prot_t prot;
	int count;

	if (nr_pages == 0 || in_interrupt())
		return (0);

	MPASS(pages != NULL);
	va = start;
	map = &curthread->td_proc->p_vmspace->vm_map;
	end = start + (((size_t)nr_pages) << PAGE_SHIFT);
	if (start < vm_map_min(map) || end > vm_map_max(map))
		return (-EINVAL);
	prot = write ? (VM_PROT_READ | VM_PROT_WRITE) : VM_PROT_READ;
	for (count = 0, mp = pages, va = start; va < end;
	    mp++, va += PAGE_SIZE, count++) {
		*mp = pmap_extract_and_hold(map->pmap, va, prot);
		if (*mp == NULL)
			break;

		if ((prot & VM_PROT_WRITE) != 0 &&
		    (*mp)->dirty != VM_PAGE_BITS_ALL) {
			/*
			 * Explicitly dirty the physical page.  Otherwise, the
			 * caller's changes may go unnoticed because they are
			 * performed through an unmanaged mapping or by a DMA
			 * operation.
			 *
			 * The object lock is not held here.
			 * See vm_page_clear_dirty_mask().
			 */
			vm_page_dirty(*mp);
		}
	}
	return (count);
}

long
get_user_pages_remote(struct task_struct *task, struct mm_struct *mm,
    unsigned long start, unsigned long nr_pages, int gup_flags,
    struct page **pages, struct vm_area_struct **vmas)
{
	vm_map_t map;

	map = &task->task_thread->td_proc->p_vmspace->vm_map;
	return (linux_get_user_pages_internal(map, start, nr_pages,
	    !!(gup_flags & FOLL_WRITE), pages));
}

long
get_user_pages(unsigned long start, unsigned long nr_pages, int gup_flags,
    struct page **pages, struct vm_area_struct **vmas)
{
	vm_map_t map;

	map = &curthread->td_proc->p_vmspace->vm_map;
	return (linux_get_user_pages_internal(map, start, nr_pages,
	    !!(gup_flags & FOLL_WRITE), pages));
}

int
is_vmalloc_addr(const void *addr)
{
	return (vtoslab((vm_offset_t)addr & ~UMA_SLAB_MASK) != NULL);
}
