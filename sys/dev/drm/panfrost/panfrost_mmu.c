/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020-2021 Ruslan Bukin <br@bsdpad.com>
 *
 * This work was supported by Innovate UK project 105694, "Digital Security
 * by Design (DSbD) Technology Platform Prototype".
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
 *
 * $FreeBSD$
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/fbio.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/rman.h>
#include <sys/resource.h>
#include <machine/bus.h>
#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/pmap.h>

#include <arm64/iommu/iommu_pmap.h>
#include <dev/extres/clk/clk.h>

#include <drm/drm_gem.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_gem_framebuffer_helper.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_probe_helper.h>
#include <drm/drm_drv.h>
#include <drm/drm_file.h>
#include <drm/drm_ioctl.h>
#include <drm/drm_vblank.h>
#include <drm/gpu_scheduler.h>

#include "panfrost_drv.h"
#include "panfrost_drm.h"
#include "panfrost_device.h"
#include "panfrost_gem.h"
#include "panfrost_regs.h"
#include "panfrost_features.h"
#include "panfrost_issues.h"
#include "panfrost_mmu.h"

#define	ARM_MALI_LPAE_TTBR_ADRMODE_TABLE	(3 << 0)
#define	ARM_MALI_LPAE_TTBR_READ_INNER		(1 << 2)
#define	ARM_MALI_LPAE_TTBR_SHARE_OUTER		(1 << 4)

#define	ARM_LPAE_MAIR_ATTR_SHIFT(n)		((n) << 3)
#define	ARM_LPAE_MAIR_ATTR_MASK			0xff
#define	ARM_LPAE_MAIR_ATTR_DEVICE		0x04
#define	ARM_LPAE_MAIR_ATTR_NC			0x44
#define	ARM_LPAE_MAIR_ATTR_INC_OWBRWA		0xf4
#define	ARM_LPAE_MAIR_ATTR_WBRWA		0xff
#define	ARM_LPAE_MAIR_ATTR_IDX_NC		0
#define	ARM_LPAE_MAIR_ATTR_IDX_CACHE		1
#define	ARM_LPAE_MAIR_ATTR_IDX_DEV		2
#define	ARM_LPAE_MAIR_ATTR_IDX_INC_OCACHE	3

#define	ARM_MALI_LPAE_MEMATTR_IMP_DEF		0x88ULL
#define	ARM_MALI_LPAE_MEMATTR_WRITE_ALLOC	0x8DULL

static const char *
panfrost_mmu_exception_name(uint32_t exc_code)
{

	switch (exc_code) {
	case 0x00: return "NOT_STARTED/IDLE/OK";
	case 0x01: return "DONE";
	case 0x02: return "INTERRUPTED";
	case 0x03: return "STOPPED";
	case 0x04: return "TERMINATED";
	case 0x08: return "ACTIVE";

	case 0xC1: return "TRANSLATION_FAULT_LEVEL1";
	case 0xC2: return "TRANSLATION_FAULT_LEVEL2";
	case 0xC3: return "TRANSLATION_FAULT_LEVEL3";
	case 0xC4: return "TRANSLATION_FAULT_LEVEL4";
	case 0xC8: return "PERMISSION_FAULT";
	case 0xC9 ... 0xCF: return "PERMISSION_FAULT";
	case 0xD1: return "TRANSTAB_BUS_FAULT_LEVEL1";
	case 0xD2: return "TRANSTAB_BUS_FAULT_LEVEL2";
	case 0xD3: return "TRANSTAB_BUS_FAULT_LEVEL3";
	case 0xD4: return "TRANSTAB_BUS_FAULT_LEVEL4";
	case 0xD8: return "ACCESS_FLAG";
	case 0xD9 ... 0xDF: return "ACCESS_FLAG";
	case 0xE0 ... 0xE7: return "ADDRESS_SIZE_FAULT";
	case 0xE8 ... 0xEF: return "MEMORY_ATTRIBUTES_FAULT";
	}

	return "UNKNOWN";
}

static const char *
access_type_name(struct panfrost_softc *sc, uint32_t fault_status)
{

	switch (fault_status & AS_FAULTSTATUS_ACCESS_TYPE_MASK) {
	case AS_FAULTSTATUS_ACCESS_TYPE_ATOMIC:
		if (panfrost_has_hw_feature(sc, HW_FEATURE_AARCH64_MMU))
			return "ATOMIC";
		else
			return "UNKNOWN";
	case AS_FAULTSTATUS_ACCESS_TYPE_READ:
		return "READ";
	case AS_FAULTSTATUS_ACCESS_TYPE_WRITE:
		return "WRITE";
	case AS_FAULTSTATUS_ACCESS_TYPE_EX:
		return "EXECUTE";
	default:
		return NULL;
	}
}

struct panfrost_gem_mapping *
panfrost_mmu_find_mapping(struct panfrost_softc *sc, int as, uint64_t addr)
{
	struct panfrost_gem_mapping *mapping;
	struct panfrost_file *pfile;
	struct panfrost_mmu *mmu;
	struct drm_mm_node *node;
	uint64_t offset;

	mapping = NULL;

	mtx_lock_spin(&sc->as_mtx);

	/* Find mmu first */
	TAILQ_FOREACH(mmu, &sc->mmu_in_use, next) {
		if (mmu->as == as)
			goto found;
	};
	goto out;

found:
	pfile = container_of(mmu, struct panfrost_file, mmu);

	mtx_lock_spin(&pfile->mm_lock);

	offset = addr >> PAGE_SHIFT;
	drm_mm_for_each_node(node, &pfile->mm) {
		if (offset >= node->start &&
		    offset < (node->start + node->size)) {
			mapping = container_of(node,
			    struct panfrost_gem_mapping, mmnode);
			refcount_acquire(&mapping->refcount);
			break;
		};
	};

	mtx_unlock_spin(&pfile->mm_lock);

out:
	mtx_unlock_spin(&sc->as_mtx);

	return (mapping);
}

static int
wait_ready(struct panfrost_softc *sc, uint32_t as)
{
	uint32_t reg;
	int timeout;

	timeout = 10000;

	do {
		reg = GPU_READ(sc, AS_STATUS(as));
		if ((reg & AS_STATUS_AS_ACTIVE) == 0)
			break;
		DELAY(10);
	} while (timeout--);

	if (timeout <= 0)
		return (ETIMEDOUT);

	return (0);
}

static int
write_cmd(struct panfrost_softc *sc, uint32_t as, uint32_t cmd)
{
	int status;

	status = wait_ready(sc, as);
	if (status == 0)
		GPU_WRITE(sc, AS_COMMAND(as), cmd);

	return (status);
}

static void
lock_region(struct panfrost_softc *sc, uint32_t as, vm_offset_t va,
    size_t size)
{
	uint8_t region_width;
	uint64_t region;

	/* Note: PAGE_PASK here includes ~ from linuxkpi */
	region = va & PAGE_MASK;

	size = round_up(size, PAGE_SIZE);

	region_width = 10 + fls(size >> PAGE_SHIFT);
	if ((size >> PAGE_SHIFT) != (1ul << (region_width - 11)))
		region_width += 1;
	region |= region_width;

	GPU_WRITE(sc, AS_LOCKADDR_LO(as), region & 0xFFFFFFFFUL);
	GPU_WRITE(sc, AS_LOCKADDR_HI(as), (region >> 32) & 0xFFFFFFFFUL);
	write_cmd(sc, as, AS_COMMAND_LOCK);
}


static int
mmu_hw_do_operation_locked(struct panfrost_softc *sc, uint32_t as,
    vm_offset_t va, size_t size, uint32_t op)
{
	int error;

	if (op != AS_COMMAND_UNLOCK)
		lock_region(sc, as, va, size);

	write_cmd(sc, as, op);

	error = wait_ready(sc, as);

	return (error);
}

static int
mmu_hw_do_operation(struct panfrost_softc *sc,
    struct panfrost_mmu *mmu, vm_offset_t va, size_t size, uint32_t op)
{
	int error;

	mtx_lock_spin(&sc->as_mtx);
	error = mmu_hw_do_operation_locked(sc, mmu->as, va, size, op);
	mtx_unlock_spin(&sc->as_mtx);

	return (error);
}

static void
panfrost_mmu_flush_range(struct panfrost_softc *sc, struct panfrost_mmu *mmu,
    vm_offset_t va, size_t size)
{

	if (mmu->as < 0)
		return;

	mmu_hw_do_operation(sc, mmu, va, size, AS_COMMAND_FLUSH_PT);
}

static int
panfrost_mmu_page_fault(struct panfrost_softc *sc, int as, uint64_t addr)
{
	struct panfrost_gem_mapping *bomapping;
	struct panfrost_gem_object *bo;
	struct panfrost_mmu *mmu;
	vm_page_t page;
	vm_offset_t page_offset;
	vm_offset_t sva;
	vm_offset_t va;
	vm_paddr_t pa;
	vm_prot_t prot;
	int i;

	bomapping = panfrost_mmu_find_mapping(sc, as, addr);
	if (!bomapping) {
		device_printf(sc->dev, "no bo mapping found\n");
		return (EINVAL);
	}

	bo = bomapping->obj;

	addr &= ~((uint64_t)2*1024*1024 - 1);
	page_offset = addr >> PAGE_SHIFT;
	page_offset -= bomapping->mmnode.start;

	KASSERT(bo->pages != NULL, ("pages is NULL"));

	va = bomapping->mmnode.start << PAGE_SHIFT;

	dprintf("addr %jx va %jx page_offset %d, npages %d\n",
	    addr, va, page_offset, bo->npages);

	mmu = bomapping->mmu;
	prot = VM_PROT_READ | VM_PROT_WRITE;

	va = addr;
	sva = va;

	/* Map 2MiB. */
	for (i = 0; i < 512; i++) {
		page = bo->pages[page_offset + i];
		pa = VM_PAGE_TO_PHYS(page);
		pmap_gpu_enter(&mmu->p, va, pa, prot, 0);
		va += PAGE_SIZE;
	}

	panfrost_mmu_flush_range(sc, mmu, sva, va - sva);

	bomapping->active = true;
	panfrost_gem_mapping_put(bomapping);

	return (0);
}

void
panfrost_mmu_intr(void *arg)
{
	struct panfrost_softc *sc;
	uint32_t fault_status;
	uint32_t exception_type;
	uint32_t access_type;
	uint32_t source_id;
	uint64_t addr;
	int error;
	uint32_t status;
	int mask;
	int i;

	sc = arg;

	status = GPU_READ(sc, MMU_INT_RAWSTAT);
	dprintf("%s: status %x\n", __func__, status);

	for (i = 0; status != 0; i++) {
		mask = (1 << i) | (1 << (i + 16)); /* fault | error */

		if ((status & mask) == 0)
			continue;

		fault_status = GPU_READ(sc, AS_FAULTSTATUS(i));
		exception_type = fault_status & 0xFF;
		access_type = (fault_status >> 8) & 0x3;
		source_id = (fault_status >> 16);

		addr = GPU_READ(sc, AS_FAULTADDRESS_LO(i));
		addr |= (uint64_t)GPU_READ(sc, AS_FAULTADDRESS_HI(i)) << 32;

		error = 1;

		if ((status & mask) == (1 << i)) {
			if ((exception_type & 0xF8) == 0xC0) {
				dprintf("%s: page fault at %jx\n",
				    __func__, addr);
				error = panfrost_mmu_page_fault(sc, i, addr);
			}
		}

		if (error)
			device_printf(sc->dev,
			    "MMU as %d fault %x: exception %x (%s), "
			    "access %x (%s), source_id %d, addr %jx\n",
			    i,
			    fault_status,
			    exception_type,
			    panfrost_mmu_exception_name(exception_type),
			    access_type,
			    access_type_name(sc, fault_status),
			    source_id,
			    addr);

		status &= ~mask;
		GPU_WRITE(sc, MMU_INT_CLEAR, mask);
	}
}

int
panfrost_mmu_pgtable_alloc(struct panfrost_file *pfile)
{
	struct panfrost_mmu *mmu;
	pmap_t p;

	mmu = &pfile->mmu;
	p = &mmu->p;

	iommu_pmap_pinit(p);
	PMAP_LOCK_INIT(p);

	/* Ensure root directory is visible to GPU. */
	cpu_dcache_wbinv_range((vm_pointer_t)p->pm_l0, sizeof(pd_entry_t));

	mmu->as = -1;

	return (0);
}

void
panfrost_mmu_pgtable_free(struct panfrost_file *pfile)
{
	struct panfrost_softc *sc;
	struct panfrost_mmu *mmu;

	sc = pfile->sc;
	mmu = &pfile->mmu;

	iommu_pmap_remove_pages(&mmu->p);
	iommu_pmap_release(&mmu->p);

	mtx_lock_spin(&sc->as_mtx);
	if (mmu->as >= 0) {
		sc->as_alloc_set &= ~(1 << mmu->as);
		TAILQ_REMOVE(&sc->mmu_in_use, mmu, next);
	}
	mtx_unlock_spin(&sc->as_mtx);
}

int
panfrost_mmu_enable(struct panfrost_softc *sc, struct panfrost_mmu *mmu)
{
	vm_paddr_t paddr;
	uint64_t memattr;
	pmap_t p;
	int as;

	as = mmu->as;
	p = &mmu->p;

	paddr = p->pm_l0_paddr;
	paddr |= ARM_MALI_LPAE_TTBR_READ_INNER;
	paddr |= ARM_MALI_LPAE_TTBR_ADRMODE_TABLE;

	memattr = (ARM_MALI_LPAE_MEMATTR_IMP_DEF
	     << ARM_LPAE_MAIR_ATTR_SHIFT(ARM_LPAE_MAIR_ATTR_IDX_NC)) |
	    (ARM_MALI_LPAE_MEMATTR_WRITE_ALLOC
	     << ARM_LPAE_MAIR_ATTR_SHIFT(ARM_LPAE_MAIR_ATTR_IDX_CACHE)) |
	    (ARM_MALI_LPAE_MEMATTR_IMP_DEF
	     << ARM_LPAE_MAIR_ATTR_SHIFT(ARM_LPAE_MAIR_ATTR_IDX_DEV));

	mmu_hw_do_operation_locked(sc, as, 0, ~0UL, AS_COMMAND_FLUSH_MEM);

	GPU_WRITE(sc, AS_TRANSTAB_LO(as), paddr & 0xffffffffUL);
	GPU_WRITE(sc, AS_TRANSTAB_HI(as), paddr >> 32);

	GPU_WRITE(sc, AS_MEMATTR_LO(as), memattr & 0xffffffffUL);
	GPU_WRITE(sc, AS_MEMATTR_HI(as), memattr >> 32);

	write_cmd(sc, as, AS_COMMAND_UPDATE);

	return (0);
}

void
panfrost_mmu_as_put(struct panfrost_softc *sc, struct panfrost_mmu *mmu)
{

	atomic_add_int(&mmu->as_count, -1);
}

uint32_t
panfrost_mmu_as_get(struct panfrost_softc *sc, struct panfrost_mmu *mmu)
{
	struct panfrost_mmu *mmu1, *tmp;
	bool found;
	int as;

	mtx_lock_spin(&sc->as_mtx);
	if (mmu->as >= 0) {
		atomic_add_int(&mmu->as_count, 1);
		mtx_unlock_spin(&sc->as_mtx);
		return (mmu->as);
	}

	as = ffz(sc->as_alloc_set);

	if ((sc->features.as_present & (1 << as)) == 0) {
		found = false;
		TAILQ_FOREACH_SAFE(mmu1, &sc->mmu_in_use, next, tmp) {
			if (mmu1->as_count == 0) {
				TAILQ_REMOVE(&sc->mmu_in_use, mmu1, next);
				found = true;
				break;
			}
		}
		if (found == false)
			device_printf(sc->dev, "as not found\n");

		as = mmu1->as;
		mmu1->as = -1;
	}

	sc->as_alloc_set |= (1 << as);

	mmu->as = as;
	mmu->as_count = 1;

	TAILQ_INSERT_TAIL(&sc->mmu_in_use, mmu, next);

	panfrost_mmu_enable(sc, mmu);
	mtx_unlock_spin(&sc->as_mtx);

	return (as);
}

void
panfrost_mmu_reset(struct panfrost_softc *sc)
{
	struct panfrost_mmu *mmu, *tmp;

	mtx_lock_spin(&sc->as_mtx);
	TAILQ_FOREACH_SAFE(mmu, &sc->mmu_in_use, next, tmp) {
		mmu->as = -1;
		mmu->as_count = 0;
		TAILQ_REMOVE(&sc->mmu_in_use, mmu, next);
	}
	sc->as_alloc_set = 0;
	mtx_unlock_spin(&sc->as_mtx);

	GPU_WRITE(sc, MMU_INT_CLEAR, ~0);
	GPU_WRITE(sc, MMU_INT_MASK, ~0);
}

int
panfrost_mmu_map(struct panfrost_softc *sc,
    struct panfrost_gem_mapping *mapping)
{
	struct panfrost_gem_object *bo;
	struct panfrost_mmu *mmu;
	vm_prot_t prot;
	vm_offset_t va;
	vm_paddr_t pa;
	int error;
	vm_offset_t sva;
	struct scatterlist *sg;
	struct page *page;
	struct sg_table *sgt;
	int count;
	int len;

	bo = mapping->obj;
	mmu = mapping->mmu;

	error = panfrost_gem_get_pages(bo);
	if (error != 0) {
		device_printf(sc->dev, "%s: no pages, bo->is_heap %d\n",
		    __func__, bo->is_heap);
		return (error);
	}

	va = mapping->mmnode.start << PAGE_SHIFT;
	sva = va;
	prot = VM_PROT_READ | VM_PROT_WRITE;
	if (bo->noexec == 0)
		prot |= VM_PROT_EXECUTE;

	dprintf("%s: bo %p mmu %p as %d sva %lx, %d pages\n",
	    __func__, bo, mmu, mmu->as, sva, bo->npages);

	sgt = bo->sgt;

	for_each_sg(sgt->sgl, sg, sgt->nents, count) {
		len = sg_dma_len(sg);
		page = sg_page(sg);
		while (len > 0) {
			pa = VM_PAGE_TO_PHYS(page);
			error = pmap_gpu_enter(&mmu->p, va, pa, prot, 0);
			va += PAGE_SIZE;
			page++;
			len -= PAGE_SIZE;
		}
	}

	mapping->active = true;

	panfrost_mmu_flush_range(sc, mmu, sva, va - sva);

	return (0);
}

void
panfrost_mmu_unmap(struct panfrost_softc *sc,
    struct panfrost_gem_mapping *mapping)
{
	struct panfrost_mmu *mmu;
	vm_offset_t sva;
	vm_offset_t va;
	int unmapped_len;
	int error;
	int len;

	mmu = mapping->mmu;

	len = mapping->mmnode.size << PAGE_SHIFT;
	va = mapping->mmnode.start << PAGE_SHIFT;
	sva = va;
	unmapped_len = 0;

	while (unmapped_len < len) {
		error = pmap_gpu_remove(&mmu->p, va);
		if (error) {
			/*
			 * It is possible that a part of memory was mapped
			 * only due to tiling operation.
			 * This could only be possible when driver minor > 0.
			 */
		}
		va += PAGE_SIZE;
		unmapped_len += PAGE_SIZE;
	}

	panfrost_mmu_flush_range(sc, mmu, sva, unmapped_len);

	mapping->active = false;
}

int
panfrost_mmu_init(struct panfrost_softc *sc)
{

	/* Enable interrupts. */
	GPU_WRITE(sc, MMU_INT_CLEAR, ~0);
	GPU_WRITE(sc, MMU_INT_MASK, ~0);

	return (0);
}
