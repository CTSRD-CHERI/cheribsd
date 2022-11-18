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
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/pmap.h>

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

#include <linux/dma-buf.h>

#include "panfrost_drv.h"
#include "panfrost_job.h"
#include "panfrost_drm.h"
#include "panfrost_device.h"
#include "panfrost_gem.h"
#include "panfrost_regs.h"
#include "panfrost_features.h"
#include "panfrost_issues.h"
#include "panfrost_mmu.h"

static void
panfrost_gem_free_object(struct drm_gem_object *obj)
{
	struct panfrost_gem_object *bo;
	vm_page_t m;
	int i;

	bo = (struct panfrost_gem_object *)obj;

	if (obj->import_attach)
		drm_prime_gem_destroy(obj, bo->sgt);

	if (bo->sgt) {
		sg_free_table(bo->sgt);
		kfree(bo->sgt);
		bo->sgt = NULL;
	}

	if (bo->pages) {
		for (i = 0; i < bo->npages; i++) {
			m = bo->pages[i];
			vm_page_lock(m);
			m->flags &= ~PG_FICTITIOUS;
			m->oflags |= VPO_UNMANAGED;
			vm_page_unwire_noq(m);
			vm_page_free(m);
			vm_page_unlock(m);
		}

		free(bo->pages, M_PANFROST);
	}

	drm_gem_object_release(obj);

	free(bo, M_PANFROST2);
}

int
panfrost_gem_open(struct drm_gem_object *obj, struct drm_file *file_priv)
{
	struct panfrost_softc *sc;
	struct panfrost_gem_mapping *mapping;
	struct panfrost_gem_object *bo;
	struct panfrost_file *pfile;
	uint32_t align;
	int error;
	int color;

	bo = (struct panfrost_gem_object *)obj;
	pfile = file_priv->driver_priv;
	sc = pfile->sc;

	mapping = malloc(sizeof(*mapping), M_PANFROST1, M_ZERO | M_WAITOK);
	mapping->obj = bo;
	mapping->mmu = &pfile->mmu;
	refcount_init(&mapping->refcount, 1);
	drm_gem_object_get(obj);

	if (!bo->noexec) {
		align = obj->size >> PAGE_SHIFT;
		color = 0;
	} else {
		align = obj->size >= 0x200000 ? 0x200000 >> PAGE_SHIFT : 0;
		color = PANFROST_BO_NOEXEC;
	}

	mtx_lock_spin(&pfile->mm_lock);
	error = drm_mm_insert_node_generic(&pfile->mm, &mapping->mmnode,
	    obj->size >> PAGE_SHIFT, align, color, 0 /* mode */);
	mtx_unlock_spin(&pfile->mm_lock);
	if (error) {
		device_printf(sc->dev,
		    "%s: Failed to insert: sz %d, align %d, color %d, err %d\n",
		    __func__, obj->size >> PAGE_SHIFT, align, color, error);
		goto error;
	}

	dprintf("%s: mapping->mmnode.start page %lx va %lx\n", __func__,
	    mapping->mmnode.start, mapping->mmnode.start << PAGE_SHIFT);

	if (!bo->is_heap) {
		error = panfrost_mmu_map(sc, mapping);
		if (error) {
			device_printf(sc->dev, "%s: could not map, error %d\n",
			    __func__, error);
			goto error;
		}
	} else {
		error = panfrost_gem_get_pages(bo);
		if (error) {
			device_printf(sc->dev,
			    "%s: could not alloc pages, error %d\n",
			    __func__, error);
			goto error;
		}
	}

	mtx_lock(&bo->mappings_lock);
	TAILQ_INSERT_TAIL(&bo->mappings, mapping, next);
	mtx_unlock(&bo->mappings_lock);

	return (0);

error:
	panfrost_gem_mapping_put(mapping);
	drm_gem_object_put(obj);
	return (error);
}

void
panfrost_gem_close(struct drm_gem_object *obj, struct drm_file *file_priv)
{
	struct panfrost_file *pfile;
	struct panfrost_gem_object *bo;
	struct panfrost_gem_mapping *mapping;
	struct panfrost_gem_mapping *tmp;
	struct panfrost_gem_mapping *result;

	pfile = file_priv->driver_priv;
	bo = (struct panfrost_gem_object *)obj;

	result = NULL;

	mtx_lock(&bo->mappings_lock);
	TAILQ_FOREACH_SAFE(mapping, &bo->mappings, next, tmp) {
		if (mapping->mmu == &pfile->mmu) {
			result = mapping;
			TAILQ_REMOVE(&bo->mappings, mapping, next);
			break;
		}
	}
	mtx_unlock(&bo->mappings_lock);

	if (result)
		panfrost_gem_mapping_put(result);
}

void
panfrost_gem_print_info(struct drm_printer *p, unsigned int indent,
    const struct drm_gem_object *obj)
{

}

static int
panfrost_gem_pin(struct drm_gem_object *obj)
{

	drm_gem_object_get(obj);

	return (0);
}

void
panfrost_gem_unpin(struct drm_gem_object *obj)
{

	drm_gem_object_put(obj);
}

struct sg_table *
panfrost_gem_get_sg_table(struct drm_gem_object *obj)
{
	struct panfrost_gem_object *bo;

	bo = (struct panfrost_gem_object *)obj;

	return (bo->sgt);
}

void *
panfrost_gem_vmap(struct drm_gem_object *obj)
{

	return (0);
}

void
panfrost_gem_vunmap(struct drm_gem_object *obj, void *vaddr)
{

}

static struct page *
sgt_get_page_by_idx(struct sg_table *sgt, int pidx)
{
	struct scatterlist *sg;
	struct page *page;
	int count;
	int len;
	int i;

	i = 0;

	for_each_sg(sgt->sgl, sg, sgt->nents, count) {
		len = sg_dma_len(sg);
		page = sg_page(sg);
		while (len > 0) {
			if (i == pidx)
				return (page);
			page++;
			len -= PAGE_SIZE;
			i++;
		}
	}

	return (NULL);
}

static vm_fault_t
panfrost_gem_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct panfrost_gem_object *bo;
	struct drm_gem_object *gem_obj;
	struct panfrost_softc *sc;
	struct page *page;
	vm_pindex_t pidx;
	vm_object_t obj;

	obj = vma->vm_obj;
	gem_obj = vma->vm_private_data;
	bo = (struct panfrost_gem_object *)gem_obj;
	sc = gem_obj->dev->dev_private;

	pidx = OFF_TO_IDX(vmf->virtual_address);

	VM_OBJECT_WLOCK(obj);
	if (bo->pages) {
		if (pidx >= bo->npages) {
			device_printf(sc->dev, "%s: error: requested page is "
			    "out of range (%d/%d)\n", __func__, bo->npages,
			    pidx);
			return (VM_FAULT_SIGBUS);
		}
		page = bo->pages[pidx];
	} else {
		/* Imported object. */
		KASSERT(bo->sgt != NULL, ("sgt is NULL"));
		page = sgt_get_page_by_idx(bo->sgt, pidx);
		if (!page)
			return (VM_FAULT_SIGBUS);
	}

	if (vm_page_busied(page))
		goto fail_unlock;
	if (vm_page_insert(page, obj, pidx))
		goto fail_unlock;
	vm_page_tryxbusy(page);
	vm_page_valid(page);
	VM_OBJECT_WUNLOCK(obj);

	vma->vm_pfn_first = pidx;
	vma->vm_pfn_count = 1;

	return (VM_FAULT_NOPAGE);

fail_unlock:
	VM_OBJECT_WUNLOCK(obj);
	return (VM_FAULT_SIGBUS);
}

static void
panfrost_gem_vm_open(struct vm_area_struct *vma)
{

	drm_gem_vm_open(vma);
}

static void
panfrost_gem_vm_close(struct vm_area_struct *vma)
{

	drm_gem_vm_close(vma);
}

static const struct vm_operations_struct panfrost_gem_vm_ops = {
	.fault = panfrost_gem_fault,
	.open = panfrost_gem_vm_open,
	.close = panfrost_gem_vm_close,
};

int
panfrost_gem_mmap(struct drm_gem_object *obj, struct vm_area_struct *vma)
{
	struct panfrost_gem_object *bo;
	struct panfrost_softc *sc;
	int error;

	dprintf("%s\n", __func__);

	bo = (struct panfrost_gem_object *)obj;

	vma->vm_pgoff -= drm_vma_node_start(&obj->vma_node);

	sc = obj->dev->dev_private;

	error = panfrost_gem_get_pages(bo);
	if (error != 0) {
		device_printf(sc->dev, "failed to get pages\n");
		return (error);
	}

	vma->vm_flags |= VM_MIXEDMAP | VM_DONTEXPAND;
	vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);
	if (!bo->map_cached)
		vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
	vma->vm_ops = &panfrost_gem_vm_ops;

	return (0);
}

static const struct drm_gem_object_funcs panfrost_gem_funcs = {
	.free = panfrost_gem_free_object,
	.open = panfrost_gem_open,
	.close = panfrost_gem_close,
	.print_info = panfrost_gem_print_info,
	.pin = panfrost_gem_pin,
	.unpin = panfrost_gem_unpin,
	.get_sg_table = panfrost_gem_get_sg_table,
	.vmap = panfrost_gem_vmap,
	.vunmap = panfrost_gem_vunmap,
	.mmap = panfrost_gem_mmap,
};

static struct panfrost_gem_object *
panfrost_gem_create_object(struct drm_device *dev, size_t size, bool private)
{
	struct panfrost_gem_object *obj;
	struct panfrost_softc *sc;
	int error;

	sc = dev->dev_private;

	obj = malloc(sizeof(*obj), M_PANFROST2, M_ZERO | M_WAITOK);
	obj->base.funcs = &panfrost_gem_funcs;
	TAILQ_INIT(&obj->mappings);
	mtx_init(&obj->mappings_lock, "mappings", NULL, MTX_DEF);
	obj->gpu_usecount = 0;

	if (private)
		drm_gem_private_object_init(dev, &obj->base, size);
	else
		drm_gem_object_init(dev, &obj->base, size);

	error = drm_gem_create_mmap_offset(&obj->base);
	if (error != 0) {
		device_printf(sc->dev, "Failed to create mmap offset.\n");
		return (NULL);
	}

	return (obj);
}

static void
panfrost_gem_object_put(struct panfrost_gem_object *bo)
{
	struct drm_gem_object *obj;
	struct drm_device *dev;

	obj = &bo->base;
	dev = obj->dev;

	mutex_lock(&dev->struct_mutex);
	drm_gem_object_put(obj);
	mutex_unlock(&dev->struct_mutex);
}

struct panfrost_gem_object *
panfrost_gem_create_object_with_handle(struct drm_file *file,
    struct drm_device *dev, size_t size, uint32_t flags, uint32_t *handle)
{
	struct panfrost_gem_object *obj;
	struct panfrost_softc *sc;
	int error;

	sc = dev->dev_private;

	dprintf("%s\n", __func__);

	if (size != PAGE_ALIGN(size))
		dprintf("%s: size %x new size %x\n", __func__,
		    size, PAGE_ALIGN(size));

	size = PAGE_ALIGN(size);

	if (flags & PANFROST_BO_HEAP)
		size = roundup(size, SZ_2M);

	obj = panfrost_gem_create_object(dev, size, false);
	if (obj == NULL) {
		device_printf(sc->dev, "%s: Failed to create object\n",
		    __func__);
		return (NULL);
	}

	if (flags & PANFROST_BO_NOEXEC)
		obj->noexec = true;

	if (flags & PANFROST_BO_HEAP)
		obj->is_heap = true;

	error = drm_gem_handle_create(file, &obj->base, handle);
	/* Drop reference from object_init(), handle holds it now. */
	panfrost_gem_object_put(obj);
	if (error) {
		device_printf(sc->dev, "%s: Failed to create handle\n",
		    __func__);
		return (NULL);
	}

	return (obj);
}

static void
panfrost_gem_teardown_mapping(struct panfrost_gem_mapping *mapping)
{
	struct panfrost_file *pfile;
	struct panfrost_softc *sc;

	pfile = container_of(mapping->mmu, struct panfrost_file, mmu);
	sc = pfile->sc;

	if (mapping->active)
		panfrost_mmu_unmap(sc, mapping);

	mtx_lock_spin(&pfile->mm_lock);
	if (drm_mm_node_allocated(&mapping->mmnode))
		drm_mm_remove_node(&mapping->mmnode);
	mtx_unlock_spin(&pfile->mm_lock);
}

void
panfrost_gem_teardown_mappings_locked(struct panfrost_gem_object *bo)
{
	struct panfrost_gem_mapping *mapping, *mapping1;

	TAILQ_FOREACH_SAFE(mapping, &bo->mappings, next, mapping1)
		panfrost_gem_teardown_mapping(mapping);
}

int
panfrost_gem_mappings_count(struct panfrost_gem_object *bo)
{
	struct panfrost_gem_mapping *mapping;
	int cnt;

	cnt = 0;

	mtx_lock(&bo->mappings_lock);
	TAILQ_FOREACH(mapping, &bo->mappings, next)
		cnt++;
	mtx_unlock(&bo->mappings_lock);

	return (cnt);
}

static void
panfrost_gem_mapping_release(struct panfrost_gem_mapping *mapping)
{

	panfrost_gem_teardown_mapping(mapping);
	panfrost_gem_object_put(mapping->obj);
	free(mapping, M_PANFROST1);
}

void
panfrost_gem_mapping_put(struct panfrost_gem_mapping *mapping)
{

	if (mapping && refcount_release(&mapping->refcount))
		panfrost_gem_mapping_release(mapping);
}

struct panfrost_gem_mapping *
panfrost_gem_mapping_get(struct panfrost_gem_object *bo,
    struct panfrost_file *file)
{
	struct panfrost_gem_mapping *mapping, *result;

	result = NULL;

	mtx_lock(&bo->mappings_lock);
	TAILQ_FOREACH(mapping, &bo->mappings, next) {
		if (mapping->mmu == &file->mmu) {
			result = mapping;
			refcount_acquire(&mapping->refcount);
			break;
		}
	}
	mtx_unlock(&bo->mappings_lock);

	return (result);
}

static int
panfrost_alloc_pages_iommu(struct panfrost_gem_object *bo, int npages)
{
	vm_paddr_t low, high, boundary;
	vm_memattr_t memattr;
	int alignment;
	vm_pointer_t va;
	int pflags;
	vm_page_t m;
	int tries;
	int i;

	alignment = PAGE_SIZE;
	low = 0;
	high = -1UL;
	boundary = 0;
	pflags = VM_ALLOC_NORMAL | VM_ALLOC_NOBUSY | VM_ALLOC_WIRED |
	    VM_ALLOC_ZERO;
	memattr = VM_MEMATTR_WRITE_COMBINING;

	for (i = 0; i < npages; i++) {
		tries = 0;
retry:
		m = vm_page_alloc_noobj_contig(pflags, 1, low, high,
		    alignment, boundary, memattr);
		if (m == NULL) {
			if (tries < 3) {
				if (!vm_page_reclaim_contig(pflags, 1, low,
				    high, alignment, boundary))
					vm_wait(NULL);
				tries++;
				goto retry;
			}

			return (ENOMEM);
		}
		if ((m->flags & PG_ZERO) == 0)
			pmap_zero_page(m);
		va = PHYS_TO_DMAP(VM_PAGE_TO_PHYS(m));
		cpu_dcache_wb_range(va, PAGE_SIZE);
		m->valid = VM_PAGE_BITS_ALL;
		m->oflags &= ~VPO_UNMANAGED;
		m->flags |= PG_FICTITIOUS;
		bo->pages[i] = m;
		bo->npages = i + 1;
	}

	return (0);
}

static int
panfrost_alloc_pages_contig(struct panfrost_gem_object *bo, int npages)
{
	vm_paddr_t low, high, boundary;
	vm_memattr_t memattr;
	int alignment;
	vm_pointer_t va;
	int pflags;
	vm_page_t m;
	int tries;
	int i;

	alignment = PAGE_SIZE;
	low = 0;
	high = -1UL;
	boundary = 0;
	pflags = VM_ALLOC_NORMAL | VM_ALLOC_NOBUSY | VM_ALLOC_WIRED |
	    VM_ALLOC_ZERO;
	memattr = VM_MEMATTR_WRITE_COMBINING;

	tries = 0;
retry:
	m = vm_page_alloc_noobj_contig(pflags, npages, low, high,
	    alignment, boundary, memattr);
	if (m == NULL) {
		if (tries < 3) {
			if (!vm_page_reclaim_contig(pflags, npages, low,
			    high, alignment, boundary))
				vm_wait(NULL);
			tries++;
			goto retry;
		}

		return (ENOMEM);
	}
	for (i = 0; i < npages; i++) {
		if ((m->flags & PG_ZERO) == 0)
			pmap_zero_page(m);
		va = PHYS_TO_DMAP(VM_PAGE_TO_PHYS(m));
		cpu_dcache_wb_range(va, PAGE_SIZE);
		m->valid = VM_PAGE_BITS_ALL;
		m->oflags &= ~VPO_UNMANAGED;
		m->flags |= PG_FICTITIOUS;
		bo->pages[i] = m;
		m++;
	}
	bo->npages = npages;

	return (0);
}

int
panfrost_gem_get_pages(struct panfrost_gem_object *bo)
{
	struct drm_gem_object *obj;
	vm_page_t *m0;
	int npages;
	int error;

	if (bo->sgt != NULL || bo->pages != NULL)
		return (0);

	obj = &bo->base;
	npages = obj->size / PAGE_SIZE;

	KASSERT(npages != 0, ("npages is 0"));

	m0 = malloc(sizeof(vm_page_t *) * npages, M_PANFROST,
	    M_WAITOK | M_ZERO);
	bo->pages = m0;
	bo->npages = 0;

	if (1 == 0)
		error = panfrost_alloc_pages_iommu(bo, npages);
	else
		error = panfrost_alloc_pages_contig(bo, npages);

	if (error)
		return (error);

	bo->sgt = drm_prime_pages_to_sg(m0, npages);

	return (0);
}

struct drm_gem_object *
panfrost_gem_prime_import_sg_table(struct drm_device *dev,
    struct dma_buf_attachment *attach, struct sg_table *sgt)
{
	struct panfrost_gem_object *bo;
	struct drm_gem_object *obj;
	size_t size;

	size = PAGE_ALIGN(attach->dmabuf->size);

	bo = panfrost_gem_create_object(dev, size, true);
	bo->sgt = sgt;
	bo->noexec = true;
	bo->npages = 0;
	bo->pages = NULL;

	obj = &bo->base;

	return (obj);
}
