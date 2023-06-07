/*-
 * Copyright (c) 2015 Michal Meloun
 * All rights reserved.
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
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/rwlock.h>
#include <sys/vmem.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/vm_pager.h>

#include <machine/bus.h>

#include <dev/extres/clk/clk.h>

#include <drm/drm_crtc_helper.h>
#include <drm/drm_gem.h>
#include <drm/drm_prime.h>
#include <drm/drm_gem_cma_helper.h>

static int
drm_gem_cma_create_with_handle(struct drm_file *file, struct drm_device *drm,
    size_t size, uint32_t *handle, struct drm_gem_cma_object **res_bo);

static void
drm_gem_cma_destruct(struct drm_gem_cma_object *bo)
{
	vm_page_t m;
	int i;

	if (bo->vbase != 0) {
		pmap_qremove(bo->vbase, bo->npages);
		vmem_free(kmem_arena, bo->vbase, round_page(bo->gem_obj.size));
	}

	for (i = 0; i < bo->npages; i++) {
		m = bo->m[i];
		if (m == NULL)
			break;
		vm_page_lock(m);
		m->oflags |= VPO_UNMANAGED;
		m->flags &= ~PG_FICTITIOUS;
		vm_page_unwire_noq(m);
		vm_page_free(m);
		vm_page_unlock(m);
	}
}

static int
drm_gem_cma_alloc_contig(size_t npages, u_long alignment, vm_memattr_t memattr,
    vm_page_t **ret_page)
{
	vm_page_t m;
	int pflags, tries, i;
	vm_paddr_t low, high, boundary;

	low = 0;
	high = -1UL;
	boundary = 0;
	pflags = VM_ALLOC_NORMAL | VM_ALLOC_NOBUSY | VM_ALLOC_WIRED |
	    VM_ALLOC_ZERO;
	tries = 0;
retry:
	m = vm_page_alloc_noobj_contig(pflags, npages, low, high, alignment,
	    boundary, memattr);
	if (m == NULL) {
		if (tries < 3) {
			if (!vm_page_reclaim_contig(pflags, npages, low, high,
			    alignment, boundary))
				vm_wait(NULL);
			tries++;
			goto retry;
		}
		return (ENOMEM);
	}

	for (i = 0; i < npages; i++, m++) {
		if ((m->flags & PG_ZERO) == 0)
			pmap_zero_page(m);
		m->valid = VM_PAGE_BITS_ALL;
		(*ret_page)[i] = m;
	}

	return (0);
}

/* Allocate memory for frame buffer */
static int
drm_gem_cma_alloc(struct drm_device *drm, struct drm_gem_cma_object *bo)
{
	size_t size;
	vm_page_t m;
	int i;	int rv;

	size = round_page(bo->gem_obj.size);
	bo->npages = atop(size);
	bo->size = round_page(size);
	bo->m = malloc(sizeof(vm_page_t *) * bo->npages, DRM_MEM_DRIVER,
	    M_WAITOK | M_ZERO);

	rv = drm_gem_cma_alloc_contig(bo->npages, PAGE_SIZE,
	    VM_MEMATTR_WRITE_COMBINING, &(bo->m));
	if (rv != 0) {
		DRM_WARN("Cannot allocate memory for gem object.\n");
		return (rv);
	}

	for (i = 0; i < bo->npages; i++) {
		m = bo->m[i];
		/*
		 * XXX This is a temporary hack.
		 * We need pager suitable for paging (mmap) managed
		 * real (non-fictitious) pages.
		 * - managed pages are needed for clean module unload.
		 * - aliasing fictitious page to real one is bad,
		 *   pmap cannot handle this situation without issues
		 *   It expects that
		 *    paddr = PHYS_TO_VM_PAGE(VM_PAGE_TO_PHYS(paddr))
		 *   for every single page passed to pmap.
		 */
		m->oflags &= ~VPO_UNMANAGED;
		m->flags |= PG_FICTITIOUS;
	}

	bo->pbase = VM_PAGE_TO_PHYS(bo->m[0]);
	return (0);
}

static int
drm_gem_cma_fault(struct vm_area_struct *dummy, struct vm_fault *vmf)
{
	struct vm_area_struct *vma;
	struct drm_gem_object *gem_obj;
	struct drm_gem_cma_object *bo;
	vm_object_t obj;
	vm_pindex_t pidx;
	struct page *page;
	int i;

	vma = vmf->vma;
	gem_obj = vma->vm_private_data;
	bo = container_of(gem_obj, struct drm_gem_cma_object, gem_obj);
	obj = vma->vm_obj;

	if (!bo->m)
		return (VM_FAULT_SIGBUS);

	pidx = OFF_TO_IDX(vmf->address - vma->vm_start);
	if (pidx >= bo->npages)
		return (VM_FAULT_SIGBUS);

	VM_OBJECT_WLOCK(obj);
	for (i = 0; i < bo->npages; i++) {
		page = bo->m[i];
		if (vm_page_busied(page))
			goto fail_unlock;
		if (vm_page_insert(page, obj, i))
			goto fail_unlock;
		vm_page_tryxbusy(page);
		page->valid = VM_PAGE_BITS_ALL;
	}
	VM_OBJECT_WUNLOCK(obj);

	vma->vm_pfn_first = 0;
	vma->vm_pfn_count =  bo->npages;
	DRM_DEBUG("%s: pidx: %llu, start: 0x%08X, addr: 0x%08lX\n", __func__, pidx, vma->vm_start, vmf->address);

	return (VM_FAULT_NOPAGE);

fail_unlock:
	VM_OBJECT_WUNLOCK(obj);
	DRM_ERROR("%s: insert failed\n", __func__);
	return (VM_FAULT_SIGBUS);
}

const struct vm_operations_struct drm_gem_cma_vm_ops = {
	.fault = drm_gem_cma_fault,
	.open = drm_gem_vm_open,
	.close = drm_gem_vm_close,
};

static int
drm_gem_cma_create_with_handle(struct drm_file *file, struct drm_device *drm,
    size_t size, uint32_t *handle, struct drm_gem_cma_object **res_bo)
{
	int rv;
	struct drm_gem_cma_object *bo;

	rv = drm_gem_cma_create(drm, size, &bo);
	if (rv != 0)
		return (rv);

	rv = drm_gem_handle_create(file, &bo->gem_obj, handle);
	if (rv != 0) {
		drm_gem_cma_free_object(&bo->gem_obj);
		drm_gem_object_release(&bo->gem_obj);
		return (rv);
	}

	drm_gem_object_put_unlocked(&bo->gem_obj);

	*res_bo = bo;
	return (0);
}

/*
 * Exported functions 
 */

vm_page_t *
drm_gem_cma_get_pages(struct drm_gem_object *gem_obj, int *npages)
{
	struct drm_gem_cma_object *bo;

	bo = container_of(gem_obj, struct drm_gem_cma_object, gem_obj);

	*npages = bo->npages;

	return (bo->m);
}

void
drm_gem_cma_free_object(struct drm_gem_object *gem_obj)
{
	struct drm_gem_cma_object *bo;

	bo = container_of(gem_obj, struct drm_gem_cma_object, gem_obj);
	drm_gem_free_mmap_offset(gem_obj);

	if (gem_obj->import_attach)
		drm_prime_gem_destroy(gem_obj, bo->sgt);

	drm_gem_object_release(gem_obj);

	drm_gem_cma_destruct(bo);

	free(bo->m, DRM_MEM_DRIVER);
	free(bo, DRM_MEM_DRIVER);
}

/*
 * drm_gem_cma_dumb_create
 */
int
drm_gem_cma_dumb_create(struct drm_file *file, struct drm_device *drm_dev,
    struct drm_mode_create_dumb *args)
{
	struct drm_gem_cma_object *bo;
	int rv;

	args->pitch = args->width * args->bpp / 8;
	args->size = args->height * args->pitch;
	rv = drm_gem_cma_create_with_handle(file, drm_dev, args->size,
	    &args->handle, &bo);
	return (rv);
}

int
drm_gem_cma_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct drm_gem_object *gem_obj;
	struct drm_gem_cma_object *bo;
	int rv;

	rv = drm_gem_mmap(file, vma);
	if (rv < 0)
		return (rv);

	gem_obj = vma->vm_private_data;
	bo = container_of(gem_obj, struct drm_gem_cma_object, gem_obj);
	if (bo->pbase == 0)
		return (0);

	vma->vm_pfn = OFF_TO_IDX(bo->pbase);
	return (rv);
}

int
drm_gem_cma_create_nobufs(struct drm_device *drm, size_t size, bool private,
    struct drm_gem_cma_object **res_bo)
{
	struct drm_gem_cma_object *bo;
	int rv;

	if (size <= 0)
		return (-EINVAL);

	bo = malloc(sizeof(*bo), DRM_MEM_DRIVER, M_WAITOK | M_ZERO);

	size = round_page(size);

	if (private) {
		drm_gem_private_object_init(drm, &bo->gem_obj, size);
	} else {
		rv = drm_gem_object_init(drm, &bo->gem_obj, size);
		if (rv != 0) {
			DRM_ERROR("%s: drm_gem_object_init failed\n", __func__);
			free(bo, DRM_MEM_DRIVER);
			return (rv);
		}
	}

	rv = drm_gem_create_mmap_offset(&bo->gem_obj);
	if (rv != 0) {
		DRM_ERROR("%s: drm_gem_create_mmap_offset failed\n", __func__);
		drm_gem_object_release(&bo->gem_obj);
		free(bo, DRM_MEM_DRIVER);
		return (rv);
	}

	*res_bo = bo;

	return (0);
}

int
drm_gem_cma_create(struct drm_device *drm, size_t size, struct drm_gem_cma_object **res_bo)
{
	struct drm_gem_cma_object *bo;
	int rv;

	rv = drm_gem_cma_create_nobufs(drm, size, false, &bo);
	if (rv != 0) {
		DRM_ERROR("%s: drm_gem_cma_alloc failed\n", __func__);
		return (rv);
	}

	rv = drm_gem_cma_alloc(drm, bo);
	if (rv != 0) {
		DRM_ERROR("%s: drm_gem_cma_alloc failed\n", __func__);
		drm_gem_cma_free_object(&bo->gem_obj);
		return (rv);
	}

	*res_bo = bo;
	return (0);
}
