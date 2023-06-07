/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2022 Ruslan Bukin <br@bsdpad.com>
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>

#include <drm/drm_gem_cma_helper.h>
#include <drm/drm_file.h>

#include <dev/drm/komeda/komeda_gem.h>
#include <linux/dma-buf.h>

MALLOC_DECLARE(M_KOMEDA_GEM);

MALLOC_DEFINE(M_KOMEDA_GEM, "kgem", "Komeda GEM");

struct sg_table *
komeda_gem_prime_get_sg_table(struct drm_gem_object *obj)
{
	struct sg_table *sgt;
	vm_page_t *m;
	int npages;

	m = drm_gem_cma_get_pages(obj, &npages);
	if (m == NULL)
		return (NULL);

	sgt = drm_prime_pages_to_sg(m, npages);

	return (sgt);
}

struct drm_gem_object *
komeda_gem_prime_import_sg_table(struct drm_device *dev,
    struct dma_buf_attachment *attach, struct sg_table *sgt)
{
	struct drm_gem_cma_object *bo;
	struct scatterlist *sg;
	struct page *page;
	unsigned count;
	size_t size;
	int ret;

	size = PAGE_ALIGN(attach->dmabuf->size);
	ret = drm_gem_cma_create_nobufs(dev, size, true, &bo);
	if (ret) {
		printf("%s: could not create CMA object\n", __func__);
		return (NULL);
	}

	size = round_page(bo->gem_obj.size);
	bo->size = round_page(size);
	bo->sgt = sgt;

	/*
	 * Since we don't have IOMMU, we expect that pages are contiguous.
	 * So take paddr of the first page.
	 */
	for_each_sg(sgt->sgl, sg, sgt->nents, count) {
		page = sg_page(sg);
		bo->pbase = VM_PAGE_TO_PHYS(page);
		break;
	}

	return (&bo->gem_obj);
}

static int
komeda_drm_gem_object_mmap(struct drm_gem_object *obj,
    struct vm_area_struct *vma)
{
	struct drm_gem_cma_object *bo;
	vm_page_t *m;
	int npages;
	int error;

	m = drm_gem_cma_get_pages(obj, &npages);
	if (m == NULL)
		return (ENXIO);

	bo = container_of(obj, struct drm_gem_cma_object, gem_obj);
	if (bo->pbase == 0)
		return (0);

	error = drm_gem_mmap_obj(obj, npages * PAGE_SIZE, vma);
	drm_gem_object_put_unlocked(obj);
	if (error)
		printf("%s: error %d\n", __func__, error);

	vma->vm_pfn = OFF_TO_IDX(bo->pbase);

	return (error);
}

int
komeda_gem_mmap_buf(struct drm_gem_object *obj, struct vm_area_struct *vma)
{

	return komeda_drm_gem_object_mmap(obj, vma);
}
