/*-
 * Copyright (c) 2019 Emmanuel Vadot <manu@FreeBSD.org>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef _DRM_GEM_CMA_H_
#define	_DRM_GEM_CMA_H_

#include <drm/drm_gem.h>
#include <linux/scatterlist.h>

struct drm_gem_cma_object {
	struct drm_gem_object	gem_obj;
	struct sg_table         *sgt;

	/* mapped memory buffer */
	vm_paddr_t		pbase;
	vm_offset_t		vbase;
	size_t			npages;
	size_t			size;		/* Rounded to page */
	vm_page_t 		*m;
};

int drm_gem_cma_create(struct drm_device *drm, size_t size,
    struct drm_gem_cma_object **res_bo);
int drm_gem_cma_create_nobufs(struct drm_device *drm, size_t size,
    bool private, struct drm_gem_cma_object **res_bo);
void drm_gem_cma_free_object(struct drm_gem_object *gem_obj);
int drm_gem_cma_dumb_create(struct drm_file *file, struct drm_device *drm_dev,
    struct drm_mode_create_dumb *args);
int drm_gem_cma_mmap(struct file *file, struct vm_area_struct *vma);
vm_page_t * drm_gem_cma_get_pages(struct drm_gem_object *gem_obj,
    int *npages);

extern const struct vm_operations_struct drm_gem_cma_vm_ops;

#endif /* _DRM_GEM_CMA_H_ */
