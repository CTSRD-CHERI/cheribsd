/*-
 * Copyright (c) 2016 Michal Meloun
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
#include <sys/vmem.h>

#include <vm/vm.h>

#include <machine/bus.h>

#include <drm/drm_crtc_helper.h>
#include <drm/drm_fb_helper.h>
#include <drm/drm_gem.h>
#include <drm/drm_gem_cma_helper.h>
#include <drm/drm_fb_cma_helper.h>
#include <drm/drm_gem_framebuffer_helper.h>
#include <drm/drm_fourcc.h>

static int drm_format_num_planes(uint32_t format)
{
	const struct drm_format_info *info;

	info = drm_format_info(format);
	return info ? info->num_planes : 1;
}

static int drm_format_horz_chroma_subsampling(uint32_t format)
{
	const struct drm_format_info *info;

	info = drm_format_info(format);
	return info ? info->hsub : 1;
}

static int drm_format_vert_chroma_subsampling(uint32_t format)
{
	const struct drm_format_info *info;

	info = drm_format_info(format);
	return info ? info->vsub : 1;
}

static inline
int drm_format_info_plane_cpp(const struct drm_format_info *info, int plane)
{
	if (!info || plane >= info->num_planes)
		return 0;

	return info->cpp[plane];
}

static void
drm_gem_fb_destroy(struct drm_framebuffer *drm_fb)
{
	struct drm_fb_cma *fb;
	struct drm_gem_cma_object *bo;
	unsigned int i;

	fb = container_of(drm_fb, struct drm_fb_cma, drm_fb);
	for (i = 0; i < fb->nplanes; i++) {
		bo = fb->planes[i];
		if (bo != NULL) {
			pmap_qremove(fb->planes_vbase[i], bo->npages);
			vmem_free(kmem_arena, fb->planes_vbase[i], bo->size);
			drm_gem_object_put_unlocked(&bo->gem_obj);
		}
	}

	drm_framebuffer_cleanup(drm_fb);
	free(fb->planes, DRM_MEM_DRIVER);
	free(fb->planes_vbase, DRM_MEM_DRIVER);
}

static int
drm_gem_fb_create_handle(struct drm_framebuffer *drm_fb, struct drm_file *file,
 unsigned int *handle)
{
	struct drm_fb_cma *fb;
	int rv;

	fb = container_of(drm_fb, struct drm_fb_cma, drm_fb);
	rv = drm_gem_handle_create(file, &fb->planes[0]->gem_obj, handle);
	return (rv);
}

static const struct drm_framebuffer_funcs gem_fb_funcs = {
	.destroy = drm_gem_fb_destroy,
	.create_handle = drm_gem_fb_create_handle,
};

static int
drm_gem_fb_alloc(struct drm_device *drm,
    const struct drm_mode_fb_cmd2 *mode_cmd,
    struct drm_gem_cma_object **planes,
    unsigned int num_planes,
    struct drm_fb_cma **res_fb)
{
	struct drm_fb_cma *fb;
	int i;
	int rv;

	fb = malloc(sizeof(*fb), DRM_MEM_DRIVER, M_WAITOK | M_ZERO);
	fb->planes = malloc(num_planes * sizeof(*fb->planes), DRM_MEM_DRIVER,
	    M_WAITOK | M_ZERO);
	fb->planes_vbase = malloc(num_planes * sizeof(*fb->planes_vbase),
	    DRM_MEM_DRIVER,  M_WAITOK | M_ZERO);
	fb->nplanes = num_planes;

	drm_helper_mode_fill_fb_struct(drm, &fb->drm_fb, mode_cmd);
	for (i = 0; i < fb->nplanes; i++) {
		fb->planes[i] = planes[i];
		rv = vmem_alloc(kmem_arena, planes[i]->size,
		    M_WAITOK | M_BESTFIT, &fb->planes_vbase[i]);
		if (rv != 0)
			return (ENOMEM);
		pmap_qenter(fb->planes_vbase[i], planes[i]->m,
		    planes[i]->npages);
	}
	rv = drm_framebuffer_init(drm, &fb->drm_fb, &gem_fb_funcs);
	if (rv < 0) {
		device_printf(drm->dev,
		    "Cannot initialize frame buffer %d\n", rv);
		free(fb->planes, DRM_MEM_DRIVER);
		return (rv);
	}
	*res_fb = fb;
	return (0);
}

/*
 * Equivalent to drm_fb_helper_generic_probe
 */
int
drm_fb_cma_probe(struct drm_fb_helper *helper,
    struct drm_fb_helper_surface_size *sizes)
{
	u_int bpp, size; //, offs;
	struct drm_fb_cma *fb;
	struct fb_info *info;
	struct drm_gem_cma_object *bo;
	struct drm_mode_fb_cmd2 mode_cmd;
	struct drm_device *drm_dev;
	int rv;

	if (helper->fb != NULL)
		return (0);

	DRM_DEBUG("surface: %d x %d (bpp: %d)\n", sizes->surface_width,
	    sizes->surface_height, sizes->surface_bpp);

	drm_dev = helper->dev;
	fb = container_of(helper, struct drm_fb_cma, fb_helper);
	bpp = (sizes->surface_bpp + 7) / 8;

	/* Create mode_cmd */
	memset(&mode_cmd, 0, sizeof(mode_cmd));
	mode_cmd.width = sizes->surface_width;
	mode_cmd.height = sizes->surface_height;
	mode_cmd.pitches[0] = sizes->surface_width * bpp;
	mode_cmd.pixel_format = drm_mode_legacy_fb_format(sizes->surface_bpp,
	    sizes->surface_depth);
	size = mode_cmd.pitches[0] * mode_cmd.height;

	rv = drm_gem_cma_create(drm_dev, size, &bo);
	if (rv != 0)
		return (rv);

	info = drm_fb_helper_alloc_fbi(helper);
	if (IS_ERR(info)) {
		DRM_ERROR("Cannot allocate DRM framebuffer info.\n");
		rv =  PTR_ERR(info);
		goto err_object;
	}

	rv = drm_gem_fb_alloc(drm_dev, &mode_cmd,  &bo, 1, &fb);
	if (rv != 0) {
		DRM_ERROR("Cannot allocate DRM framebuffer.\n");
		goto err_fb;
	}

	helper->fb = &fb->drm_fb;
	helper->fbdev = info;

	/* Fill FB info */
	info->fb_vbase = fb->planes_vbase[0];
	info->fb_pbase = fb->planes[0]->pbase;
	info->fb_size = size;
	info->fb_bpp = sizes->surface_bpp;
	drm_fb_helper_fill_info(info, helper, sizes);

	drm_dev->mode_config.fb_base =  bo->pbase;

	DRM_DEBUG("allocated %dx%d (s %dbits) fb size: %d, bo %p\n",
		      fb->drm_fb.width, fb->drm_fb.height,
		      fb->drm_fb.format->depth, size, bo);
	DRM_DEBUG(" vbase: 0x%08X, pbase: 0x%08X\n",
		      info->fb_vbase, info->fb_pbase);
	return (0);
err_fb:
	drm_gem_object_put_unlocked(&bo->gem_obj);
	framebuffer_release(info);
err_object:
	drm_gem_object_release(&bo->gem_obj);
	return (rv);
}

struct drm_framebuffer *
drm_gem_fb_create(struct drm_device *drm, struct drm_file *file,
    const struct drm_mode_fb_cmd2 *cmd)
{
	int hsub, vsub, i;
	int width, height, size, bpp;
	struct drm_gem_cma_object *planes[4];
	struct drm_gem_object *gem_obj;
	struct drm_fb_cma *fb;
	int rv, nplanes;

	hsub = drm_format_horz_chroma_subsampling(cmd->pixel_format);
	vsub = drm_format_vert_chroma_subsampling(cmd->pixel_format);

	nplanes = drm_format_num_planes(cmd->pixel_format);
	for (i = 0; i < nplanes; i++) {
		const struct drm_format_info *info;

		width = cmd->width;
		height = cmd->height;
		if (i != 0) {
			width /= hsub;
			height /= vsub;
		}
		gem_obj = drm_gem_object_lookup(file, cmd->handles[i]);
		if (gem_obj == NULL)
			goto fail;

		info = drm_format_info(cmd->pixel_format);
		bpp = drm_format_info_plane_cpp(info, i);
		size = (height - 1) * cmd->pitches[i] +
		    width * bpp + cmd->offsets[i];
		if (gem_obj->size < size)
			goto fail;
		planes[i] = container_of(gem_obj, struct drm_gem_cma_object, gem_obj);
	}

	rv = drm_gem_fb_alloc(drm, cmd, planes, nplanes, &fb);
	if (rv != 0)
		goto fail;

	return (&fb->drm_fb);

fail:
	while (i--)
		drm_gem_object_put_unlocked(&planes[i]->gem_obj);
	return (NULL);
}
