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

#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <drm/drm_drv.h>
#include <drm/drm_atomic.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_gem_framebuffer_helper.h>
#include <drm/drm_plane_helper.h>
#include <drm/drm_fb_helper.h>
#include <drm/drm_fb_cma_helper.h>
#include <drm/drm_gem_cma_helper.h>
#include <drm/drm_fourcc.h>

#include <dev/drm/allwinner/aw_de2_mixer.h>
#include <dev/drm/allwinner/aw_de2_vi_plane.h>

void aw_de2_vi_plane_dump_regs(struct aw_de2_mixer_softc *sc, int num);

static const u32 aw_de2_vi_plane_formats[] = {
	/*
	 * Do not set those format
	 * Even if they work xorg will try to use them
	 * for the cursor plane as VI is the only other plane
	 * available for that and since alpha isn't available
	 * for VI plane this will make a black square around the
	 * mouse cursor.
	DRM_FORMAT_ARGB8888,
	DRM_FORMAT_ABGR8888,
	DRM_FORMAT_RGBA8888,
	DRM_FORMAT_BGRA8888,
	*/

	DRM_FORMAT_XRGB8888,
	DRM_FORMAT_XBGR8888,
	DRM_FORMAT_RGBX8888,
	DRM_FORMAT_BGRX8888,
	DRM_FORMAT_RGB888,
	DRM_FORMAT_BGR888,
	DRM_FORMAT_RGB565,
	DRM_FORMAT_BGR565,
	DRM_FORMAT_NV16,
	DRM_FORMAT_NV61,
	DRM_FORMAT_YUV422,
	DRM_FORMAT_NV12,
	DRM_FORMAT_NV21,
	DRM_FORMAT_YUV420,
	DRM_FORMAT_YUV411,
};

static int
aw_de2_vi_plane_atomic_check(struct drm_plane *plane,
    struct drm_plane_state *state)
{
	struct drm_crtc *crtc = state->crtc;
	struct drm_crtc_state *crtc_state;

	if (crtc == NULL)
		return (0);

	crtc_state = drm_atomic_get_existing_crtc_state(state->state, crtc);
	if (crtc_state == NULL)
		return (-EINVAL);

	return drm_atomic_helper_check_plane_state(state, crtc_state,
						   DRM_PLANE_HELPER_NO_SCALING, DRM_PLANE_HELPER_NO_SCALING,
						   true, true);
}

static uint32_t
aw_de2_vi_plane_format(u32 drm_format, bool *is_rgb) {

	switch (drm_format) {
		/* RGB format first */
	case DRM_FORMAT_ARGB8888:
		*is_rgb = true;
		return (0x00);
	case DRM_FORMAT_ABGR8888:
		*is_rgb = true;
		return (0x01);
	case DRM_FORMAT_RGBA8888:
		*is_rgb = true;
		return (0x02);
	case DRM_FORMAT_BGRA8888:
		*is_rgb = true;
		return (0x03);
	case DRM_FORMAT_XRGB8888:
		*is_rgb = true;
		return (0x04);
	case DRM_FORMAT_XBGR8888:
		*is_rgb = true;
		return (0x05);
	case DRM_FORMAT_RGBX8888:
		*is_rgb = true;
		return (0x06);
	case DRM_FORMAT_BGRX8888:
		*is_rgb = true;
		return (0x07);
	case DRM_FORMAT_RGB888:
		*is_rgb = true;
		return (0x08);
	case DRM_FORMAT_BGR888:
		*is_rgb = true;
		return (0x09);
	case DRM_FORMAT_RGB565:
		*is_rgb = true;
		return (0x0A);
	case DRM_FORMAT_BGR565:
		*is_rgb = true;
		return (0x0B);

	/* YUV format, Interleaved format (0x00 to 0x03) not included yet */
	case DRM_FORMAT_NV16:
		*is_rgb = false;
		return (0x04);
		break;
	case DRM_FORMAT_NV61:
		*is_rgb = false;
		return (0x05);
		break;
	case DRM_FORMAT_YUV422:
		*is_rgb = false;
		return (0x06);
		break;
	case DRM_FORMAT_NV12:
		*is_rgb = false;
		return (0x08);
		break;
	case DRM_FORMAT_NV21:
		*is_rgb = false;
		return (0x09);
		break;
	case DRM_FORMAT_YUV420:
		*is_rgb = false;
		return (0x0A);
		break;
	case DRM_FORMAT_YUV411:
		*is_rgb = false;
		return (0x0E);
		break;
	}

	return (0);
}

static void
aw_de2_vi_plane_atomic_disable(struct drm_plane *plane,
    struct drm_plane_state *old_state)
{
	struct aw_de2_mixer_plane *mixer_plane;
	struct aw_de2_mixer_softc *sc;
	uint32_t reg;

	mixer_plane = container_of(plane, struct aw_de2_mixer_plane, plane);
	sc = mixer_plane->sc;

	DRM_DEBUG_DRIVER("%s: Disabling VI plane\n", __func__);
	reg = AW_DE2_MIXER_READ_4(sc, OVL_VI_ATTR_CTL);
	reg &= ~OVL_VI_ATTR_EN;
	AW_DE2_MIXER_WRITE_4(sc, OVL_VI_ATTR_CTL, reg);

	/* HACK, Disable Pipe1 */
	reg = AW_DE2_MIXER_READ_4(sc, BLD_PIPE_CTL);
	reg &= ~0x202;
	AW_DE2_MIXER_WRITE_4(sc, BLD_PIPE_CTL,
	  reg);
}

static void
aw_de2_vi_plane_atomic_update(struct drm_plane *plane,
    struct drm_plane_state *old_state)
{
	struct aw_de2_mixer_plane *mixer_plane;
	struct aw_de2_mixer_softc *sc;
	struct drm_plane_state *state = plane->state;
	uint32_t src_w, src_h, dst_w, dst_h, src_x, src_y;
	struct drm_fb_cma *fb;
	struct drm_gem_cma_object *bo;
	dma_addr_t paddr;
	uint32_t reg;
	uint32_t format;
	int id, i;
	bool is_rgb = false;

	mixer_plane = container_of(plane, struct aw_de2_mixer_plane, plane);
	fb = container_of(plane->state->fb, struct drm_fb_cma, drm_fb);
	sc = mixer_plane->sc;
	id = mixer_plane->id;

	DRM_DEBUG_DRIVER("%s: plane=%p fb=%p\n", __func__, plane, fb);

	src_w = drm_rect_width(&state->src) >> 16;
	src_h = drm_rect_height(&state->src) >> 16;
	dst_w = drm_rect_width(&state->dst);
	dst_h = drm_rect_height(&state->dst);

	if (!plane->state->visible) {
		DRM_DEBUG_DRIVER("%s: Disabling VI layer %d\n", __func__, id);
		reg = AW_DE2_MIXER_READ_4(sc, OVL_VI_ATTR_CTL);
		reg &= ~OVL_VI_ATTR_EN;
		AW_DE2_MIXER_WRITE_4(sc, OVL_VI_ATTR_CTL, reg);
		return;
	}

	DRM_DEBUG_DRIVER("%s: %d %d %d %d\n", __func__,
	    src_w, src_h,
	    dst_w, dst_h);
	DRM_DEBUG_DRIVER("%s: VI Layer destination coordinates X: %d Y: %d\n",
	    __func__,
	    state->dst.x1, state->dst.y1);
	DRM_DEBUG_DRIVER("%s: VI Layer destination size W: %d H: %d\n",
	    __func__,
	    dst_w, dst_h);

	AW_DE2_MIXER_WRITE_4(sc, OVL_VI_MBSIZE,
	    ((src_h - 1) << 16) | (src_w - 1));
	AW_DE2_MIXER_WRITE_4(sc, OVL_VI_SIZE,
	    ((src_h - 1) << 16) | (src_w - 1));

	AW_DE2_MIXER_WRITE_4(sc, BLD_INSIZE(id),
	    ((dst_h - 1) << 16) | (dst_w - 1));
	AW_DE2_MIXER_WRITE_4(sc, BLD_COORD(id),
	    state->dst.y1 << 16 | state->dst.x1);

	src_x = (state->src.x1 >> 16) & ~(fb->drm_fb.format->hsub - 1);
	src_y = (state->src.y1 >> 16) & ~(fb->drm_fb.format->vsub - 1);

	DRM_DEBUG_DRIVER("%s: format->hsub: %d, format->vsub: %d\n",
	    __func__,
	    fb->drm_fb.format->hsub, fb->drm_fb.format->vsub);

	/* Update addr and pitch */
	for (i = 0; i < fb->drm_fb.format->num_planes; i++) {
		bo = drm_fb_cma_get_gem_obj(fb, i);

		DRM_DEBUG_DRIVER("%s: gem: %p\n", __func__, bo);
		DRM_DEBUG_DRIVER("%s: fb: %p\n", __func__, fb);

		if (i != 0) {
			src_x /= fb->drm_fb.format->hsub;
			src_y /= fb->drm_fb.format->vsub;
		}
		paddr = bo->pbase + fb->drm_fb.offsets[i];
		paddr += src_x * fb->drm_fb.format->cpp[i];
		paddr += src_y * fb->drm_fb.pitches[i];

		AW_DE2_MIXER_WRITE_4(sc, OVL_VI_TOP_Y_LADD(i), paddr & 0xFFFFFFFF);
		AW_DE2_MIXER_WRITE_4(sc, OVL_VI_Y_PITCH(i), fb->drm_fb.pitches[i]);
	}

	/* Update format */
	reg = AW_DE2_MIXER_READ_4(sc, OVL_VI_ATTR_CTL);
	reg &= ~OVL_VI_PIX_FORMAT_MASK;
	format = aw_de2_vi_plane_format(state->fb->format->format, &is_rgb);
	reg |= format << OVL_VI_PIX_FORMAT_SHIFT;
	if (is_rgb)
		reg |= OVL_VI_PIX_FORMAT_SEL;
	DRM_DEBUG_DRIVER("%s: format reg:%x\n", __func__, reg);
	AW_DE2_MIXER_WRITE_4(sc, OVL_VI_ATTR_CTL, reg);

	/* Enable overlay */
	reg = AW_DE2_MIXER_READ_4(sc, OVL_VI_ATTR_CTL);
	AW_DE2_MIXER_WRITE_4(sc, OVL_VI_ATTR_CTL,
	  reg | OVL_VI_ATTR_EN);

	/* HACK, Enable Pipe1 */
	reg = AW_DE2_MIXER_READ_4(sc, BLD_PIPE_CTL);
	reg |= 0x202;
	AW_DE2_MIXER_WRITE_4(sc, BLD_PIPE_CTL,
	  reg);

	/* HACK, Route channel 0 to pipe 1 */
	reg = AW_DE2_MIXER_READ_4(sc, BLD_CH_ROUTING);
	reg &= 0xFF0F;
	AW_DE2_MIXER_WRITE_4(sc, BLD_CH_ROUTING, reg);

	if (__drm_debug & DRM_UT_DRIVER)
		aw_de2_vi_plane_dump_regs(sc, 1);
}

static struct drm_plane_helper_funcs aw_de2_vi_plane_helper_funcs = {
	.atomic_check	= aw_de2_vi_plane_atomic_check,
	.atomic_disable	= aw_de2_vi_plane_atomic_disable,
	.atomic_update	= aw_de2_vi_plane_atomic_update,
};

static const struct drm_plane_funcs aw_de2_vi_plane_funcs = {
	.atomic_destroy_state	= drm_atomic_helper_plane_destroy_state,
	.atomic_duplicate_state	= drm_atomic_helper_plane_duplicate_state,
	.destroy		= drm_plane_cleanup,
	.disable_plane		= drm_atomic_helper_disable_plane,
	.reset			= drm_atomic_helper_plane_reset,
	.update_plane		= drm_atomic_helper_update_plane,
};

int
aw_de2_vi_plane_create(struct aw_de2_mixer_softc *sc, struct drm_device *drm)
{
	int i;

	for (i = 0; i < sc->conf->vi_planes; i++) {
		drm_universal_plane_init(drm,
		    &sc->vi_planes[i].plane,
		    0,
		    &aw_de2_vi_plane_funcs,
		    aw_de2_vi_plane_formats,
		    nitems(aw_de2_vi_plane_formats),
		    NULL, DRM_PLANE_TYPE_OVERLAY, NULL);

		drm_plane_helper_add(&sc->vi_planes[i].plane,
		    &aw_de2_vi_plane_helper_funcs);

		sc->vi_planes[i].sc = sc;
		sc->vi_planes[i].id = sc->conf->ui_planes + i;
	}

	return (0);
}

void
aw_de2_vi_plane_dump_regs(struct aw_de2_mixer_softc *sc, int num)
{
	uint32_t reg;

	DRM_DEBUG_DRIVER("%s: VI Plane\n", __func__);

	reg = AW_DE2_MIXER_READ_4(sc, OVL_VI_ATTR_CTL);
	DRM_DEBUG_DRIVER("%s: ATTR_CTL: %x\n", __func__, reg);

	reg = AW_DE2_MIXER_READ_4(sc, OVL_VI_MBSIZE);
	DRM_DEBUG_DRIVER("%s: MBSIZE: %x (%dx%d)\n", __func__, reg,
	  (reg & OVL_VI_MBSIZE_WIDTH_MASK) >> OVL_VI_MBSIZE_WIDTH_SHIFT,
	  (reg & OVL_VI_MBSIZE_HEIGHT_MASK) >> OVL_VI_MBSIZE_HEIGHT_SHIFT);

	reg = AW_DE2_MIXER_READ_4(sc, OVL_VI_COORD);
	DRM_DEBUG_DRIVER("%s: COOR: %x (%d %d)\n", __func__, reg,
	  (reg & OVL_VI_COORD_X_MASK) >> OVL_VI_COORD_X_SHIFT,
	  (reg & OVL_VI_COORD_Y_MASK) >> OVL_VI_COORD_Y_SHIFT);
	reg = AW_DE2_MIXER_READ_4(sc, OVL_VI_Y_PITCH(0));
	DRM_DEBUG_DRIVER("%s: PITCH0: %d\n", __func__, reg);
	reg = AW_DE2_MIXER_READ_4(sc, OVL_VI_Y_PITCH(1));
	DRM_DEBUG_DRIVER("%s: PITCH1: %d\n", __func__, reg);
	reg = AW_DE2_MIXER_READ_4(sc, OVL_VI_Y_PITCH(2));
	DRM_DEBUG_DRIVER("%s: PITCH2: %d\n", __func__, reg);
	reg = AW_DE2_MIXER_READ_4(sc, OVL_VI_TOP_Y_LADD(0));
	DRM_DEBUG_DRIVER("%s: TOP_LADD0: %x\n", __func__, reg);
	reg = AW_DE2_MIXER_READ_4(sc, OVL_VI_TOP_Y_LADD(1));
	DRM_DEBUG_DRIVER("%s: TOP_LADD1: %x\n", __func__, reg);
	reg = AW_DE2_MIXER_READ_4(sc, OVL_VI_TOP_Y_LADD(2));
	DRM_DEBUG_DRIVER("%s: TOP_LADD2: %x\n", __func__, reg);
	reg = AW_DE2_MIXER_READ_4(sc, OVL_VI_SIZE);
	DRM_DEBUG_DRIVER("%s: SIZE: %x (%dx%d)\n", __func__, reg,
	  (reg & OVL_VI_SIZE_WIDTH_MASK) >> OVL_VI_SIZE_WIDTH_SHIFT,
	  (reg & OVL_VI_SIZE_HEIGHT_MASK) >> OVL_VI_SIZE_HEIGHT_SHIFT);
	reg = AW_DE2_MIXER_READ_4(sc, BLD_INSIZE(num));
	DRM_DEBUG_DRIVER("%s: BLD_INSIZE(%d): %x (%dx%d)\n", __func__, num, reg,
	  (reg & OVL_VI_SIZE_WIDTH_MASK) >> OVL_VI_SIZE_WIDTH_SHIFT,
	  (reg & OVL_VI_SIZE_HEIGHT_MASK) >> OVL_VI_SIZE_HEIGHT_SHIFT);
	reg = AW_DE2_MIXER_READ_4(sc, BLD_COORD(num));
	DRM_DEBUG_DRIVER("%s: BLD_COORD(%d): %x (%dx%d)\n", __func__, num, reg,
	  (reg & OVL_VI_SIZE_WIDTH_MASK) >> OVL_VI_SIZE_WIDTH_SHIFT,
	  (reg & OVL_VI_SIZE_HEIGHT_MASK) >> OVL_VI_SIZE_HEIGHT_SHIFT);
}
