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
#include <drm/drm_fb_cma_helper.h>
#include <drm/drm_fb_helper.h>
#include <drm/drm_fb_cma_helper.h>
#include <drm/drm_gem_cma_helper.h>
#include <drm/drm_fourcc.h>

#include <dev/drm/allwinner/aw_de2_mixer.h>
#include <dev/drm/allwinner/aw_de2_ui_plane.h>

void aw_de2_ui_plane_dump_regs(struct aw_de2_mixer_softc *sc, int num);

static const u32 aw_de2_ui_plane_formats[] = {
	DRM_FORMAT_ARGB8888,
	DRM_FORMAT_ABGR8888,
	DRM_FORMAT_RGBA8888,
	DRM_FORMAT_BGRA8888,
	DRM_FORMAT_XRGB8888,
	DRM_FORMAT_XBGR8888,
	DRM_FORMAT_RGBX8888,
	DRM_FORMAT_BGRX8888,
	DRM_FORMAT_RGB888,
	DRM_FORMAT_BGR888,
	DRM_FORMAT_RGB565,
	DRM_FORMAT_BGR565,
	DRM_FORMAT_ARGB4444,
	DRM_FORMAT_ABGR4444,
	DRM_FORMAT_RGBA4444,
	DRM_FORMAT_BGRA4444,
	DRM_FORMAT_ARGB1555,
	DRM_FORMAT_ABGR1555,
	DRM_FORMAT_RGBA5551,
	DRM_FORMAT_BGRA5551,
};

static int aw_de2_ui_plane_atomic_check(struct drm_plane *plane,
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
	    DRM_PLANE_HELPER_NO_SCALING,
	    DRM_PLANE_HELPER_NO_SCALING,
	    true, true);
}

static void aw_de2_ui_plane_atomic_disable(struct drm_plane *plane,
					  struct drm_plane_state *old_state)
{
	struct aw_de2_mixer_plane *mixer_plane;
	struct aw_de2_mixer_softc *sc;
	uint32_t reg;

	mixer_plane = container_of(plane, struct aw_de2_mixer_plane, plane);
	sc = mixer_plane->sc;

	reg = AW_DE2_MIXER_READ_4(sc, OVL_UI_ATTR_CTL(mixer_plane->id));
	reg &= ~OVL_UI_ATTR_EN;
	AW_DE2_MIXER_WRITE_4(sc, OVL_UI_ATTR_CTL(mixer_plane->id), reg);
}

static void aw_de2_ui_plane_atomic_update(struct drm_plane *plane,
					 struct drm_plane_state *old_state)
{
	struct aw_de2_mixer_plane *mixer_plane;
	struct aw_de2_mixer_softc *sc;
	struct drm_plane_state *state = plane->state;
	uint32_t src_w, src_h, dst_w, dst_h;
	struct drm_fb_cma *fb;
	struct drm_gem_cma_object *bo;
	dma_addr_t paddr;
	uint32_t reg;
	int id, i;

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
		DRM_DEBUG_DRIVER("%s: Disabling UI layer %d\n", __func__, id);
		reg = AW_DE2_MIXER_READ_4(sc, OVL_UI_ATTR_CTL(id));
		AW_DE2_MIXER_WRITE_4(sc, OVL_UI_ATTR_CTL(id),
		  reg & ~OVL_UI_ATTR_EN);
		return;
	}

	DRM_DEBUG_DRIVER("%s: %d %d %d %d\n", __func__,
	    src_w, src_h,
	    dst_w, dst_h);
	DRM_DEBUG_DRIVER("%s: Layer destination coordinates X: %d Y: %d\n",
	    __func__, state->dst.x1, state->dst.y1);
	DRM_DEBUG_DRIVER("%s: Layer destination size W: %d H: %d\n",
	    __func__,
	    dst_w, dst_h);

	AW_DE2_MIXER_WRITE_4(sc, OVL_UI_MBSIZE(id),
	  ((src_h - 1) << 16) | (src_w - 1));
	AW_DE2_MIXER_WRITE_4(sc, OVL_UI_SIZE(id),
	  ((src_h - 1) << 16) | (src_w - 1));

	if (plane->type == DRM_PLANE_TYPE_PRIMARY) {
		AW_DE2_MIXER_WRITE_4(sc, GBL_SIZE,
		  ((dst_h - 1) << 16) | (dst_w - 1));
		AW_DE2_MIXER_WRITE_4(sc, BLD_OUTSIZE,
		  ((dst_h - 1) << 16) | (dst_w - 1));
	}
	AW_DE2_MIXER_WRITE_4(sc, BLD_INSIZE(id),
	  ((dst_h - 1) << 16) | (dst_w - 1));
	AW_DE2_MIXER_WRITE_4(sc, BLD_COORD(id),
	  state->dst.y1 << 16 | state->dst.x1);

	/* Update addr and pitch */
	bo = drm_fb_cma_get_gem_obj(fb, 0);

	DRM_DEBUG_DRIVER("%s: gem: %p\n", __func__, bo);
	DRM_DEBUG_DRIVER("%s: fb: %p\n", __func__, fb);

	paddr = bo->pbase + fb->drm_fb.offsets[0];
	paddr += (state->src.x1 >> 16) * fb->drm_fb.format->cpp[0];
	paddr += (state->src.y1 >> 16) * fb->drm_fb.pitches[0];

	AW_DE2_MIXER_WRITE_4(sc, OVL_UI_TOP_LADD(id), paddr & 0xFFFFFFFF);
	AW_DE2_MIXER_WRITE_4(sc, OVL_UI_BOT_LADD(id), 0);
	AW_DE2_MIXER_WRITE_4(sc, OVL_UI_TOP_HADD(id), 0);
	AW_DE2_MIXER_WRITE_4(sc, OVL_UI_BOT_HADD(id), 0);
	AW_DE2_MIXER_WRITE_4(sc, OVL_UI_PITCH(id), fb->drm_fb.pitches[0]);

	/* Update format */
	reg = AW_DE2_MIXER_READ_4(sc, OVL_UI_ATTR_CTL(id));
	reg &= ~OVL_UI_PIX_FORMAT_MASK;
	for (i = 0; i < nitems(aw_de2_ui_plane_formats); i++)
		if (aw_de2_ui_plane_formats[i] == state->fb->format->format)
			break;
	reg |= i << OVL_UI_PIX_FORMAT_SHIFT;

	AW_DE2_MIXER_WRITE_4(sc, OVL_UI_ATTR_CTL(id), reg);

	/* Enable overlay */
	reg = AW_DE2_MIXER_READ_4(sc, OVL_UI_ATTR_CTL(id));
	AW_DE2_MIXER_WRITE_4(sc, OVL_UI_ATTR_CTL(id),
	  reg | OVL_UI_ATTR_EN);

	/* Enable pipe0 */
	reg = AW_DE2_MIXER_READ_4(sc, BLD_PIPE_CTL);
	reg |= 0x101;
	AW_DE2_MIXER_WRITE_4(sc, BLD_PIPE_CTL,
	  reg);

	reg = AW_DE2_MIXER_READ_4(sc, BLD_CH_ROUTING);
	/* route channel 1 to pipe0 */
	reg |= 1 << 0;
	AW_DE2_MIXER_WRITE_4(sc, BLD_CH_ROUTING, reg);

	if (__drm_debug & DRM_UT_DRIVER)
		aw_de2_ui_plane_dump_regs(sc, 0);
}

static struct drm_plane_helper_funcs aw_de2_ui_plane_helper_funcs = {
	.atomic_check	= aw_de2_ui_plane_atomic_check,
	.atomic_disable	= aw_de2_ui_plane_atomic_disable,
	.atomic_update	= aw_de2_ui_plane_atomic_update,
};

static const struct drm_plane_funcs aw_de2_ui_plane_funcs = {
	.atomic_destroy_state	= drm_atomic_helper_plane_destroy_state,
	.atomic_duplicate_state	= drm_atomic_helper_plane_duplicate_state,
	.destroy		= drm_plane_cleanup,
	.disable_plane		= drm_atomic_helper_disable_plane,
	.reset			= drm_atomic_helper_plane_reset,
	.update_plane		= drm_atomic_helper_update_plane,
};

int
aw_de2_ui_plane_create(struct aw_de2_mixer_softc *sc, struct drm_device *drm)
{
	enum drm_plane_type type = DRM_PLANE_TYPE_PRIMARY;
	int i;

	for (i = 0; i < sc->conf->ui_planes; i++) {
		if (i > 0)
			type = DRM_PLANE_TYPE_OVERLAY;
		drm_universal_plane_init(drm,
		    &sc->ui_planes[i].plane,
		    0,
		    &aw_de2_ui_plane_funcs,
		    aw_de2_ui_plane_formats,
		    nitems(aw_de2_ui_plane_formats),
		    NULL, type, NULL);

		drm_plane_helper_add(&sc->ui_planes[i].plane,
		    &aw_de2_ui_plane_helper_funcs);

		sc->ui_planes[i].sc= sc;
		sc->ui_planes[i].id = i;
	}

	return (0);
}

void
aw_de2_ui_plane_dump_regs(struct aw_de2_mixer_softc *sc, int num)
{
	uint32_t reg;
	int i;

	DRM_DEBUG_DRIVER("%s: UI Plane %d\n", __func__, num);

	reg = AW_DE2_MIXER_READ_4(sc, OVL_UI_ATTR_CTL(num));
	DRM_DEBUG_DRIVER("%s: ATTR_CTL(%d): %x\n", __func__, num, reg);

	reg = AW_DE2_MIXER_READ_4(sc, OVL_UI_MBSIZE(num));
	DRM_DEBUG_DRIVER("%s: MBSIZE(%d): %x (%dx%d)\n", __func__, num, reg,
	  (reg & OVL_UI_MBSIZE_WIDTH_MASK) >> OVL_UI_MBSIZE_WIDTH_SHIFT,
	  (reg & OVL_UI_MBSIZE_HEIGHT_MASK) >> OVL_UI_MBSIZE_HEIGHT_SHIFT);

	reg = AW_DE2_MIXER_READ_4(sc, OVL_UI_COORD(num));
	DRM_DEBUG_DRIVER("%s: COOR(%d): %x (%d %d)\n", __func__, num, reg,
	    (reg & OVL_UI_COOR_X_MASK) >> OVL_UI_COOR_X_SHIFT,
	    (reg & OVL_UI_COOR_Y_MASK) >> OVL_UI_COOR_Y_SHIFT);
	reg = AW_DE2_MIXER_READ_4(sc, OVL_UI_PITCH(num));
	DRM_DEBUG_DRIVER("%s: PITCH(%d): %d\n", __func__, num, reg);
	reg = AW_DE2_MIXER_READ_4(sc, OVL_UI_TOP_LADD(num));
	DRM_DEBUG_DRIVER("%s: TOP_LADD(%d): %x\n", __func__, num, reg);
	reg = AW_DE2_MIXER_READ_4(sc, OVL_UI_BOT_LADD(num));
	DRM_DEBUG_DRIVER("%s: BOT_LADD(%d): %x\n", __func__, num, reg);
	reg = AW_DE2_MIXER_READ_4(sc, OVL_UI_FILL_COLOR(num));
	DRM_DEBUG_DRIVER("%s: FILL_COLOR(%d): %x\n", __func__, num, reg);
	reg = AW_DE2_MIXER_READ_4(sc, OVL_UI_TOP_HADD(num));
	DRM_DEBUG_DRIVER("%s: TOP_HADD(%d): %x\n", __func__, num, reg);
	reg = AW_DE2_MIXER_READ_4(sc, OVL_UI_BOT_HADD(num));
	DRM_DEBUG_DRIVER("%s: BOT_HADD(%d): %x\n", __func__, num, reg);
	reg = AW_DE2_MIXER_READ_4(sc, OVL_UI_SIZE(num));
	DRM_DEBUG_DRIVER("%s: SIZE(%d): %x (%dx%d)\n", __func__, num, reg,
	    (reg & OVL_UI_SIZE_WIDTH_MASK) >> OVL_UI_SIZE_WIDTH_SHIFT,
	    (reg & OVL_UI_SIZE_HEIGHT_MASK) >> OVL_UI_SIZE_HEIGHT_SHIFT);
	reg = AW_DE2_MIXER_READ_4(sc, BLD_PIPE_CTL);
	DRM_DEBUG_DRIVER("%s: BLD_PIPE_CTL: %x\n", __func__, reg);
	for (i = 0; i < 4; i++) {
		reg = AW_DE2_MIXER_READ_4(sc, BLD_FILL_COLOR(i));
		DRM_DEBUG_DRIVER("%s: BLD_FILL_COLOR(%d): %x\n", __func__,
		    i, reg);
	}
	reg = AW_DE2_MIXER_READ_4(sc, BLD_INSIZE(num));
	DRM_DEBUG_DRIVER("%s: BLD_INSIZE(%d): %x (%dx%d)\n", __func__, num, reg,
	    (reg & OVL_UI_SIZE_WIDTH_MASK) >> OVL_UI_SIZE_WIDTH_SHIFT,
	    (reg & OVL_UI_SIZE_HEIGHT_MASK) >> OVL_UI_SIZE_HEIGHT_SHIFT);
	reg = AW_DE2_MIXER_READ_4(sc, BLD_COORD(num));
	DRM_DEBUG_DRIVER("%s: BLD_COORD(%d): %x (%dx%d)\n", __func__, num, reg,
	    (reg & OVL_UI_SIZE_WIDTH_MASK) >> OVL_UI_SIZE_WIDTH_SHIFT,
	    (reg & OVL_UI_SIZE_HEIGHT_MASK) >> OVL_UI_SIZE_HEIGHT_SHIFT);
	reg = AW_DE2_MIXER_READ_4(sc, BLD_CH_ROUTING);
	DRM_DEBUG_DRIVER("%s: BLD_CH_ROUTING: %x\n", __func__, reg);
	reg = AW_DE2_MIXER_READ_4(sc, BLD_OUTSIZE);
	DRM_DEBUG_DRIVER("%s: BLD_OUTSIZE: %x (%dx%d)\n", __func__, reg,
	    (reg & OVL_UI_SIZE_WIDTH_MASK) >> OVL_UI_SIZE_WIDTH_SHIFT,
	    (reg & OVL_UI_SIZE_HEIGHT_MASK) >> OVL_UI_SIZE_HEIGHT_SHIFT);
}
