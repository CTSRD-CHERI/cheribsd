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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/rman.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/eventhandler.h>
#include <sys/gpio.h>
#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/pmap.h>

#include <machine/bus.h>

#include <dev/fdt/fdt_common.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#include <dev/ofw/ofw_graph.h>

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
#include <drm/drm_print.h>
#include <drm/drm_vblank.h>

#include <dev/extres/hwreset/hwreset.h>
#include <dev/extres/clk/clk.h>
#include <dev/extres/phy/phy.h>

#include <dev/videomode/videomode.h>
#include <dev/videomode/edidvar.h>

#include <dev/drm/rockchip/rk_plane.h>
#include <dev/drm/rockchip/rk_vop.h>

#include "rk_vop_if.h"
#include "dw_hdmi_if.h"

#define	VOP_READ(sc, reg)	bus_read_4((sc)->res[0], (reg))
#define	VOP_WRITE(sc, reg, val)	bus_write_4((sc)->res[0], (reg), (val))

#define	dprintf(fmt, ...)

static const u32 rk_vop_plane_formats[] = {
	DRM_FORMAT_XRGB8888,
	DRM_FORMAT_ARGB8888,
	DRM_FORMAT_XBGR8888,
	DRM_FORMAT_ABGR8888,
	DRM_FORMAT_RGB888,
	DRM_FORMAT_BGR888,
	DRM_FORMAT_RGB565,
	DRM_FORMAT_BGR565,
	DRM_FORMAT_NV12,
	DRM_FORMAT_NV16,
	DRM_FORMAT_NV24,
};

static enum rockchip_data_format
vop_convert_format(uint32_t format)
{

	switch (format) {
	case DRM_FORMAT_XRGB8888:
	case DRM_FORMAT_ARGB8888:
	case DRM_FORMAT_XBGR8888:
	case DRM_FORMAT_ABGR8888:
		return VOP_FMT_ARGB8888;
	case DRM_FORMAT_RGB888:
	case DRM_FORMAT_BGR888:
		return VOP_FMT_RGB888;
	case DRM_FORMAT_RGB565:
	case DRM_FORMAT_BGR565:
		return VOP_FMT_RGB565;
	case DRM_FORMAT_NV12:
		return VOP_FMT_YUV420SP;
	case DRM_FORMAT_NV16:
		return VOP_FMT_YUV422SP;
	case DRM_FORMAT_NV24:
		return VOP_FMT_YUV444SP;
	default:
		return (-1);
	}
}

static int
rk_vop_plane_atomic_check(struct drm_plane *plane,
    struct drm_plane_state *state)
{
	struct drm_crtc *crtc;
	struct drm_crtc_state *crtc_state;

	dprintf("%s\n", __func__);

	crtc = state->crtc;
	if (crtc == NULL)
		return (0);

	crtc_state = drm_atomic_get_existing_crtc_state(state->state, crtc);
	if (crtc_state == NULL)
		return (-EINVAL);

	return (drm_atomic_helper_check_plane_state(state, crtc_state,
	    DRM_PLANE_HELPER_NO_SCALING,
	    DRM_PLANE_HELPER_NO_SCALING,
	    true, true));
}

static void
rk_vop_plane_atomic_disable(struct drm_plane *plane,
    struct drm_plane_state *old_state)
{

}

static void
rk_vop_plane_atomic_update(struct drm_plane *plane,
    struct drm_plane_state *old_state)
{
	struct drm_plane_state *state;
	struct rk_vop_plane *vop_plane;
	struct rk_vop_softc *sc;
	struct drm_gem_cma_object *bo;
	struct drm_fb_cma *fb;
	uint32_t src_w, src_h, dst_w, dst_h;
	dma_addr_t paddr;
	uint32_t reg;
	struct drm_crtc *crtc;
	struct drm_rect *dst;
	uint32_t dsp_stx, dsp_sty;
	int rgb_mode;
	int lb_mode;
	int id;
	int i;

	state = plane->state;
	dst = &state->dst;
	crtc = state->crtc;
	vop_plane = container_of(plane, struct rk_vop_plane, plane);
	fb = container_of(plane->state->fb, struct drm_fb_cma, drm_fb);

	sc = vop_plane->sc;
	id = vop_plane->id;

	dprintf("%s: id %d\n", __func__, vop_plane->id);

	src_w = drm_rect_width(&state->src) >> 16;
	src_h = drm_rect_height(&state->src) >> 16;
	dst_w = drm_rect_width(&state->dst);
	dst_h = drm_rect_height(&state->dst);

	dprintf("%s: src w %d h %d, dst w %d h %d\n",
	    __func__, src_w, src_h, dst_w, dst_h);

	/* TODO */
	if (!plane->state->visible)
		panic("plane is not visible");

	/* Actual size. */
	reg = (src_w - 1);
	reg |= (src_h - 1) << 16;
	if (id == 0)
		VOP_WRITE(sc, RK3399_WIN0_ACT_INFO, reg);

	dsp_stx = dst->x1 + crtc->mode.htotal - crtc->mode.hsync_start;
	dsp_sty = dst->y1 + crtc->mode.vtotal - crtc->mode.vsync_start;
	reg = dsp_sty << 16 | (dsp_stx & 0xffff);
	if (id == 0)
		VOP_WRITE(sc, RK3399_WIN0_DSP_ST, reg);
	else
		VOP_WRITE(sc, RK3399_WIN2_DSP_ST0, reg);

	reg = (dst_w - 1);
	reg |= (dst_h - 1) << 16;
	if (id == 0)
		VOP_WRITE(sc, RK3399_WIN0_DSP_INFO, reg);
	else
		VOP_WRITE(sc, RK3399_WIN2_DSP_INFO0, reg);

	for (i = 0; i < nitems(rk_vop_plane_formats); i++)
		if (rk_vop_plane_formats[i] == state->fb->format->format)
			break;

	rgb_mode = vop_convert_format(rk_vop_plane_formats[i]);
	dprintf("fmt %d\n", rgb_mode);

	if (dst_w <= 1280)
		lb_mode = LB_RGB_1280X8;
	else if (dst_w <= 1920)
		lb_mode = LB_RGB_1920X5;
	else if (dst_w <= 2560)
		lb_mode = LB_RGB_2560X4;
	else if (dst_w <= 3840)
		lb_mode = LB_RGB_3840X2;
	else
		panic("unknown lb_mode, dst_w %d", dst_w);

	if (id == 0) {
		VOP_WRITE(sc, RK3399_WIN0_VIR, state->fb->pitches[0] >> 2);

		reg = VOP_READ(sc, RK3399_WIN0_CTRL0);
		reg &= ~WIN0_CTRL0_LB_MODE_M;
		reg &= ~WIN0_CTRL0_DATA_FMT_M;
		reg &= ~WIN0_CTRL0_EN;
		VOP_WRITE(sc, RK3399_WIN0_CTRL0, reg);
		reg |= lb_mode << WIN0_CTRL0_LB_MODE_S;
		reg |= rgb_mode << WIN0_CTRL0_DATA_FMT_S;
		reg |= WIN0_CTRL0_EN;
		VOP_WRITE(sc, RK3399_WIN0_CTRL0, reg);
	} else {
		VOP_WRITE(sc, RK3399_WIN2_VIR0_1, state->fb->pitches[0] >> 2);

		reg = VOP_READ(sc, RK3399_WIN2_CTRL0);
		reg &= ~WIN2_CTRL0_DATA_FMT_M;
		reg &= ~WIN2_CTRL0_EN;
		VOP_WRITE(sc, RK3399_WIN2_CTRL0, reg);
		reg |= rgb_mode << WIN2_CTRL0_DATA_FMT_S;
		reg |= WIN2_CTRL0_EN;
		reg |= WIN2_CTRL0_GATE;
		VOP_WRITE(sc, RK3399_WIN2_CTRL0, reg);
	}

	/* Cursor plane alpha. */
	if (state->fb->format->has_alpha && id > 0) {
		VOP_WRITE(sc, RK3399_WIN2_DST_ALPHA_CTRL, DST_FACTOR_M0(3));

		reg = SRC_ALPHA_EN;
		reg |= 1 << SRC_BLEND_M0_S;
		reg |= SRC_ALPHA_CAL_M0;
		reg |= SRC_FACTOR_M0;
		VOP_WRITE(sc, RK3399_WIN2_SRC_ALPHA_CTRL, reg);
	}

	bo = drm_fb_cma_get_gem_obj(fb, 0);
	paddr = bo->pbase + fb->drm_fb.offsets[0];
	paddr += (state->src.x1 >> 16) * fb->drm_fb.format->cpp[0];
	paddr += (state->src.y1 >> 16) * fb->drm_fb.pitches[0];

	if (id == 0)
		VOP_WRITE(sc, RK3399_WIN0_YRGB_MST, paddr);
	else
		VOP_WRITE(sc, RK3399_WIN2_MST0, paddr);

	VOP_WRITE(sc, RK3399_REG_CFG_DONE, 1);
}

static struct drm_plane_helper_funcs rk_vop_plane_helper_funcs = {
	.atomic_check	= rk_vop_plane_atomic_check,
	.atomic_disable	= rk_vop_plane_atomic_disable,
	.atomic_update	= rk_vop_plane_atomic_update,
};

static const struct drm_plane_funcs rk_vop_plane_funcs = {
	.atomic_destroy_state	= drm_atomic_helper_plane_destroy_state,
	.atomic_duplicate_state	= drm_atomic_helper_plane_duplicate_state,
	.destroy		= drm_plane_cleanup,
	.disable_plane		= drm_atomic_helper_disable_plane,
	.reset			= drm_atomic_helper_plane_reset,
	.update_plane		= drm_atomic_helper_update_plane,
};

int
rk_plane_create(struct rk_vop_softc *sc, struct drm_device *drm)
{
	enum drm_plane_type type;
	int error;
	int i;

	dprintf("%s\n", __func__);

	for (i = 0; i < 2; i++) {
		if (i == 0)
			type = DRM_PLANE_TYPE_PRIMARY;
		else
			type = DRM_PLANE_TYPE_CURSOR;

		error = drm_universal_plane_init(drm,
		    &sc->planes[i].plane,
		    0,
		    &rk_vop_plane_funcs,
		    rk_vop_plane_formats,
		    nitems(rk_vop_plane_formats),
		    NULL, type, NULL);
		if (error != 0) {
			device_printf(sc->dev, "Could not init plane.");
			return (error);
		}
		drm_plane_helper_add(&sc->planes[i].plane,
		    &rk_vop_plane_helper_funcs);

		sc->planes[i].sc = sc;
		sc->planes[i].id = i;
	}

	return (0);
}
