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

#include <dev/drm/komeda/komeda_plane.h>
#include <dev/drm/komeda/komeda_pipeline.h>
#include <dev/drm/komeda/komeda_drv.h>
#include <dev/drm/komeda/komeda_regs.h>

#define	dprintf(fmt, ...)

static const u32 komeda_plane_formats[] = {
	DRM_FORMAT_ARGB2101010,
	DRM_FORMAT_ABGR2101010,
	DRM_FORMAT_RGBA1010102,
	DRM_FORMAT_BGRA1010102,
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
	/* Except last (WB) layer. */
	DRM_FORMAT_RGBA5551,
	DRM_FORMAT_ABGR1555,
	DRM_FORMAT_RGB565,
	DRM_FORMAT_BGR565,
};

static uint32_t
komeda_convert_format(uint32_t format)
{

	switch (format) {
	case DRM_FORMAT_ARGB2101010:
		return (0);
	case DRM_FORMAT_ABGR2101010:
		return (1);
	case DRM_FORMAT_RGBA1010102:
		return (2);
	case DRM_FORMAT_BGRA1010102:
		return (3);
	case DRM_FORMAT_ARGB8888:
		return (8);
	case DRM_FORMAT_ABGR8888:
		return (9);
	case DRM_FORMAT_RGBA8888:
		return (10);
	case DRM_FORMAT_BGRA8888:
		return (11);
	case DRM_FORMAT_XRGB8888:
	/*
	 * Documentation states this should be 16, but it works better with 17.
	 * FALLTHROUGH
	 */
	case DRM_FORMAT_XBGR8888:
		return (17);
	case DRM_FORMAT_RGBX8888:
		return (18);
	case DRM_FORMAT_BGRX8888:
		return (19);
	case DRM_FORMAT_RGB888:
		return (24);
	case DRM_FORMAT_BGR888:
		return (25);
	case DRM_FORMAT_RGBA5551:
		return (32);
	case DRM_FORMAT_ABGR1555:
		return (33);
	case DRM_FORMAT_RGB565:
		return (34);
	case DRM_FORMAT_BGR565:
		return (35);
	default:
		return (-1);
	}

	return (-1);
}

static int
komeda_plane_atomic_check(struct drm_plane *plane,
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
komeda_plane_atomic_disable(struct drm_plane *plane,
    struct drm_plane_state *old_state)
{

	dprintf("%s\n", __func__);
}

void
dou_ds_control(struct komeda_drm_softc *sc, bool enable)
{
	int reg;

	if (enable)
		reg = BS_CONTROL_EN | BS_CONTROL_VM;
	else
		reg = 0;

	DPU_WR4(sc, BS_CONTROL, reg);
}

void
dou_ds_timing_setup(struct komeda_drm_softc *sc, struct drm_display_mode *m)
{
	uint32_t hactive, hfront_porch, hback_porch, hsync_len;
	uint32_t vactive, vfront_porch, vback_porch, vsync_len;
	uint32_t reg;

	hactive = m->crtc_hdisplay;
	hfront_porch = m->crtc_hsync_start - m->crtc_hdisplay;
	hsync_len = m->crtc_hsync_end - m->crtc_hsync_start;
	hback_porch = m->crtc_htotal - m->crtc_hsync_end;

	vactive = m->crtc_vdisplay;
	vfront_porch = m->crtc_vsync_start - m->crtc_vdisplay;
	vsync_len = m->crtc_vsync_end - m->crtc_vsync_start;
	vback_porch = m->crtc_vtotal - m->crtc_vsync_end;

	reg = hactive << ACTIVESIZE_HACTIVE_S;
	reg |= vactive << ACTIVESIZE_VACTIVE_S;
	DPU_WR4(sc, BS_ACTIVESIZE, reg);

	reg = hfront_porch << HINTERVALS_HFRONTPORCH_S;
	reg |= hback_porch << HINTERVALS_HBACKPORCH_S;
	DPU_WR4(sc, BS_HINTERVALS, reg);

	reg = vfront_porch << VINTERVALS_VFRONTPORCH_S;
	reg |= vback_porch << VINTERVALS_VBACKPORCH_S;
	DPU_WR4(sc, BS_VINTERVALS, reg);

	reg = vsync_len << SYNC_VSYNCWIDTH_S;
	reg |= hsync_len << SYNC_HSYNCWIDTH_S;
	reg |= m->flags & DRM_MODE_FLAG_PVSYNC ? SYNC_VSP : 0;
	reg |= m->flags & DRM_MODE_FLAG_PHSYNC ? SYNC_HSP : 0;
	DPU_WR4(sc, BS_SYNC, reg);

	DPU_WR4(sc, BS_PROG_LINE, D71_DEFAULT_PREPRETCH_LINE - 1);
	DPU_WR4(sc, BS_PREFETCH_LINE, D71_DEFAULT_PREPRETCH_LINE);

	dou_ds_control(sc, true);
}

void
dou_intr(struct komeda_drm_softc *sc)
{
	struct komeda_pipeline *pipeline;
	uint32_t reg;

	reg = DPU_RD4(sc, DOU0_IRQ_STATUS);

	pipeline = &sc->pipelines[0];	/* TODO */

	if ((reg & DOU_IRQ_PL0) != reg)
		printf("%s: reg %x\n", __func__, reg);

	if (reg & DOU_IRQ_PL0) {
		atomic_add_32(&pipeline->vbl_counter, 1);
		drm_crtc_handle_vblank(&pipeline->crtc);
	}

	DPU_WR4(sc, DOU0_IRQ_CLEAR, reg);
}

void
gcu_intr(struct komeda_drm_softc *sc)
{
	uint32_t reg;
	int mask;

	reg = DPU_RD4(sc, GCU_IRQ_STATUS);

	mask = GCU_IRQ_CVAL0;

	if ((reg & mask) != reg)
		printf("%s: reg %x\n", __func__, reg);

	DPU_WR4(sc, GCU_IRQ_CLEAR, reg);
}

void
cu_intr(struct komeda_drm_softc *sc)
{
	uint32_t reg;

	reg = DPU_RD4(sc, CU0_CU_IRQ_STATUS);

	printf("%s: reg %x\n", __func__, reg);

	DPU_WR4(sc, CU0_CU_IRQ_CLEAR, reg);
}

void
lpu_intr(struct komeda_drm_softc *sc)
{
	uint32_t reg;

	reg = DPU_RD4(sc, LPU0_IRQ_STATUS);

	printf("%s: reg %x\n", __func__, reg);

	DPU_WR4(sc, LPU0_IRQ_CLEAR, reg);
}

static int
gcu_configure(struct komeda_drm_softc *sc)
{

	if (komeda_pipeline_set_mode(sc, CONTROL_MODE_DO0_ACTIVE) != 0) {
		printf("%s: Failed to set DO0 active\n", __func__);
		return (-1);
	}

	DPU_WR4(sc, GCU_CONFIG_VALID0, CONFIG_VALID0_CVAL);

	dprintf("%s: GCU initialized\n", __func__);

	return (0);
}

void
dou_configure(struct komeda_drm_softc *sc, struct drm_display_mode *m)
{
	uint32_t reg;

	reg = DPU_RD4(sc, CU0_OUTPUT_ID0);
	DPU_WR4(sc, DOU0_IPS_INPUT_ID0, reg);

	reg = m->hdisplay << IPS_SIZE_HSIZE_S;
	reg |= m->vdisplay << IPS_SIZE_VSIZE_S;
	DPU_WR4(sc, DOU0_IPS_SIZE, reg);
	DPU_WR4(sc, DOU0_IPS_DEPTH, IPS_OUT_DEPTH_10);
	DPU_WR4(sc, DOU0_IPS_CONTROL, 0);
}

static void
lpu_configure(struct komeda_drm_softc *sc, struct drm_fb_cma *fb,
    struct drm_plane_state *state, int id)
{
	const struct drm_format_info *info;
	struct drm_gem_cma_object *bo;
	uint32_t dst_w, dst_h;
	dma_addr_t paddr;
	uint32_t reg;
	int block_h;
	int fmt;
	int i;

	for (i = 0; i < nitems(komeda_plane_formats); i++)
		if (komeda_plane_formats[i] == state->fb->format->format)
			break;

	fmt = komeda_convert_format(komeda_plane_formats[i]);
	dprintf("%s: fmt %d\n", __func__, fmt);

	if (state->fb->format->has_alpha && id > 0)
		dprintf("%s: cursor plane\n", __func__);

	bo = drm_fb_cma_get_gem_obj(fb, 0);
	paddr = bo->pbase + fb->drm_fb.offsets[0];
	paddr += (state->src.x1 >> 16) * fb->drm_fb.format->cpp[0];
	paddr += (state->src.y1 >> 16) * fb->drm_fb.pitches[0];
	dprintf("%s: pbase %lx, paddr %lx\n", __func__, bo->pbase, paddr);

	info = fb->drm_fb.format;
	block_h = drm_format_info_block_height(info, 0);

	dprintf("%s: num_planes %d\n", __func__, info->num_planes);

	/*
	 * LPU configuration. Setup layer.
	 */
	DPU_WR4(sc, LR_P0_STRIDE(id), fb->drm_fb.pitches[0] * block_h);
	dprintf("%s: plane 0 STRIDE is %x\n", __func__,
	    fb->drm_fb.pitches[0] * block_h);
	DPU_WR8(sc, LR_P0_PTR_LOW(id), paddr);
	DPU_WR4(sc, LR_FORMAT(id), fmt);

	dst_w = drm_rect_width(&state->dst);
	dst_h = drm_rect_height(&state->dst);
	reg = dst_w | dst_h << 16;
	DPU_WR4(sc, LR_IN_SIZE(id), reg);

	DPU_WR4(sc, LR_PALPHA(id), D71_PALPHA_DEF_MAP);
	DPU_WR4(sc, LR_AD_CONTROL(id), 0); /* No modifiers. */
	reg = CONTROL_EN | CONTROL_ARCACHE_AXIC_BUF_CACHE;
	DPU_WR4(sc, LR_CONTROL(id), reg);
}

void
cu_configure(struct komeda_drm_softc *sc, struct drm_display_mode *m, 
    struct drm_plane_state *state, int id)
{
	uint32_t dst_w, dst_h;
	struct drm_rect *dst;
	uint32_t ctrl;
	uint32_t reg;

	dst = &state->dst;

	/*
	 * CU configuration. CU0 inputs from layer 0.
	 */
	reg = DPU_RD4(sc, LR_OUTPUT_ID0(id));
	DPU_WR4(sc, CU0_CU_INPUT_ID(id), reg);

	reg = (m->hdisplay << CU_SIZE_HSIZE_S);
	reg |= (m->vdisplay << CU_SIZE_VSIZE_S);
	DPU_WR4(sc, CU0_CU_SIZE, reg);

	dst_w = drm_rect_width(&state->dst);
	dst_h = drm_rect_height(&state->dst);
	reg = dst_w << INPUT0_SIZE_HSIZE_S;
	reg |= dst_h << INPUT0_SIZE_VSIZE_S;

	ctrl = INPUT0_CONTROL_LALPHA_MAX | INPUT0_CONTROL_EN;

	if (id == 0) {
		DPU_WR4(sc, CU0_INPUT0_SIZE, reg);
		DPU_WR4(sc, CU0_INPUT0_OFFSET, 0);
		DPU_WR4(sc, CU0_INPUT0_CONTROL, ctrl);
		/* Disable cursor plane, it will be enabled if needed. */
		DPU_WR4(sc, CU0_INPUT1_CONTROL, 0);
	} else {
		DPU_WR4(sc, CU0_INPUT1_SIZE, reg);
		reg = dst->x1 << INPUT0_OFFSET_HOFFSET_S;
		reg |= dst->y1 << INPUT0_OFFSET_VOFFSET_S;
		DPU_WR4(sc, CU0_INPUT1_OFFSET, reg);
		DPU_WR4(sc, CU0_INPUT1_CONTROL, ctrl);
	}
}

static void
komeda_plane_atomic_update(struct drm_plane *plane,
    struct drm_plane_state *old_state)
{
	struct komeda_plane *komeda_plane;
	struct komeda_drm_softc *sc;
	struct drm_crtc *crtc;
	struct drm_fb_cma *fb;
	struct drm_display_mode *m;
	struct drm_plane_state *state;
	uint32_t reg;

	dprintf("%s\n", __func__);

	state = plane->state;
	crtc = state->crtc;

	komeda_plane = container_of(plane, struct komeda_plane, plane);

	fb = container_of(plane->state->fb, struct drm_fb_cma, drm_fb);
	sc = komeda_plane->sc;

	m = &crtc->state->adjusted_mode;
	dprintf("%s: adj mode hdisplay %d vdisplay %d\n", __func__,
	    m->hdisplay, m->vdisplay);

	dprintf("%s: Clock freq needed: %d\n", __func__, m->crtc_clock);

	/* Enable IRQs */
	DPU_WR4(sc, GCU_IRQ_MASK, GCU_IRQ_ERR | GCU_IRQ_MODE | GCU_IRQ_CVAL0);

	reg = DPU_RD4(sc, DOU0_IRQ_MASK);
	reg |= DOU_IRQ_ERR | DOU_IRQ_UND;
	DPU_WR4(sc, DOU0_IRQ_MASK, reg);

	DPU_WR4(sc, LPU0_IRQ_MASK, (LPU_IRQ_MASK_PL0 | LPU_IRQ_MASK_EOW | \
					LPU_IRQ_MASK_ERR | LPU_IRQ_MASK_IBSY));
	DPU_WR4(sc, CU0_CU_IRQ_MASK, CU_IRQ_MASK_OVR | CU_IRQ_MASK_ERR);

	lpu_configure(sc, fb, state, komeda_plane->id);
	cu_configure(sc, m, state, komeda_plane->id);
	gcu_configure(sc);

	dprintf("%s: GCU_STATUS %x\n", __func__, DPU_RD4(sc, GCU_STATUS));
	dprintf("%s: LPU0_IRQ_RAW_STATUS %x\n", __func__,
	    DPU_RD4(sc, LPU0_IRQ_RAW_STATUS));
	dprintf("%s: LPU0_STATUS %x\n", __func__, DPU_RD4(sc, LPU0_STATUS));
	dprintf("%s: CU0_CU_STATUS %x\n", __func__, DPU_RD4(sc, CU0_CU_STATUS));
	dprintf("%s: DOU0_STATUS %x\n", __func__, DPU_RD4(sc, DOU0_STATUS));
}

static struct drm_plane_helper_funcs komeda_plane_helper_funcs = {
	.atomic_check	= komeda_plane_atomic_check,
	.atomic_disable	= komeda_plane_atomic_disable,
	.atomic_update	= komeda_plane_atomic_update,
};

static const struct drm_plane_funcs komeda_plane_funcs = {
	.atomic_destroy_state	= drm_atomic_helper_plane_destroy_state,
	.atomic_duplicate_state	= drm_atomic_helper_plane_duplicate_state,
	.destroy		= drm_plane_cleanup,
	.disable_plane		= drm_atomic_helper_disable_plane,
	.reset			= drm_atomic_helper_plane_reset,
	.update_plane		= drm_atomic_helper_update_plane,
};

int
komeda_plane_create(struct komeda_pipeline *pipeline, struct drm_device *drm)
{
	struct komeda_drm_softc *sc;
	enum drm_plane_type type;
	int error;
	int i;

	sc = pipeline->sc;

	dprintf("%s\n", __func__);

	for (i = 0; i < 2; i++) {
		if (i == 0)
			type = DRM_PLANE_TYPE_PRIMARY;
		else
			type = DRM_PLANE_TYPE_CURSOR;

		pipeline->planes[i].sc = sc;
		pipeline->planes[i].id = i;

		error = drm_universal_plane_init(drm,
		    &pipeline->planes[i].plane,
		    0,
		    &komeda_plane_funcs,
		    komeda_plane_formats,
		    nitems(komeda_plane_formats),
		    NULL, type, NULL);
		if (error != 0) {
			device_printf(sc->dev, "Could not init plane.");
			return (error);
		}
		drm_plane_helper_add(&pipeline->planes[i].plane,
		    &komeda_plane_helper_funcs);
	}

	return (0);
}
