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

#include <dev/clk/clk.h>
#include <dev/fdt/fdt_common.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#include <dev/ofw/ofw_graph.h>

#include <drm/drm_drv.h>
#include <drm/drm_atomic.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_gem_framebuffer_helper.h>
#include <drm/drm_plane_helper.h>
#include <drm/drm_fb_helper.h>
#include <drm/drm_fourcc.h>
#include <drm/drm_print.h>
#include <drm/drm_vblank.h>

#include <dev/hwreset/hwreset.h>
#include <dev/clk/clk.h>
#include <dev/phy/phy.h>

#include <dev/videomode/videomode.h>
#include <dev/videomode/edidvar.h>

#include <dev/drm/komeda/komeda_plane.h>
#include <dev/drm/komeda/komeda_pipeline.h>
#include <dev/drm/komeda/komeda_drv.h>
#include <dev/drm/komeda/komeda_regs.h>

#include "drm_bridge_if.h"

#define	dprintf(fmt, ...)

/*
 * VBLANK functions
 */
static int
komeda_pipeline_enable_vblank(struct drm_crtc *crtc)
{
	struct komeda_pipeline *pipeline;
	struct komeda_drm_softc *sc;
	uint32_t reg;

	dprintf("%s\n", __func__);

	pipeline = container_of(crtc, struct komeda_pipeline, crtc);
	sc = pipeline->sc;

	reg = DPU_RD4(sc, DOU0_IRQ_MASK);
	reg |= DOU_IRQ_PL0;
	DPU_WR4(sc, DOU0_IRQ_MASK, reg);

	return (0);
}

static void
komeda_pipeline_disable_vblank(struct drm_crtc *crtc)
{
	struct komeda_pipeline *pipeline;
	struct komeda_drm_softc *sc;
	uint32_t reg;

	dprintf("%s\n", __func__);

	pipeline = container_of(crtc, struct komeda_pipeline, crtc);
	sc = pipeline->sc;

	reg = DPU_RD4(sc, DOU0_IRQ_MASK);
	reg &= ~DOU_IRQ_PL0;
	DPU_WR4(sc, DOU0_IRQ_MASK, reg);
}

static uint32_t
komeda_pipeline_get_vblank_counter(struct drm_crtc *crtc)
{
	struct komeda_pipeline *pipeline;

	dprintf("%s\n", __func__);

	pipeline = container_of(crtc, struct komeda_pipeline, crtc);

	return (pipeline->vbl_counter);
}

static const struct drm_crtc_funcs komeda_pipeline_funcs = {
	.atomic_destroy_state	= drm_atomic_helper_crtc_destroy_state,
	.atomic_duplicate_state	= drm_atomic_helper_crtc_duplicate_state,
	.destroy		= drm_crtc_cleanup,
	.page_flip		= drm_atomic_helper_page_flip,
	.reset			= drm_atomic_helper_crtc_reset,
	.set_config		= drm_atomic_helper_set_config,

	.get_vblank_counter	= komeda_pipeline_get_vblank_counter,
	.enable_vblank		= komeda_pipeline_enable_vblank,
	.disable_vblank		= komeda_pipeline_disable_vblank,

	.gamma_set		= drm_atomic_helper_legacy_gamma_set,
};

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

	reg = BS_CONTROL_EN | BS_CONTROL_VM;
	DPU_WR4(sc, BS_CONTROL, reg);
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

static int
gcu_enable(struct komeda_drm_softc *sc, bool enable)
{
	uint32_t reg, mode;
	int timeout;

	timeout = 10000;

	if (enable)
		mode = CONTROL_MODE_DO0_ACTIVE;
	else
		mode = CONTROL_MODE_INACTIVE;

	DPU_WR4(sc, GCU_CONTROL, mode);
	do {
		reg = DPU_RD4(sc, GCU_CONTROL);
		if ((reg & CONTROL_MODE_M) == mode)
			break;
	} while (timeout--);

	if (timeout <= 0) {
		printf("%s: Failed to set mode\n", __func__);
		return (-1);
	}

	if (enable)
		DPU_WR4(sc, GCU_IRQ_MASK, GCU_IRQ_ERR | GCU_IRQ_MODE |
		    GCU_IRQ_CVAL0);
	else
		DPU_WR4(sc, GCU_IRQ_MASK, 0);

	return (0);
}

static void
gcu_flush(struct komeda_drm_softc *sc)
{
	DPU_WR4(sc, GCU_CONFIG_VALID0, CONFIG_VALID0_CVAL);
}

static int
komeda_crtc_atomic_check(struct drm_crtc *crtc, struct drm_crtc_state *state)
{

	dprintf("%s\n", __func__);

	return (0);
}

static void
komeda_crtc_atomic_begin(struct drm_crtc *crtc,
    struct drm_crtc_state *old_state)
{
	dprintf("%s\n", __func__);
}

static void
komeda_crtc_atomic_flush(struct drm_crtc *crtc,
    struct drm_crtc_state *old_state)
{
	struct drm_pending_vblank_event *event;
	struct komeda_pipeline *pipeline;
	struct komeda_drm_softc *sc;

	dprintf("%s\n", __func__);

	event = crtc->state->event;

	pipeline = container_of(crtc, struct komeda_pipeline, crtc);
	sc = pipeline->sc;

	gcu_flush(sc);

	if (event) {
		crtc->state->event = NULL;

		spin_lock_irq(&sc->drm_dev.event_lock);
		/*
		 * If not in page flip, arm it for later
		 * Else send it
		 */
		if (drm_crtc_vblank_get(crtc) == 0)
			drm_crtc_arm_vblank_event(crtc, event);
		else
			drm_crtc_send_vblank_event(crtc, event);
		spin_unlock_irq(&sc->drm_dev.event_lock);
	}
}

static void
komeda_crtc_atomic_enable(struct drm_crtc *crtc,
    struct drm_crtc_state *old_state)
{
	struct komeda_drm_softc *sc;
	struct komeda_pipeline *pipeline;
	struct drm_display_mode *adj;

	adj = &crtc->state->adjusted_mode;

	pipeline = container_of(crtc, struct komeda_pipeline, crtc);
	sc = pipeline->sc;

	dprintf("%s\n", __func__);

	dou_configure(sc, adj);
	dou_ds_timing_setup(sc, adj);

	gcu_enable(sc, true);

	/* Enable VBLANK events */
	drm_crtc_vblank_on(crtc);
}

static void
komeda_crtc_atomic_disable(struct drm_crtc *crtc,
    struct drm_crtc_state *old_state)
{
	struct komeda_drm_softc *sc;
	struct komeda_pipeline *pipeline;

	dprintf("%s\n", __func__);

	pipeline = container_of(crtc, struct komeda_pipeline, crtc);
	sc = pipeline->sc;

	/* Disable VBLANK events */
	drm_crtc_vblank_off(crtc);

	gcu_enable(sc, false);
	gcu_flush(sc);
}

static void
komeda_crtc_mode_set_nofb(struct drm_crtc *crtc)
{
	struct komeda_pipeline *pipeline;
	struct drm_display_mode *mode;

	pipeline = container_of(crtc, struct komeda_pipeline, crtc);
	mode = &crtc->state->adjusted_mode;

	dprintf("%s: clk_set_freq %d\n", __func__, mode->crtc_clock);
	clk_set_freq(pipeline->pxclk, mode->crtc_clock * 1000,
	    CLK_SET_ROUND_ANY);
}

static const struct drm_crtc_helper_funcs komeda_pipeline_crtc_helper_funcs = {
	.atomic_check	= komeda_crtc_atomic_check,
	.atomic_begin	= komeda_crtc_atomic_begin,
	.atomic_flush	= komeda_crtc_atomic_flush,
	.atomic_enable	= komeda_crtc_atomic_enable,
	.atomic_disable	= komeda_crtc_atomic_disable,
	.mode_set_nofb	= komeda_crtc_mode_set_nofb,
};

static int
komeda_pipeline_add_encoder(struct komeda_pipeline *pipeline,
    struct drm_device *drm)
{
	device_t dev;
	int ret;

	dprintf("%s\n", __func__);

	dev = ofw_graph_get_device_by_port_ep(pipeline->node, 0, 1);
	if (dev == NULL)
		return (ENOENT);

	ret = DRM_BRIDGE_ADD_ENCODER(dev, &pipeline->crtc, drm);
	if (ret == 0)
		return (ENODEV);

	return (0);
}

int
komeda_pipeline_create_pipeline(struct komeda_drm_softc *sc, phandle_t node,
    struct komeda_pipeline *pipeline)
{
	struct drm_device *drm;
	int error;

	drm = &sc->drm_dev;

	dprintf("%s\n", __func__);

	pipeline->node = node;
	pipeline->sc = sc;
	pipeline->vbl_counter = 0;
	komeda_plane_create(pipeline, drm);

	error = clk_get_by_ofw_name(sc->dev, node, "pxclk", &pipeline->pxclk);
	if (error != 0) {
		device_printf(sc->dev, "Cannot get pixel clock, error %d\n",
		    error);
		return (error);
	}

	error = drm_crtc_init_with_planes(drm, &pipeline->crtc,
	    &pipeline->planes[0].plane, &pipeline->planes[1].plane,
	    &komeda_pipeline_funcs, NULL);
	if (error != 0) {
		device_printf(sc->dev,
		    "%s: drm_crtc_init_with_planes failed\n", __func__);
		return (error);
	}

	drm_crtc_helper_add(&pipeline->crtc,
	    &komeda_pipeline_crtc_helper_funcs);

	error = komeda_pipeline_add_encoder(pipeline, drm);

	return (error);
}
