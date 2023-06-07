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

#include <dev/extres/clk/clk.h>
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

#include <dev/extres/hwreset/hwreset.h>
#include <dev/extres/clk/clk.h>
#include <dev/extres/phy/phy.h>

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
	unsigned long flags;

	dprintf("%s\n", __func__);

	if (crtc->state->event == NULL)
		return;

	spin_lock_irqsave(&crtc->dev->event_lock, flags);

	if (drm_crtc_vblank_get(crtc) != 0)
		drm_crtc_send_vblank_event(crtc, crtc->state->event);
	else
		drm_crtc_arm_vblank_event(crtc, crtc->state->event);

	crtc->state->event = NULL;
	spin_unlock_irqrestore(&crtc->dev->event_lock, flags);
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

	/* Enable VBLANK events */
	drm_crtc_vblank_on(crtc);
}

static void
komeda_crtc_atomic_disable(struct drm_crtc *crtc,
    struct drm_crtc_state *old_state)
{
	uint32_t irqflags;

	dprintf("%s\n", __func__);

	/* Disable VBLANK events */
	drm_crtc_vblank_off(crtc);

	spin_lock_irqsave(&crtc->dev->event_lock, irqflags);

	if (crtc->state->event) {
		drm_crtc_send_vblank_event(crtc, crtc->state->event);
		crtc->state->event = NULL;
	}

	spin_unlock_irqrestore(&crtc->dev->event_lock, irqflags);
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
