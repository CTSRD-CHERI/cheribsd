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

#define	RK_VOP_MAX_ENDPOINTS	32

#define	dprintf(fmt, ...)

static char * clk_table[CLK_NENTRIES] = { "aclk_vop", "dclk_vop", "hclk_vop" };

/*
 * Note: vop-big is not supported by this driver: it has different registers
 * for planes configuration.
 */
static struct ofw_compat_data compat_data[] = {
	{ "rockchip,rk3399-vop-lit",	1 },
	{ NULL,				0 }
};

static struct resource_spec rk_vop_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ SYS_RES_IRQ,		0,	RF_ACTIVE | RF_SHAREABLE },
	{ -1, 0 }
};

static void
rk_vop_set_polarity(struct rk_vop_softc *sc, uint32_t pin_polarity)
{
	uint32_t reg;

	/* HDMI */
	reg = VOP_READ(sc, RK3399_DSP_CTRL1);
	reg &= ~DSP_CTRL1_HDMI_POL_M;
	reg |= pin_polarity << DSP_CTRL1_HDMI_POL_S;
	VOP_WRITE(sc, RK3399_DSP_CTRL1, reg);
}

static int
rk_vop_clk_enable(device_t dev, struct drm_display_mode *mode)
{
	struct rk_vop_softc *sc;
	phandle_t node;
	uint64_t rate;
	int error;
	int i;

	sc = device_get_softc(dev);
	node = ofw_bus_get_node(dev);

	/* Resets. */
	error = hwreset_get_by_ofw_name(sc->dev, 0, "axi", &sc->hwreset_axi);
	if (error != 0) {
		device_printf(sc->dev, "Cannot get 'axi' reset\n");
		return (ENXIO);
	}

	error = hwreset_get_by_ofw_name(sc->dev, 0, "ahb", &sc->hwreset_ahb);
	if (error != 0) {
		device_printf(sc->dev, "Cannot get 'ahb' reset\n");
		return (ENXIO);
	}

	error = hwreset_get_by_ofw_name(sc->dev, 0, "dclk", &sc->hwreset_dclk);
	if (error != 0) {
		device_printf(sc->dev, "Cannot get 'dclk' reset\n");
		return (ENXIO);
	}

	error = hwreset_assert(sc->hwreset_axi);
	if (error != 0) {
		device_printf(sc->dev, "Cannot assert 'axi' reset\n");
		return (error);
	}

	error = hwreset_assert(sc->hwreset_ahb);
	if (error != 0) {
		device_printf(sc->dev, "Cannot assert 'ahb' reset\n");
		return (error);
	}

	error = hwreset_assert(sc->hwreset_dclk);
	if (error != 0) {
		device_printf(sc->dev, "Cannot assert 'dclk' reset\n");
		return (error);
	}

	for (i = 0; i < CLK_NENTRIES; i++) {
		error = clk_get_by_ofw_name(dev, 0, clk_table[i], &sc->clk[i]);
		if (error != 0) {
			device_printf(dev, "cannot get '%s' clock\n",
			    clk_table[i]);
			return (ENXIO);
		}
	}

	/*
	 * Set ACLK, HCLK based on entires in DTS.
	 * If some of them is not present in DTS nothing will work, so give up.
	 */
	if (!OF_hasprop(node, "assigned-clocks")) {
		device_printf(sc->dev,
		    "Failed to find assigned-clocks property.\n");
		return (error);
	}

	error = clk_set_assigned(sc->dev, node);
	if (error != 0) {
		device_printf(dev, "Cannot set assigned clocks\n");
		return (error);
	}

	/* DCLK */
	clk_set_freq(sc->clk[1], mode->crtc_clock * 1000, CLK_SET_ROUND_ANY);

	for (i = 0; i < CLK_NENTRIES; i++) {
		error = clk_enable(sc->clk[i]);
		if (error != 0) {
			device_printf(dev, "cannot enable '%s' clock\n",
			    clk_table[i]);
			return (ENXIO);
		}

		error = clk_get_freq(sc->clk[i], &rate);
		if (error != 0) {
			device_printf(dev, "cannot get '%s' clock frequency\n",
			    clk_table[i]);
			return (ENXIO);
		}
		if (bootverbose)
			device_printf(dev, "%s rate is %ld Hz\n", clk_table[i],
			    rate);
	}

	error = hwreset_deassert(sc->hwreset_axi);
	if (error != 0) {
		device_printf(sc->dev, "Cannot deassert 'axi' reset\n");
		return (error);
	}

	error = hwreset_deassert(sc->hwreset_ahb);
	if (error != 0) {
		device_printf(sc->dev, "Cannot deassert 'ahb' reset\n");
		return (error);
	}

	error = hwreset_deassert(sc->hwreset_dclk);
	if (error != 0) {
		device_printf(sc->dev, "Cannot deassert 'dclk' reset\n");
		return (error);
	}

	return (0);
}

static void
rk_vop_intr(void *arg)
{
	struct rk_vop_softc *sc;
	int status;

	sc = arg;

	status = VOP_READ(sc, RK3399_INTR_STATUS0);

	/* Ack all the interrupts. */
	VOP_WRITE(sc, RK3399_INTR_CLEAR0, ~0);

	if (status & INTR_STATUS0_FS_INTR) {
		atomic_add_32(&sc->vbl_counter, 1);
		drm_crtc_handle_vblank(&sc->crtc);
		status &= ~INTR_STATUS0_FS_INTR;
	}

	if (status)
		device_printf(sc->dev, "Unhandled intr %x\n", status);
}

static int
rk_vop_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_search_compatible(dev, compat_data)->ocd_data == 0)
		return (ENXIO);

	device_set_desc(dev, "Rockchip RK3399 Visual Output Processor");
	return (BUS_PROBE_DEFAULT);
}

static int
rk_vop_attach(device_t dev)
{
	struct rk_vop_softc *sc;
	phandle_t node;

	sc = device_get_softc(dev);
	sc->dev = dev;

	node = ofw_bus_get_node(dev);

	if (bus_alloc_resources(dev, rk_vop_spec, sc->res) != 0) {
		device_printf(dev, "cannot allocate resources for device\n");
		return (ENXIO);
	}

	if (bus_setup_intr(dev, sc->res[1],
	    INTR_TYPE_MISC | INTR_MPSAFE, NULL, rk_vop_intr, sc,
	    &sc->intrhand)) {
		bus_release_resources(dev, rk_vop_spec, sc->res);
		device_printf(dev, "cannot setup interrupt handler\n");
		return (ENXIO);
	}

	/* There is a single port node. */
	node = ofw_bus_find_child(node, "port");
	if (node == 0) {
		device_printf(sc->dev, "port node not found\n");
		return (ENXIO);
	}

	OF_device_register_xref(OF_xref_from_node(node), dev);

	device_printf(sc->dev, "VOP version: %x\n",
	    VOP_READ(sc, RK3399_VERSION_INFO));

	return (0);
}

/*
 * VBLANK functions
 */
static int
rk_vop_enable_vblank(struct drm_crtc *crtc)
{
	struct rk_vop_softc *sc;
	uint32_t reg;

	dprintf("%s\n", __func__);

	sc = container_of(crtc, struct rk_vop_softc, crtc);

	DRM_DEBUG_DRIVER("%s: Enabling VBLANK\n", __func__);

	reg = INTR_EN0_FS_INTR;
	reg |= 0xffff0000; /* Not sure why this is needed. */
	VOP_WRITE(sc, RK3399_INTR_EN0, reg);

	dprintf("%s: en0 %x\n", __func__,
	    VOP_READ(sc, RK3399_INTR_EN0));
	dprintf("%s: status0 %x\n", __func__,
	    VOP_READ(sc, RK3399_INTR_STATUS0));
	dprintf("%s: rstatus0 %x\n", __func__,
	    VOP_READ(sc, RK3399_INTR_RAW_STATUS0));

	return (0);
}

static void
rk_vop_disable_vblank(struct drm_crtc *crtc)
{
	struct rk_vop_softc *sc;
	uint32_t reg;

	sc = container_of(crtc, struct rk_vop_softc, crtc);

	DRM_DEBUG_DRIVER("%s: Disabling VBLANK\n", __func__);

	dprintf("%s\n", __func__);

	/* Disable all interrupts. */
	reg = 0xffff0000; /* Not sure why this is needed. */
	VOP_WRITE(sc, RK3399_INTR_EN0, reg);
}

static uint32_t
rk_vop_get_vblank_counter(struct drm_crtc *crtc)
{
	struct rk_vop_softc *sc;

	dprintf("%s\n", __func__);

	sc = container_of(crtc, struct rk_vop_softc, crtc);

	return (sc->vbl_counter);
}

static const struct drm_crtc_funcs rk_vop_funcs = {
	.atomic_destroy_state	= drm_atomic_helper_crtc_destroy_state,
	.atomic_duplicate_state	= drm_atomic_helper_crtc_duplicate_state,
	.destroy		= drm_crtc_cleanup,
	.page_flip		= drm_atomic_helper_page_flip,
	.reset			= drm_atomic_helper_crtc_reset,
	.set_config		= drm_atomic_helper_set_config,

	.get_vblank_counter	= rk_vop_get_vblank_counter,
	.enable_vblank		= rk_vop_enable_vblank,
	.disable_vblank		= rk_vop_disable_vblank,

	.gamma_set		= drm_atomic_helper_legacy_gamma_set,
};

static int
rk_crtc_atomic_check(struct drm_crtc *crtc, struct drm_crtc_state *state)
{

	dprintf("%s\n", __func__);

	return (0);
}

static void
rk_crtc_atomic_begin(struct drm_crtc *crtc, struct drm_crtc_state *old_state)
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
rk_crtc_atomic_flush(struct drm_crtc *crtc,
    struct drm_crtc_state *old_state)
{
	struct rk_vop_softc *sc;
	struct drm_pending_vblank_event *event;

	dprintf("%s\n", __func__);

	event = crtc->state->event;

	sc = container_of(crtc, struct rk_vop_softc, crtc);

	if (event) {
		crtc->state->event = NULL;

		spin_lock_irq(&sc->drm->event_lock);
		/*
		 * If not in page flip, arm it for later
		 * Else send it
		 */
		if (drm_crtc_vblank_get(crtc) == 0)
			drm_crtc_arm_vblank_event(crtc, event);
		else
			drm_crtc_send_vblank_event(crtc, event);
		spin_unlock_irq(&sc->drm->event_lock);
	}
}

static void
rk_crtc_atomic_enable(struct drm_crtc *crtc, struct drm_crtc_state *old_state)
{
	uint32_t hsync_len, vsync_len;
	uint32_t hact_st, hact_end;
	uint32_t vact_st, vact_end;
	struct rk_vop_softc *sc;
	struct drm_display_mode *adj;
	uint32_t mode1;
	uint32_t reg;
	int pol;

	adj = &crtc->state->adjusted_mode;

	sc = container_of(crtc, struct rk_vop_softc, crtc);

	dprintf("%s\n", __func__);

	pol = (1 << DCLK_INVERT);
	if (adj->flags & DRM_MODE_FLAG_PHSYNC)
		pol |= (1 << HSYNC_POSITIVE);
	if (adj->flags & DRM_MODE_FLAG_PVSYNC)
		pol |= (1 << VSYNC_POSITIVE);
	rk_vop_set_polarity(sc, pol);

	/* Remove standby bit */
	reg = VOP_READ(sc, RK3399_SYS_CTRL);
	reg &= ~SYS_CTRL_STANDBY_EN;
	VOP_WRITE(sc, RK3399_SYS_CTRL, reg);

	/* Enable HDMI output only. */
	reg = VOP_READ(sc, RK3399_SYS_CTRL);
	reg &= ~SYS_CTRL_ALL_OUT_EN;
	reg |= SYS_CTRL_HDMI_OUT_EN;
	VOP_WRITE(sc, RK3399_SYS_CTRL, reg);

	dprintf("SYS_CTRL %x\n", VOP_READ(sc, RK3399_SYS_CTRL));

	/* Set mode */
	mode1 = 0; /* RGB888 */
	/*
	 * Note: for VOP big this should be RGBaaa:
	 * mode1 = 15;
	 */
	reg = VOP_READ(sc, RK3399_DSP_CTRL0);
	reg &= ~DSP_CTRL0_OUT_MODE_M;
	reg |= (mode1 << DSP_CTRL0_OUT_MODE_S);
	VOP_WRITE(sc, RK3399_DSP_CTRL0, reg);

	hsync_len = adj->hsync_end - adj->hsync_start;
	vsync_len = adj->vsync_end - adj->vsync_start;
	hact_st = adj->htotal - adj->hsync_start;
	hact_end = hact_st + adj->hdisplay;
	vact_st = adj->vtotal - adj->vsync_start;
	vact_end = vact_st + adj->vdisplay;

	reg = hsync_len;
	reg |= adj->htotal << 16;
	VOP_WRITE(sc, RK3399_DSP_HTOTAL_HS_END, reg);

	reg = hact_end;
	reg |= hact_st << 16;
	VOP_WRITE(sc, RK3399_DSP_HACT_ST_END, reg);
	VOP_WRITE(sc, RK3399_POST_DSP_HACT_INFO, reg);

	reg = vsync_len;
	reg |= adj->vtotal << 16;
	VOP_WRITE(sc, RK3399_DSP_VTOTAL_VS_END, reg);

	reg = vact_end;
	reg |= vact_st << 16;
	VOP_WRITE(sc, RK3399_DSP_VACT_ST_END, reg);
	VOP_WRITE(sc, RK3399_POST_DSP_VACT_INFO, reg);

	VOP_WRITE(sc, RK3399_LINE_FLAG, vact_end);
	VOP_WRITE(sc, RK3399_REG_CFG_DONE, 1);

	/* Enable VBLANK events */
	drm_crtc_vblank_on(crtc);
}

static void
rk_crtc_atomic_disable(struct drm_crtc *crtc, struct drm_crtc_state *old_state)
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
rk_crtc_mode_set_nofb(struct drm_crtc *crtc)
{
	struct drm_display_mode *mode;
	struct rk_vop_softc *sc;

	sc = container_of(crtc, struct rk_vop_softc, crtc);
	mode = &crtc->state->adjusted_mode;

	rk_vop_clk_enable(sc->dev, mode);
}

static const struct drm_crtc_helper_funcs rk_vop_crtc_helper_funcs = {
	.atomic_check	= rk_crtc_atomic_check,
	.atomic_begin	= rk_crtc_atomic_begin,
	.atomic_flush	= rk_crtc_atomic_flush,
	.atomic_enable	= rk_crtc_atomic_enable,
	.atomic_disable	= rk_crtc_atomic_disable,
	.mode_set_nofb	= rk_crtc_mode_set_nofb,
};

static int
rk_vop_add_encoder(struct rk_vop_softc *sc, struct drm_device *drm)
{
	phandle_t node;
	device_t dev;
	int ret;

	node = ofw_bus_get_node(sc->dev);
	if (node == 0)
		return (ENOENT);

	dev = ofw_graph_get_device_by_port_ep(ofw_bus_get_node(sc->dev),
	    0, 2 /* HDMI */);
	if (dev == NULL)
		return (ENOENT);

	ret = DW_HDMI_ADD_ENCODER(dev, &sc->crtc, drm);
	if (ret == 0)
		return (ENODEV);

	sc->outport = dev;

	return (0);

}

static int
rk_vop_create_pipeline(device_t dev, struct drm_device *drm)
{
	struct rk_vop_softc *sc;
	int error;

	sc = device_get_softc(dev);

	dprintf("%s\n", __func__);

	rk_plane_create(sc, drm);

	error = drm_crtc_init_with_planes(drm, &sc->crtc, &sc->planes[0].plane,
	    &sc->planes[1].plane, &rk_vop_funcs, NULL);
	if (error != 0) {
		device_printf(sc->dev,
		    "%s: drm_crtc_init_with_planes failed\n", __func__);
		return (error);
	}

	drm_crtc_helper_add(&sc->crtc, &rk_vop_crtc_helper_funcs);

	error = rk_vop_add_encoder(sc, drm);

	return (error);
}

static device_method_t rk_vop_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		rk_vop_probe),
	DEVMETHOD(device_attach,	rk_vop_attach),

	/* VOP interface */
	DEVMETHOD(rk_vop_create_pipeline,	rk_vop_create_pipeline),

	DEVMETHOD_END
};

static driver_t rk_vop_driver = {
	"rk_vop",
	rk_vop_methods,
	sizeof(struct rk_vop_softc)
};

static devclass_t rk_vop_devclass;
EARLY_DRIVER_MODULE(rk_vop, simplebus, rk_vop_driver,
    rk_vop_devclass, 0, 0, BUS_PASS_INTERRUPT + BUS_PASS_ORDER_LAST);
MODULE_VERSION(rk_vop, 1);
