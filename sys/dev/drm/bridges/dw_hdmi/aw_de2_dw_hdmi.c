/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019-2021 Emmanuel Vadot <manu@FreeBSD.org>
 *
 * Portions of this work were supported by Innovate UK project 105694,
 * "Digital Security by Design (DSbD) Technology Platform Prototype".
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
 *
 * $FreeBSD$
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>

#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <dev/extres/clk/clk.h>
#include <dev/extres/hwreset/hwreset.h>

#include <drm/drm_atomic_helper.h>
#include <drm/drm_bridge.h>
#include <drm/drm_drv.h>
#include <drm/drm_print.h>

#include "dw_hdmireg.h"

#include "dw_hdmi.h"
#include "dw_hdmi_if.h"

static struct ofw_compat_data aw_compat_data[] = {
	{ "allwinner,sun50i-a64-dw-hdmi",	1 },
	{ "allwinner,sun8i-h3-dw-hdmi",		1 },
	{ NULL,					0 }
};

struct aw_de2_dw_hdmi_softc {
	struct dw_hdmi_softc base_sc;

	clk_t		clk_tmds;
	hwreset_t	reset_ctrl;
};

static int aw_de2_dw_hdmi_probe(device_t dev);
static int aw_de2_dw_hdmi_attach(device_t dev);
static int aw_de2_dw_hdmi_detach(device_t dev);

static void aw_de2_dw_hdmi_encoder_mode_set(struct drm_encoder *encoder,
    struct drm_display_mode *mode,
    struct drm_display_mode *adj_mode)
{
	struct aw_de2_dw_hdmi_softc *sc;
	struct dw_hdmi_softc *base_sc;
	uint64_t freq;

	base_sc = container_of(encoder, struct dw_hdmi_softc, encoder);
	sc = container_of(base_sc, struct aw_de2_dw_hdmi_softc, base_sc);

	clk_get_freq(sc->clk_tmds, &freq);
	DRM_DEBUG_DRIVER("%s: Setting clock %s from %ju to %ju\n",
	    __func__,
	    clk_get_name(sc->clk_tmds),
	    freq,
	    (uintmax_t)mode->crtc_clock * 1000);
	clk_set_freq(sc->clk_tmds, mode->crtc_clock * 1000, CLK_SET_ROUND_ANY);
	clk_get_freq(sc->clk_tmds, &freq);
	DRM_DEBUG_DRIVER("%s: New clock %s is %ju\n",
	    __func__,
	    clk_get_name(sc->clk_tmds),
	    freq);
}

static const struct drm_encoder_helper_funcs
    aw_de2_dw_hdmi_encoder_helper_funcs = {
	.mode_set = aw_de2_dw_hdmi_encoder_mode_set,
};

static const struct drm_encoder_funcs aw_de2_dw_hdmi_encoder_funcs = {
	.destroy = drm_encoder_cleanup,
};

static int
aw_de2_dw_hdmi_add_encoder(device_t dev, struct drm_crtc *crtc,
    struct drm_device *drm)
{
	struct aw_de2_dw_hdmi_softc *sc;

	sc = device_get_softc(dev);

	drm_encoder_helper_add(&sc->base_sc.encoder,
	    &aw_de2_dw_hdmi_encoder_helper_funcs);
	sc->base_sc.encoder.possible_crtcs = drm_crtc_mask(crtc);
	drm_encoder_init(drm, &sc->base_sc.encoder, &aw_de2_dw_hdmi_encoder_funcs,
	  DRM_MODE_ENCODER_TMDS, NULL);

	dw_hdmi_add_bridge(&sc->base_sc);
	return (0);
}

static int
aw_de2_dw_hdmi_probe(device_t dev)
{
	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_search_compatible(dev, aw_compat_data)->ocd_data == 0)
		return (ENXIO);

	device_set_desc(dev, "Allwinner SUN8I DW HDMI");
	return (BUS_PROBE_DEFAULT);
}

static int
aw_de2_dw_hdmi_attach(device_t dev)
{
	struct aw_de2_dw_hdmi_softc *sc;
	phandle_t node;
	int error;

	sc = device_get_softc(dev);

	node = ofw_bus_get_node(dev);

	if ((error = clk_get_by_ofw_name(dev, node, "tmds",
	    &sc->clk_tmds)) != 0) {
		device_printf(dev, "Cannot get tmds clock\n");
		goto fail;
	}
	if (clk_enable(sc->clk_tmds) != 0) {
		device_printf(dev, "Cannot enable tmds clock\n");
		goto fail;
	}
	if ((error = hwreset_get_by_ofw_name(dev, node, "ctrl",
	    &sc->reset_ctrl)) != 0) {
		device_printf(dev, "Cannot get reset\n");
		goto fail;
	}
	if (hwreset_deassert(sc->reset_ctrl) != 0) {
		device_printf(dev, "Cannot deassert reset\n");
		goto fail;
	}

	error = dw_hdmi_attach(dev);
	if (error != 0)
		goto fail;
	return (0);

fail:
	aw_de2_dw_hdmi_detach(dev);
	return (error);
}

static int
aw_de2_dw_hdmi_detach(device_t dev)
{

	dw_hdmi_detach(dev);
	return (0);
}

static device_method_t aw_de2_dw_hdmi_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		aw_de2_dw_hdmi_probe),
	DEVMETHOD(device_attach,	aw_de2_dw_hdmi_attach),
	DEVMETHOD(device_detach,	aw_de2_dw_hdmi_detach),

	/* DW_HDMI interface */
	DEVMETHOD(dw_hdmi_add_encoder,	aw_de2_dw_hdmi_add_encoder),

	DEVMETHOD_END
};

DEFINE_CLASS_1(aw_de2_dw_hdmi, aw_de2_dw_hdmi_driver, aw_de2_dw_hdmi_methods,
    sizeof(struct aw_de2_dw_hdmi_softc), dw_hdmi_driver);

static devclass_t aw_de2_dw_hdmi_devclass;

EARLY_DRIVER_MODULE(aw_de2_dw_hdmi, simplebus, aw_de2_dw_hdmi_driver,
  aw_de2_dw_hdmi_devclass, 0, 0, BUS_PASS_SUPPORTDEV + BUS_PASS_ORDER_EARLY);
MODULE_VERSION(aw_de2_dw_hdmi, 1);
MODULE_DEPEND(aw_de2_dw_hdmi, aw_de2_hdmi_phy, 1, 1, 1);
