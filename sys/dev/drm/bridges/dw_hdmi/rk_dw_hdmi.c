/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020-2021 Ruslan Bukin <br@bsdpad.com>
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
#include <dev/extres/syscon/syscon.h>
#include <dev/extres/hwreset/hwreset.h>

#include <drm/drm_atomic_helper.h>
#include <drm/drm_bridge.h>
#include <drm/drm_drv.h>
#include <drm/drm_print.h>

#include "dw_hdmireg.h"

#include "dw_hdmi.h"
#include "dw_hdmi_if.h"

#include "syscon_if.h"

static struct ofw_compat_data rk_compat_data[] = {
	{ "rockchip,rk3399-dw-hdmi",		1 },
	{ NULL,					0 }
};

struct rk_dw_hdmi_softc {
	struct dw_hdmi_softc base_sc;
	struct syscon		*grf;
	clk_t			clk_vpll;
	clk_t			clk_grf;
};

static int rk_dw_hdmi_probe(device_t dev);
static int rk_dw_hdmi_attach(device_t dev);
static int rk_dw_hdmi_detach(device_t dev);

static void rk_dw_hdmi_encoder_mode_set(struct drm_encoder *encoder,
    struct drm_display_mode *mode,
    struct drm_display_mode *adj_mode)
{
	struct rk_dw_hdmi_softc *sc;
	struct dw_hdmi_softc *base_sc;

	base_sc = container_of(encoder, struct dw_hdmi_softc, encoder);
	sc = container_of(base_sc, struct rk_dw_hdmi_softc, base_sc);

	/*
	 * Note: we are setting vpll, which should be the same as vop dclk.
	 */
	if (sc->clk_vpll)
		clk_set_freq(sc->clk_vpll, mode->crtc_clock * 1000, 0);
}

static const struct drm_encoder_helper_funcs rk_dw_hdmi_encoder_helper_funcs = {
	.mode_set = rk_dw_hdmi_encoder_mode_set,
};

static const struct drm_encoder_funcs rk_dw_hdmi_encoder_funcs = {
	.destroy = drm_encoder_cleanup,
};

static int
rk_dw_hdmi_add_encoder(device_t dev, struct drm_crtc *crtc,
    struct drm_device *drm)
{
	struct rk_dw_hdmi_softc *sc;

	sc = device_get_softc(dev);

	drm_encoder_helper_add(&sc->base_sc.encoder,
	    &rk_dw_hdmi_encoder_helper_funcs);
	sc->base_sc.encoder.possible_crtcs = drm_crtc_mask(crtc);
	drm_encoder_init(drm, &sc->base_sc.encoder, &rk_dw_hdmi_encoder_funcs,
	  DRM_MODE_ENCODER_TMDS, NULL);

	dw_hdmi_add_bridge(&sc->base_sc);
	return (0);
}

static void
rk_hdmi_configure(struct rk_dw_hdmi_softc *sc)
{
	uint32_t reg;

	/* Select VOP Little for HDMI. */
	reg = SYSCON_READ_4(sc->grf, GRF_SOC_CON20);
	reg &= ~CON20_HDMI_VOP_SEL_M;
	reg |= CON20_HDMI_VOP_SEL_L;
	SYSCON_WRITE_4(sc->grf, GRF_SOC_CON20, reg);
}

static int
rk_hdmi_clk_enable(device_t dev)
{
	struct rk_dw_hdmi_softc *sc;
	int error;

	sc = device_get_softc(dev);

	error = clk_get_by_ofw_name(dev, 0, "vpll", &sc->clk_vpll);
	if (error == 0) {
		error = clk_enable(sc->clk_vpll);
		if (error != 0) {
			device_printf(dev, "cannot enable vpll\n");
			return (ENXIO);
		}
	}

	error = clk_get_by_ofw_name(dev, 0, "grf", &sc->clk_grf);
	if (error == 0) {
		error = clk_enable(sc->clk_grf);
		if (error != 0) {
			device_printf(dev, "cannot enable grf\n");
			return (ENXIO);
		}
	}

	return (0);
}

static int
rk_dw_hdmi_probe(device_t dev)
{
	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_search_compatible(dev, rk_compat_data)->ocd_data == 0)
		return (ENXIO);

	device_set_desc(dev, "RockChip DW HDMI");
	return (BUS_PROBE_DEFAULT);
}

static int
rk_dw_hdmi_attach(device_t dev)
{
	struct rk_dw_hdmi_softc *sc;
	phandle_t ddc;
	phandle_t node;
	device_t i2c_dev;
	int error;

	sc = device_get_softc(dev);

	node = ofw_bus_get_node(dev);

	error = syscon_get_by_ofw_property(dev, node, "rockchip,grf", &sc->grf);
	if (error != 0) {
		device_printf(dev, "cannot get grf syscon: %d\n", error);
		return (ENXIO);
	}

	rk_hdmi_configure(sc);
	rk_hdmi_clk_enable(dev);

	ddc = 0;
	OF_getencprop(node, "ddc-i2c-bus", &ddc, sizeof(ddc));
	if (ddc > 0) {
		i2c_dev = OF_device_from_xref(ddc);
		sc->base_sc.ddc = i2c_bsd_adapter(i2c_dev);
	}

	error = dw_hdmi_attach(dev);
	if (error != 0)
		goto fail;
	return (0);

fail:
	rk_dw_hdmi_detach(dev);
	return (error);
}

static int
rk_dw_hdmi_detach(device_t dev)
{
	struct rk_dw_hdmi_softc *sc;

	sc = device_get_softc(dev);

	if (sc->clk_vpll)
		clk_disable(sc->clk_vpll);
	if (sc->clk_grf)
		clk_disable(sc->clk_grf);

	dw_hdmi_detach(dev);
	return (0);
}

static device_method_t rk_dw_hdmi_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		rk_dw_hdmi_probe),
	DEVMETHOD(device_attach,	rk_dw_hdmi_attach),
	DEVMETHOD(device_detach,	rk_dw_hdmi_detach),

	/* DW_HDMI interface */
	DEVMETHOD(dw_hdmi_add_encoder,	rk_dw_hdmi_add_encoder),

	DEVMETHOD_END
};

DEFINE_CLASS_1(rk_dw_hdmi, rk_dw_hdmi_driver, rk_dw_hdmi_methods,
    sizeof(struct rk_dw_hdmi_softc), dw_hdmi_driver);

static devclass_t rk_dw_hdmi_devclass;

EARLY_DRIVER_MODULE(rk_dw_hdmi, simplebus, rk_dw_hdmi_driver,
  rk_dw_hdmi_devclass, 0, 0, BUS_PASS_SUPPORTDEV + BUS_PASS_ORDER_EARLY);
MODULE_VERSION(rk_dw_hdmi, 1);
