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
#include <dev/ofw/ofw_graph.h>

#include <drm/drm_atomic_helper.h>
#include <drm/drm_drv.h>
#include <drm/drm_print.h>

#include <dev/drm/allwinner/aw_de2_mixer.h>
#include <dev/drm/allwinner/aw_de2_ui_plane.h>
#include <dev/drm/allwinner/aw_de2_vi_plane.h>

#include "aw_de2_mixer_if.h"
#include "aw_de2_tcon_if.h"

static const struct aw_de2_mixer_config a64_mixer0_config = {
	.name = "Allwinner DE2 A64-Mixer 0",
	.vi_planes = 1,
	.ui_planes = 3,
	.dst_tcon = 0,
};

static const struct aw_de2_mixer_config a64_mixer1_config = {
	.name = "Allwinner DE2 A64-Mixer 1",
	.vi_planes = 1,
	.ui_planes = 1,
	.dst_tcon = 1,
};

static const struct aw_de2_mixer_config h3_mixer0_config = {
	.name = "Allwinner DE2 H3-Mixer 0",
	.vi_planes = 1,
	.ui_planes = 1,
	.dst_tcon = 0,
};

static struct ofw_compat_data compat_data[] = {
	{ "allwinner,sun50i-a64-de2-mixer-0",	(uintptr_t)&a64_mixer0_config },
	{ "allwinner,sun50i-a64-de2-mixer-1",	(uintptr_t)&a64_mixer1_config },
	{ "allwinner,sun8i-h3-de2-mixer-0",	(uintptr_t)&h3_mixer0_config },
	{ NULL,					0 }
};

static struct resource_spec aw_de2_mixer_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ -1, 0 }
};

#define	AW_DE2_MIXER_READ_4(sc, reg)		bus_read_4((sc)->res[0], (reg))
#define	AW_DE2_MIXER_WRITE_4(sc, reg, val)	bus_write_4((sc)->res[0], (reg), (val))

static int aw_de2_mixer_attach(device_t dev);
static int aw_de2_mixer_detach(device_t dev);
static int aw_de2_mixer_commit(device_t dev);
static int aw_de2_mixer_create_pipeline(device_t dev, struct drm_device *drm);

static inline void
aw_de2_mixer_dump_regs(struct aw_de2_mixer_softc *sc)
{
	uint32_t reg, pipe_ctl, pipe_routing;
	int i;

	reg = AW_DE2_MIXER_READ_4(sc, GBL_CTL);
	DRM_DEBUG_DRIVER("%s: Mixer %sabled\n", __func__,
	    reg & GBL_CTL_EN ? "En" : "Dis");

	reg = AW_DE2_MIXER_READ_4(sc, GBL_SIZE);
	DRM_DEBUG_DRIVER("%s: Mixer Global Size %dx%d\n", __func__,
	    GBL_SIZE_WIDTH(reg), GBL_SIZE_HEIGHT(reg));

	for (i = 0; i < 4; i++) {
		reg = AW_DE2_MIXER_READ_4(sc, BLD_FILL_COLOR(i));
		DRM_DEBUG_DRIVER("%s: BLD_FILL_COLOR(%d): %x\n", __func__,
		    i, reg);
	}
	for (i = 0; i < 4; i++) {
		reg = AW_DE2_MIXER_READ_4(sc, BLD_INSIZE(i));
		DRM_DEBUG_DRIVER("%s: BLD_INSIZE(%d): %x (%dx%d)\n", __func__,
		    i, reg,
		    (reg & OVL_VI_SIZE_WIDTH_MASK) >> OVL_VI_SIZE_WIDTH_SHIFT,
		    (reg & OVL_VI_SIZE_HEIGHT_MASK) >> OVL_VI_SIZE_HEIGHT_SHIFT);
	}
	for (i = 0; i < 4; i++) {
		reg = AW_DE2_MIXER_READ_4(sc, BLD_COORD(i));
		DRM_DEBUG_DRIVER("%s: BLD_COORD(%d): %x\n", __func__, i, reg);
	}
	reg = AW_DE2_MIXER_READ_4(sc, BLD_OUTSIZE);
	DRM_DEBUG_DRIVER("%s: BLD_OUTSIZE: %x (%dx%d)\n", __func__, reg,
	    (reg & OVL_VI_SIZE_WIDTH_MASK) >> OVL_VI_SIZE_WIDTH_SHIFT,
	    (reg & OVL_VI_SIZE_HEIGHT_MASK) >> OVL_VI_SIZE_HEIGHT_SHIFT);
	pipe_ctl = AW_DE2_MIXER_READ_4(sc, BLD_PIPE_CTL);
	DRM_DEBUG_DRIVER("%s: BLD_PIPE_CTL: %x\n", __func__, pipe_ctl);
	pipe_routing = AW_DE2_MIXER_READ_4(sc, BLD_CH_ROUTING);
	DRM_DEBUG_DRIVER("%s: BLD_CH_ROUTING: %x\n", __func__, pipe_routing);
	for (i = 0; i < 4; i++) {
		DRM_DEBUG_DRIVER("%s: Pipe %d %sabled\n", __func__,
		    i, pipe_ctl & (1 << (i + 8)) ? "En" : "Dis");
		DRM_DEBUG_DRIVER("%s: Pipe %d Fill color %sabled\n", __func__,
		    i, pipe_ctl & (1 << i) ? "En" : "Dis");
	}
	DRM_DEBUG_DRIVER("%s: Pipe0 routed from channel %d\n", __func__,
	    pipe_routing & 0xF);
	DRM_DEBUG_DRIVER("%s: Pipe1 routed from channel %d\n", __func__,
	    (pipe_routing & 0xF0) >> 4);
	DRM_DEBUG_DRIVER("%s: Pipe2 routed from channel %d\n", __func__,
	    (pipe_routing & 0xF00) >> 8);
	DRM_DEBUG_DRIVER("%s: Pipe3 routed from channel %d\n", __func__,
	    (pipe_routing & 0xF000) >> 12);
}

static int
aw_de2_mixer_probe(device_t dev)
{
	struct aw_de2_mixer_softc *sc;

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	sc = device_get_softc(dev);
	sc->conf = (struct aw_de2_mixer_config *)ofw_bus_search_compatible(dev, compat_data)->ocd_data;
	if (sc->conf == 0)
		return (ENXIO);

	/* If we can't get the tcon now no need to attach */
	sc->tcon = ofw_graph_get_device_by_port_ep(ofw_bus_get_node(dev),
	    1, sc->conf->dst_tcon);
	if (sc->tcon == NULL) {
		if (bootverbose)
			device_printf(dev, "%s: Cannot find tcon, aborting\n",
			    sc->conf->name);
		return (ENXIO);
	}

	device_set_desc(dev, sc->conf->name);
	return (BUS_PROBE_DEFAULT);
}

static int
aw_de2_mixer_attach(device_t dev)
{
	struct aw_de2_mixer_softc *sc;
	phandle_t node;
	int error, i;

	node = ofw_bus_get_node(dev);
	sc = device_get_softc(dev);
	sc->dev = dev;

	sc->conf = (struct aw_de2_mixer_config *)ofw_bus_search_compatible(dev, compat_data)->ocd_data;

	if (bus_alloc_resources(dev, aw_de2_mixer_spec, sc->res) != 0) {
		device_printf(dev, "cannot allocate resources for device\n");
		error = ENXIO;
		goto fail;
	}

	if ((error = clk_get_by_ofw_name(dev, node, "bus", &sc->clk_bus)) != 0) {
		device_printf(dev, "Cannot get bus clock\n");
		error = ENXIO;
		goto fail;
	}
	if (clk_enable(sc->clk_bus) != 0) {
		device_printf(dev, "Cannot enable bus clock\n");
		error = ENXIO;
		goto fail;
	}
	if ((error = clk_get_by_ofw_name(dev, node, "mod", &sc->clk_mod)) != 0) {
		device_printf(dev, "Cannot get mod clock\n");
		error = ENXIO;
		goto fail;
	}
	if (clk_enable(sc->clk_mod) != 0) {
		device_printf(dev, "Cannot enable mod clock\n");
		error = ENXIO;
		goto fail;
	}
	if ((error = hwreset_get_by_ofw_idx(dev, node, 0, &sc->reset)) != 0) {
		device_printf(dev, "Cannot get reset\n");
		goto fail;
	}
	if ((error = hwreset_deassert(sc->reset)) != 0) {
		device_printf(dev, "Cannot deassert reset\n");
		goto fail;
	}

	sc->tcon = ofw_graph_get_device_by_port_ep(node, 1, sc->conf->dst_tcon);
	if (sc->tcon == NULL) {
		device_printf(dev, "Cannot get device from remote endpoint\n");
		error = ENXIO;
		goto fail;
	}
	AW_DE2_TCON_SET_MIXER(sc->tcon, dev);

	/* Register ourself so aw_de can resolve who we are */
	OF_device_register_xref(OF_xref_from_node(node), dev);

	sc->vi_planes = malloc(sizeof(struct aw_de2_mixer_plane) * sc->conf->vi_planes,
	    DRM_MEM_DRIVER, M_WAITOK | M_ZERO);
	sc->ui_planes = malloc(sizeof(struct aw_de2_mixer_plane) * sc->conf->ui_planes,
	    DRM_MEM_DRIVER, M_WAITOK | M_ZERO);

	/* Clear all regs */
	for (i = 0; i < 0x6000; i += 4)
		AW_DE2_MIXER_WRITE_4(sc, i, 0x0);

	/* Set all pipes X to select from channel X */
	AW_DE2_MIXER_WRITE_4(sc, BLD_CH_ROUTING, 0x3210);

	/* Enable the mixer */
	AW_DE2_MIXER_WRITE_4(sc, GBL_CTL, GBL_CTL_EN);

	if (__drm_debug & DRM_UT_DRIVER)
		aw_de2_mixer_dump_regs(sc);

	return (0);

fail:
	aw_de2_mixer_detach(dev);
	return (error);
}

static int
aw_de2_mixer_detach(device_t dev)
{
	struct aw_de2_mixer_softc *sc;

	sc = device_get_softc(dev);

	if (sc->vi_planes)
		free(sc->vi_planes, DRM_MEM_DRIVER);
	if (sc->ui_planes)
		free(sc->ui_planes, DRM_MEM_DRIVER);
	clk_release(sc->clk_mod);
	clk_release(sc->clk_bus);
	hwreset_release(sc->reset);

	bus_release_resources(dev, aw_de2_mixer_spec, sc->res);

	return (0);
}

static device_method_t aw_de2_mixer_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		aw_de2_mixer_probe),
	DEVMETHOD(device_attach,	aw_de2_mixer_attach),
	DEVMETHOD(device_detach,	aw_de2_mixer_detach),

	/* Mixer interface */
	DEVMETHOD(aw_de2_mixer_create_pipeline,	aw_de2_mixer_create_pipeline),
	DEVMETHOD(aw_de2_mixer_commit,	aw_de2_mixer_commit),
	DEVMETHOD_END
};

static driver_t aw_de2_mixer_driver = {
	"aw_de2_mixer",
	aw_de2_mixer_methods,
	sizeof(struct aw_de2_mixer_softc),
};

static devclass_t aw_de2_mixer_devclass;

EARLY_DRIVER_MODULE(aw_de2_mixer, simplebus, aw_de2_mixer_driver,
  aw_de2_mixer_devclass, 0, 0, BUS_PASS_SUPPORTDEV + BUS_PASS_ORDER_LATE);
MODULE_DEPEND(aw_de2_mixer, aw_de2_tcon, 1, 1, 1);
MODULE_VERSION(aw_de2_mixer, 1);

static int
aw_de2_mixer_commit(device_t dev)
{
	struct aw_de2_mixer_softc *sc;

	sc = device_get_softc(dev);

	AW_DE2_MIXER_WRITE_4(sc, 0x08, 1);

	if (__drm_debug & DRM_UT_DRIVER)
		aw_de2_mixer_dump_regs(sc);

	return (0);
}

static int
aw_de2_mixer_create_pipeline(device_t dev, struct drm_device *drm)
{
	struct aw_de2_mixer_softc *sc;

	sc = device_get_softc(dev);

	/* Create the different planes available */
	aw_de2_ui_plane_create(sc, drm);
	aw_de2_vi_plane_create(sc, drm);

	/* 
	 * Init the crtc
	 * UI 0 and VI are the only plane available in both mixers
	 */
	AW_DE2_TCON_CREATE_CRTC(sc->tcon, drm,
	    &sc->ui_planes[0].plane, &sc->vi_planes[0].plane);

	return (0);
}
