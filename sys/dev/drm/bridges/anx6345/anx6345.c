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

#include "opt_platform.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/clock.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/sysctl.h>

#include <dev/iicbus/iicbus.h>
#include <dev/iicbus/iiconf.h>
#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <dev/drm/bridges/anx6345/anx6345reg.h>

#include <drm/drm_atomic_helper.h>
#include <drm/drm_bridge.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_probe_helper.h>
#include <drm/drm_edid.h>

#include "iicbus_if.h"
#include "drm_bridge_if.h"

#define	ANX6345_DP_AUX_CH_CTL_1		0xe5
#define	 ANX6345_AUX_LENGTH(x)		(((x - 1) & 0xF) << 4)
#define	 ANX6345_AUX_TX_COMM_MOT	(1 << 2)
#define	 ANX6345_AUX_TX_COMM_READ	(1 << 0)

#define	ANX6345_DP_AUX_ADDR_7_0		0xe6
#define	ANX6345_DP_AUX_ADDR_15_8	0xe7
#define	ANX6345_DP_AUX_ADDR_19_16	0xe8

#define	ANX6345_DP_AUX_CH_CTL_2		0xe9
#define	 ANX6345_ADDR_ONLY		(1 << 1)
#define	 ANX6345_AUX_EN			(1 << 0)

#define	ANX6345_BUF_DATA_0		0xf0

#define	ANX6345_DP_INT_STA		0xf7
#define	ANX6345_REPLY_RCVED		(1 << 1)

static const struct ofw_compat_data compat_data[] = {
    {"analogix,anx6345",	1},
    { NULL, 0 }
};

struct anx6345_softc {
	device_t dev;

	uint16_t addr;

	struct i2c_adapter *	ddc;

	struct drm_encoder	encoder;
	struct drm_connector	connector;
	struct drm_bridge	bridge;
};

static int
anx6345_read(struct anx6345_softc *sc, uint8_t offset, uint8_t reg, uint8_t *data)
{
	struct iic_msg msg[2];

	msg[0].slave = sc->addr + offset;
	msg[0].flags = IIC_M_WR | IIC_M_NOSTOP;
	msg[0].len = 1;
	msg[0].buf = &reg;

	msg[1].slave = sc->addr + offset;
	msg[1].flags = IIC_M_RD;
	msg[1].len = 1;
	msg[1].buf = data;

	return (iicbus_transfer(sc->dev, msg, 2));
}

static int
anx6345_write(struct anx6345_softc *sc, uint8_t offset, uint8_t reg, uint8_t data)
{
	struct iic_msg msg[2];

	msg[0].slave = sc->addr + offset;
	msg[0].flags = IIC_M_WR | IIC_M_NOSTOP;
	msg[0].len = 1;
	msg[0].buf = &reg;

	msg[1].slave = sc->addr + offset;
	msg[1].flags = IIC_M_WR;
	msg[1].len = 1;
	msg[1].buf = &data;

	return (iicbus_transfer(sc->dev, msg, 2));
}

static int
anx6345_aux_wait(struct anx6345_softc *sc)
{
	int retry;
	uint8_t reg;

	for (retry = 1000; retry > 0; retry--) {
		anx6345_read(sc, 0, ANX6345_DP_AUX_CH_CTL_2, &reg);
		if (reg & ANX6345_AUX_EN)
			break;
		DELAY(100);
	}
	if (retry == 0) {
		device_printf(sc->dev, "Timeout waiting for AUX_EN\n");
		return (ETIMEDOUT);
	}

	for (retry = 1000; retry > 0; retry--) {
		anx6345_read(sc, 1, ANX6345_DP_INT_STA, &reg);
		if (reg & ANX6345_REPLY_RCVED)
			break;
		DELAY(100);
	}
	if (retry == 0) {
		device_printf(sc->dev, "Timeout waiting for INT_STA\n");
		return (ETIMEDOUT);
	}

	return (0);
}

static int
anx6345_aux_transfer(struct anx6345_softc *sc, uint8_t comm, uint8_t addr,
    uint8_t *buf, size_t len)
{
	int i;
	uint8_t crtl[2];

	crtl[0] = comm;
	crtl[1] = ANX6345_AUX_EN;
	if (len > 0)
		crtl[0] |= ANX6345_AUX_LENGTH(len);
	else
		crtl[1] |= ANX6345_ADDR_ONLY;

	if ((crtl[0] & ANX6345_AUX_TX_COMM_READ) == 0)
		for (i = 0; i < len; i++)
			anx6345_write(sc, 0, ANX6345_BUF_DATA_0 + i, buf[i]);

	anx6345_write(sc, 0, ANX6345_DP_AUX_ADDR_7_0, addr & 0xff);
	anx6345_write(sc, 0, ANX6345_DP_AUX_ADDR_15_8, (addr >> 8) & 0xff);
	anx6345_write(sc, 0, ANX6345_DP_AUX_ADDR_19_16, (addr >> 16) & 0xff);
	anx6345_write(sc, 0, ANX6345_DP_AUX_CH_CTL_1, crtl[0]);
	anx6345_write(sc, 0, ANX6345_DP_AUX_CH_CTL_2, crtl[1]);

	i = anx6345_aux_wait(sc);
	if (i != 0) {
		device_printf(sc->dev, "aux_wait returned %d\n", i);
		return (i);
	}

	if (comm & ANX6345_AUX_TX_COMM_READ) {
		for (i = 0; i < len; i++)
			anx6345_read(sc, 0, ANX6345_BUF_DATA_0 + i, &buf[i]);
	}
	return (0);
}

static int
anx6345_read_edid(struct anx6345_softc *sc, uint8_t *buf)
{
	uint8_t blah;
	int i, error;

	for (i = 0; i < EDID_LENGTH; i += 16) {
		error = anx6345_aux_transfer(sc, ANX6345_AUX_TX_COMM_MOT, DDC_ADDR, &blah, 1);
		if (error != 0)
			return (error);

		error = anx6345_aux_transfer(sc, ANX6345_AUX_TX_COMM_READ, DDC_ADDR, &buf[i], 16);
		if (error != 0)
			return (error);
	}

	return (0);
}

static enum drm_connector_status
anx6345_connector_detect(struct drm_connector *connector, bool force)
{
	struct anx6345_softc *sc;

	sc = container_of(connector, struct anx6345_softc, connector);

	device_printf(sc->dev, "%s called\n", __func__);

	return (connector_status_connected);
}

static const struct drm_connector_funcs anx6345_connector_funcs = {
	.fill_modes = drm_helper_probe_single_connector_modes,
	.detect = anx6345_connector_detect,
	.destroy = drm_connector_cleanup,
	.reset = drm_atomic_helper_connector_reset,
	.atomic_duplicate_state = drm_atomic_helper_connector_duplicate_state,
	.atomic_destroy_state = drm_atomic_helper_connector_destroy_state,
};

/* hack */
static uint8_t raw_edid[EDID_LENGTH] = {
	0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0, 0x9, 0xe5, 0xf0, 0x5, 0x0, 0x0, 0x0, 0x0, 0x1, 0x18, 0x1, 0x4, 0x95, 0x1f, 0x11, 0x78, 0x2, 0x8f, 0xa0, 0x92, 0x5c, 0x56, 0x95, 0x28, 0x1a, 0x50, 0x54, 0x0, 0x0, 0x0, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x3e, 0x1c, 0x56, 0xa0, 0x50, 0x0, 0x16, 0x30, 0x30, 0x20, 0x36, 0x0, 0x35, 0xad, 0x10, 0x0, 0x0, 0x1a, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1a, 0x0, 0x0, 0x0, 0xfe, 0x0, 0x42, 0x4f, 0x45, 0x20, 0x44, 0x54, 0xa, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x0, 0x0, 0x0, 0xfe, 0x0, 0x48, 0x42, 0x31, 0x34, 0x30, 0x57, 0x58, 0x31, 0x2d, 0x33, 0x30, 0x31, 0xa, 0x0, 0x18
};

static int
anx6345_connector_get_modes(struct drm_connector *connector)
{
	struct anx6345_softc *sc;
	/* uint8_t edid[EDID_LENGTH]; */
	/* struct edid *edid = NULL; */
	int ret = 0;

	sc = container_of(connector, struct anx6345_softc, connector);

	device_printf(sc->dev, "%s called\n", __func__);
	/* ret = anx6345_read_edid(sc, edid); */

	/* edid = drm_get_edid(connector, sc->ddc); */
	drm_connector_update_edid_property(connector, (struct edid *)raw_edid);
	ret = drm_add_edid_modes(connector, (struct edid *)raw_edid);

	return (ret);
}

static const struct drm_connector_helper_funcs anx6345_connector_helper_funcs = {
	.get_modes = anx6345_connector_get_modes,
};

static int
anx6345_bridge_attach(struct drm_bridge *bridge,
    enum drm_bridge_attach_flags flags)
{
	struct anx6345_softc *sc;

	sc = container_of(bridge, struct anx6345_softc, bridge);

	device_printf(sc->dev, "%s called\n", __func__);

	sc->connector.polled = DRM_CONNECTOR_POLL_CONNECT;
	drm_connector_helper_add(&sc->connector, &anx6345_connector_helper_funcs);

	drm_connector_init(bridge->dev, &sc->connector, &anx6345_connector_funcs,
			   DRM_MODE_CONNECTOR_eDP);

	drm_connector_attach_encoder(&sc->connector, &sc->encoder);

	return (0);
}

static enum drm_mode_status
anx6345_bridge_mode_valid(struct drm_bridge *bridge,
			  const struct drm_display_mode *mode)
{
	struct anx6345_softc *sc;

	sc = container_of(bridge, struct anx6345_softc, bridge);

	device_printf(sc->dev, "%s called\n", __func__);

	return (MODE_OK);
}

static void
anx6345_bridge_mode_set(struct drm_bridge *bridge,
  const struct drm_display_mode *orig_mode,
  const struct drm_display_mode *mode)
{
	struct anx6345_softc *sc;

	sc = container_of(bridge, struct anx6345_softc, bridge);

	device_printf(sc->dev, "%s called\n", __func__);
}

static void
anx6345_bridge_disable(struct drm_bridge *bridge)
{
	struct anx6345_softc *sc;

	sc = container_of(bridge, struct anx6345_softc, bridge);

	device_printf(sc->dev, "%s called\n", __func__);
}

static void
anx6345_bridge_enable(struct drm_bridge *bridge)
{
	struct anx6345_softc *sc;

	sc = container_of(bridge, struct anx6345_softc, bridge);

	device_printf(sc->dev, "%s called\n", __func__);
}

static const struct drm_bridge_funcs anx6345_bridge_funcs = {
	.attach = anx6345_bridge_attach,
	.enable = anx6345_bridge_enable,
	.disable = anx6345_bridge_disable,
	.mode_set = anx6345_bridge_mode_set,
	.mode_valid = anx6345_bridge_mode_valid,
};

static int
anx6345_add_bridge(device_t dev, struct drm_encoder *encoder, struct drm_device *drm)
{
	struct anx6345_softc *sc;

	sc = device_get_softc(dev);

	device_printf(sc->dev, "%s called\n", __func__);

	sc->encoder = *encoder;
	sc->bridge.funcs = &anx6345_bridge_funcs;
	drm_bridge_attach(&sc->encoder, &sc->bridge, NULL, 0);

	return (0);
}

static int
anx6345_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if(ofw_bus_search_compatible(dev, compat_data)->ocd_data == 0)
		return (ENXIO);

	return (BUS_PROBE_DEFAULT);
}

static void
anx6345_start(void *pdev)
{
	struct anx6345_softc *sc;
	uint8_t chipid;

	sc = device_get_softc(pdev);

	anx6345_read(sc, 1, 0x03, &chipid);
	device_printf(pdev, "ANX CHIPID: %x\n", chipid);
};

static int
anx6345_attach(device_t dev)
{
	struct anx6345_softc *sc;
	phandle_t node;

	sc = device_get_softc(dev);
	sc->dev = dev;

	node = ofw_bus_get_node(dev);

	sc->addr = iicbus_get_addr(dev);
	sc->ddc = i2c_bsd_adapter(dev);

	/* Register ourself */
	OF_device_register_xref(OF_xref_from_node(node), dev);

	config_intrhook_oneshot(anx6345_start, dev);
	return (0);
}

static device_method_t anx6345_methods[] = {
	DEVMETHOD(device_probe,		anx6345_probe),
	DEVMETHOD(device_attach,	anx6345_attach),

	/* DRM_BRIDGE */
	DEVMETHOD(drm_bridge_add_bridge,	anx6345_add_bridge),

	DEVMETHOD_END
};

static driver_t anx6345_driver = {
	"anx6345",
	anx6345_methods,
	sizeof(struct anx6345_softc),
};

static devclass_t anx6345_devclass;

EARLY_DRIVER_MODULE(anx6345, iicbus, anx6345_driver, anx6345_devclass,
    0, 0, BUS_PASS_SUPPORTDEV + BUS_PASS_ORDER_FIRST);
MODULE_VERSION(anx6345, 1);
MODULE_DEPEND(anx6345, iicbus, 1, 1, 1);
