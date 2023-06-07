/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020-2021 Ruslan Bukin <br@bsdpad.com>
 * Copyright (c) 2019 Emmanuel Vadot <manu@FreeBSD.org>
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
#include <sys/rman.h>
#include <sys/resource.h>
#include <machine/bus.h>

#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <dev/extres/clk/clk.h>
#include <dev/extres/syscon/syscon.h>
#include <dev/extres/hwreset/hwreset.h>

#include <drm/drm_atomic_helper.h>
#include <drm/drm_bridge.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_drv.h>
#include <drm/drm_probe_helper.h>
#include <drm/drm_edid.h>
#include <drm/drm_print.h>

#include "dw_hdmireg.h"

#include "dw_hdmi.h"
#include "dw_hdmi_if.h"
#include "dw_hdmi_phy_if.h"

#include "syscon_if.h"
#include "iicbus_if.h"

#define	DW_HDMI_MAX_PORTS	32

static struct resource_spec dw_hdmi_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ SYS_RES_IRQ,		0,	RF_ACTIVE | RF_SHAREABLE },
	{ -1, 0 }
};

#define	DW_HDMI_READ_1(sc, reg)		bus_read_1((sc)->res[0], (reg))
#define	DW_HDMI_WRITE_1(sc, reg, val)	bus_write_1((sc)->res[0], (reg), (val))
#define	DW_HDMI_READ_4(sc, reg)		bus_read_4((sc)->res[0], (reg))
#define	DW_HDMI_WRITE_4(sc, reg, val)	bus_write_4((sc)->res[0], (reg), (val))

#define	DW_HDMI_LOCK(sc)		mtx_lock(&(sc)->mtx)
#define	DW_HDMI_UNLOCK(sc)		mtx_unlock(&(sc)->mtx)

#define DDC_SEGMENT_ADDR 0x30

static uint32_t dw_hdmi_read(struct dw_hdmi_softc *sc, uint32_t reg);
static void dw_hdmi_write(struct dw_hdmi_softc *sc, uint32_t reg, uint32_t val);

static enum drm_connector_status
dw_hdmi_connector_detect(struct drm_connector *connector, bool force)
{
	struct dw_hdmi_softc *sc;
	uint32_t reg;

	sc = container_of(connector, struct dw_hdmi_softc, connector);

	if (sc->phydev != NULL) {
		if (DW_HDMI_PHY_DETECT_HPD(sc->phydev))
			return (connector_status_connected);
	} else {
		reg = dw_hdmi_read(sc, DW_HDMI_PHY_STAT0);
		if (reg & HDMI_PHY_STAT0_HPD)
			return (connector_status_connected);
	}

	return (connector_status_disconnected);
}

static const struct drm_connector_funcs dw_hdmi_connector_funcs = {
	.fill_modes = drm_helper_probe_single_connector_modes,
	.detect = dw_hdmi_connector_detect,
	.destroy = drm_connector_cleanup,
	.reset = drm_atomic_helper_connector_reset,
	.atomic_duplicate_state = drm_atomic_helper_connector_duplicate_state,
	.atomic_destroy_state = drm_atomic_helper_connector_destroy_state,
};

static void
dw_hdmi_i2cm_init(struct dw_hdmi_softc *sc)
{

	/* I2CM Setup */
	dw_hdmi_write(sc, DW_HDMI_PHY_I2CM_INT_ADDR, 0x08);
	dw_hdmi_write(sc, DW_HDMI_PHY_I2CM_CTLINT_ADDR, 0x88);

	/* Soft reset */
	dw_hdmi_write(sc, DW_HDMI_I2CM_SOFTRSTZ, 0);

	/* standard speed mode */
	dw_hdmi_write(sc, DW_HDMI_I2CM_DIV, 0);

	dw_hdmi_write(sc, DW_HDMI_I2CM_INT,
	    DW_HDMI_I2CM_INT_DONE_POL);
	dw_hdmi_write(sc, DW_HDMI_I2CM_CLINT,
	    DW_HDMI_I2CM_CLINT_NACK_POL | DW_HDMI_I2CM_CLINT_ARB_POL);

	/* Clear interrupts */
	dw_hdmi_write(sc, DW_HDMI_IH_I2CM_STAT0,
	  DW_HDMI_IH_I2CM_STAT0_ERROR |
	  DW_HDMI_IH_I2CM_STAT0_DONE);
}

static int
dw_hdmi_i2c_write(struct dw_hdmi_softc *sc, uint8_t *buf, uint16_t len)
{
	int i, err = 0;

	for (i = 0; i < len; i++) {
		dw_hdmi_write(sc, DW_HDMI_I2CM_DATAO, buf[i]);
		dw_hdmi_write(sc, DW_HDMI_I2CM_ADDRESS, i);
		dw_hdmi_write(sc, DW_HDMI_I2CM_OP, DW_HDMI_I2CM_OP_WR);

		while (err == 0 && sc->i2cm_stat == 0) {
			err = msleep(sc, &sc->mtx, 0, "dw_hdmi_ddc", 10 * hz);
		}
		if (err || sc->i2cm_stat & DW_HDMI_IH_I2CM_STAT0_ERROR) {
			device_printf(sc->dev, "%s: error\n", __func__);
			return (ENXIO);
		}
	}
	return (0);
}

static int
dw_hdmi_i2c_read(struct dw_hdmi_softc *sc, uint8_t *buf, uint16_t len)
{
	int i, err = 0;

	for (i = 0; i < len; i++) {
		dw_hdmi_write(sc, DW_HDMI_I2CM_ADDRESS, sc->i2cm_addr++);
		dw_hdmi_write(sc, DW_HDMI_I2CM_OP, DW_HDMI_I2CM_OP_RD);

		while (err == 0 && sc->i2cm_stat == 0) {
			err = msleep(sc, &sc->mtx, 0, "dw_hdmi_ddc", 10 * hz);
		}
		if (err || sc->i2cm_stat & DW_HDMI_IH_I2CM_STAT0_ERROR) {
			device_printf(sc->dev, "%s: error\n", __func__);
			return (ENXIO);
		}

		buf[i] = dw_hdmi_read(sc, DW_HDMI_I2CM_DATAI);
		sc->i2cm_stat = 0;
	}

	return (0);
}

int
dw_hdmi_transfer(device_t dev, struct iic_msg *msgs, uint32_t nmsgs)
{
	struct dw_hdmi_softc *sc;
	int i, ret;

	sc = device_get_softc(dev);
	DW_HDMI_LOCK(sc);

	sc->i2cm_addr = 0;
	for (i = 0; i < nmsgs; i++) {
		sc->i2cm_stat = 0;
		/* Unmute done and error interrups */
		dw_hdmi_write(sc, DW_HDMI_IH_MUTE_I2CM_STAT0, 0x00);

		/* Set DDC seg/addr */
		dw_hdmi_write(sc, DW_HDMI_I2CM_SLAVE, msgs[i].slave >> 1);
		dw_hdmi_write(sc, DW_HDMI_I2CM_SEGADDR, DDC_SEGMENT_ADDR);

		if (msgs[i].flags & IIC_M_RD)
			ret = dw_hdmi_i2c_read(sc, msgs[i].buf, msgs[i].len);
		else {
			if (msgs[i].len == 1) {
				sc->i2cm_addr = msgs[i].buf[0];
			} else 
				ret = dw_hdmi_i2c_write(sc, msgs[i].buf,
				    msgs[i].len);
		}

		if (ret != 0)
			break;
	}

	/* mute done and error interrups */
	dw_hdmi_write(sc, DW_HDMI_IH_MUTE_I2CM_STAT0, 0xFF);

	DW_HDMI_UNLOCK(sc);
	return (0);
}

static int
dw_hdmi_connector_get_modes(struct drm_connector *connector)
{
	struct dw_hdmi_softc *sc;
	struct edid *edid = NULL;
	int ret = 0;

	sc = container_of(connector, struct dw_hdmi_softc, connector);

	edid = drm_get_edid(connector, sc->ddc);
	drm_connector_update_edid_property(connector, edid);
	ret = drm_add_edid_modes(connector, edid);

	return (ret);
}

static const struct drm_connector_helper_funcs
    dw_hdmi_connector_helper_funcs = {
	.get_modes = dw_hdmi_connector_get_modes,
};

static int
dw_hdmi_bridge_attach(struct drm_bridge *bridge,
    enum drm_bridge_attach_flags flags)
{
	struct dw_hdmi_softc *sc;

	sc = container_of(bridge, struct dw_hdmi_softc, bridge);

	sc->connector.polled = DRM_CONNECTOR_POLL_HPD;
	drm_connector_helper_add(&sc->connector,
	    &dw_hdmi_connector_helper_funcs);

	drm_connector_init(bridge->dev, &sc->connector,
	    &dw_hdmi_connector_funcs, DRM_MODE_CONNECTOR_HDMIA);

	drm_connector_attach_encoder(&sc->connector, &sc->encoder);

	return (0);
}

/* TODO: Is there some mode that we don't support ? */
static enum drm_mode_status
dw_hdmi_bridge_mode_valid(struct drm_bridge *bridge,
			  const struct drm_display_mode *mode)
{

	return (MODE_OK);
}

static void
dw_hdmi_bridge_mode_set(struct drm_bridge *bridge,
  const struct drm_display_mode *orig_mode,
  const struct drm_display_mode *mode)
{
	struct dw_hdmi_softc *sc;

	sc = container_of(bridge, struct dw_hdmi_softc, bridge);

	/* Copy the mode, this will be set in bridge_enable function */
	memcpy(&sc->mode, mode, sizeof(struct drm_display_mode));
}

static void
dw_hdmi_bridge_disable(struct drm_bridge *bridge)
{
}

static inline void
dw_hdmi_dump_vp_regs(struct dw_hdmi_softc *sc)
{
	uint8_t	reg;

	DRM_DEBUG_DRIVER("%s: DW_HDMI VP Registers\n", __func__);
	reg = dw_hdmi_read(sc, DW_HDMI_VP_STATUS);
	DRM_DEBUG_DRIVER("%s: DW_HDMI_VP_STATUS: %x\n", __func__, reg);
	reg = dw_hdmi_read(sc, DW_HDMI_VP_PR_CD);
	DRM_DEBUG_DRIVER("%s: DW_HDMI_VP_PR_CD: %x\n", __func__, reg);
	reg = dw_hdmi_read(sc, DW_HDMI_VP_STUFF);
	DRM_DEBUG_DRIVER("%s: DW_HDMI_VP_STUFF: %x\n", __func__, reg);
	reg = dw_hdmi_read(sc, DW_HDMI_VP_REMAP);
	DRM_DEBUG_DRIVER("%s: DW_HDMI_VP_REMAP: %x\n", __func__, reg);
	reg = dw_hdmi_read(sc, DW_HDMI_VP_CONF);
	DRM_DEBUG_DRIVER("%s: DW_HDMI_VP_CONF: %x\n", __func__, reg);
	reg = dw_hdmi_read(sc, DW_HDMI_VP_MASK);
	DRM_DEBUG_DRIVER("%s: DW_HDMI_VP_MASK: %x\n", __func__, reg);
}

static inline void
dw_hdmi_dump_fc_regs(struct dw_hdmi_softc *sc)
{
	uint8_t	reg;

	DRM_DEBUG_DRIVER("%s: DW_HDMI FC Registers\n", __func__);
	reg = dw_hdmi_read(sc, DW_HDMI_FC_INVIDCONF);
	DRM_DEBUG_DRIVER("%s: DW_HDMI_FC_INVIDCONF: %d\n", __func__, reg);
	reg = dw_hdmi_read(sc, DW_HDMI_FC_INHACTIV0);
	DRM_DEBUG_DRIVER("%s: DW_HDMI_FC_INHACTIV0: %d\n", __func__, reg);
	reg = dw_hdmi_read(sc, DW_HDMI_FC_INHACTIV1);
	DRM_DEBUG_DRIVER("%s: DW_HDMI_FC_INHACTIV1: %d\n", __func__, reg);
	reg = dw_hdmi_read(sc, DW_HDMI_FC_INHBLANK0);
	DRM_DEBUG_DRIVER("%s: DW_HDMI_FC_INHBLANK0: %d\n", __func__, reg);
	reg = dw_hdmi_read(sc, DW_HDMI_FC_INHBLANK1);
	DRM_DEBUG_DRIVER("%s: DW_HDMI_FC_INHBLANK1: %d\n", __func__, reg);
	reg = dw_hdmi_read(sc, DW_HDMI_FC_INVACTIV0);
	DRM_DEBUG_DRIVER("%s: DW_HDMI_FC_INVACTIV1: %d\n", __func__, reg);
	reg = dw_hdmi_read(sc, DW_HDMI_FC_HSYNCINDELAY0);
	DRM_DEBUG_DRIVER("%s: DW_HDMI_FC_HSYNCINDELAY0: %d\n", __func__, reg);
	reg = dw_hdmi_read(sc, DW_HDMI_FC_HSYNCINDELAY1);
	DRM_DEBUG_DRIVER("%s: DW_HDMI_FC_HSYNCINDELAY1: %d\n", __func__, reg);
	reg = dw_hdmi_read(sc, DW_HDMI_FC_HSYNCINWIDTH0);
	DRM_DEBUG_DRIVER("%s: DW_HDMI_FC_HSYNCINWIDTH0: %d\n", __func__, reg);
	reg = dw_hdmi_read(sc, DW_HDMI_FC_HSYNCINWIDTH1);
	DRM_DEBUG_DRIVER("%s: DW_HDMI_FC_HSYNCINWIDTH1: %d\n", __func__, reg);
	reg = dw_hdmi_read(sc, DW_HDMI_FC_VSYNCINDELAY);
	DRM_DEBUG_DRIVER("%s: DW_HDMI_FC_VSYNCINDELAY: %d\n", __func__, reg);
	reg = dw_hdmi_read(sc, DW_HDMI_FC_VSYNCINWIDTH);
	DRM_DEBUG_DRIVER("%s: DW_HDMI_FC_VSYNCINWIDTH: %d\n", __func__, reg);
	reg = dw_hdmi_read(sc, DW_HDMI_FC_CTRLDUR);
	DRM_DEBUG_DRIVER("%s: DW_HDMI_FC_CTRLDUR: %d\n", __func__, reg);
	reg = dw_hdmi_read(sc, DW_HDMI_FC_EXCTRLDUR);
	DRM_DEBUG_DRIVER("%s: DW_HDMI_FC_EXCTRLDUR: %d\n", __func__, reg);
	reg = dw_hdmi_read(sc, DW_HDMI_FC_EXCTRLSPAC);
	DRM_DEBUG_DRIVER("%s: DW_HDMI_FC_EXCTRLSPAC: %d\n", __func__, reg);
	reg = dw_hdmi_read(sc, DW_HDMI_FC_CH0PREAM);
	DRM_DEBUG_DRIVER("%s: DW_HDMI_FC_CH0PREAM: %d\n", __func__, reg);
	reg = dw_hdmi_read(sc, DW_HDMI_FC_CH1PREAM);
	DRM_DEBUG_DRIVER("%s: DW_HDMI_FC_CH1PREAM: %d\n", __func__, reg);
	reg = dw_hdmi_read(sc, DW_HDMI_FC_CH2PREAM);
	DRM_DEBUG_DRIVER("%s: DW_HDMI_FC_CH2PREAM: %d\n", __func__, reg);
}

static void
dw_hdmi_phy_sel_data_en_pol(struct dw_hdmi_softc *sc, uint8_t enable)
{
	uint8_t reg;

	reg = dw_hdmi_read(sc, DW_HDMI_PHY_CONF0);
	reg &= ~HDMI_PHY_CONF0_SELDATAENPOL_MASK;
	reg |= (enable << HDMI_PHY_CONF0_SELDATAENPOL_OFFSET);
	dw_hdmi_write(sc, DW_HDMI_PHY_CONF0, reg);
}

static void
dw_hdmi_phy_sel_interface_control(struct dw_hdmi_softc *sc, uint8_t enable)
{
	uint8_t reg;

	reg = dw_hdmi_read(sc, DW_HDMI_PHY_CONF0);
	reg &= ~HDMI_PHY_CONF0_SELDIPIF_MASK;
	reg |= (enable << HDMI_PHY_CONF0_SELDIPIF_OFFSET);
	dw_hdmi_write(sc, DW_HDMI_PHY_CONF0, reg);
}

static void
dw_hdmi_phy_enable_tmds(struct dw_hdmi_softc *sc, uint8_t enable)
{
	uint8_t reg;

	reg = dw_hdmi_read(sc, DW_HDMI_PHY_CONF0);
	reg &= ~HDMI_PHY_CONF0_ENTMDS_MASK;
	reg |= (enable << HDMI_PHY_CONF0_ENTMDS_OFFSET);
	dw_hdmi_write(sc, DW_HDMI_PHY_CONF0, reg);
}

static void
dw_hdmi_phy_enable_power(struct dw_hdmi_softc *sc, uint8_t enable)
{
	uint8_t reg;

	reg = dw_hdmi_read(sc, DW_HDMI_PHY_CONF0);
	reg &= ~HDMI_PHY_CONF0_PDZ_MASK;
	reg |= (enable << HDMI_PHY_CONF0_PDZ_OFFSET);
	dw_hdmi_write(sc, DW_HDMI_PHY_CONF0, reg);
}

static void
dw_hdmi_phy_enable_spare(struct dw_hdmi_softc *sc, uint8_t enable)
{
	uint8_t reg;

	reg = dw_hdmi_read(sc, DW_HDMI_PHY_CONF0);
	reg &= ~HDMI_PHY_CONF0_SPARECTRL_MASK;
	reg |= (enable << HDMI_PHY_CONF0_SPARECTRL_OFFSET);
	dw_hdmi_write(sc, DW_HDMI_PHY_CONF0, reg);
}

static void
dw_hdmi_phy_gen2_txpwron(struct dw_hdmi_softc *sc, uint8_t enable)
{
	uint8_t reg;

	reg = dw_hdmi_read(sc, DW_HDMI_PHY_CONF0);
	reg &= ~HDMI_PHY_CONF0_GEN2_TXPWRON_MASK;
	reg |= (enable << HDMI_PHY_CONF0_GEN2_TXPWRON_OFFSET);
	dw_hdmi_write(sc, DW_HDMI_PHY_CONF0, reg);
}

static void
dw_hdmi_phy_gen2_pddq(struct dw_hdmi_softc *sc, uint8_t enable)
{
	uint8_t reg;

	reg = dw_hdmi_read(sc, DW_HDMI_PHY_CONF0);
	reg &= ~HDMI_PHY_CONF0_GEN2_PDDQ_MASK;
	reg |= (enable << HDMI_PHY_CONF0_GEN2_PDDQ_OFFSET);
	dw_hdmi_write(sc, DW_HDMI_PHY_CONF0, reg);
}

static inline void
dw_hdmi_phy_test_clear(struct dw_hdmi_softc *sc, unsigned char bit)
{
	uint8_t val;

	val = dw_hdmi_read(sc, DW_HDMI_PHY_TST0);
	val &= ~HDMI_PHY_TST0_TSTCLR_MASK;
	val |= (bit << HDMI_PHY_TST0_TSTCLR_OFFSET) &
		HDMI_PHY_TST0_TSTCLR_MASK;
	dw_hdmi_write(sc, DW_HDMI_PHY_TST0, val);
}

static void
dw_hdmi_phy_wait_i2c_done(struct dw_hdmi_softc *sc, int msec)
{
	uint8_t val;

	val = dw_hdmi_read(sc, DW_HDMI_IH_I2CMPHY_STAT0) &
	    (DW_HDMI_IH_I2CMPHY_STAT0_DONE | DW_HDMI_IH_I2CMPHY_STAT0_ERROR);
	while (val == 0) {
		pause("DW_HDMI_PHY", hz/100);
		msec -= 10;
		if (msec <= 0)
			return;
		val = dw_hdmi_read(sc, DW_HDMI_IH_I2CMPHY_STAT0) &
		    (DW_HDMI_IH_I2CMPHY_STAT0_DONE |
		    DW_HDMI_IH_I2CMPHY_STAT0_ERROR);
	}
}

static void
dw_hdmi_phy_i2c_write(struct dw_hdmi_softc *sc, unsigned short data,
    unsigned char addr)
{

	/* clear DONE and ERROR flags */
	dw_hdmi_write(sc, DW_HDMI_IH_I2CMPHY_STAT0,
	    DW_HDMI_IH_I2CMPHY_STAT0_DONE | DW_HDMI_IH_I2CMPHY_STAT0_ERROR);
	dw_hdmi_write(sc, DW_HDMI_PHY_I2CM_ADDRESS_ADDR, addr);
	dw_hdmi_write(sc, DW_HDMI_PHY_I2CM_DATAO_1_ADDR, ((data >> 8) & 0xff));
	dw_hdmi_write(sc, DW_HDMI_PHY_I2CM_DATAO_0_ADDR, ((data >> 0) & 0xff));
	dw_hdmi_write(sc, DW_HDMI_PHY_I2CM_OPERATION_ADDR,
	    HDMI_PHY_I2CM_OPERATION_ADDR_WRITE);
	dw_hdmi_phy_wait_i2c_done(sc, 1000);
}

/*
 * The phy configuration values here are for RK3399 and not tested
 * on any other platform.
 */
static int
dw_hdmi_phy_configure(struct dw_hdmi_softc *sc)
{
	uint8_t val;
	uint8_t msec;

	dw_hdmi_write(sc, DW_HDMI_MC_FLOWCTRL,
	    HDMI_MC_FLOWCTRL_FEED_THROUGH_OFF_CSC_BYPASS);

	/* gen2 tx power off */
	dw_hdmi_phy_gen2_txpwron(sc, 0);

	/* gen2 pddq */
	dw_hdmi_phy_gen2_pddq(sc, 1);

	/* PHY reset */
	dw_hdmi_write(sc, DW_HDMI_MC_PHYRSTZ, HDMI_MC_PHYRSTZ_DEASSERT);
	dw_hdmi_write(sc, DW_HDMI_MC_PHYRSTZ, HDMI_MC_PHYRSTZ_ASSERT);

	dw_hdmi_write(sc, DW_HDMI_MC_HEACPHY_RST, HDMI_MC_HEACPHY_RST_ASSERT);

	dw_hdmi_phy_test_clear(sc, 1);
	dw_hdmi_write(sc, DW_HDMI_PHY_I2CM_SLAVE_ADDR,
	    HDMI_PHY_I2CM_SLAVE_ADDR_PHY_GEN2);
	dw_hdmi_phy_test_clear(sc, 0);

	/*
	 * Following initialization are for 8bit per color case
	 */
	dw_hdmi_phy_i2c_write(sc, 0x0051, DW_HDMI_PHY_I2C_CPCE_CTRL);
	dw_hdmi_phy_i2c_write(sc, 0x0003, DW_HDMI_PHY_I2C_GMPCTRL);
	dw_hdmi_phy_i2c_write(sc, 0x0000, DW_HDMI_PHY_I2C_CURRCTRL);

	dw_hdmi_phy_i2c_write(sc, 0x0000, DW_HDMI_PHY_I2C_PLLPHBYCTRL);
	dw_hdmi_phy_i2c_write(sc, MSM_CTRL_FB_CLK, DW_HDMI_PHY_I2C_MSM_CTRL);

	/* REMOVE CLK TERM */
	dw_hdmi_phy_i2c_write(sc, CKCALCTRL_OVERRIDE,
	    DW_HDMI_PHY_I2C_CKCALCTRL);

	/* Those value are rockchip specific, will need to put that in the subclassed driver */
	if (sc->mode.crtc_clock <= 74250) {
		dw_hdmi_phy_i2c_write(sc, 0x8009, DW_HDMI_PHY_I2C_CKSYMTXCTRL);
		dw_hdmi_phy_i2c_write(sc, 0x0004, DW_HDMI_PHY_I2C_TXTERM);
		dw_hdmi_phy_i2c_write(sc, 0x0272, DW_HDMI_PHY_I2C_VLEVCTRL);
	} else if (sc->mode.crtc_clock <= 148500) {
		dw_hdmi_phy_i2c_write(sc, 0x802b, DW_HDMI_PHY_I2C_CKSYMTXCTRL);
		dw_hdmi_phy_i2c_write(sc, 0x0004, DW_HDMI_PHY_I2C_TXTERM);
		dw_hdmi_phy_i2c_write(sc, 0x028d, DW_HDMI_PHY_I2C_VLEVCTRL);
	} else if (sc->mode.crtc_clock <= 297000) {
		dw_hdmi_phy_i2c_write(sc, 0x8039, DW_HDMI_PHY_I2C_CKSYMTXCTRL);
		dw_hdmi_phy_i2c_write(sc, 0x0005, DW_HDMI_PHY_I2C_TXTERM);
		dw_hdmi_phy_i2c_write(sc, 0x028d, DW_HDMI_PHY_I2C_VLEVCTRL);
	} else {
		device_printf(sc->dev, "unknown clock %d\n",
		    sc->mode.crtc_clock);
		return (ENXIO);
	}

	dw_hdmi_phy_enable_power(sc, 1);

	/* toggle TMDS enable */
	dw_hdmi_phy_enable_tmds(sc, 0);
	dw_hdmi_phy_enable_tmds(sc, 1);

	/* gen2 tx power on */
	dw_hdmi_phy_gen2_txpwron(sc, 1);
	dw_hdmi_phy_gen2_pddq(sc, 0);

	dw_hdmi_phy_enable_spare(sc, 1);

	/* Wait for PHY PLL lock */
	msec = 4;
	val = dw_hdmi_read(sc, DW_HDMI_PHY_STAT0) & HDMI_PHY_TX_PHY_LOCK;
	while (val == 0) {
		DELAY(1000);
		if (msec-- == 0) {
			device_printf(sc->dev, "PHY PLL not locked\n");
			return (-1);
		}
		val = dw_hdmi_read(sc, DW_HDMI_PHY_STAT0) & \
		    HDMI_PHY_TX_PHY_LOCK;
	}

	return true;
}

static void
dw_hdmi_phy_init(struct dw_hdmi_softc *sc)
{
	int i;

	/* HDMI Phy spec says to do the phy initialization sequence twice */
	for (i = 0 ; i < 2 ; i++) {
		dw_hdmi_phy_sel_data_en_pol(sc, 1);
		dw_hdmi_phy_sel_interface_control(sc, 0);
		dw_hdmi_phy_enable_tmds(sc, 0);
		dw_hdmi_phy_enable_power(sc, 0);

		/* Enable CSC */
		dw_hdmi_phy_configure(sc);
	}
}

static void
dw_hdmi_bridge_enable(struct drm_bridge *bridge)
{
	struct dw_hdmi_softc *sc;
	uint8_t reg;

	sc = container_of(bridge, struct dw_hdmi_softc, bridge);

	DRM_DEBUG_DRIVER("%s: Mode information:\n"
	    "hdisplay: %d\n"
	    "vdisplay: %d\n"
	    "htotal: %d\n"
	    "vtotal: %d\n"
	    "hsync_start: %d\n"
	    "hsync_end: %d\n"
	    "vsync_start: %d\n"
	    "vsync_end: %d\n",
	    __func__,
	    sc->mode.hdisplay,
	    sc->mode.vdisplay,
	    sc->mode.htotal,
	    sc->mode.vtotal,
	    sc->mode.hsync_start,
	    sc->mode.hsync_end,
	    sc->mode.vsync_start,
	    sc->mode.vsync_end);

	/* VP stuff, need to find what's really needed */
	dw_hdmi_write(sc, DW_HDMI_VP_STUFF, 0x27);
	dw_hdmi_write(sc, DW_HDMI_VP_CONF, 0x47);

	/* AV composer setup */
	reg = (sc->mode.flags & DRM_MODE_FLAG_PVSYNC) ?
		DW_HDMI_FC_INVIDCONF_VSYNC_POL_HIGH : 0;
	reg |= (sc->mode.flags & DRM_MODE_FLAG_PHSYNC) ?
		DW_HDMI_FC_INVIDCONF_HSYNC_POL_HIGH : 0;
	reg |= DW_HDMI_FC_INVIDCONF_DATA_POL_HIGH;

	reg |= (sc->mode.flags & DRM_MODE_FLAG_INTERLACE) ?
		DW_HDMI_FC_INVIDCONF_INTERLACED_MODE : 0;

	/* Will need to depend on drm_detect_hdmi_monitor return value */
	reg |= DW_HDMI_FC_INVIDCONF_HDMI_MODE;
	dw_hdmi_write(sc, DW_HDMI_FC_INVIDCONF, reg);

	/* Frame composer setup */
	dw_hdmi_write(sc, DW_HDMI_FC_INHACTIV0, sc->mode.hdisplay & 0xFF);
	dw_hdmi_write(sc, DW_HDMI_FC_INHACTIV1, sc->mode.hdisplay >> 8);
	dw_hdmi_write(sc, DW_HDMI_FC_INHBLANK0,
	    (sc->mode.htotal - sc->mode.hdisplay) & 0xFF);
	dw_hdmi_write(sc, DW_HDMI_FC_INHBLANK1,
	    (sc->mode.htotal - sc->mode.hdisplay) >> 8);
	dw_hdmi_write(sc, DW_HDMI_FC_INVACTIV0, sc->mode.vdisplay & 0xFF);
	dw_hdmi_write(sc, DW_HDMI_FC_INVACTIV1, sc->mode.vdisplay >> 8);
	dw_hdmi_write(sc, DW_HDMI_FC_INVBLANK,
	    sc->mode.vtotal - sc->mode.vdisplay);
	dw_hdmi_write(sc, DW_HDMI_FC_HSYNCINDELAY0,
	    (sc->mode.hsync_start - sc->mode.hdisplay) & 0xFF);
	dw_hdmi_write(sc, DW_HDMI_FC_HSYNCINDELAY1,
	    (sc->mode.hsync_start - sc->mode.hdisplay) >> 8);
	dw_hdmi_write(sc, DW_HDMI_FC_HSYNCINWIDTH0,
	    (sc->mode.hsync_end - sc->mode.hsync_start) & 0xFF);
	dw_hdmi_write(sc, DW_HDMI_FC_HSYNCINWIDTH1,
	    (sc->mode.hsync_end - sc->mode.hsync_start) >> 8);
	dw_hdmi_write(sc, DW_HDMI_FC_VSYNCINDELAY,
	    sc->mode.vsync_start - sc->mode.vdisplay);
	dw_hdmi_write(sc, DW_HDMI_FC_VSYNCINWIDTH,
	    sc->mode.vsync_end - sc->mode.vsync_start);

	/* Configure the PHY */
	if (sc->phydev != NULL)
		DW_HDMI_PHY_CONFIG(sc->phydev, &sc->mode);
	else /* Internal PHY. */
		dw_hdmi_phy_init(sc);

	/* 12 pixel clock cycles */
	dw_hdmi_write(sc, DW_HDMI_FC_CTRLDUR, 12);
	/* 32 pixel clock cycles */
	dw_hdmi_write(sc, DW_HDMI_FC_EXCTRLDUR, 32);
	/* 1 50msec spacing */
	dw_hdmi_write(sc, DW_HDMI_FC_EXCTRLSPAC, 1);

	/* pream defaults */
	dw_hdmi_write(sc, DW_HDMI_FC_CH0PREAM, 11);
	dw_hdmi_write(sc, DW_HDMI_FC_CH1PREAM, 22);
	dw_hdmi_write(sc, DW_HDMI_FC_CH2PREAM, 33);

	/* Enable pixel clock and TMDS clock */
	reg = DW_HDMI_MC_CLKDIS_PREPCLK |
		DW_HDMI_MC_CLKDIS_AUDCLK |
		DW_HDMI_MC_CLKDIS_CSCCLK |
		DW_HDMI_MC_CLKDIS_CECCLK |
		DW_HDMI_MC_CLKDIS_HDCPCLK;
	reg &= ~DW_HDMI_MC_CLKDIS_PIXELCLK;
	dw_hdmi_write(sc, DW_HDMI_MC_CLKDIS, reg);

	reg &= ~DW_HDMI_MC_CLKDIS_TMDSCLK;
	dw_hdmi_write(sc, DW_HDMI_MC_CLKDIS, reg);

	if (__drm_debug & DRM_UT_DRIVER) {
		dw_hdmi_dump_vp_regs(sc);
		dw_hdmi_dump_fc_regs(sc);
	}
}

static const struct drm_bridge_funcs dw_hdmi_bridge_funcs = {
	.attach = dw_hdmi_bridge_attach,
	.enable = dw_hdmi_bridge_enable,
	.disable = dw_hdmi_bridge_disable,
	.mode_set = dw_hdmi_bridge_mode_set,
	.mode_valid = dw_hdmi_bridge_mode_valid,
};

void
dw_hdmi_add_bridge(struct dw_hdmi_softc *sc)
{

	sc->bridge.funcs = &dw_hdmi_bridge_funcs;
	drm_bridge_attach(&sc->encoder, &sc->bridge, NULL, 0);
}

static void
dw_hdmi_intr(void *arg)
{
	struct dw_hdmi_softc *sc;

	sc = (struct dw_hdmi_softc *)arg;

	sc->i2cm_stat = dw_hdmi_read(sc, DW_HDMI_IH_I2CM_STAT0);
	if (sc->i2cm_stat != 0) {
		/* Ack interrupts */
		dw_hdmi_write(sc, DW_HDMI_IH_I2CM_STAT0, sc->i2cm_stat);
	}

	wakeup(sc);
}

/*
 * Driver routines
 */
static uint32_t
dw_hdmi_read(struct dw_hdmi_softc *sc, uint32_t reg)
{

	switch (sc->reg_width) {
	case 4:
		return (DW_HDMI_READ_4(sc, reg << 2));
		break;
	case 1:
	default:
		return (DW_HDMI_READ_1(sc, reg));
		break;
	}
}

static void
dw_hdmi_write(struct dw_hdmi_softc *sc, uint32_t reg, uint32_t val)
{

	switch (sc->reg_width) {
	case 4:
		DW_HDMI_WRITE_4(sc, reg << 2, val);
		break;
	case 1:
	default:
		DW_HDMI_WRITE_1(sc, reg, val);
		break;
	}
}

int
dw_hdmi_attach(device_t dev)
{
	struct dw_hdmi_softc *sc;
	phandle_t node, phy;
	int error;
	uint16_t version;

	sc = device_get_softc(dev);
	sc->dev = dev;

	if (bus_alloc_resources(dev, dw_hdmi_spec, sc->res) != 0) {
		device_printf(dev, "cannot allocate resources for device\n");
		error = ENXIO;
		goto fail;
	}
	if (bus_setup_intr(dev, sc->res[1],
	    INTR_TYPE_MISC | INTR_MPSAFE, NULL, dw_hdmi_intr, sc,
	    &sc->intrhand)) {
		bus_release_resources(dev, dw_hdmi_spec, sc->res);
		device_printf(dev, "cannot setup interrupt handler\n");
		return (ENXIO);
	}

	mtx_init(&sc->mtx, device_get_nameunit(dev), "dw_hdmi", MTX_DEF);

	node = ofw_bus_get_node(dev);

	/* Clock and reset */
	if ((error = clk_get_by_ofw_name(dev, node, "iahb",
	    &sc->clk_iahb)) != 0) {
		device_printf(dev, "Cannot get iahb clock\n");
		goto fail;
	}
	if (clk_enable(sc->clk_iahb) != 0) {
		device_printf(dev, "Cannot enable iahb clock\n");
		goto fail;
	}
	if ((error = clk_get_by_ofw_name(dev, node, "isfr",
	    &sc->clk_isfr)) != 0) {
		device_printf(dev, "Cannot get isfr clock\n");
		goto fail;
	}
	if (clk_enable(sc->clk_isfr) != 0) {
		device_printf(dev, "Cannot enable isfr clock\n");
		goto fail;
	}
	if (clk_get_by_ofw_name(dev, node, "cec",
	      &sc->clk_cec) == 0) {
		error = clk_enable(sc->clk_cec);
		if (error != 0)
			device_printf(dev, "Cannot enable cec clock\n");
		error = 0;
	}

	/* Get the res-io-width */
	if (OF_getencprop(node, "reg-io-width", &sc->reg_width,
	    sizeof(uint32_t)) <= 0)
		sc->reg_width = 1;

	/* Get and init the phy */
	if (OF_hasprop(node, "phys")) {
		if (OF_getencprop(node, "phys", &phy, sizeof(phy)) == -1) {
			device_printf(dev, "Cannot get the phys property\n");
			error = ENXIO;
			goto fail;
		}
		sc->phydev = OF_device_from_xref(phy);
		if (sc->phydev == NULL) {
			device_printf(dev, "Cannot get the phy device\n");
			error = ENXIO;
			goto fail;
		}
		DW_HDMI_PHY_INIT(sc->phydev);
	} else {
		/* Use internal phy */
	}

	/* Register ourself */
	OF_device_register_xref(OF_xref_from_node(node), dev);

	if (bootverbose) {
		version = dw_hdmi_read(sc, DW_HDMI_DESIGN_ID) << 8;
		version |= dw_hdmi_read(sc, DW_HDMI_REVISION_ID);
		if (bootverbose) {
			device_printf(dev, "Version: %x\n", version);
			device_printf(dev, "Product ID0: %x, Product ID1: %x\n",
			    dw_hdmi_read(sc, DW_HDMI_PRODUCT_ID0),
			    dw_hdmi_read(sc, DW_HDMI_PRODUCT_ID1));
		}
	}

	dw_hdmi_i2cm_init(sc);

	/* Disable interrupts */
	dw_hdmi_write(sc, DW_HDMI_IH_FC_STAT0, 0xFF);
	dw_hdmi_write(sc, DW_HDMI_IH_FC_STAT1, 0xFF);
	dw_hdmi_write(sc, DW_HDMI_IH_FC_STAT2, 0xFF);
	dw_hdmi_write(sc, DW_HDMI_IH_AS_STAT0, 0xFF);
	dw_hdmi_write(sc, DW_HDMI_IH_PHY_STAT0, 0xFF);
	dw_hdmi_write(sc, DW_HDMI_IH_I2CM_STAT0, 0xFF);
	dw_hdmi_write(sc, DW_HDMI_IH_CEC_STAT0, 0xFF);
	dw_hdmi_write(sc, DW_HDMI_IH_VP_STAT0, 0xFF);
	dw_hdmi_write(sc, DW_HDMI_IH_I2CMPHY_STAT0, 0xFF);
	dw_hdmi_write(sc, DW_HDMI_IH_AHBDMAAUD_STAT0, 0xFF);

	/* Mute interrupts*/
	dw_hdmi_write(sc, DW_HDMI_IH_MUTE_FC_STAT0,
	  0xFF);
	dw_hdmi_write(sc, DW_HDMI_IH_MUTE_FC_STAT1,
	  0xFF);
	dw_hdmi_write(sc, DW_HDMI_IH_MUTE_FC_STAT2,
	  0xFF);
	dw_hdmi_write(sc, DW_HDMI_IH_MUTE_AS_STAT0,
	  0xFF);
	dw_hdmi_write(sc, DW_HDMI_IH_MUTE_PHY_STAT0,
	  0xFF);
	dw_hdmi_write(sc, DW_HDMI_IH_MUTE_I2CM_STAT0,
	  0xFF);
	dw_hdmi_write(sc, DW_HDMI_IH_MUTE_CEC_STAT0,
	  0xFF);
	dw_hdmi_write(sc, DW_HDMI_IH_MUTE_VP_STAT0,
	  0xFF);
	dw_hdmi_write(sc, DW_HDMI_IH_MUTE_I2CMPHY_STAT0,
	  0xFF);
	dw_hdmi_write(sc, DW_HDMI_IH_MUTE_AHBDMAAUD_STAT0,
	  0xFF);

	/* Unmute global interrupts */
	dw_hdmi_write(sc, DW_HDMI_IH_MUTE,
	  ~(DW_HDMI_IH_MUTE_ALL |
	    DW_HDMI_IH_MUTE_WAKEUP));

	/* If no ddc is provided by the driver use the internal one */
	if (sc->ddc == NULL) {
		if ((sc->iicbus = device_add_child(dev, "iicbus", -1)) == NULL){
			device_printf(dev,
			    "could not allocate iicbus instance\n");
			return (ENXIO);
		}
		sc->ddc = i2c_bsd_adapter(sc->iicbus);
	}

	if (__drm_debug & DRM_UT_DRIVER) {
		dw_hdmi_dump_vp_regs(sc);
		dw_hdmi_dump_fc_regs(sc);
	}
fail:
	return (error);
}

int
dw_hdmi_detach(device_t dev)
{
	struct dw_hdmi_softc *sc;

	sc = device_get_softc(dev);

	bus_release_resources(dev, dw_hdmi_spec, sc->res);
	mtx_destroy(&sc->mtx);

	return (0);
}

static device_method_t dw_hdmi_methods[] = {
	/* iicbus interface */
	DEVMETHOD(iicbus_transfer,	dw_hdmi_transfer),
};

DEFINE_CLASS_0(dw_hdmi, dw_hdmi_driver, dw_hdmi_methods,
    sizeof(struct dw_hdmi_softc));
