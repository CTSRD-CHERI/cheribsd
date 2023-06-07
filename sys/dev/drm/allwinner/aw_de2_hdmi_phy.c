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
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/rman.h>
#include <sys/resource.h>
#include <machine/bus.h>

#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <dev/extres/clk/clk.h>
#include <dev/extres/hwreset/hwreset.h>

#include <drm/drm_drv.h>
#include <drm/drm_modes.h>
#include <drm/drm_print.h>

#include "dw_hdmi_phy_if.h"

#define	ANA_CFG1			0x20
#define	 ANA_CFG1_ENBI			(1 << 0)
#define	 ANA_CFG1_ENVBS			(1 << 1)
#define	 ANA_CFG1_LDOEN			(1 << 2)
#define	 ANA_CFG1_CKEN			(1 << 3)
#define	 ANA_CFG1_ENP2S_TMDS0		(1 << 4)
#define	 ANA_CFG1_ENP2S_TMDS1		(1 << 5)
#define	 ANA_CFG1_ENP2S_TMDS2		(1 << 6)
#define	 ANA_CFG1_ENP2S_TMDSCLK		(1 << 7)
#define	 ANA_CFG1_BIASEN_TMDS0		(1 << 8)
#define	 ANA_CFG1_BIASEN_TMDS1		(1 << 9)
#define	 ANA_CFG1_BIASEN_TMDS2		(1 << 10)
#define	 ANA_CFG1_BIASEN_TMDSCLK	(1 << 11)
#define	 ANA_CFG1_BIASEN_ALL		(0xf << 8)
#define	 ANA_CFG1_TXEN_TMDS0		(1 << 12)
#define	 ANA_CFG1_TXEN_TMDS1		(1 << 13)
#define	 ANA_CFG1_TXEN_TMDS2		(1 << 14)
#define	 ANA_CFG1_TXEN_TMDSCLK		(1 << 15)
#define	 ANA_CFG1_TXEN_ALL		(0xf << 12)
#define	 ANA_CFG1_TMDSCLK_EN		(1 << 16)
#define	 ANA_CFG1_SCLKTMDS		(1 << 17)
#define	 ANA_CFG1_ENCALOG		(1 << 18)
#define	 ANA_CFG1_ENRCAL		(1 << 19)
#define	 ANA_CFG1_EMPCK_OPT		(1 << 20)
#define	 ANA_CFG1_AMPCK_OPT		(1 << 21)
#define	 ANA_CFG1_EMP_OPT		(1 << 22)
#define	 ANA_CFG1_AMP_OPT		(1 << 23)
#define	 ANA_CFG1_SVBH(x)		(x << 24)
#define	 ANA_CFG1_SVRCAL(x)		(x << 26)
#define	 ANA_CFG1_CALSW			(1 << 28)
#define	 ANA_CFG1_PWENC			(1 << 29)
#define	 ANA_CFG1_PWEND			(1 << 30)
#define	 ANA_CFG1_SWI			(1 << 31)

#define	ANA_CFG2	0x24
#define	ANA_CFG2_RESDI(x)	(x << 0)
#define	ANA_CFG2_BOOST(x)	(x << 6)
#define	ANA_CFG2_BOOSTCK(x)	(x << 8)
#define	ANA_CFG2_SLV(x)		(x << 10)
#define	ANA_CFG2_CSMPS(x)	(x << 13)
#define	ANA_CFG2_BIGSW		(1 << 15)
#define	ANA_CFG2_BIGSWCK	(1 << 16)
#define	ANA_CFG2_CKSS(x)	(x << 17)
#define	ANA_CFG2_CD(x)		(x << 19)
#define	ANA_CFG2_DEN		(1 << 21)
#define	ANA_CFG2_DENCK		(1 << 22)
#define	ANA_CFG2_PLR(x)		(x << 23)
#define	ANA_CFG2_PLRCK		(1 << 26)
#define	ANA_CFG2_HPDEN		(1 << 27)
#define	ANA_CFG2_HPDPD		(1 << 28)
#define	ANA_CFG2_SEN		(1 << 29)
#define	ANA_CFG2_PLLBEN		(1 << 30)
#define	ANA_CFG2_M_EN		(1 << 31)

#define	ANA_CFG3		0x28
#define	ANA_CFG3_SCLEN		(1 << 0)
#define	ANA_CFG3_SCLPD		(1 << 1)
#define	ANA_CFG3_SDAEN		(1 << 2)
#define	ANA_CFG3_SDAPD		(1 << 3)
#define	ANA_CFG3_EMP(x)		(x << 4)
#define	ANA_CFG3_AMP(x)		(x << 7)
#define	ANA_CFG3_EMPCK(x)	(x << 11)
#define	ANA_CFG3_AMPCK(x)	(x << 14)
#define	ANA_CFG3_WIRE(x)	(x << 18)
#define	ANA_CFG3_SLOW(x)	(x << 28)
#define	ANA_CFG3_SLOWCK(x)	(x << 30)

#define	PLL_CFG1	0x2C
#define	 PLL_CFG1_B_IN(x)	(x << 0)
#define	 PLL_CFG1_BWS		(1 << 6)
#define	 PLL_CFG1_CNT_INT(x)	(x << 7)
#define	 PLL_CFG1_CP_S(x)	(x << 13)
#define	 PLL_CFG1_CS		(1 << 18)
#define	 PLL_CFG1_PLLDBEN	(1 << 19)
#define	 PLL_CFG1_UNKNOWN	(1 << 20)
#define	 PLL_CFG1_LDO_VSET(x)	(x << 22)
#define	 PLL_CFG1_PLLEN		(1 << 25)
#define	 PLL_CFG1_CKINSEL_SHIFT	26
#define	 PLL_CFG1_HV_IS_33	(1 << 27)
#define	 PLL_CFG1_LDO1_EN	(1 << 28)
#define	 PLL_CFG1_LDO2_EN	(1 << 29)
#define	 PLL_CFG1_OD		(1 << 30)
#define	 PLL_CFG1_OD1		(1 << 31)

#define	PLL_CFG2	0x30
#define	 PLL_CFG2_PREDIV_MASK	0xF
#define	 PLL_CFG2_S5_7		(1 << 4)
#define	 PLL_CFG2_S6P25_7P5	(1 << 5)
#define	 PLL_CFG2_S(x)		(x << 6)
#define	 PLL_CFG2_SDIV2		(1 << 9)
#define	 PLL_CFG2_SINT_FRAC	(1 << 10)
#define	 PLL_CFG2_VCO_RST_IN	(1 << 11)
#define	 PLL_CFG2_VCO_S(x)	(x << 12)
#define	 PLL_CFG2_VCOGAIN(x)	(x << 16)
#define	 PLL_CFG2_VCOGAIN_EN	(1 << 19)
#define	 PLL_CFG2_VREG1_OUT_EN	(1 << 20)
#define	 PLL_CFG2_VREG2_OUT_EN	(1 << 21)
#define	 PLL_CFG2_AUTOSYNC_DIS	(1 << 22)
#define	 PLL_CFG2_PCLK_SEL	(1 << 23)
#define	 PLL_CFG2_PSET(x)	(x << 24)
#define	 PLL_CFG2_CLKSTEP(x)	(x << 27)
#define	 PLL_CFG2_PDCLKSEL(x)	(x << 29)
#define	 PLL_CFG2_SV_H		(1 << 31)

#define	PLL_CFG3		0x34
#define	 PLL_CFG3_SOUT_DIV2	(1 << 0)

#define	ANA_STS	0x38
#define	 ANA_STS_RESDO2D_MASK	0x3F
#define	 ANA_STS_COUT2D		(1 << 6)
#define	 ANA_STS_RCALEND2D	(1 << 7)
#define	 ANA_STS_PHYRXSENSE	(1 << 8)
#define	 ANA_STS_LOCK_FLAG2	(1 << 9)
#define	 ANA_STS_LOCK_FLAG1	(1 << 10)
#define	 ANA_STS_B_OUT_MASK	0x1F800
#define	 ANA_STS_B_OUT_SHIFT	11
#define	 ANA_STS_ERROR_DET_SF	(1 << 17)
#define	 ANA_STS_ERROR_SF	(1 << 18)
#define	 ANA_STS_HPDO		(1 << 19)

#define	READ_EN		0x10
#define	 READ_EN_MAGIC	0x54524545

#define	UNSCRAMBLE	0x14
#define	 UNSCRAMBLE_MAGIC	0x42494E47

static struct ofw_compat_data compat_data[] = {
	{ "allwinner,sun50i-a64-hdmi-phy",	1 },
	{ "allwinner,sun8i-h3-hdmi-phy",	1 },
	{ NULL,					0 }
};

static struct resource_spec aw_de2_hdmi_phy_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ -1, 0 }
};

struct aw_de2_hdmi_phy_softc {
	device_t	dev;
	struct resource	*res[1];
	clk_t		clk_bus;
	clk_t		clk_mod;
	clk_t		clk_pll;
	hwreset_t	reset;

	uint32_t	rcal;
};

#define	AW_DE2_HDMI_PHY_READ_4(sc, reg)		bus_read_4((sc)->res[0], (reg))
#define	AW_DE2_HDMI_PHY_WRITE_4(sc, reg, val)	bus_write_4((sc)->res[0], (reg), (val))

static int aw_de2_hdmi_phy_probe(device_t dev);
static int aw_de2_hdmi_phy_attach(device_t dev);
static int aw_de2_hdmi_phy_detach(device_t dev);

static inline void
PHY_UPDATE_BITS(struct aw_de2_hdmi_phy_softc *sc, uint32_t reg, uint32_t mask, uint32_t val)
{
	uint32_t tmp;

	tmp = AW_DE2_HDMI_PHY_READ_4(sc, reg);
	tmp &= ~mask;
	tmp |= val;
	AW_DE2_HDMI_PHY_WRITE_4(sc, reg, tmp);
}

static inline void
aw_de2_hdmi_phy_dump_regs(struct aw_de2_hdmi_phy_softc *sc)
{

	DRM_DEBUG_DRIVER("%s: ANA_CFG1: %x\n", __func__,
	    AW_DE2_HDMI_PHY_READ_4(sc, ANA_CFG1));
	DRM_DEBUG_DRIVER("%s: ANA_CFG2: %x\n", __func__,
	    AW_DE2_HDMI_PHY_READ_4(sc, ANA_CFG2));
	DRM_DEBUG_DRIVER("%s: ANA_CFG3: %x\n", __func__,
	    AW_DE2_HDMI_PHY_READ_4(sc, ANA_CFG3));
	DRM_DEBUG_DRIVER("%s: PLL_CFG1: %x\n", __func__,
	    AW_DE2_HDMI_PHY_READ_4(sc, PLL_CFG1));
	DRM_DEBUG_DRIVER("%s: PLL_CFG2: %x\n", __func__,
	    AW_DE2_HDMI_PHY_READ_4(sc, PLL_CFG2));
	DRM_DEBUG_DRIVER("%s: PLL_CFG3: %x\n", __func__,
	    AW_DE2_HDMI_PHY_READ_4(sc, PLL_CFG3));
	DRM_DEBUG_DRIVER("%s: ANA_STS: %x\n", __func__,
	    AW_DE2_HDMI_PHY_READ_4(sc, ANA_STS));

}

static int
aw_de2_hdmi_phy_init(device_t dev)
{
	struct aw_de2_hdmi_phy_softc *sc;
	uint32_t reg;
	int timeout = 1000;

	sc = device_get_softc(dev);

	aw_de2_hdmi_phy_dump_regs(sc);

	AW_DE2_HDMI_PHY_WRITE_4(sc, ANA_CFG1, 0);
	PHY_UPDATE_BITS(sc, ANA_CFG1, ANA_CFG1_ENBI, ANA_CFG1_ENBI);
	DELAY(5);

	/* Enable TMDS clock and voltage reference module */
	PHY_UPDATE_BITS(sc, ANA_CFG1, ANA_CFG1_TMDSCLK_EN, ANA_CFG1_TMDSCLK_EN);
	PHY_UPDATE_BITS(sc, ANA_CFG1, ANA_CFG1_ENVBS, ANA_CFG1_ENVBS);
	DELAY(20);

	/* Enable LDO */
	PHY_UPDATE_BITS(sc, ANA_CFG1, ANA_CFG1_LDOEN, ANA_CFG1_LDOEN);
	DELAY(5);

	/* Enable clock */
	PHY_UPDATE_BITS(sc, ANA_CFG1, ANA_CFG1_CKEN, ANA_CFG1_CKEN);
	DELAY(100);

	/* Enable calibration */
	PHY_UPDATE_BITS(sc, ANA_CFG1, ANA_CFG1_ENCALOG, ANA_CFG1_ENCALOG);
	DELAY(100);
	PHY_UPDATE_BITS(sc, ANA_CFG1, ANA_CFG1_ENRCAL, ANA_CFG1_ENRCAL);

	/* TMDS lanes */
	PHY_UPDATE_BITS(sc, ANA_CFG1,
	  ANA_CFG1_ENP2S_TMDS0 |
	  ANA_CFG1_ENP2S_TMDS1 |
	  ANA_CFG1_ENP2S_TMDS2,
	  ANA_CFG1_ENP2S_TMDS0 |
	  ANA_CFG1_ENP2S_TMDS1 |
	  ANA_CFG1_ENP2S_TMDS2);

	DRM_DEBUG_DRIVER("Waiting calibration\n");
	if (__drm_debug & DRM_UT_DRIVER)
		aw_de2_hdmi_phy_dump_regs(sc);

	/* Wait for calibration to finish */
	while (timeout > 0) {
		reg = AW_DE2_HDMI_PHY_READ_4(sc, ANA_STS);
		if (reg & ANA_STS_RCALEND2D) {
			DRM_DEBUG_DRIVER("Calibration ok: %x\n", reg);
			break;
		}
		timeout--;
		DELAY(1000);
	}
	if (timeout == 0) {
		DRM_DEBUG_DRIVER("Calibration failed\n");
	}
	if (__drm_debug & DRM_UT_DRIVER)
		aw_de2_hdmi_phy_dump_regs(sc);

	PHY_UPDATE_BITS(sc, ANA_CFG1,
	  ANA_CFG1_BIASEN_TMDS0 |
	  ANA_CFG1_BIASEN_TMDS1 |
	  ANA_CFG1_BIASEN_TMDS2 |
	  ANA_CFG1_BIASEN_TMDSCLK,
	  ANA_CFG1_BIASEN_TMDS0 |
	  ANA_CFG1_BIASEN_TMDS1 |
	  ANA_CFG1_BIASEN_TMDS2 |
	  ANA_CFG1_BIASEN_TMDSCLK);

	PHY_UPDATE_BITS(sc, ANA_CFG1,
	  ANA_CFG1_ENP2S_TMDSCLK,
	  ANA_CFG1_ENP2S_TMDSCLK);

	AW_DE2_HDMI_PHY_WRITE_4(sc, PLL_CFG1, 0x39dc5040);
	AW_DE2_HDMI_PHY_WRITE_4(sc, PLL_CFG2, 0x80084342);
	DELAY(1000);
	AW_DE2_HDMI_PHY_WRITE_4(sc, PLL_CFG3, 1);

	PHY_UPDATE_BITS(sc, PLL_CFG1, PLL_CFG1_PLLEN, PLL_CFG1_PLLEN);
	DELAY(1000);

	if (__drm_debug & DRM_UT_DRIVER)
		aw_de2_hdmi_phy_dump_regs(sc);

	reg = (AW_DE2_HDMI_PHY_READ_4(sc, ANA_STS) & ANA_STS_B_OUT_MASK) >> ANA_STS_B_OUT_SHIFT;
	DRM_DEBUG_DRIVER("B_OUT: %x\n", reg);
	PHY_UPDATE_BITS(sc, PLL_CFG1, PLL_CFG1_OD | PLL_CFG1_OD1, PLL_CFG1_OD | PLL_CFG1_OD1);
	PHY_UPDATE_BITS(sc, PLL_CFG1, PLL_CFG1_B_IN(reg), PLL_CFG1_B_IN(reg));

	if (__drm_debug & DRM_UT_DRIVER)
		aw_de2_hdmi_phy_dump_regs(sc);

	/* Magic values from the datasheet for 297Mhz TMDS rate, will need to split those into known bits */
	DRM_DEBUG_DRIVER("Write ANA_CFG* values\n");
	AW_DE2_HDMI_PHY_WRITE_4(sc, ANA_CFG1, 0x01FFFF7F);
	AW_DE2_HDMI_PHY_WRITE_4(sc, ANA_CFG2, 0x8063B000);
	AW_DE2_HDMI_PHY_WRITE_4(sc, ANA_CFG3, 0x0F8246B5);

	/* Read calibration value */
	sc->rcal = AW_DE2_HDMI_PHY_READ_4(sc, ANA_STS) & ANA_STS_RESDO2D_MASK;

	if (__drm_debug & DRM_UT_DRIVER)
		aw_de2_hdmi_phy_dump_regs(sc);

	/* unscrambler the hdmi registers */
	AW_DE2_HDMI_PHY_WRITE_4(sc, READ_EN,
	    READ_EN_MAGIC);
	AW_DE2_HDMI_PHY_WRITE_4(sc, UNSCRAMBLE,
	    UNSCRAMBLE_MAGIC);

	return (0);
}

static int
aw_de2_hdmi_phy_get_prediv(struct aw_de2_hdmi_phy_softc *sc, uint64_t pixel_clock)
{
	uint64_t pll_freq;
	uint64_t cur, best;
	int m, best_m;

	clk_get_freq(sc->clk_pll, &pll_freq);

	cur = best = 0;
	for (m = 1; m < 16; m++) {
		cur = pll_freq / m;
		if (abs(pixel_clock - cur) < abs(pixel_clock - best)) {
			best = cur;
			best_m = m;
		}
	}

	return (best_m);
}

static int
aw_de2_hdmi_phy_config(device_t dev, struct drm_display_mode *mode)
{
	struct aw_de2_hdmi_phy_softc *sc;
	uint32_t ana_cfg1, ana_cfg2, ana_cfg3;
	uint32_t pll_cfg1, pll_cfg2;
	uint32_t reg;
	int pll2_prediv;

	sc = device_get_softc(dev);

	DRM_DEBUG_DRIVER("Pixel clock: %d\n", mode->crtc_clock);

	pll2_prediv = aw_de2_hdmi_phy_get_prediv(sc, mode->crtc_clock* 1000);
	DRM_DEBUG_DRIVER("Found a prediv of %d\n", pll2_prediv);
	if (__drm_debug & DRM_UT_DRIVER)
		aw_de2_hdmi_phy_dump_regs(sc);

	/* Some magic value are from the datasheet */

	/* Enable LDOs */
	pll_cfg1 = PLL_CFG1_LDO2_EN | PLL_CFG1_LDO1_EN;
	pll_cfg1 |= PLL_CFG1_LDO_VSET(7);

	/* Enable PLLDB */
	pll_cfg1 |= PLL_CFG1_PLLDBEN;

	/* CS ? */
	pll_cfg1 |= PLL_CFG1_CS | PLL_CFG1_CP_S(2);

	/* Unknown bit */
	pll_cfg1 |= PLL_CFG1_UNKNOWN;

	/* BWS ? */
	pll_cfg1 |= PLL_CFG1_BWS;

	pll_cfg2 = PLL_CFG2_SV_H | PLL_CFG2_VCOGAIN_EN | PLL_CFG2_SDIV2;

	ana_cfg1 = ANA_CFG1_SVBH(1) |
		ANA_CFG1_AMP_OPT |
		ANA_CFG1_EMP_OPT |
		ANA_CFG1_AMPCK_OPT |
		ANA_CFG1_EMPCK_OPT |
		ANA_CFG1_ENRCAL |
		ANA_CFG1_ENCALOG |
		ANA_CFG1_SCLKTMDS |
		ANA_CFG1_TMDSCLK_EN |
		ANA_CFG1_TXEN_ALL |
		ANA_CFG1_BIASEN_ALL |
		ANA_CFG1_ENP2S_TMDS2 |
		ANA_CFG1_ENP2S_TMDS1 |
		ANA_CFG1_ENP2S_TMDS0 |
		ANA_CFG1_CKEN |
		ANA_CFG1_LDOEN |
		ANA_CFG1_ENVBS |
		ANA_CFG1_ENBI;

	ana_cfg2 = ANA_CFG2_M_EN |
		ANA_CFG2_DENCK |
		ANA_CFG2_DEN |
		ANA_CFG2_CKSS(1) |
		ANA_CFG2_CSMPS(1);

	ana_cfg3 = ANA_CFG3_WIRE(0x3e0) |
		ANA_CFG3_SDAEN |
		ANA_CFG3_SCLEN;

	/* Pixel clock is in kHz */
	if (mode->crtc_clock <= 27000) {
		pll_cfg1 |= PLL_CFG1_HV_IS_33 |
			PLL_CFG1_CNT_INT(32);
		pll_cfg2 |= PLL_CFG2_VCO_S(4) |
			PLL_CFG2_S(4);
		ana_cfg1 |= ANA_CFG1_CALSW;
		ana_cfg2 |= ANA_CFG2_SLV(4) |
			ANA_CFG2_RESDI(sc->rcal >> 2);
		ana_cfg3 |= ANA_CFG3_AMPCK(3) |
			ANA_CFG3_AMP(5);
	} else if (mode->crtc_clock <= 74250) {
		pll_cfg1 |= PLL_CFG1_HV_IS_33 |
			PLL_CFG1_CNT_INT(32);
		pll_cfg2 |= PLL_CFG2_VCO_S(4) |
			PLL_CFG2_S(5);
		ana_cfg1 |= ANA_CFG1_CALSW;
		ana_cfg2 |= ANA_CFG2_SLV(4) |
			ANA_CFG2_RESDI(sc->rcal >> 2);
		ana_cfg3 |= ANA_CFG3_AMPCK(5) |
			ANA_CFG3_AMP(7);
	} else if (mode->crtc_clock <= 148500) {
		pll_cfg1 |= PLL_CFG1_HV_IS_33 |
			PLL_CFG1_CNT_INT(32);
		pll_cfg2 |= PLL_CFG2_VCO_S(4) |
			PLL_CFG2_S(6);
		ana_cfg2 |= ANA_CFG2_BIGSWCK |
			ANA_CFG2_BIGSW |
			ANA_CFG2_SLV(2);
		ana_cfg3 |= ANA_CFG3_AMPCK(7) |
			ANA_CFG3_AMP(9);
	} else {
		/* mode->crtc_clock <= 297000 */
		pll_cfg1 |= PLL_CFG1_CNT_INT(63);
		pll_cfg2 |= PLL_CFG2_VCO_S(6) |
			PLL_CFG2_S(7);
		ana_cfg2 |= ANA_CFG2_BIGSWCK |
			ANA_CFG2_BIGSW |
			ANA_CFG2_SLV(4);
		ana_cfg3 |= ANA_CFG3_AMPCK(9) |
			ANA_CFG3_AMP(13) |
			ANA_CFG3_EMP(3);
	}

	PHY_UPDATE_BITS(sc, ANA_CFG1, ANA_CFG1_TXEN_ALL, 0);

	/* We can only use pll-0 so select it */
	AW_DE2_HDMI_PHY_WRITE_4(sc, PLL_CFG1, pll_cfg1 & ~(1 << PLL_CFG1_CKINSEL_SHIFT));
	reg = AW_DE2_HDMI_PHY_READ_4(sc, PLL_CFG2);
	pll_cfg2 &= ~PLL_CFG2_PREDIV_MASK;
	pll_cfg2 |= (pll2_prediv - 1);
	AW_DE2_HDMI_PHY_WRITE_4(sc, PLL_CFG2, pll_cfg2);
	DELAY(1000);
	AW_DE2_HDMI_PHY_WRITE_4(sc, PLL_CFG3, PLL_CFG3_SOUT_DIV2);

	PHY_UPDATE_BITS(sc, PLL_CFG1, PLL_CFG1_PLLEN, PLL_CFG1_PLLEN);
	DELAY(100000);

	reg = (AW_DE2_HDMI_PHY_READ_4(sc, ANA_STS) & ANA_STS_B_OUT_MASK) >> ANA_STS_B_OUT_SHIFT;
	DRM_DEBUG_DRIVER("B_OUT: %x\n", reg);
	PHY_UPDATE_BITS(sc, PLL_CFG1, PLL_CFG1_OD | PLL_CFG1_OD1, PLL_CFG1_OD | PLL_CFG1_OD1);
	PHY_UPDATE_BITS(sc, PLL_CFG1, PLL_CFG1_B_IN(reg), PLL_CFG1_B_IN(reg));

	AW_DE2_HDMI_PHY_WRITE_4(sc, ANA_CFG1, ana_cfg1);
	AW_DE2_HDMI_PHY_WRITE_4(sc, ANA_CFG2, ana_cfg2);
	AW_DE2_HDMI_PHY_WRITE_4(sc, ANA_CFG3, ana_cfg3);

	if (__drm_debug & DRM_UT_DRIVER)
		aw_de2_hdmi_phy_dump_regs(sc);

	return (0);
}

static bool
aw_de2_hdmi_phy_detect_hpd(device_t dev)
{
	struct aw_de2_hdmi_phy_softc *sc;
	uint32_t reg;

	sc = device_get_softc(dev);

	reg = AW_DE2_HDMI_PHY_READ_4(sc, ANA_STS);
	DRM_DEBUG_DRIVER("%s: ANA_STS: %x\n", __func__, reg);

	return (reg & ANA_STS_HPDO);
}

static int
aw_de2_hdmi_phy_probe(device_t dev)
{
	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_search_compatible(dev, compat_data)->ocd_data == 0)
		return (ENXIO);

	device_set_desc(dev, "Allwinner SUN8I HDMI PHY");
	return (BUS_PROBE_DEFAULT);
}

static int
aw_de2_hdmi_phy_attach(device_t dev)
{
	struct aw_de2_hdmi_phy_softc *sc;
	phandle_t node;
	int error;

	sc = device_get_softc(dev);
	sc->dev = dev;
	node = ofw_bus_get_node(dev);

	if (bus_alloc_resources(dev, aw_de2_hdmi_phy_spec, sc->res) != 0) {
		device_printf(dev, "cannot allocate resources for device\n");
		error = ENXIO;
		goto fail;
	}

	if ((error = clk_get_by_ofw_name(dev, node, "bus", &sc->clk_bus)) != 0) {
		device_printf(dev, "Cannot get bus clock\n");
		goto fail;
	}
	if (clk_enable(sc->clk_bus) != 0) {
		device_printf(dev, "Cannot enable bus clock\n");
		goto fail;
	}
	if ((error = clk_get_by_ofw_name(dev, node, "mod", &sc->clk_mod)) != 0) {
		device_printf(dev, "Cannot get mod clock\n");
		goto fail;
	}
	if (clk_enable(sc->clk_mod) != 0) {
		device_printf(dev, "Cannot enable mod clock\n");
		goto fail;
	}
	if ((error = clk_get_by_ofw_name(dev, node, "pll-0", &sc->clk_pll)) != 0) {
		device_printf(dev, "Cannot get pll-0 clock\n");
		goto fail;
	}
	if (clk_enable(sc->clk_pll) != 0) {
		device_printf(dev, "Cannot enable pll-0 clock\n");
		goto fail;
	}
	if ((error = hwreset_get_by_ofw_name(dev, node, "phy", &sc->reset)) != 0) {
		device_printf(dev, "Cannot get reset\n");
		goto fail;
	}
	if (hwreset_deassert(sc->reset) != 0) {
		device_printf(dev, "Cannot deassert reset\n");
		goto fail;
	}

	/* Register ourself */
	OF_device_register_xref(OF_xref_from_node(node), dev);

	return (0);

fail:
	aw_de2_hdmi_phy_detach(dev);
	return (error);
}

static int
aw_de2_hdmi_phy_detach(device_t dev)
{
	struct aw_de2_hdmi_phy_softc *sc;
	sc = device_get_softc(dev);

	if (hwreset_assert(sc->reset) != 0)
		device_printf(dev, "Cannot assert reset\n");
	if (clk_disable(sc->clk_pll) != 0)
		device_printf(dev, "Cannot disable pll-0 clock\n");
	if (clk_disable(sc->clk_mod) != 0)
		device_printf(dev, "Cannot disable mod clock\n");
	if (clk_disable(sc->clk_bus) != 0)
		device_printf(dev, "Cannot disable bus clock\n");

	bus_release_resources(dev, aw_de2_hdmi_phy_spec, sc->res);

	return (0);
}

static device_method_t aw_de2_hdmi_phy_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		aw_de2_hdmi_phy_probe),
	DEVMETHOD(device_attach,	aw_de2_hdmi_phy_attach),
	DEVMETHOD(device_detach,	aw_de2_hdmi_phy_detach),

	/* DW HDMI Phy interface */
	DEVMETHOD(dw_hdmi_phy_init,	aw_de2_hdmi_phy_init),
	DEVMETHOD(dw_hdmi_phy_config,	aw_de2_hdmi_phy_config),
	DEVMETHOD(dw_hdmi_phy_detect_hpd,	aw_de2_hdmi_phy_detect_hpd),

	DEVMETHOD_END
};

static driver_t aw_de2_hdmi_phy_driver = {
	"aw_de2_hdmi_phy",
	aw_de2_hdmi_phy_methods,
	sizeof(struct aw_de2_hdmi_phy_softc),
};

static devclass_t aw_de2_hdmi_phy_devclass;

EARLY_DRIVER_MODULE(aw_de2_hdmi_phy, simplebus, aw_de2_hdmi_phy_driver,
  aw_de2_hdmi_phy_devclass, 0, 0, BUS_PASS_SUPPORTDEV + BUS_PASS_ORDER_FIRST);
MODULE_VERSION(aw_de2_hdmi_phy, 1);
