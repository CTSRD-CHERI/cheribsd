/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2021 Emmanuel Vadot <manu@FreeBSD.org>
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

#ifndef __DW_HDMI_H__
#define	__DW_HDMI_H__

struct dw_hdmi_softc {
	device_t	dev;
	device_t	phydev;		/* Optional */
	struct resource	*res[2];
	void *		intrhand;
	struct mtx	mtx;

	clk_t		clk_iahb;
	clk_t		clk_isfr;
	clk_t		clk_cec;

	device_t		iicbus;
	struct i2c_adapter	*ddc;
	uint8_t			i2cm_stat;
	uint8_t			i2cm_addr;

	uint32_t		reg_width;

	struct drm_encoder	encoder;
	struct drm_connector	connector;
	struct drm_bridge	bridge;
	struct drm_display_mode	mode;
};

int dw_hdmi_attach(device_t dev);
int dw_hdmi_detach(device_t dev);
void dw_hdmi_add_bridge(struct dw_hdmi_softc *sc);

DECLARE_CLASS(dw_hdmi_driver);

#endif /* __DW_HDMI_H__ */
