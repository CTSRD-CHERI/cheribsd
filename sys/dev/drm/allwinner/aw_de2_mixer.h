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

#ifndef _AW_DE2_MIXER_H_
#define	_AW_DE2_MIXER_H_

#include <dev/extres/clk/clk.h>
#include <dev/extres/hwreset/hwreset.h>

/* Global Control register */
#define	GBL_CTL			0x00
#define	 GBL_CTL_EN		(1 << 0)
#define	 GBL_CTL_FINISH_IRQ_EN	(1 << 4)
#define	 GBL_CTL_ERROR_IRQ_EN	(1 << 5)

#define	GBL_STS			0x04
#define	 GBL_STS_FINISH_IRQ	(1 << 0)
#define	 GBL_STS_ERROR_IRQ	(1 << 1)
#define	 GBL_STS_BUSY		(1 << 4)
#define	 GBL_STS_ERROR		(1 << 5)
#define	 GBL_STS_ODD_FIELD	(1 << 8)

#define	GBL_DBUFFER	0x08

#define	GBL_SIZE	0x0C
#define	 GBL_SIZE_HEIGHT(x)	(((x & 0xFFFF0000) >> 16) + 1)
#define	 GBL_SIZE_WIDTH(x)	((x & 0xFFFF) + 1)

/* Blender registers defines */
#define	BLD_BASE		0x1000
#define	BLD_PIPE_CTL		(BLD_BASE + 0x0)
#define	BLD_FILL_COLOR(pipe)	(BLD_BASE + pipe * 0x10 + 0x4)
#define	BLD_INSIZE(pipe)	(BLD_BASE + pipe * 0x10 + 0x8)
#define	BLD_COORD(pipe)		(BLD_BASE + pipe * 0x10 + 0xC)
#define	BLD_CH_ROUTING		(BLD_BASE + 0x80)
#define	BLD_OUTSIZE		(BLD_BASE + 0x8C)

#define	AW_DE2_MIXER_READ_4(sc, reg)		bus_read_4((sc)->res[0], (reg))
#define	AW_DE2_MIXER_WRITE_4(sc, reg, val)	bus_write_4((sc)->res[0], (reg), (val))

struct aw_de2_mixer_config {
	char			*name;
	size_t			vi_planes;
	size_t			ui_planes;
	int			dst_tcon;
};

struct aw_de2_mixer_plane {
	struct drm_plane		plane;
	struct aw_de2_mixer_softc	*sc;
	int				id;
};

struct aw_de2_mixer_softc {
	device_t			dev;
	struct resource			*res[1];
	struct aw_de2_mixer_config	*conf;

	clk_t				clk_bus;
	clk_t				clk_mod;
	hwreset_t			reset;

	struct aw_de2_mixer_plane	*vi_planes;
	struct aw_de2_mixer_plane	*ui_planes;

	device_t			tcon;
};

#endif /* _AW_DE2_MIXER_H_ */
