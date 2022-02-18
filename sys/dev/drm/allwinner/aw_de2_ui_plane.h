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

#ifndef _AW_DE2_UI_PLANE_H_
#define	_AW_DE2_UI_PLANE_H_

/* Overlay registers defines */
#define	OVL_UI_BASE	0x3000
#define	OVL_UI_CHANNEL_SIZE	0x1000

#define	OVL_UI_CH_BASE(channel)	(OVL_UI_BASE + (channel * OVL_UI_CHANNEL_SIZE))

#define	OVL_UI_ATTR_CTL(channel)	(OVL_UI_CH_BASE(channel))
#define	 OVL_UI_ATTR_EN			(1 << 0)
#define	 OVL_UI_ATTR_ALPHA_MASK		0x6
#define	 OVL_UI_ATTR_ALPHA_SHIFT	1
#define	 OVL_UI_ATTR_ALPHA_EN		2
#define	 OVL_UI_ATTR_ALPHA_MIX		3
#define	 OVL_UI_ATTR_FILLCOLOR_EN	(1 << 4)
#define	 OVL_UI_PIX_FORMAT_MASK		0x1F00
#define	 OVL_UI_PIX_FORMAT_SHIFT	8

#define	OVL_UI_MBSIZE(channel)	(OVL_UI_CH_BASE(channel) + 0x04)
#define	 OVL_UI_MBSIZE_WIDTH_MASK	0x1FFF
#define	 OVL_UI_MBSIZE_WIDTH_SHIFT	0
#define	 OVL_UI_MBSIZE_HEIGHT_MASK	0x1FFF0000
#define	 OVL_UI_MBSIZE_HEIGHT_SHIFT	16

#define	OVL_UI_COORD(channel)		(OVL_UI_CH_BASE(channel) + 0x08)
#define	 OVL_UI_COOR_X_MASK	0xFFFF
#define	 OVL_UI_COOR_X_SHIFT	0
#define	 OVL_UI_COOR_Y_MASK	0xFFFF0000
#define	 OVL_UI_COOR_Y_SHIFT	16

#define	OVL_UI_PITCH(channel)		(OVL_UI_CH_BASE(channel) + 0x0C)
#define	OVL_UI_TOP_LADD(channel)	(OVL_UI_CH_BASE(channel) + 0x10)
#define	OVL_UI_BOT_LADD(channel)	(OVL_UI_CH_BASE(channel) + 0x14)
#define	OVL_UI_FILL_COLOR(channel)	(OVL_UI_CH_BASE(channel) + 0x18)
#define	OVL_UI_TOP_HADD(channel)	(OVL_UI_CH_BASE(channel) + 0x80)
#define	OVL_UI_BOT_HADD(channel)	(OVL_UI_CH_BASE(channel) + 0x84)

#define	OVL_UI_SIZE(channel)		(OVL_UI_CH_BASE(channel) + 0x88)
#define	 OVL_UI_SIZE_WIDTH_MASK		0x1FFF
#define	 OVL_UI_SIZE_WIDTH_SHIFT	0
#define	 OVL_UI_SIZE_HEIGHT_MASK	0x1FFF0000
#define	 OVL_UI_SIZE_HEIGHT_SHIFT	16

int aw_de2_ui_plane_create(struct aw_de2_mixer_softc *sc, struct drm_device *drm);

#endif /* _AW_DE2_UI_PLANE_H_ */
