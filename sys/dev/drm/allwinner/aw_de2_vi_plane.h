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

#ifndef _AW_DE2_VI_PLANE_H_
#define	_AW_DE2_VI_PLANE_H_

/* Overlay registers defines */
#define	OVL_VI_BASE	0x2000

#define	OVL_VI_ATTR_CTL			OVL_VI_BASE
#define	 OVL_VI_ATTR_EN			(1 << 0)
#define	 OVL_VI_PIX_FORMAT_MASK		0x1F00
#define	 OVL_VI_PIX_FORMAT_SHIFT	8
#define	 OVL_VI_PIX_FORMAT_SEL		(1 << 15)

#define	OVL_VI_MBSIZE			(OVL_VI_BASE + 0x04)
#define	 OVL_VI_MBSIZE_WIDTH_MASK	0x1FFF
#define	 OVL_VI_MBSIZE_WIDTH_SHIFT	0
#define	 OVL_VI_MBSIZE_HEIGHT_MASK	0x1FFF0000
#define	 OVL_VI_MBSIZE_HEIGHT_SHIFT	16

#define	OVL_VI_COORD		(OVL_VI_BASE + 0x08)
#define	 OVL_VI_COORD_X_MASK	0xFFFF
#define	 OVL_VI_COORD_X_SHIFT	0
#define	 OVL_VI_COORD_Y_MASK	0xFFFF0000
#define	 OVL_VI_COORD_Y_SHIFT	16

#define	OVL_VI_Y_PITCH(x)	(OVL_VI_BASE + 0x0C + (x * 0x4))
#define	OVL_VI_TOP_Y_LADD(x)	(OVL_VI_BASE + 0x18 + (x * 0x4))

#define	OVL_VI_SIZE			(OVL_VI_BASE + 0xE8)
#define	 OVL_VI_SIZE_WIDTH_MASK		0x1FFF
#define	 OVL_VI_SIZE_WIDTH_SHIFT	0
#define	 OVL_VI_SIZE_HEIGHT_MASK	0x1FFF0000
#define	 OVL_VI_SIZE_HEIGHT_SHIFT	16

#define	OVL_VI_FORMAT_YUV422	0x6
#define	OVL_VI_FORMAT_YUV420	0x9
#define	OVL_VI_FORMAT_YUV411	0xe

int aw_de2_vi_plane_create(struct aw_de2_mixer_softc *sc, struct drm_device *drm);

#endif /* _AW_DE2_VI_PLANE_H_ */
