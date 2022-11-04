/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2022 Ruslan Bukin <br@bsdpad.com>
 *
 * This work was supported by Innovate UK project 105694, "Digital Security
 * by Design (DSbD) Technology Platform Prototype".
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

#ifndef	_DEV_DRM_KOMEDA_KOMEDA_DRV_H_
#define	_DEV_DRM_KOMEDA_KOMEDA_DRV_H_

MALLOC_DECLARE(M_KOMEDA);

#define	KOMEDA_MAX_PIPELINES	2	/* Mali D71 limitation */

struct komeda_drm_softc {
	device_t		dev;
	struct drm_device	drm_dev;
	struct drm_fb_cma	*fb;
	struct komeda_pipeline	pipelines[KOMEDA_MAX_PIPELINES];
	struct resource		*res[2];
	void			*intrhand;

	uint32_t max_line_size;
	uint32_t max_num_lines;
	uint32_t num_rich_layers;
	uint32_t dual_link_supp;
	uint32_t tbu_en;
};

#define	KOMEDA_DEBUG
#undef	KOMEDA_DEBUG

#ifdef	KOMEDA_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

#define	DPU_RD4(sc, reg)	bus_read_4((sc)->res[0], (reg))
#define	DPU_WR4(sc, reg, val)	bus_write_4((sc)->res[0], (reg), (val))

#define	DPU_RD8(sc, reg)	bus_read_8((sc)->res[0], (reg))
#define	DPU_WR8(sc, reg, val)	bus_write_8((sc)->res[0], (reg), (val))

#endif /* !_DEV_DRM_KOMEDA_KOMEDA_DRV_H_ */
