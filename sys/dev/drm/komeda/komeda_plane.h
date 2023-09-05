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

#ifndef _DEV_DRM_KOMEDA_KOMEDA_PLANE_H_
#define	_DEV_DRM_KOMEDA_KOMEDA_PLANE_H_

struct komeda_drm_softc;
struct komeda_pipeline;

struct komeda_plane {
	struct drm_plane	plane;
	struct komeda_drm_softc	*sc;
	int id;
};

int komeda_plane_create(struct komeda_pipeline *pipeline,
    struct drm_device *drm);

void gcu_intr(struct komeda_drm_softc *sc);
void dou_intr(struct komeda_drm_softc *sc);
void lpu_intr(struct komeda_drm_softc *sc);
void cu_intr(struct komeda_drm_softc *sc);
void dou_configure(struct komeda_drm_softc *sc, struct drm_display_mode *m);
void dou_bs_timing_setup(struct komeda_drm_softc *sc, struct drm_display_mode *m);
void dou_bs_control(struct komeda_drm_softc *sc, bool enable);

void cu_configure(struct komeda_drm_softc *sc, struct drm_display_mode *m,
    struct drm_plane_state *state, int id);

#endif /* !_DEV_DRM_KOMEDA_KOMEDA_PLANE_H_ */
