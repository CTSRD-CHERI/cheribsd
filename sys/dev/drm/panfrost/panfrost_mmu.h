/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020-2021 Ruslan Bukin <br@bsdpad.com>
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

#ifndef	_DEV_DRM_PANFROST_PANFROST_MMU_H_
#define	_DEV_DRM_PANFROST_PANFROST_MMU_H_

int panfrost_mmu_map(struct panfrost_softc *sc,
    struct panfrost_gem_mapping *mapping);
int panfrost_mmu_enable(struct panfrost_softc *sc, struct panfrost_mmu *mmu);
void panfrost_mmu_as_put(struct panfrost_softc *sc, struct panfrost_mmu *mmu);
uint32_t panfrost_mmu_as_get(struct panfrost_softc *sc,
    struct panfrost_mmu *mmu);
void panfrost_mmu_intr(void *arg);
int panfrost_mmu_init(struct panfrost_softc *sc);
void panfrost_mmu_unmap(struct panfrost_softc *sc,
    struct panfrost_gem_mapping *mapping);
void panfrost_mmu_reset(struct panfrost_softc *sc);
struct panfrost_mmu *panfrost_mmu_ctx_create(struct panfrost_softc *sc);
void panfrost_mmu_ctx_put(struct panfrost_mmu *mmu);
struct panfrost_mmu * panfrost_mmu_ctx_get(struct panfrost_mmu *mmu);

#endif /* !_DEV_DRM_PANFROST_PANFROST_MMU_H_ */
