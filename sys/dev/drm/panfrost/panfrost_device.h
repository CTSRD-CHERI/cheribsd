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

#ifndef	_DEV_DRM_PANFROST_PANFROST_DEVICE_H_
#define	_DEV_DRM_PANFROST_PANFROST_DEVICE_H_

#define	NUM_JOB_SLOTS	3

struct panfrost_mmu {
	struct pmap p;
	int as;		/* asid set */
	int as_count;	/* usage count */
	TAILQ_ENTRY(panfrost_mmu)	next;	/* entry in mmu_in_use list */
};

struct panfrost_file {
	struct		panfrost_softc *sc;
	struct		panfrost_mmu mmu;
	struct		drm_sched_entity sched_entity[NUM_JOB_SLOTS];
	struct		drm_mm mm;
	struct mtx	mm_lock;
};

int panfrost_device_init(struct panfrost_softc *);
int panfrost_device_reset(struct panfrost_softc *sc);
uint32_t panfrost_device_get_latest_flush_id(struct panfrost_softc *sc);
int panfrost_device_power_on(struct panfrost_softc *sc);

#endif /* !_DEV_DRM_PANFROST_PANFROST_DEVICE_H_ */
