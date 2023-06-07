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

#ifndef	_DEV_DRM_PANFROST_PANFROST_DRV_H_
#define	_DEV_DRM_PANFROST_PANFROST_DRV_H_

MALLOC_DECLARE(M_PANFROST); /* lots of leak */
MALLOC_DECLARE(M_PANFROST1); /* no leak */
MALLOC_DECLARE(M_PANFROST2); /* no leak */
MALLOC_DECLARE(M_PANFROST3); /* done fence leak */
MALLOC_DECLARE(M_PANFROST4); /* contig */

struct panfrost_features {
	uint16_t		revision;
	uint16_t		id;
	uint32_t		l2_features;
	uint32_t		core_features;
	uint32_t		tiler_features;
	uint32_t		mem_features;
	uint32_t		mmu_features;
	uint32_t		thread_features;
	uint32_t		thread_max_threads;
	uint32_t		thread_max_workgroup_size;
	uint32_t		thread_max_barrier_size;
	uint32_t		coherency_features;
	uint32_t		afbc_features;
	uint32_t		texture_features[4];
	uint32_t		js_features[16];

	uint32_t		as_present;
	uint32_t		js_present;
	uint64_t		shader_present;
	uint64_t		tiler_present;
	uint64_t		l2_present;
	uint64_t		stack_present;

	uint32_t		nr_core_groups;
	uint32_t		thread_tls_alloc;

	uint64_t		hw_features;
	uint64_t		hw_issues;
};

struct panfrost_job;

struct panfrost_softc {
	device_t		dev;
	struct drm_device	drm_dev;
	struct resource		*res[4];
	void			*intrhand[4];
	struct panfrost_features features;
	clk_t			clk;

	uint64_t		as_alloc_set;
	struct mtx		as_mtx;

	TAILQ_HEAD(, panfrost_mmu)	mmu_in_use;
	struct mtx			mmu_lock;

	struct panfrost_job		*jobs[3];
	int job_count;
	struct panfrost_job_slot *js;
	struct mtx			sched_lock;
	int job_cnt;
	struct task			reset_work;
	int				reset_pending;
};

#define	PAN_DEBUG
#undef	PAN_DEBUG

#ifdef	PAN_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

#define	GPU_READ(sc, reg)	bus_read_4((sc)->res[0], (reg))
#define	GPU_WRITE(sc, reg, val)	bus_write_4((sc)->res[0], (reg), (val))

#endif /* !_DEV_DRM_PANFROST_PANFROST_DRV_H_ */
