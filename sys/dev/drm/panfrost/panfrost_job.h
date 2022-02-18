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

#ifndef	_DEV_DRM_PANFROST_PANFROST_JOB_H_
#define	_DEV_DRM_PANFROST_PANFROST_JOB_H_

struct panfrost_job {
	struct drm_sched_job base;	/* must go first */
	struct panfrost_softc *sc;
	struct panfrost_file *pfile;
	uint64_t jc;
	uint32_t requirements;
	uint32_t flush_id;

	struct dma_fence **in_fences;
	uint32_t in_fence_count;

	struct dma_fence *done_fence;

	struct dma_fence **implicit_fences;
	struct panfrost_gem_mapping **mappings;
	struct drm_gem_object **bos;
	uint32_t bo_count;

	struct dma_fence *render_done_fence;
	int slot;
	TAILQ_ENTRY(panfrost_job)	next;

	struct dma_fence		finished;
	u_int				refcount;
};

int panfrost_job_open(struct panfrost_file *pfile);
int panfrost_job_push(struct panfrost_job *job);
int panfrost_job_init(struct panfrost_softc *sc);
void panfrost_job_intr(void *arg);
void panfrost_job_put(struct panfrost_job *job);
void panfrost_job_close(struct panfrost_file *pfile);
void panfrost_job_enable_interrupts(struct panfrost_softc *sc);

#endif /* !_DEV_DRM_PANFROST_PANFROST_JOB_H_ */
