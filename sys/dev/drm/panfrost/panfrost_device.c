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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/fbio.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/rman.h>
#include <sys/resource.h>
#include <machine/bus.h>
#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/pmap.h>

#include <dev/extres/clk/clk.h>

#include <drm/drm_gem.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_gem_framebuffer_helper.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_probe_helper.h>
#include <drm/drm_drv.h>
#include <drm/drm_file.h>
#include <drm/drm_ioctl.h>
#include <drm/drm_vblank.h>
#include <drm/gpu_scheduler.h>

#include "panfrost_drv.h"
#include "panfrost_device.h"
#include "panfrost_gem.h"
#include "panfrost_regs.h"
#include "panfrost_features.h"
#include "panfrost_issues.h"
#include "panfrost_mmu.h"
#include "panfrost_job.h"

int
panfrost_device_soft_reset(struct panfrost_softc *sc)
{
	uint32_t reg;
	int timeout;

	GPU_WRITE(sc, GPU_INT_MASK, 0);
	GPU_WRITE(sc, GPU_INT_CLEAR, GPU_IRQ_RESET_COMPLETED);
	GPU_WRITE(sc, GPU_CMD, GPU_CMD_SOFT_RESET);

	timeout = 100;

	do {
		reg = GPU_READ(sc, GPU_INT_RAWSTAT);
		if (reg & GPU_IRQ_RESET_COMPLETED)
			break;
	} while (timeout--);

	if (timeout <= 0)
		return (-1);

	return (0);
}

int
panfrost_device_reset(struct panfrost_softc *sc)
{
	int error;

	error = panfrost_device_soft_reset(sc);
	if (error != 0)
		return (error);

	GPU_WRITE(sc, GPU_CMD, GPU_CMD_CLEAN_CACHES);

	error = panfrost_device_power_on(sc);
	if (error != 0)
		return (error);

	panfrost_mmu_reset(sc);
	panfrost_job_enable_interrupts(sc);

	return (0);
}

int
panfrost_device_power_on(struct panfrost_softc *sc)
{
	uint32_t reg;
	int timeout;

	GPU_WRITE(sc, L2_PWRON_LO, sc->features.l2_present);

	timeout = 100;

	do {
		reg = GPU_READ(sc, L2_READY_LO);
		if (reg == sc->features.l2_present)
			break;
	} while (timeout--);

	if (timeout <= 0)
		return (-1);

	GPU_WRITE(sc, SHADER_PWRON_LO, sc->features.shader_present);

	timeout = 100;

	do {
		reg = GPU_READ(sc, SHADER_READY_LO);
		if (reg == sc->features.shader_present)
			break;
	} while (timeout--);

	if (timeout <= 0)
		return (-2);

	GPU_WRITE(sc, TILER_PWRON_LO, sc->features.tiler_present);

	timeout = 100;

	do {
		reg = GPU_READ(sc, TILER_READY_LO);
		if (reg == sc->features.tiler_present)
			break;
	} while (timeout--);

	if (timeout <= 0)
		return (-3);

	return (0);
}

struct panfrost_gpu_model {
	const char *name;
	uint32_t id;
	uint32_t revision;
	uint64_t features;
	uint64_t issues;
	uint64_t issues_rev;
};

#define	GPU_MOD(_name, _id)					\
{								\
	.name = __stringify(_name),				\
	.id = _id,						\
	.features = hw_features_##_name,			\
	.issues = hw_issues_##_name,				\
	.revision = 0,						\
	.issues_rev = 0,					\
}

#define	GPU_REV(_name, _id, _rev, _p, _s, _stat)		\
{								\
	.name = __stringify(_name),				\
	.id = _id,						\
	.features = hw_features_##_name,			\
	.issues = hw_issues_##_name,				\
	.revision = (_rev) << 12 | (_p) << 4 | (_s),		\
	.issues_rev = hw_issues_##_name##_r##_rev##p##_p##_stat,\
}

static const struct panfrost_gpu_model gpu_models[] = {
	GPU_MOD(t600, 0x600),
	GPU_REV(t600, 0x600, 0, 0, 1, _15dev0),

	GPU_MOD(t620, 0x620),
	GPU_REV(t620, 0x620, 0, 1, 0, ),
	GPU_REV(t620, 0x620, 1, 0, 0, ),

	GPU_MOD(t720, 0x720),

	GPU_MOD(t760, 0x750),
	GPU_REV(t760, 0x750, 0, 0, 0, ),
	GPU_REV(t760, 0x750, 0, 1, 0, ),
	GPU_REV(t760, 0x750, 0, 1, 0, _50rel0),
	GPU_REV(t760, 0x750, 0, 2, 0, ),
	GPU_REV(t760, 0x750, 0, 3, 0, ),

	GPU_MOD(t820, 0x820),
	GPU_MOD(t830, 0x830),
	GPU_MOD(t860, 0x860),
	GPU_MOD(t880, 0x880),

	GPU_MOD(g71, 0x6000),
	GPU_REV(g71, 0x6000, 0, 0, 1, _05dev0),

	GPU_MOD(g72, 0x6001),
	GPU_MOD(g51, 0x7000),
	GPU_MOD(g76, 0x7001),
	GPU_MOD(g52, 0x7002),

	GPU_MOD(g31, 0x7003),
	GPU_REV(g31, 0x7003, 1, 0, 0, ),
	{},
};

void
panfrost_device_init_features(struct panfrost_softc *sc)
{
	const struct panfrost_gpu_model *model;
	uint32_t major, minor, status;
	uint32_t reg;
	int num_js;
	int i;

	reg = GPU_READ(sc, GPU_ID);
	sc->features.revision = reg & 0xffff;
	sc->features.id = reg >> 16;
	sc->features.l2_features = GPU_READ(sc, GPU_L2_FEATURES);
	sc->features.core_features = GPU_READ(sc, GPU_CORE_FEATURES);
	sc->features.tiler_features = GPU_READ(sc, GPU_TILER_FEATURES);
	sc->features.mem_features = GPU_READ(sc, GPU_MEM_FEATURES);
	sc->features.mmu_features = GPU_READ(sc, GPU_MMU_FEATURES);
	sc->features.thread_features = GPU_READ(sc, GPU_THREAD_FEATURES);
	sc->features.thread_max_threads = GPU_READ(sc, GPU_THREAD_MAX_THREADS);
	sc->features.thread_max_workgroup_size =
	    GPU_READ(sc, GPU_THREAD_MAX_WORKGROUP_SIZE);
	sc->features.thread_max_barrier_size =
	    GPU_READ(sc, GPU_THREAD_MAX_BARRIER_SIZE);
	sc->features.coherency_features = GPU_READ(sc, GPU_COHERENCY_FEATURES);
	sc->features.afbc_features = GPU_READ(sc, GPU_AFBC_FEATURES);
	sc->features.as_present = GPU_READ(sc, GPU_AS_PRESENT);
	sc->features.js_present = GPU_READ(sc, GPU_JS_PRESENT);

	for (i = 0; i < 4; i++)
		sc->features.texture_features[i] =
		    GPU_READ(sc, GPU_TEXTURE_FEATURES(i));

	num_js = hweight32(sc->features.js_present);
	for (i = 0; i < num_js; i++)
		sc->features.js_features[i] = GPU_READ(sc, GPU_JS_FEATURES(i));

	device_printf(sc->dev, "GPU revision %x, id %x\n",
	    sc->features.revision, sc->features.id);

	sc->features.nr_core_groups = hweight64(sc->features.l2_present);
	sc->features.thread_tls_alloc = GPU_READ(sc, GPU_THREAD_TLS_ALLOC);

	sc->features.shader_present = GPU_READ(sc, GPU_SHADER_PRESENT_LO);
	sc->features.shader_present |=
	    (uint64_t)GPU_READ(sc, GPU_SHADER_PRESENT_HI) << 32;

	sc->features.tiler_present = GPU_READ(sc, GPU_TILER_PRESENT_LO);
	sc->features.tiler_present |=
	    (uint64_t)GPU_READ(sc, GPU_TILER_PRESENT_HI) << 32;

	sc->features.l2_present = GPU_READ(sc, GPU_L2_PRESENT_LO);
	sc->features.l2_present |=
	    (uint64_t)GPU_READ(sc, GPU_L2_PRESENT_HI) << 32;

	sc->features.stack_present = GPU_READ(sc, GPU_STACK_PRESENT_LO);
	sc->features.stack_present |=
	    (uint64_t)GPU_READ(sc, GPU_STACK_PRESENT_HI) << 32;

	/* Patch T60x ID so userspace is happy. */
	if (sc->features.id == 0x6956)
		sc->features.id = 0x0600;

	major = (sc->features.revision >> 12) & 0xf;
	minor = (sc->features.revision >> 4) & 0xff;
	status = sc->features.revision & 0xf;

	device_printf(sc->dev, "Mali %x, major %x, minor %x, status %x\n",
	    sc->features.id, major, minor, status);

	device_printf(sc->dev, "Features: L2 %x, Shader %x, Tiler %x, Mem %x,"
	    " MMU %x, AS %x, JS %x\n",
	    sc->features.l2_features,
	    sc->features.core_features,
	    sc->features.tiler_features,
	    sc->features.mem_features,
	    sc->features.mmu_features,
	    sc->features.as_present,
	    sc->features.js_present);

	for (i = 0; gpu_models[i].id; i++) {
		model = &gpu_models[i];
		if (sc->features.id == model->id) {
			sc->features.hw_features = model->features;
			sc->features.hw_issues = hw_issues_all | model->issues;
			if (sc->features.revision == model->revision) {
				sc->features.hw_issues |= model->issues_rev;
				break;
			}
		}
	}
}

void
panfrost_device_init_quirks(struct panfrost_softc *sc)
{
	uint32_t quirks;

	quirks = 0;

	if (panfrost_has_hw_issue(sc, HW_ISSUE_8443) ||
	    panfrost_has_hw_issue(sc, HW_ISSUE_11035))
		quirks |= SC_LS_PAUSEBUFFER_DISABLE;

	if (panfrost_has_hw_issue(sc, HW_ISSUE_10327))
		quirks |= SC_SDC_DISABLE_OQ_DISCARD;

	if (panfrost_has_hw_issue(sc, HW_ISSUE_10797))
		quirks |= SC_ENABLE_TEXGRD_FLAGS;

	if (!panfrost_has_hw_issue(sc, GPUCORE_1619)) {
		if (sc->features.id < 0x750)
			quirks |= SC_LS_ATTR_CHECK_DISABLE;
		else if (sc->features.id < 0x880)
			quirks |= SC_LS_ALLOW_ATTR_TYPES;
	}

	if (panfrost_has_hw_feature(sc, HW_FEATURE_TLS_HASHING))
		quirks |= SC_TLS_HASH_ENABLE;

	if (quirks)
		GPU_WRITE(sc, GPU_SHADER_CONFIG, quirks);

	quirks = GPU_READ(sc, GPU_TILER_CONFIG);
	if (panfrost_has_hw_issue(sc, HW_ISSUE_T76X_3953))
		quirks |= TC_CLOCK_GATE_OVERRIDE;
	GPU_WRITE(sc, GPU_TILER_CONFIG, quirks);

	quirks = GPU_READ(sc, GPU_L2_MMU_CONFIG);
	if (panfrost_has_hw_feature(sc, HW_FEATURE_3BIT_EXT_RW_L2_MMU_CONFIG))
		quirks &= ~(L2_MMU_CONFIG_3BIT_LIMIT_EXTERNAL_READS |
		    L2_MMU_CONFIG_3BIT_LIMIT_EXTERNAL_WRITES);
	else
		quirks &= ~(L2_MMU_CONFIG_LIMIT_EXTERNAL_READS |
		    L2_MMU_CONFIG_LIMIT_EXTERNAL_WRITES);
	GPU_WRITE(sc, GPU_L2_MMU_CONFIG, quirks);

	quirks = 0;
	if ((sc->features.id == 0x860 || sc->features.id == 0x880) &&
	    sc->features.revision >= 0x2000)
		quirks |= JM_MAX_JOB_THROTTLE_LIMIT <<
		    JM_JOB_THROTTLE_LIMIT_SHIFT;

	else if (sc->features.id == 0x6000 &&
	    sc->features.coherency_features == COHERENCY_ACE)
		quirks |= (COHERENCY_ACE_LITE | COHERENCY_ACE) <<
		    JM_FORCE_COHERENCY_FEATURES_SHIFT;

	if (quirks)
		GPU_WRITE(sc, GPU_JM_CONFIG, quirks);

	/* Put here any platform specific quirks if needed. */
}

int
panfrost_device_init(struct panfrost_softc *sc)
{
	int error;

	error = panfrost_device_soft_reset(sc);
	if (error != 0)
		return (error);

	GPU_WRITE(sc, GPU_INT_MASK, GPU_IRQ_MASK_ALL);
	GPU_WRITE(sc, GPU_INT_CLEAR, GPU_IRQ_MASK_ALL);

	panfrost_device_init_features(sc);
	panfrost_device_init_quirks(sc);

	/* Disable perfc */
	GPU_WRITE(sc, GPU_PERFCNT_CFG,
	    GPU_PERFCNT_CFG_MODE(GPU_PERFCNT_CFG_MODE_OFF));
	GPU_WRITE(sc, GPU_PRFCNT_JM_EN, 0);
	GPU_WRITE(sc, GPU_PRFCNT_SHADER_EN, 0);
	GPU_WRITE(sc, GPU_PRFCNT_MMU_L2_EN, 0);
	GPU_WRITE(sc, GPU_PRFCNT_TILER_EN, 0);

	error = panfrost_device_power_on(sc);
	if (error != 0)
		return (error);

	panfrost_mmu_reset(sc);

	device_printf(sc->dev, "GPU is powered on\n");

	GPU_WRITE(sc, GPU_CMD, GPU_CMD_CLEAN_CACHES);

	return (0);
}

uint32_t
panfrost_device_get_latest_flush_id(struct panfrost_softc *sc)
{
	uint32_t flush_id;

	flush_id = 0;

	if (panfrost_has_hw_feature(sc, HW_FEATURE_FLUSH_REDUCTION))
		flush_id = GPU_READ(sc, GPU_LATEST_FLUSH_ID);

	return (flush_id);
}
