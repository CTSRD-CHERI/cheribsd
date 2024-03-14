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
 */

#ifdef COMPAT_FREEBSD64
#include <sys/abi_compat.h>
#endif
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/fbio.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/rman.h>
#include <sys/resource.h>
#include <sys/sysent.h>
#include <machine/bus.h>
#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/pmap.h>

#include <dev/fdt/simplebus.h>

#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <dev/clk/clk.h>

#include <drm/drm_gem.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_gem_framebuffer_helper.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_probe_helper.h>
#include <drm/drm_drv.h>
#include <drm/drm_file.h>
#include <drm/drm_ioctl.h>
#include <drm/drm_vblank.h>
#include <drm/drm_syncobj.h>
#include <drm/drm_utils.h>
#include <drm/gpu_scheduler.h>

#include "panfrost_drm.h"
#include "panfrost_drv.h"
#include "panfrost_device.h"
#include "panfrost_regs.h"
#include "panfrost_gem.h"
#include "panfrost_mmu.h"
#include "panfrost_job.h"

MALLOC_DEFINE(M_PANFROST, "panfrost", "Panfrost driver");
MALLOC_DEFINE(M_PANFROST1, "panfrost1", "Panfrost 1 driver");
MALLOC_DEFINE(M_PANFROST2, "panfrost2", "Panfrost 2 driver");
MALLOC_DEFINE(M_PANFROST3, "panfrost3", "Panfrost 3 driver");
MALLOC_DEFINE(M_PANFROST4, "panfrost4", "Panfrost 4 driver");

static struct resource_spec mali_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ SYS_RES_IRQ,		0,	RF_ACTIVE | RF_SHAREABLE },
	{ SYS_RES_IRQ,		1,	RF_ACTIVE | RF_SHAREABLE },
	{ SYS_RES_IRQ,		2,	RF_ACTIVE | RF_SHAREABLE },
	{ -1, 0 }
};

static struct ofw_compat_data compat_data[] = {
	{ "arm,mali-t604",	1 },
	{ "arm,mali-t624",	1 },
	{ "arm,mali-t628",	1 },
	{ "arm,mali-t720",	1 },
	{ "arm,mali-t760",	1 },
	{ "arm,mali-t820",	1 },
	{ "arm,mali-t830",	1 },
	{ "arm,mali-t860",	1 },
	{ "arm,mali-t880",	1 },
	{ "arm,mali-bifrost",	1 },
	{ NULL,			0 }
};

static const struct file_operations panfrost_drm_driver_fops = {
	.owner		= THIS_MODULE,
	.open		= drm_open,
	.release	= drm_release,
	.unlocked_ioctl	= drm_ioctl,
	.compat_ioctl	= drm_compat_ioctl,
	.poll		= drm_poll,
	.read		= drm_read,
	.kqfilter	= drm_kqfilter,
	/*.llseek	= noop_llseek,*/
	.mmap		= drm_gem_mmap,
};

static int
panfrost_open(struct drm_device *dev, struct drm_file *file)
{
	struct panfrost_file *pfile;
	struct panfrost_softc *sc;
	int error;

	dprintf("%s\n", __func__);

	sc = dev->dev_private;

	pfile = malloc(sizeof(*pfile), M_PANFROST, M_WAITOK | M_ZERO);
	pfile->sc = sc;
	file->driver_priv = pfile;

	pfile->mmu = panfrost_mmu_ctx_create(sc);
	if (pfile->mmu == NULL) {
		device_printf(sc->dev, "%s: can't create mmu context\n",
		    __func__);
		free(pfile, M_PANFROST);
		return (-ENXIO);
	}

	error = panfrost_job_open(pfile);
	if (error != 0) {
		device_printf(sc->dev, "%s: can't open job\n", __func__);
		return (error);
	}

	return (0);
}

static void
panfrost_postclose(struct drm_device *dev, struct drm_file *file)
{
	struct panfrost_file *pfile;

	dprintf("%s\n", __func__);

	pfile = file->driver_priv;

	panfrost_job_close(pfile);
	panfrost_mmu_ctx_put(pfile->mmu);

	free(pfile, M_PANFROST);
}

static int
panfrost_copy_in_fences(struct drm_device *dev, struct drm_file *file_priv,
    struct drm_panfrost_submit *args, struct panfrost_job *job)
{
	uint32_t *handles;
	int error;
	int sz;
	int i;

	job->in_fence_count = args->in_sync_count;
	if (job->in_fence_count == 0)
		return (0);

	dprintf("%s: fence count %d\n", __func__, job->in_fence_count);

	sz = job->in_fence_count * sizeof(struct dma_fence *);
	job->in_fences = malloc(sz, M_PANFROST1, M_WAITOK | M_ZERO);

	sz = job->in_fence_count * sizeof(uint32_t);
	handles = malloc(sz, M_PANFROST1, M_WAITOK | M_ZERO);

	error = copyin((void * __capability)args->in_syncs, handles, sz);
	if (error) {
		free(job->in_fences, M_PANFROST1);
		goto done;
	}

	for (i = 0; i < job->in_fence_count; i++) {
		error = drm_syncobj_find_fence(file_priv, handles[i], 0, 0,
		    &job->in_fences[i]);
		if (error) {
			free(job->in_fences, M_PANFROST1);
			goto done;
		}
	}

done:
	free(handles, M_PANFROST1);
	return (error);
}

static int
panfrost_lookup_bos(struct drm_device *dev, struct drm_file *file_priv,
    struct drm_panfrost_submit *args, struct panfrost_job *job)
{
	struct panfrost_file *pfile;
	struct panfrost_gem_object *bo;
	struct panfrost_gem_mapping *mapping;
	int error;
	int i;
	int sz;

	pfile = file_priv->driver_priv;

	job->bo_count = args->bo_handle_count;
	if (job->bo_count == 0)
		return (0);

	sz = job->bo_count * sizeof(struct dma_fence *);
	job->implicit_fences = malloc(sz, M_PANFROST1, M_WAITOK | M_ZERO);

	error = drm_gem_objects_lookup(file_priv,
	    (void __user * __capability)args->bo_handles, job->bo_count,
	    &job->bos);
	if (error) {
		free(job->implicit_fences, M_PANFROST1);
		return (error);
	}

	sz = job->bo_count * sizeof(struct panfrost_gem_mapping *);
	job->mappings = malloc(sz, M_PANFROST1, M_WAITOK | M_ZERO);

	for (i = 0; i < job->bo_count; i++) {
		bo = (struct panfrost_gem_object *)job->bos[i];
		mapping = panfrost_gem_mapping_get(bo, pfile);
		if (mapping == NULL) {
			error = EINVAL;
			break;
		}
		atomic_add_int(&bo->gpu_usecount, 1);
		job->mappings[i] = mapping;
	}

	return (error);
}

static int
panfrost_ioctl_submit(struct drm_device *dev, void *data,
    struct drm_file *file)
{
	struct panfrost_file *pfile;
	struct panfrost_softc *sc;
#ifdef COMPAT_FREEBSD64
	struct drm_panfrost_submit64 *args64;
	struct drm_panfrost_submit local_args;
	int sz;
#endif
	struct drm_panfrost_submit *args;
	struct panfrost_job *job;
	struct drm_syncobj *sync_out;
	struct drm_sched_entity *entity;
	int error;
	int slot;

	sc = dev->dev_private;

	args = data;

#ifdef COMPAT_FREEBSD64
	if (!SV_CURPROC_FLAG(SV_CHERI)) {
		args64 = (struct drm_panfrost_submit64 *)data;
		args = &local_args;
		CP(*args64, *args, jc);
		CP(*args64, *args, in_sync_count);
		CP(*args64, *args, out_sync);
		CP(*args64, *args, bo_handle_count);
		CP(*args64, *args, requirements);

		sz = args64->in_sync_count * sizeof(uint32_t);
		args->in_syncs = (uintcap_t)__USER_CAP(args64->in_syncs, sz);

		sz = args64->bo_handle_count * sizeof(uint32_t);
		args->bo_handles = (uintcap_t)__USER_CAP(args64->bo_handles,sz);
	}
#endif

	sync_out = NULL;

	dprintf("%s: jc %x\n", __func__, args->jc);

	if (args->jc == 0)
		return (-EINVAL);

	if (args->requirements && args->requirements != PANFROST_JD_REQ_FS)
		return (-EINVAL);

	if (args->out_sync > 0) {
		sync_out = drm_syncobj_find(file, args->out_sync);
		if (sync_out == NULL) {
			dprintf("sync out is NULL\n");
			return (-ENODEV);
		}
	}

	pfile = file->driver_priv;

	job = malloc(sizeof(*job), M_PANFROST1, M_WAITOK | M_ZERO);
	job->sc = sc;
	job->jc = args->jc;
	job->requirements = args->requirements;
	job->flush_id = panfrost_device_get_latest_flush_id(sc);
	job->mmu = pfile->mmu;

	refcount_init(&job->refcount, 1);

	slot = panfrost_job_get_slot(job);

	job->slot = slot;

	entity = &pfile->sched_entity[slot];

	error = drm_sched_job_init(&job->base, entity, NULL);
	if (error)
		return (-EINVAL);

	error = panfrost_copy_in_fences(dev, file, args, job);
	if (error)
		return (-EINVAL);

	error = panfrost_lookup_bos(dev, file, args, job);
	if (error)
		return (-EINVAL);

	error = panfrost_job_push(job);
	if (error)
		return (-EINVAL);

	if (sync_out)
		drm_syncobj_replace_fence(sync_out, job->render_done_fence);

	panfrost_job_put(job);

	if (sync_out)
		drm_syncobj_put(sync_out);

	return (0);
}

static int
panfrost_ioctl_wait_bo(struct drm_device *dev, void *data,
    struct drm_file *file_priv)
{
	struct drm_panfrost_wait_bo *args;
	struct drm_gem_object *gem_obj;
	unsigned long timeout;
	int error;

	args = data;
	if (args->pad)
		return (-EINVAL);

	timeout = drm_timeout_abs_to_jiffies(args->timeout_ns);

	gem_obj = drm_gem_object_lookup(file_priv, args->handle);
	if (!gem_obj)
		return (-ENOENT);

	error = reservation_object_wait_timeout_rcu(gem_obj->resv, true,
	    true, timeout);
	/*
	 * error == 0 means not signaled,
	 * error > 0 means signaled
	 * error < 0 means interrupted before timeout
	 */

	if (error == 0)
		error = timeout ? -ETIMEDOUT : -EBUSY;
	else if (error > 0)
		error = 0;

	mutex_lock(&dev->struct_mutex);
	drm_gem_object_put(gem_obj);
	mutex_unlock(&dev->struct_mutex);

	return (error);
}

static int
panfrost_ioctl_create_bo(struct drm_device *dev, void *data,
    struct drm_file *file)
{
	struct panfrost_gem_mapping *mapping;
	struct drm_panfrost_create_bo *args;
	struct panfrost_gem_object *bo;
	struct panfrost_softc *sc;

	args = data;

	sc = dev->dev_private;

	dprintf("%s: size %d flags %d handle %d pad %d offset %jd\n",
	    __func__, args->size, args->flags, args->handle, args->pad,
	    args->offset);

	bo = panfrost_gem_create_object_with_handle(file, dev, args->size,
	    args->flags, &args->handle);
	if (bo == NULL) {
		device_printf(sc->dev, "%s: Failed to create object\n",
		    __func__);
		return (-EINVAL);
	}

	mapping = panfrost_gem_mapping_get(bo, file->driver_priv);
	if (mapping == NULL) {
		mutex_lock(&dev->struct_mutex);
		drm_gem_object_put(&bo->base);
		mutex_unlock(&dev->struct_mutex);
		return (-EINVAL);
	}

	args->offset = mapping->mmnode.start << PAGE_SHIFT;
	panfrost_gem_mapping_put(mapping);

	return (0);
}

static int
panfrost_ioctl_mmap_bo(struct drm_device *dev, void *data,
    struct drm_file *file)
{
	struct drm_panfrost_mmap_bo *args;
	struct drm_gem_object *obj;
	int error;

	args = data;

	if (args->flags != 0)
		return (-EINVAL);

	obj = drm_gem_object_lookup(file, args->handle);
	if (obj == NULL)
		return (-EINVAL);

	error = drm_gem_create_mmap_offset(obj);
	if (error == 0)
		args->offset = drm_vma_node_offset_addr(&obj->vma_node);

	dprintf("%s: error %d args->offset %lx\n", __func__, error,
	    args->offset);

	mutex_lock(&dev->struct_mutex);
	drm_gem_object_put(obj);
	mutex_unlock(&dev->struct_mutex);

	return (error);
}

static int
panfrost_ioctl_get_param(struct drm_device *ddev, void *data,
    struct drm_file *file)
{
	struct drm_panfrost_get_param *param;
	struct panfrost_softc *sc;

	sc = ddev->dev_private;
	param = data;

	if (param->pad != 0)
		return (-EINVAL);

	dprintf("%s: param %d\n", __func__, param->param);

	switch (param->param) {
	case DRM_PANFROST_PARAM_GPU_PROD_ID:
		param->value = sc->features.id;
		break;
	case DRM_PANFROST_PARAM_GPU_REVISION:
		param->value = sc->features.revision;
		break;
	case DRM_PANFROST_PARAM_SHADER_PRESENT:
		param->value = sc->features.shader_present;
		break;
	case DRM_PANFROST_PARAM_TILER_PRESENT:
		param->value = sc->features.tiler_present;
		break;
	case DRM_PANFROST_PARAM_L2_PRESENT:
		param->value = sc->features.l2_present;
		break;
	case DRM_PANFROST_PARAM_STACK_PRESENT:
		param->value = sc->features.stack_present;
		break;
	case DRM_PANFROST_PARAM_AS_PRESENT:
		param->value = sc->features.as_present;
		break;
	case DRM_PANFROST_PARAM_JS_PRESENT:
		param->value = sc->features.js_present;
		break;
	case DRM_PANFROST_PARAM_L2_FEATURES:
		param->value = sc->features.l2_features;
		break;
	case DRM_PANFROST_PARAM_CORE_FEATURES:
		param->value = sc->features.core_features;
		break;
	case DRM_PANFROST_PARAM_TILER_FEATURES:
		param->value = sc->features.tiler_features;
		break;
	case DRM_PANFROST_PARAM_MEM_FEATURES:
		param->value = sc->features.mem_features;
		break;
	case DRM_PANFROST_PARAM_MMU_FEATURES:
		param->value = sc->features.mmu_features;
		break;
	case DRM_PANFROST_PARAM_THREAD_FEATURES:
		param->value = sc->features.thread_features;
		break;
	case DRM_PANFROST_PARAM_MAX_THREADS:
		param->value = sc->features.thread_max_threads;
		break;
	case DRM_PANFROST_PARAM_THREAD_MAX_WORKGROUP_SZ:
		param->value = sc->features.thread_max_workgroup_size;
		break;
	case DRM_PANFROST_PARAM_THREAD_MAX_BARRIER_SZ:
		param->value = sc->features.thread_max_barrier_size;
		break;
	case DRM_PANFROST_PARAM_COHERENCY_FEATURES:
		param->value = sc->features.coherency_features;
		break;
	case DRM_PANFROST_PARAM_NR_CORE_GROUPS:
		param->value = sc->features.nr_core_groups;
		break;
	case DRM_PANFROST_PARAM_THREAD_TLS_ALLOC:
		param->value = sc->features.thread_tls_alloc;
		break;
	case DRM_PANFROST_PARAM_TEXTURE_FEATURES0 ...
	    DRM_PANFROST_PARAM_TEXTURE_FEATURES3:
		param->value = sc->features.texture_features[param->param -
		    DRM_PANFROST_PARAM_TEXTURE_FEATURES0];
		break;
	case DRM_PANFROST_PARAM_JS_FEATURES0 ...
	    DRM_PANFROST_PARAM_JS_FEATURES15:
		param->value = sc->features.js_features[param->param -
		    DRM_PANFROST_PARAM_JS_FEATURES0];
		break;
	case DRM_PANFROST_PARAM_AFBC_FEATURES:
		param->value = sc->features.afbc_features;
		break;
	default:
		return (-EINVAL);
	}

	return (0);
}

static int
panfrost_ioctl_get_bo_offset(struct drm_device *dev, void *data,
    struct drm_file *file_priv)
{
	struct drm_panfrost_get_bo_offset *args;
	struct panfrost_file *pfile;
	struct drm_gem_object *obj;
	struct panfrost_gem_object *bo;
	struct panfrost_gem_mapping *mapping;

	pfile = file_priv->driver_priv;
	args = data;

	obj = drm_gem_object_lookup(file_priv, args->handle);
	if (obj == NULL)
		return (-EINVAL);

	bo = (struct panfrost_gem_object *)obj;

	mapping = panfrost_gem_mapping_get(bo, pfile);

	mutex_lock(&dev->struct_mutex);
	drm_gem_object_put(obj);
	mutex_unlock(&dev->struct_mutex);

	if (mapping == NULL)
		return (-EINVAL);

	args->offset = mapping->mmnode.start << PAGE_SHIFT;
	panfrost_gem_mapping_put(mapping);

	return (0);
}

static int
panfrost_ioctl_madvise(struct drm_device *dev, void *data,
    struct drm_file *file_priv)
{
	struct drm_panfrost_madvise *args;
	struct drm_gem_object *obj;
	struct panfrost_gem_object *bo;
	vm_pointer_t va;
	vm_page_t m;
	int i;

	dprintf("%s\n", __func__);

	args = data;

	obj = drm_gem_object_lookup(file_priv, args->handle);
	if (obj == NULL)
		return (-EINVAL);

	bo = (struct panfrost_gem_object *)obj;

	if (args->madv == PANFROST_MADV_WILLNEED) {
		if (bo->pages) {
			for (i = 0; i < bo->npages; i++) {
				m = bo->pages[i];
				vm_page_lock(m);
				pmap_zero_page(m);
				va = PHYS_TO_DMAP(VM_PAGE_TO_PHYS(m));
				cpu_dcache_wb_range(va, PAGE_SIZE);
				vm_page_unlock(m);
			}
		}
		args->retained = 1;
	}

	mutex_lock(&dev->struct_mutex);
	drm_gem_object_put(obj);
	mutex_unlock(&dev->struct_mutex);

	return (0);
}

static const struct drm_ioctl_desc panfrost_drm_driver_ioctls[] = {
#define	PANFROST_IOCTL(name, func, flags) \
	DRM_IOCTL_DEF_DRV(PANFROST_##name, panfrost_ioctl_##func, flags)

	PANFROST_IOCTL(SUBMIT,		submit,		DRM_RENDER_ALLOW),
	PANFROST_IOCTL(WAIT_BO,		wait_bo,	DRM_RENDER_ALLOW),
	PANFROST_IOCTL(CREATE_BO,	create_bo,	DRM_RENDER_ALLOW),
	PANFROST_IOCTL(MMAP_BO,		mmap_bo,	DRM_RENDER_ALLOW),
	PANFROST_IOCTL(GET_PARAM,	get_param,	DRM_RENDER_ALLOW),
	PANFROST_IOCTL(GET_BO_OFFSET,	get_bo_offset,	DRM_RENDER_ALLOW),
	PANFROST_IOCTL(MADVISE,		madvise,	DRM_RENDER_ALLOW),
};

static struct drm_driver panfrost_drm_driver = {
	.driver_features = DRIVER_RENDER | DRIVER_GEM | DRIVER_SYNCOBJ |
	    DRIVER_PRIME,

	.open			= panfrost_open,
	.postclose		= panfrost_postclose,
	.ioctls			= panfrost_drm_driver_ioctls,
	.num_ioctls		= ARRAY_SIZE(panfrost_drm_driver_ioctls),
	.fops			= &panfrost_drm_driver_fops,

	.prime_handle_to_fd	= drm_gem_prime_handle_to_fd,
	.prime_fd_to_handle	= drm_gem_prime_fd_to_handle,
	.gem_prime_import_sg_table = panfrost_gem_prime_import_sg_table,

	.name			= "panfrost",
	.desc			= "panfrost DRM",
	.date			= "20201124",
	.major			= 1,
	.minor			= 2,
};

static void
panfrost_gpu_intr(void *arg)
{
	struct panfrost_softc *sc;
	uint32_t pending;

	sc = arg;

	pending = GPU_READ(sc, GPU_INT_STAT);

	device_printf(sc->dev, "%s: pending %x\n", __func__, pending);

	if (pending & GPU_IRQ_POWER_CHANGED ||
	    pending & GPU_IRQ_POWER_CHANGED_ALL) {
		/* Ignore power events. */
	}

	GPU_WRITE(sc, GPU_INT_CLEAR, pending);
}

static void
panfrost_irq_hook(void *arg)
{
	struct panfrost_softc *sc;
	uint64_t rate;
	int err;

	sc = arg;

	drm_mode_config_init(&sc->drm_dev);

	if (clk_get_by_ofw_index(sc->dev, 0, 0, &sc->clk) == 0) {
		err = clk_enable(sc->clk);
		if (err == 0) {
			clk_get_freq(sc->clk, &rate);
			device_printf(sc->dev, "Mali GPU clock rate %jd Hz\n",
			    rate);
		} else
			device_printf(sc->dev,
			    "could not enable clock: %d\n", err);
	} else
		device_printf(sc->dev, "Mali GPU clock is unknown\n");

	err = drm_dev_init(&sc->drm_dev, &panfrost_drm_driver,
	    sc->dev);
	if (err != 0) {
		device_printf(sc->dev, "drm_dev_init(): %d\n", err);
		return;
	}

	sc->drm_dev.dev_private = sc;

	err = panfrost_device_init(sc);
	if (err != 0) {
		device_printf(sc->dev, "Failed to init panfrost device\n");
		return;
	}

	err = panfrost_mmu_init(sc);
	if (err != 0) {
		device_printf(sc->dev, "Failed to init panfrost mmu\n");
		return;
	}

	err = panfrost_job_init(sc);
	if (err != 0) {
		device_printf(sc->dev, "Failed to init panfrost job\n");
		return;
	}

	err = drm_dev_register(&sc->drm_dev, 0);
	if (err < 0) {
		device_printf(sc->dev, "drm_dev_register(): %d\n", err);
		return;
	}
}

static int
panfrost_probe(device_t dev)
{
	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_search_compatible(dev, compat_data)->ocd_data == 0)
		return (ENXIO);

	device_set_desc(dev, "Mali Midgard/Bifrost GPU");
	return (BUS_PROBE_DEFAULT);
}

static int
panfrost_attach(device_t dev)
{
	struct panfrost_softc *sc;

	sc = device_get_softc(dev);
	sc->dev = dev;

	TAILQ_INIT(&sc->mmu_in_use);
	mtx_init(&sc->mmu_lock, "mmu list", NULL, MTX_DEF);
	mtx_init(&sc->sched_lock, "sched", NULL, MTX_DEF);

	if (bus_alloc_resources(dev, mali_spec, sc->res) != 0) {
		device_printf(dev, "cannot allocate resources for device\n");
		return (ENXIO);
	}

	if (bus_setup_intr(dev, sc->res[1],
	    INTR_TYPE_MISC | INTR_MPSAFE, NULL, panfrost_job_intr, sc,
	    &sc->intrhand[0])) {
		device_printf(dev, "cannot setup interrupt handler\n");
		return (ENXIO);
	}

	if (bus_setup_intr(dev, sc->res[2],
	    INTR_TYPE_MISC | INTR_MPSAFE, NULL, panfrost_mmu_intr, sc,
	    &sc->intrhand[1])) {
		device_printf(dev, "cannot setup interrupt handler\n");
		return (ENXIO);
	}

	if (bus_setup_intr(dev, sc->res[3],
	    INTR_TYPE_MISC | INTR_MPSAFE, NULL, panfrost_gpu_intr, sc,
	    &sc->intrhand[2])) {
		device_printf(dev, "cannot setup interrupt handler\n");
		return (ENXIO);
	}

	mtx_init(&sc->as_mtx, "asid set mtx", NULL, MTX_DEF);

	config_intrhook_oneshot(&panfrost_irq_hook, sc);

	return (0);
}

static int
panfrost_detach(device_t dev)
{
	struct panfrost_softc *sc;

	sc = device_get_softc(dev);

	drm_dev_unregister(&sc->drm_dev);
	drm_kms_helper_poll_fini(&sc->drm_dev);
	drm_atomic_helper_shutdown(&sc->drm_dev);
	drm_mode_config_cleanup(&sc->drm_dev);

	return (0);
}

static device_method_t panfrost_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		panfrost_probe),
	DEVMETHOD(device_attach,	panfrost_attach),
	DEVMETHOD(device_detach,	panfrost_detach),

	DEVMETHOD_END
};

static driver_t panfrost_driver = {
	"panfrost",
	panfrost_methods,
	sizeof(struct panfrost_softc),
};

EARLY_DRIVER_MODULE(panfrost, simplebus, panfrost_driver, 0, 0,
    BUS_PASS_INTERRUPT + BUS_PASS_ORDER_LAST);
