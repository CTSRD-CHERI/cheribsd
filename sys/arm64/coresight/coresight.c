/*-
 * Copyright (c) 2018-2023 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/rman.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/smp.h>
#include <sys/hwt.h>
#include <machine/bus.h>

#include <arm64/coresight/coresight.h>

#include <dev/hwt/hwt_config.h>
#include <dev/hwt/hwt_context.h>
#include <dev/hwt/hwt_config.h>
#include <dev/hwt/hwt_cpu.h>
#include <dev/hwt/hwt_thread.h>
#include <dev/hwt/hwt_backend.h>
#include <dev/hwt/hwt_vm.h>

#define	CORESIGHT_DEBUG
#undef CORESIGHT_DEBUG

#ifdef CORESIGHT_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

MALLOC_DEFINE(M_CORESIGHT, "coresight", "ARM Coresight");

static struct mtx cs_mtx;
struct coresight_device_list cs_devs;
static struct hwt_backend_ops coresight_ops;

static struct hwt_backend backend = {
		.ops = &coresight_ops,
		.name = "coresight",
};
static struct coresight_pipeline cs_pipeline[MAXCPU];

/*
 * Example pipeline (SoC-dependent).
 * https://people.freebsd.org/~br/coresight_diagram.png
 */

static int
coresight_backend_init_thread(struct hwt_context *ctx)
{
	struct coresight_pipeline *pipeline;
	struct hwt_thread *thr;
	struct hwt_vm *vm;
	int cpu_id;
	int error;

	/*
	 * 1. Use buffer from the first thread as Funnel merges traces from
	 * all CPUs to a single place.
	 *
	 * 2. Ctx was just allocated, so the lock is not really needed.
	 */
	HWT_CTX_LOCK(ctx);
	thr = hwt_thread_first(ctx);
	HWT_CTX_UNLOCK(ctx);

	vm = thr->vm;

	for (cpu_id = 0; cpu_id < mp_ncpus; cpu_id++) {
		pipeline = &cs_pipeline[cpu_id];
		memset(pipeline, 0, sizeof(struct coresight_pipeline));
		pipeline->excp_level = 0;
		pipeline->src = CORESIGHT_ETMV4;
		pipeline->sink = CORESIGHT_TMC_ETR;

		error = coresight_init_pipeline(pipeline, cpu_id);
		if (error)
			return (error);
	}

	/*
	 * These methods are TMC-ETR only. We have single
	 * TMC-ETR per system, so call them on first pipeline
	 * only. The request will reach destination.
	 */
	pipeline = &cs_pipeline[0];
	pipeline->etr.low = 0;
	pipeline->etr.high = 0;
	pipeline->etr.pages = vm->pages;
	pipeline->etr.npages = vm->npages;
	pipeline->etr.bufsize = vm->npages * PAGE_SIZE;

	error = coresight_setup(pipeline);
	if (error)
		return (error);

	error = coresight_start(pipeline);
	if (error)
		return (error);

	return (0);
}

static int
coresight_backend_init_cpu(struct hwt_context *ctx)
{
	struct coresight_pipeline *pipeline;
	struct hwt_vm *vm;
	int error;
	int cpu_id;

	CPU_FOREACH(cpu_id) {
		pipeline = &cs_pipeline[cpu_id];
		memset(pipeline, 0, sizeof(struct coresight_pipeline));

		pipeline->excp_level = 1;
		pipeline->src = CORESIGHT_ETMV4;
		pipeline->sink = CORESIGHT_TMC_ETR;

		error = coresight_init_pipeline(pipeline, cpu_id);
		if (error)
			return (error);
	}

	/*
	 * The following is TMC (ETR) only, so pick vm from the first CPU.
	 */
	pipeline = &cs_pipeline[0];

	HWT_CTX_LOCK(ctx);
	vm = hwt_cpu_first(ctx)->vm;
	HWT_CTX_UNLOCK(ctx);

	/* TMC(ETR) configuration. */
	pipeline->etr.low = 0;
	pipeline->etr.high = 0;
	pipeline->etr.pages = vm->pages;
	pipeline->etr.npages = vm->npages;
	pipeline->etr.bufsize = vm->npages * PAGE_SIZE;

	error = coresight_setup(pipeline);
	if (error)
		return (error);

	error = coresight_start(pipeline);
	if (error)
		return (error);

	return (0);
}

static int
coresight_backend_init(struct hwt_context *ctx)
{
	int error;

	if (ctx->mode == HWT_MODE_THREAD)
		error = coresight_backend_init_thread(ctx);
	else
		error = coresight_backend_init_cpu(ctx);

	return (error);
}

static void
coresight_backend_deinit(struct hwt_context *ctx)
{
	struct coresight_pipeline *pipeline;
	int cpu_id;

	for (cpu_id = 0; cpu_id < mp_ncpus; cpu_id++) {
		pipeline = &cs_pipeline[cpu_id];
		coresight_disable(pipeline);
	}

	/* Now as TMC-ETF buffers flushed, stop TMC-ETR. */
	pipeline = &cs_pipeline[0];
	coresight_stop(pipeline);

	for (cpu_id = 0; cpu_id < mp_ncpus; cpu_id++) {
		pipeline = &cs_pipeline[cpu_id];
		coresight_deinit_pipeline(pipeline);
	}
}

static int
coresight_backend_configure(struct hwt_context *ctx, int cpu_id, int session_id)
{
	struct coresight_pipeline *pipeline;
	int error;

	pipeline = &cs_pipeline[cpu_id];

	/*
	 * OpenCSD needs a trace ID to distinguish trace sessions
	 * as they are merged to a single buffer by using funnel
	 * device.
	 *
	 * etmv4 session_id can't be 0.
	 */
	pipeline->etm.trace_id = session_id + 1;

	error = coresight_configure(pipeline, ctx);

	return (error);
}

static void
coresight_backend_enable(int cpu_id)
{
	struct coresight_pipeline *pipeline;

	pipeline = &cs_pipeline[cpu_id];

	coresight_enable(pipeline);
}

static void
coresight_backend_disable(int cpu_id)
{
	struct coresight_pipeline *pipeline;

	pipeline = &cs_pipeline[cpu_id];

	coresight_disable(pipeline);
}

static int
coresight_backend_read(int cpu_id, int *curpage, vm_offset_t *curpage_offset)
{
	struct coresight_pipeline *pipeline;
	int error;

	/*
	 * coresight_read() is TMC(ETR) only method. Also, we have a single
	 * TMC(ETR) per system configured from pipeline 0. So read data from
	 * pipeline 0.
	 */

	pipeline = &cs_pipeline[0];

	KASSERT(pipeline != NULL, ("No pipeline found"));

	error = coresight_read(pipeline);
	if (error == 0) {
		*curpage = pipeline->etr.curpage;
		*curpage_offset = pipeline->etr.curpage_offset;
	}

	return (error);
}

static void
coresight_backend_dump(int cpu_id)
{
	struct coresight_pipeline *pipeline;

	pipeline = &cs_pipeline[cpu_id];

	coresight_dump(pipeline);
}

static struct hwt_backend_ops coresight_ops = {
	.hwt_backend_init = coresight_backend_init,
	.hwt_backend_deinit = coresight_backend_deinit,

	.hwt_backend_configure = coresight_backend_configure,

	.hwt_backend_enable = coresight_backend_enable,
	.hwt_backend_disable = coresight_backend_disable,

	.hwt_backend_read = coresight_backend_read,
	.hwt_backend_dump = coresight_backend_dump,
};

int
coresight_register(struct coresight_desc *desc)
{
	struct coresight_device *cs_dev;
	int error;

	cs_dev = malloc(sizeof(struct coresight_device),
	    M_CORESIGHT, M_WAITOK | M_ZERO);
	cs_dev->dev = desc->dev;
	cs_dev->pdata = desc->pdata;
	cs_dev->dev_type = desc->dev_type;

	if (desc->dev_type == CORESIGHT_TMC_ETR) {
		error = hwt_backend_register(&backend);
		if (error != 0) {
			free(cs_dev, M_CORESIGHT);
			return (error);
		}
	}

	mtx_lock(&cs_mtx);
	TAILQ_INSERT_TAIL(&cs_devs, cs_dev, link);
	mtx_unlock(&cs_mtx);

	return (0);
}

int
coresight_unregister(device_t dev)
{
	struct coresight_device *cs_dev, *tmp;

	mtx_lock(&cs_mtx);
	TAILQ_FOREACH_SAFE(cs_dev, &cs_devs, link, tmp) {
		if (cs_dev->dev == dev) {
			TAILQ_REMOVE(&cs_devs, cs_dev, link);
			mtx_unlock(&cs_mtx);
			if (cs_dev->dev_type == CORESIGHT_TMC_ETR)
				hwt_backend_unregister(&backend);
			free(cs_dev, M_CORESIGHT);
			return (0);
		}
	}
	mtx_unlock(&cs_mtx);

	return (ENOENT);
}

struct endpoint *
coresight_get_output_endpoint(struct coresight_platform_data *pdata)
{
	struct endpoint *endp;

	if (pdata->out_ports != 1)
		return (NULL);

	TAILQ_FOREACH(endp, &pdata->endpoints, link) {
		if (endp->input == 0)
			return (endp);
	}

	return (NULL);
}

struct coresight_device *
coresight_get_output_device(struct coresight_device *cs_dev0,
    struct endpoint *endp, struct endpoint **out_endp)
{
	struct coresight_platform_data *pdata;
	struct coresight_device *cs_dev;
	struct endpoint *endp2;

	TAILQ_FOREACH(cs_dev, &cs_devs, link) {
		pdata = cs_dev->pdata;
		TAILQ_FOREACH(endp2, &cs_dev->pdata->endpoints, link) {
			switch (pdata->bus_type) {
			case CORESIGHT_BUS_FDT:
#ifdef FDT
				if (endp->their_node == endp2->my_node) {
					*out_endp =
					    malloc(sizeof(struct endpoint),
						M_CORESIGHT, M_WAITOK | M_ZERO);
					memcpy(*out_endp, endp2,
					    sizeof(struct endpoint));
					return (cs_dev);
				}
#endif
				break;

			case CORESIGHT_BUS_ACPI:
#ifdef DEV_ACPI
				if (endp->their_handle == endp2->my_handle) {
					*out_endp =
					    malloc(sizeof(struct endpoint),
						M_CORESIGHT, M_WAITOK | M_ZERO);
					memcpy(*out_endp, endp2,
					    sizeof(struct endpoint));
					return (cs_dev);
				}
#endif
				break;
			}
		}
	}

	return (NULL);
}

static int
coresight_modevent(module_t mod, int type, void *data)
{

	switch (type) {
	case MOD_LOAD:
		mtx_init(&cs_mtx, "ARM Coresight", NULL, MTX_DEF);
		TAILQ_INIT(&cs_devs);
		break;
	case MOD_UNLOAD:
		mtx_destroy(&cs_mtx);
		break;
	default:
		break;
	}
 
        return (0);
}
 
static moduledata_t coresight_mod = {
	"coresight",
        coresight_modevent,
        NULL
};
   
DECLARE_MODULE(coresight, coresight_mod, SI_SUB_DRIVERS, SI_ORDER_FIRST);
MODULE_DEPEND(coresight, hwt, 1, 1, 1);
MODULE_VERSION(coresight, 1);
