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
#include <machine/bus.h>

#include <arm64/coresight/coresight.h>
#include <dev/hwt/hwtvar.h>

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
static struct coresight_event cs_event[MAXCPU];

static void
coresight_event_init(struct hwt_thread *thr)
{
	struct coresight_event *event;
	int cpu;

	for (cpu = 0; cpu < mp_ncpus; cpu++) {
		event = &cs_event[cpu];
		memset(event, 0, sizeof(struct coresight_event));
		event->etr.started = 0;
		event->etr.low = 0;
		event->etr.high = 0;
		event->etr.pages = thr->pages;
		event->etr.npages = thr->npages;
		event->etr.bufsize = thr->npages * PAGE_SIZE;
		event->excp_level = 0; /* TODO: User level only for now. */
		event->src = CORESIGHT_ETMV4;
		event->sink = CORESIGHT_TMC_ETR;

		/*
		 * Set the trace ID required for ETM component.
		 * TODO: this should be derived from hwt(1).
		 */

		event->etm.trace_id = 0x10;
		coresight_init_event(event, cpu);

		/*
		 * Configure pipeline immediately since Coresight merges
		 * everything to a single buffer. We don't need to reconfigure
		 * components until this user releases coresight.
		 */

		coresight_configure(event, cpu);
		coresight_start(event, cpu);
	}
}

static void
coresight_event_deinit(void)
{
	struct coresight_event *event;
	int cpu;

	for (cpu = 0; cpu < mp_ncpus; cpu++) {
		event = &cs_event[cpu];
		coresight_disable(event, cpu);
		coresight_stop(event, cpu);
	}
}

static void
coresight_event_configure(struct hwt_thread *thr, int cpu_id)
{

}

static void
coresight_event_enable(struct hwt_thread *thr, int cpu_id)
{
	struct coresight_event *event;

	event = &cs_event[cpu_id];

	coresight_enable(event, cpu_id);
}

static void
coresight_event_disable(struct hwt_thread *thr, int cpu_id)
{
	struct coresight_event *event;

	event = &cs_event[cpu_id];

	coresight_disable(event, cpu_id);
}

static int
coresight_event_read(struct hwt_thread *thr, int cpu_id,
    int *curpage, vm_offset_t *curpage_offset)
{
	struct coresight_event *event;

	event = &cs_event[cpu_id];

	KASSERT(event != NULL, ("No event found"));

	coresight_read(event, cpu_id);

	*curpage = event->etr.curpage;
	*curpage_offset = event->etr.curpage_offset;

	return (0);
}

static void
coresight_event_dump(struct hwt_thread *thr, int cpu_id)
{
	struct coresight_event *event;

	event = &cs_event[cpu_id];

	coresight_dump(event, cpu_id);
}

static struct hwt_backend_ops coresight_ops = {
	.hwt_backend_init = coresight_event_init,
	.hwt_backend_deinit = coresight_event_deinit,
	.hwt_backend_configure = coresight_event_configure,
	.hwt_backend_enable = coresight_event_enable,
	.hwt_backend_disable = coresight_event_disable,
	.hwt_backend_read = coresight_event_read,
	.hwt_backend_dump = coresight_event_dump,
};

int
coresight_register(struct coresight_desc *desc)
{
	struct coresight_device *cs_dev;

	cs_dev = malloc(sizeof(struct coresight_device),
	    M_CORESIGHT, M_WAITOK | M_ZERO);
	cs_dev->dev = desc->dev;
	cs_dev->pdata = desc->pdata;
	cs_dev->dev_type = desc->dev_type;

	mtx_lock(&cs_mtx);
	TAILQ_INSERT_TAIL(&cs_devs, cs_dev, link);
	mtx_unlock(&cs_mtx);

	if (desc->dev_type == CORESIGHT_TMC_ETR)
		hwt_register(&backend);

	return (0);
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

static void
coresight_init(void)
{

	mtx_init(&cs_mtx, "ARM Coresight", NULL, MTX_DEF);
	TAILQ_INIT(&cs_devs);
}

SYSINIT(coresight, SI_SUB_DRIVERS, SI_ORDER_FIRST, coresight_init, NULL);
