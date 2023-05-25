/*-
 * Copyright (c) 2018-2020 Ruslan Bukin <br@bsdpad.com>
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
#include <machine/bus.h>

#include <arm64/coresight/coresight.h>
#include <dev/hwt/hwtvar.h>

static struct mtx cs_mtx;
struct coresight_device_list cs_devs;

static struct hwt_backend backend;
static struct coresight_event cs_event[MAXCPU];

static void
coresight_event_init(struct hwt_ctx *hwt)
{
	struct coresight_event *event;

	printf("%s: cpu_id %d\n", __func__, hwt->cpu_id);

	event = &cs_event[hwt->cpu_id];
	memset(event, 0, sizeof(struct coresight_event));
	event->etr.started = 0;
	event->etr.low = 0;
	event->etr.high = 0;
	event->etr.flags = ETR_FLAG_ALLOCATE;
	event->etr.pages = hwt->pages;
	event->etr.npages = hwt->npages;
	event->etr.bufsize = hwt->npages * PAGE_SIZE;
	event->excp_level = 1; /* Kernel */
	event->excp_level = 0; /* User level */
	event->src = CORESIGHT_ETMV4;
	event->sink = CORESIGHT_TMC_ETR;

	/*
	 * Set the trace ID required for ETM component.
	 * TODO: this should be derived from pmctrace.
	 */

	event->etm.trace_id = 0x10;
	coresight_init_event(hwt->cpu_id, event);
}

static void
coresight_event_start(struct hwt_ctx *hwt)
{
	struct coresight_event *event;

	printf("%s: cpu_id %d\n", __func__, hwt->cpu_id);

	event = &cs_event[hwt->cpu_id];

	coresight_start(hwt->cpu_id, event);
}

static void
coresight_event_stop(struct hwt_ctx *hwt)
{
	struct coresight_event *event;

	printf("%s: cpu_id %d\n", __func__, hwt->cpu_id);

	event = &cs_event[hwt->cpu_id];

	coresight_stop(hwt->cpu_id, event);
}

static void
coresight_event_enable(struct hwt_ctx *hwt)
{
	struct coresight_event *event;

	printf("%s: cpu_id %d\n", __func__, hwt->cpu_id);

	event = &cs_event[hwt->cpu_id];

	coresight_enable(hwt->cpu_id, event);
}

static void
coresight_event_disable(struct hwt_ctx *hwt)
{
	struct coresight_event *event;

	printf("%s: cpu_id %d\n", __func__, hwt->cpu_id);

	event = &cs_event[hwt->cpu_id];

	coresight_disable(hwt->cpu_id, event);
}

static void
coresight_event_dump(struct hwt_ctx *hwt)
{
	struct coresight_event *event;

	//printf("%s: cpu_id %d\n", __func__, hwt->cpu_id);

	event = &cs_event[hwt->cpu_id];

	coresight_dump(hwt->cpu_id, event);
}

static struct hwt_backend_ops coresight_ops = {
	.hwt_event_init = coresight_event_init,
	.hwt_event_start = coresight_event_start,
	.hwt_event_stop = coresight_event_stop,
	.hwt_event_enable = coresight_event_enable,
	.hwt_event_disable = coresight_event_disable,
	.hwt_event_dump = coresight_event_dump,
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

	if (desc->dev_type == CORESIGHT_TMC_ETR) {
		backend.ops = &coresight_ops;
		hwt_register(&backend);
	}

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
coresight_get_output_device(struct coresight_device *cs_dev0, struct endpoint *endp, struct endpoint **out_endp)
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
					*out_endp = malloc(sizeof(struct endpoint), M_CORESIGHT, M_WAITOK | M_ZERO);
					memcpy(*out_endp, endp2, sizeof(struct endpoint));
					return (cs_dev);
				}
#endif
				break;

			case CORESIGHT_BUS_ACPI:
#ifdef DEV_ACPI
				if (endp->their_handle == endp2->my_handle) {
					*out_endp = malloc(sizeof(struct endpoint), M_CORESIGHT, M_WAITOK | M_ZERO);
					memcpy(*out_endp, endp2, sizeof(struct endpoint));
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
