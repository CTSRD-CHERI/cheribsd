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
#include <sys/module.h>
#include <machine/bus.h>

#include <arm64/coresight/coresight.h>

#include "coresight_if.h"

extern struct coresight_device_list cs_devs;

static struct coresight_device *
coresight_next_device(struct coresight_device *cs_dev,
    struct coresight_pipeline *pipeline)
{
	struct coresight_device *out;
	struct endpoint *out_endp, *src_endp;
	struct endpoint *endp;

	TAILQ_FOREACH(endp, &cs_dev->pdata->endpoints, link) {
		if (endp->input != 0)
			continue;

		out = coresight_get_output_device(cs_dev, endp, &out_endp);
		if (out != NULL) {
			if (TAILQ_EMPTY(&pipeline->endplist)) {

				/* Add source device */
				src_endp = malloc(sizeof(struct endpoint),
				    M_CORESIGHT, M_WAITOK | M_ZERO);
				memcpy(src_endp, endp, sizeof(struct endpoint));

				src_endp->cs_dev = cs_dev;
				TAILQ_INSERT_TAIL(&pipeline->endplist, src_endp,
				    endplink);
			}

			/* Add output device */
			if (bootverbose)
				printf("Adding device %s to the chain\n",
				    device_get_nameunit(out->dev));
			out_endp->cs_dev = out;
			TAILQ_INSERT_TAIL(&pipeline->endplist, out_endp,
			    endplink);

			return (out);
		}
	}

	return (NULL);
}

static int
coresight_build_pipeline(struct coresight_device *cs_dev,
    struct coresight_pipeline *pipeline)
{
	struct coresight_device *out;

	out = cs_dev;
	while (out != NULL)
		out = coresight_next_device(out, pipeline);

	return (0);
}

int
coresight_init_pipeline(struct coresight_pipeline *pipeline, int cpu)
{
	struct coresight_device *cs_dev;
	struct endpoint *endp;
	int error;

	/* Start building path from source device */
	TAILQ_FOREACH(cs_dev, &cs_devs, link) {
		if (cs_dev->dev_type == pipeline->src &&
		    cs_dev->pdata->cpu == cpu) {
			TAILQ_INIT(&pipeline->endplist);
			coresight_build_pipeline(cs_dev, pipeline);
			break;
		}
	}

	/* Ensure Coresight is initialized for the CPU */
	TAILQ_FOREACH(cs_dev, &cs_devs, link) {
		if (cs_dev->dev_type == CORESIGHT_CPU_DEBUG &&
		    cs_dev->pdata->cpu == cpu) {
			error = CORESIGHT_INIT(cs_dev->dev);
			if (error != ENXIO && error != 0)
				return (error);
		}
	}

	/* Init all devices in the path */
	TAILQ_FOREACH(endp, &pipeline->endplist, endplink) {
		cs_dev = endp->cs_dev;
		error = CORESIGHT_INIT(cs_dev->dev);
		if (error != ENXIO && error != 0)
			return (error);
	}

	return (0);
}

void
coresight_deinit_pipeline(struct coresight_pipeline *pipeline)
{
	struct coresight_device *cs_dev;
	struct endpoint *endp, *tmp;

	TAILQ_FOREACH_SAFE(endp, &pipeline->endplist, endplink, tmp) {
		cs_dev = endp->cs_dev;
		CORESIGHT_DEINIT(cs_dev->dev);

		TAILQ_REMOVE(&pipeline->endplist, endp, endplink);
		free(endp, M_CORESIGHT);
	}
}

int
coresight_setup(struct coresight_pipeline *pipeline)
{
	struct coresight_device *cs_dev;
	struct endpoint *endp;
	int error;

	TAILQ_FOREACH(endp, &pipeline->endplist, endplink) {
		cs_dev = endp->cs_dev;
		error = CORESIGHT_SETUP(cs_dev->dev, endp, pipeline);
		if (error != ENXIO && error != 0)
			return (error);
	}

	return (0);
}

int
coresight_configure(struct coresight_pipeline *pipeline,
    struct hwt_context *ctx)
{
	struct coresight_device *cs_dev;
	struct endpoint *endp;
	int error;

	TAILQ_FOREACH(endp, &pipeline->endplist, endplink) {
		cs_dev = endp->cs_dev;
		error = CORESIGHT_CONFIGURE(cs_dev->dev, endp, pipeline, ctx);
		if (error != ENXIO && error != 0)
			return (error);
	}

	return (0);
}

int
coresight_start(struct coresight_pipeline *pipeline)
{
	struct coresight_device *cs_dev;
	struct endpoint *endp;
	int error;

	TAILQ_FOREACH_REVERSE(endp, &pipeline->endplist, endplistname,
	    endplink) {
		cs_dev = endp->cs_dev;
		error = CORESIGHT_START(cs_dev->dev, endp, pipeline);
		if (error != ENXIO && error != 0)
			return (error);
	}

	return (0);
}

void
coresight_stop(struct coresight_pipeline *pipeline)
{
	struct coresight_device *cs_dev;
	struct endpoint *endp;

	TAILQ_FOREACH(endp, &pipeline->endplist, endplink) {
		cs_dev = endp->cs_dev;
		CORESIGHT_STOP(cs_dev->dev, endp, pipeline);
	}
}

void
coresight_enable(struct coresight_pipeline *pipeline)
{
	struct coresight_device *cs_dev;
	struct endpoint *endp;

	TAILQ_FOREACH(endp, &pipeline->endplist, endplink) {
		cs_dev = endp->cs_dev;
		CORESIGHT_ENABLE(cs_dev->dev, endp, pipeline);
	}
}

void
coresight_disable(struct coresight_pipeline *pipeline)
{
	struct coresight_device *cs_dev;
	struct endpoint *endp;

	TAILQ_FOREACH(endp, &pipeline->endplist, endplink) {
		cs_dev = endp->cs_dev;
		CORESIGHT_DISABLE(cs_dev->dev, endp, pipeline);
	}
}

void
coresight_dump(struct coresight_pipeline *pipeline)
{
	struct coresight_device *cs_dev;
	struct endpoint *endp;

	TAILQ_FOREACH(endp, &pipeline->endplist, endplink) {
		cs_dev = endp->cs_dev;
		CORESIGHT_DUMP(cs_dev->dev);
	}
}

int
coresight_read(struct coresight_pipeline *pipeline)
{
	struct coresight_device *cs_dev;
	struct endpoint *endp;
	int error;

	TAILQ_FOREACH(endp, &pipeline->endplist, endplink) {
		cs_dev = endp->cs_dev;
		error = CORESIGHT_READ(cs_dev->dev, endp, pipeline);
		if (error != ENXIO && error != 0)
			return (error);
	}

	return (0);
}
