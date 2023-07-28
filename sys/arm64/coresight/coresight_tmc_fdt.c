/*-
 * Copyright (c) 2018-2023 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
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

#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <arm64/coresight/coresight.h>
#include <arm64/coresight/coresight_tmc.h>

#include "coresight_if.h"

static struct ofw_compat_data compat_data[] = {
	{ "arm,coresight-tmc",			1 },
	{ NULL,					0 }
};

static int
tmc_fdt_probe(device_t dev)
{
	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_search_compatible(dev, compat_data)->ocd_data == 0)
		return (ENXIO);

	device_set_desc(dev, "ARM Coresight TMC");

	return (BUS_PROBE_DEFAULT);
}

static int
tmc_fdt_attach(device_t dev)
{
	struct tmc_softc *sc;
	phandle_t node;
	ssize_t len;

	sc = device_get_softc(dev);
	sc->pdata = coresight_fdt_get_platform_data(dev);

	node = ofw_bus_get_node(dev);

	len = OF_getproplen(node, "arm,scatter-gather");
	if (len >= 0)
		sc->scatter_gather = true;
	else
		sc->scatter_gather = false;

	return (tmc_attach(dev));
}

static int
tmc_fdt_detach(device_t dev)
{
	struct tmc_softc *sc;
	int error;

	sc = device_get_softc(dev);
 
	coresight_fdt_release_platform_data(sc->pdata);

	sc->pdata = NULL;

	error = tmc_detach(dev);

	return (error);
}

static device_method_t tmc_fdt_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		tmc_fdt_probe),
	DEVMETHOD(device_attach,	tmc_fdt_attach),
	DEVMETHOD(device_detach,	tmc_fdt_detach),
	DEVMETHOD_END
};

DEFINE_CLASS_1(coresight_tmc, tmc_fdt_driver, tmc_fdt_methods,
    sizeof(struct tmc_softc), coresight_tmc_driver);

EARLY_DRIVER_MODULE(coresight_tmc, simplebus, tmc_fdt_driver, 0, 0,
    BUS_PASS_INTERRUPT + BUS_PASS_ORDER_MIDDLE);
MODULE_DEPEND(coresight_tmc, coresight, 1, 1, 1);
MODULE_DEPEND(coresight_tmc, coresight_cpu_debug, 1, 1, 1);
MODULE_DEPEND(coresight_tmc, coresight_etm4x, 1, 1, 1);
MODULE_DEPEND(coresight_tmc, coresight_funnel, 1, 1, 1);
MODULE_DEPEND(coresight_tmc, coresight_replicator, 1, 1, 1);
MODULE_VERSION(coresight_tmc, 1);
