/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2022 Ruslan Bukin <br@bsdpad.com>
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/cpu.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/mutex.h>

#include <dev/extres/clk/clk.h>

#include <dev/fdt/simplebus.h>
#include <dev/fdt/fdt_common.h>
#include <dev/ofw/ofw_bus_subr.h>

#include "cpufreq_if.h"

#define	dprintf(fmt, ...)

struct dt_cpufreq_softc {
	device_t dev;
	clk_t	clk;
};

static void
dt_cpufreq_identify(driver_t *driver, device_t parent)
{
	phandle_t node;

	node = ofw_bus_get_node(parent);
	if (node <= 0)
		return;

	if (device_find_child(parent, "dt_cpufreq", -1) != NULL)
		return;
	if (BUS_ADD_CHILD(parent, 0, "dt_cpufreq", -1) == NULL)
		device_printf(parent, "add child failed\n");
}

static int
dt_cpufreq_probe(device_t dev)
{

	device_set_desc(dev, "ARM CPU Frequency driver");

	return (BUS_PROBE_DEFAULT);
}

static int
dt_cpufreq_attach(device_t dev)
{
	struct dt_cpufreq_softc *sc;
	device_t parent;
	phandle_t node;

	sc = device_get_softc(dev);
	sc->dev = dev;

	parent = device_get_parent(dev);

	node = ofw_bus_get_node(parent);
	if (node <= 0)
		return (ENXIO);

	if (clk_get_by_ofw_index(dev, node, 0, &sc->clk) != 0)
		return (ENXIO);

	cpufreq_register(sc->dev);

	return (0);
}

static int
dt_cpufreq_detach(device_t dev)
{

	return (0);
}

static int
dt_cpufreq_set(device_t dev, const struct cf_setting *cf)
{
	struct dt_cpufreq_softc *sc;
	int error;

	dprintf("%s\n", __func__);

	if (cf == NULL)
		return (EINVAL);

	sc = device_get_softc(dev);

	error = clk_set_freq(sc->clk, cf->freq * 1000000, 0);
	if (error)
		return (error);

	return (0);
}

static int
dt_cpufreq_get(device_t dev, struct cf_setting *cf)
{
	struct dt_cpufreq_softc *sc;
	uint64_t freq;
	int error;

	dprintf("%s\n", __func__);

	if (cf == NULL)
		return (EINVAL);

	sc = device_get_softc(dev);

	error = clk_get_freq(sc->clk, &freq);
	if (error)
		return (error);

	memset(cf, CPUFREQ_VAL_UNKNOWN, sizeof(*cf));
	cf->freq = freq / 1000000;
	cf->dev = dev;

	dprintf("%s: freq %d\n", __func__, cf->freq);

	return (0);
}

static int
dt_cpufreq_settings(device_t dev, struct cf_setting *sets, int *count)
{
	struct dt_cpufreq_softc *sc;
	uint64_t freq[MAX_SETTINGS];
	int freq_count;
	int error;
	int i;

	sc = device_get_softc(dev);

	freq_count = MAX_SETTINGS;

	error = clk_list_freq(sc->clk, freq, &freq_count);
	if (error)
		return (error);

	/* fill data with unknown value */
	memset(sets, CPUFREQ_VAL_UNKNOWN, sizeof(*sets) * (*count));

	for (i = 0; i < freq_count; i++) {
		sets[i].freq = freq[i] / 1000000;
		sets[i].dev = dev;
	}

	*count = freq_count;

	return (0);
}

static int
dt_cpufreq_type(device_t dev, int *type)
{

	if (type == NULL)
		return (EINVAL);

	*type = CPUFREQ_TYPE_ABSOLUTE;

	return (0);
}

static device_method_t dt_cpufreq_methods[] = {
	DEVMETHOD(device_identify,	dt_cpufreq_identify),
	DEVMETHOD(device_probe,		dt_cpufreq_probe),
	DEVMETHOD(device_attach,	dt_cpufreq_attach),
	DEVMETHOD(device_detach,	dt_cpufreq_detach),

	DEVMETHOD(cpufreq_drv_set,	dt_cpufreq_set),
	DEVMETHOD(cpufreq_drv_get,	dt_cpufreq_get),
	DEVMETHOD(cpufreq_drv_settings,	dt_cpufreq_settings),
	DEVMETHOD(cpufreq_drv_type,	dt_cpufreq_type),

	DEVMETHOD_END
};

static driver_t dt_cpufreq_driver = {
	"dt_cpufreq",
	dt_cpufreq_methods,
	sizeof(struct dt_cpufreq_softc),
};

DRIVER_MODULE(dt_cpufreq, cpu, dt_cpufreq_driver, 0, 0);
MODULE_DEPEND(dt_cpufreq, ofw_cpu, 1, 1, 1);
