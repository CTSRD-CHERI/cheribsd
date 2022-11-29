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

#include "scmi.h"
#include "scmi_protocols.h"
#include "scmi_perf.h"

struct scmi_perf_softc {
	device_t		scmi;
	device_t		dev;
	struct clkdom		*clkdom;
	struct scmi_perf_domain	*domains;
	int			domain_count;
};

struct scmi_perf_clknode_softc {
	device_t	dev;
	int		domain_id;
};

static int
scmi_perf_clknode_init(struct clknode *clk, device_t dev)
{

	clknode_init_parent_idx(clk, 0);

	return (0);
}

static int
scmi_perf_clknode_list_freq(struct clknode *clk, uint64_t *freq,
    int *freq_count)
{
	struct scmi_perf_clknode_softc *clk_sc;
	struct scmi_perf_domain *domain;
	struct scmi_perf_level *levels;
	struct scmi_perf_softc *sc;
	int i;

	clk_sc = clknode_get_softc(clk);
	sc = device_get_softc(clk_sc->dev);

	domain = &sc->domains[clk_sc->domain_id];
	levels = domain->levels;

	if (freq == NULL)
		return (ENXIO);

	if (*freq_count < domain->level_count)
		return (ENXIO);

	for (i = 0; i < domain->level_count; i++)
		freq[i] = levels[i].rate;

	*freq_count = domain->level_count;

	return (0);
}

static int
scmi_perf_get_level(struct scmi_perf_softc *sc, int domain_id, uint64_t *freq)
{
	struct scmi_perf_level_get_out out;
	struct scmi_perf_level_get_in in;
	struct scmi_req req;
	int error;

	req.protocol_id = SCMI_PROTOCOL_ID_PERF;
	req.message_id = SCMI_PERFORMANCE_LEVEL_GET;
	req.in_buf = (uint8_t *)&in;
	req.in_size = sizeof(struct scmi_perf_level_get_in);
	req.out_buf = (uint8_t *)&out;
	req.out_size = sizeof(struct scmi_perf_level_get_out);

	in.domain_id = domain_id;

	error = scmi_request(sc->scmi, &req);
	if (error != 0)
		return (error);

	if (out.status != 0)
		return (ENXIO);

	*freq = out.performance_level;

	return (0);
}

static int
scmi_perf_clknode_recalc_freq(struct clknode *clk, uint64_t *freq_out)
{
	struct scmi_perf_clknode_softc *clk_sc;
	struct scmi_perf_softc *sc;
	uint64_t freq;
	int error;

	dprintf("%s\n", __func__);

	clk_sc = clknode_get_softc(clk);
	sc = device_get_softc(clk_sc->dev);

	error = scmi_perf_get_level(sc, clk_sc->domain_id, &freq);
	if (error)
		return (ENXIO);

	*freq_out = freq;

	return (0);
}

static int
scmi_perf_set_level(struct scmi_perf_softc *sc, int domain_id, uint64_t freq)
{
	struct scmi_perf_level_set_out out;
	struct scmi_perf_level_set_in in;
	struct scmi_req req;
	int error;

	req.protocol_id = SCMI_PROTOCOL_ID_PERF;
	req.message_id = SCMI_PERFORMANCE_LEVEL_SET;
	req.in_buf = (uint8_t *)&in;
	req.in_size = sizeof(struct scmi_perf_level_set_in);
	req.out_buf = (uint8_t *)&out;
	req.out_size = sizeof(struct scmi_perf_level_set_out);

	in.domain_id = domain_id;
	in.performance_level = freq;

	error = scmi_request(sc->scmi, &req);
	if (error != 0)
		return (error);

	if (out.status != 0)
		return (ENXIO);

	return (0);
}

static int
scmi_perf_clknode_set_freq(struct clknode *clk, uint64_t fin, uint64_t *fout,
    int flags, int *stop)
{
	struct scmi_perf_clknode_softc *clk_sc;
	struct scmi_perf_softc *sc;

	clk_sc = clknode_get_softc(clk);
	sc = device_get_softc(clk_sc->dev);

	dprintf("%s: %lu\n", __func__, *fout);

	scmi_perf_set_level(sc, clk_sc->domain_id, *fout);

	*stop = 1;

	return (0);
}

static clknode_method_t scmi_perf_clknode_methods[] = {
	/* Device interface */
	CLKNODEMETHOD(clknode_init,		scmi_perf_clknode_init),
	CLKNODEMETHOD(clknode_list_freq,	scmi_perf_clknode_list_freq),
	CLKNODEMETHOD(clknode_recalc_freq,	scmi_perf_clknode_recalc_freq),
	CLKNODEMETHOD(clknode_set_freq,		scmi_perf_clknode_set_freq),
	CLKNODEMETHOD_END
};

DEFINE_CLASS_1(scmi_perf_clknode, scmi_perf_clknode_class,
    scmi_perf_clknode_methods, sizeof(struct scmi_perf_clknode_softc),
    clknode_class);

static int
scmi_perf_add_node(struct scmi_perf_softc *sc, int index, char *clock_name)
{
	struct scmi_perf_clknode_softc *clk_sc;
	struct clknode_init_def def;
	struct clknode *clk;

	memset(&def, 0, sizeof(def));
	def.id = index;
	def.name = clock_name;
	def.parent_names = NULL;
	def.parent_cnt = 0;

	clk = clknode_create(sc->clkdom, &scmi_perf_clknode_class, &def);
	if (clk == NULL) {
		device_printf(sc->dev, "Cannot create clknode.\n");
		return (ENXIO);
	}

	clk_sc = clknode_get_softc(clk);
	clk_sc->dev = sc->dev;
	clk_sc->domain_id = index;

	if (clknode_register(sc->clkdom, clk) == NULL) {
		device_printf(sc->dev, "Could not register perf clock '%s'.\n",
		   def.name);
		return (ENXIO);
	}

	device_printf(sc->dev, "Perf clock '%s' registered.\n", def.name);

	return (0);
}

static int
scmi_perf_get_num_levels(struct scmi_perf_softc *sc, int domain,
    int *num_levels)
{
	struct scmi_perf_describe_levels_out out;
	struct scmi_perf_describe_levels_in in;
	struct scmi_req req;
	int error;

	req.protocol_id = SCMI_PROTOCOL_ID_PERF;
	req.message_id = SCMI_PERFORMANCE_DESCRIBE_LEVELS;
	req.in_buf = (uint8_t *)&in;
	req.in_size = sizeof(struct scmi_perf_describe_levels_in);
	req.out_buf = (uint8_t *)&out;
	req.out_size = sizeof(struct scmi_perf_describe_levels_out);

	in.domain_id = domain;
	in.level_index = 0;

	error = scmi_request(sc->scmi, &req);
	if (error != 0)
		return (error);

	if (out.status != 0)
		return (ENXIO);

	device_printf(sc->dev, "%s: status %d, num_levels %d\n", __func__,
	    out.status, out.num_levels);

	*num_levels = (out.num_levels & NUM_LEVELS_M) >> NUM_LEVELS_S;

	return (0);
}

static int
scmi_perf_describe_levels(struct scmi_perf_softc *sc, int domain,
    int num_levels)
{
	struct scmi_perf_describe_levels_out *out;
	struct scmi_perf_describe_levels_in in;
	struct scmi_perf_level_out *level;
	struct scmi_req req;
	int error;
	int size;
	int i;

	size = sizeof(struct scmi_perf_describe_levels_out) +
	    sizeof(struct scmi_perf_level_out) * num_levels;
	out = malloc(size, M_DEVBUF, M_WAITOK);

	req.protocol_id = SCMI_PROTOCOL_ID_PERF;
	req.message_id = SCMI_PERFORMANCE_DESCRIBE_LEVELS;
	req.in_buf = (uint8_t *)&in;
	req.in_size = sizeof(struct scmi_perf_describe_levels_in);
	req.out_buf = (uint8_t *)out;
	req.out_size = size;

	in.domain_id = domain;
	in.level_index = 0;

	error = scmi_request(sc->scmi, &req);
	if (error != 0)
		return (error);

	if (out->status != 0)
		return (ENXIO);

	for (i = 0; i < num_levels; i++) {
		level = &out->levels[i];
		device_printf(sc->dev, " -- Perf level #%d\n", i);
		device_printf(sc->dev, "  Perf level value %x\n",
		    level->perf_level_value);
		device_printf(sc->dev, "  Power cost %x\n", level->power_cost);
		device_printf(sc->dev, "  Attributes %x\n", level->attributes);

		sc->domains[domain].levels[i].rate = level->perf_level_value;
	}

	free(out, M_DEVBUF);

	return (0);
}

static int
scmi_perf_domain_info(struct scmi_perf_softc *sc, int index)
{
	struct scmi_perf_domain_attrs_out out;
	struct scmi_perf_domain_attrs_in in;
	struct scmi_req req;
	int error;

	req.protocol_id = SCMI_PROTOCOL_ID_PERF;
	req.message_id = SCMI_PERFORMANCE_DOMAIN_ATTRIBUTES;
	req.in_buf = (uint8_t *)&in;
	req.in_size = sizeof(struct scmi_perf_domain_attrs_in);
	req.out_buf = (uint8_t *)&out;
	req.out_size = sizeof(struct scmi_perf_domain_attrs_out);

	in.domain_id = index;

	error = scmi_request(sc->scmi, &req);
	if (error != 0)
		return (error);

	if (out.status != 0)
		return (ENXIO);

	device_printf(sc->dev, "Perf domain name: %s\n", out.name);
	device_printf(sc->dev, "Perf protocol attributes: %x\n",
	    out.attributes);
	device_printf(sc->dev, "Perf rate limit: %x\n", out.rate_limit);
	device_printf(sc->dev, "Perf sustained freq: %x\n", out.sustained_freq);
	device_printf(sc->dev, "Sustained Perf Level: %x\n",
	    out.sustained_perf_level);

	scmi_perf_add_node(sc, index, out.name);

	return (0);
}

static int
scmi_perf_get_ndomains(struct scmi_perf_softc *sc, int *ndomains)
{
	struct scmi_perf_protocol_attrs_out out;
	struct scmi_req req;
	int error;

	req.protocol_id = SCMI_PROTOCOL_ID_PERF;
	req.message_id = SCMI_PROTOCOL_ATTRIBUTES;
	req.in_buf = NULL;
	req.in_size = 0;
	req.out_buf = (uint8_t *)&out;
	req.out_size = sizeof(struct scmi_perf_protocol_attrs_out);

	error = scmi_request(sc->scmi, &req);
	if (error != 0)
		return (error);

	if (out.status != 0)
		return (ENXIO);

	device_printf(sc->dev, "Perf protocol attributes: %x\n",
	    out.attributes);

	*ndomains = out.attributes & 0xffff;

	return (0);
}

static int
scmi_perf_init(struct scmi_perf_softc *sc)
{
	struct scmi_perf_domain *domain;
	phandle_t node;
	int num_levels;
	int ndomains;
	int error;
	int i;

	node = ofw_bus_get_node(sc->dev);
	if (node <= 0)
		return (ENXIO);

	OF_device_register_xref(OF_xref_from_node(node), sc->dev);

	sc->clkdom = clkdom_create(sc->dev);
	if (sc->clkdom == NULL)
		return (ENXIO);

	error = scmi_perf_get_ndomains(sc, &ndomains);
	if (error)
		return (error);

	sc->domain_count = ndomains;
	sc->domains = malloc(sizeof(struct scmi_perf_domain) * ndomains,
	    M_DEVBUF, M_WAITOK);

	for (i = 0; i < ndomains; i++) {
		domain = &sc->domains[i];
		domain->id = i;

		scmi_perf_domain_info(sc, i);

		error = scmi_perf_get_num_levels(sc, i, &num_levels);
		if (error)
			return (error);

		domain->level_count = num_levels;
		domain->levels = malloc(sizeof(struct scmi_perf_level) *
		    num_levels, M_DEVBUF, M_WAITOK);

		scmi_perf_describe_levels(sc, i, num_levels);
	}

	error = clkdom_finit(sc->clkdom);
	if (error) {
		device_printf(sc->dev, "Failed to init perf clock domain.\n");
		return (ENXIO);
	}

	return (0);
}

static int
scmi_perf_probe(device_t dev)
{
	phandle_t node;
	uint32_t reg;
	int error;

	node = ofw_bus_get_node(dev);

	error = OF_getencprop(node, "reg", &reg, sizeof(uint32_t));
	if (error < 0)
		return (ENXIO);

	if (reg != SCMI_PROTOCOL_ID_PERF)
		return (ENXIO);

	device_set_desc(dev, "SCMI Performance Management Unit");

	return (BUS_PROBE_DEFAULT);
}

static int
scmi_perf_attach(device_t dev)
{
	struct scmi_perf_softc *sc;
	phandle_t node;

	sc = device_get_softc(dev);
	sc->dev = dev;
	sc->scmi = device_get_parent(dev);

	node = ofw_bus_get_node(sc->dev);

	OF_device_register_xref(OF_xref_from_node(node), sc->dev);

	scmi_perf_init(sc);

	return (0);
}

static int
scmi_perf_detach(device_t dev)
{

	return (0);
}

static device_method_t scmi_perf_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		scmi_perf_probe),
	DEVMETHOD(device_attach,	scmi_perf_attach),
	DEVMETHOD(device_detach,	scmi_perf_detach),
	DEVMETHOD_END
};

static driver_t scmi_perf_driver = {
	"scmi_perf",
	scmi_perf_methods,
	sizeof(struct scmi_perf_softc),
};

EARLY_DRIVER_MODULE(scmi_perf, scmi, scmi_perf_driver, 0, 0,
    BUS_PASS_INTERRUPT + BUS_PASS_ORDER_MIDDLE);
MODULE_VERSION(scmi_perf, 1);
