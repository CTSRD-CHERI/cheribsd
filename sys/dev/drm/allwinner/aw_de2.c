/*-
 * Copyright (c) 2019 Emmanuel Vadot <manu@FreeBSD.org>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
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

#include <dev/fdt/simplebus.h>

#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <dev/extres/syscon/syscon.h>

#include "syscon_if.h"

#define	SRAM_C_SYSCON_OFFSET		0x4
#define	SRAM_C_ASSIGN_TO_DE_VALUE	1
#define	SRAM_C_ASSIGN_TO_DE_SHIFT	24

static struct ofw_compat_data compat_data[] = {
	{ "allwinner,sun50i-a64-de2",	1 },
	{ NULL,				0 }
};

struct aw_de2_softc {
	struct simplebus_softc	sc;
	device_t		dev;
};

static int aw_de2_probe(device_t dev);
static int aw_de2_attach(device_t dev);
static int aw_de2_detach(device_t dev);

static int
aw_de2_probe(device_t dev)
{
	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_search_compatible(dev, compat_data)->ocd_data == 0)
		return (ENXIO);

	device_set_desc(dev, "Allwinner DE2");
	return (BUS_PROBE_DEFAULT);
}

static int
aw_de2_attach(device_t dev)
{
	struct aw_de2_softc *sc;
	struct syscon *syscon;
	device_t cdev;
	phandle_t node, child;
	phandle_t sram[2];
	uint32_t reg;

	sc = device_get_softc(dev);
	sc->dev = dev;
	node = ofw_bus_get_node(dev);

	/* Assign sram to DE */
	if (OF_getencprop(node, "allwinner,sram", sram, sizeof(sram)) <= 0) {
		device_printf(dev, "Cannot get allwinner,sram property\n");
		return (ENXIO);
	}
	sram[0] = OF_parent(OF_parent(OF_node_from_xref(sram[0])));
	if (syscon_get_by_ofw_node(dev, sram[0], &syscon) != 0) {
		device_printf(dev, "Cannot get syscon node\n");
		return (ENXIO);
	}
	reg = SYSCON_READ_4(syscon, SRAM_C_SYSCON_OFFSET);
	reg &= ~(SRAM_C_ASSIGN_TO_DE_VALUE << SRAM_C_ASSIGN_TO_DE_SHIFT);
	SYSCON_WRITE_4(syscon, SRAM_C_SYSCON_OFFSET, reg);

	simplebus_init(dev, node);
	if (simplebus_fill_ranges(node, &sc->sc) < 0) {
		device_printf(dev, "could not get ranges\n");
		return (ENXIO);
	}

	for (child = OF_child(node); child > 0; child = OF_peer(child)) {
		cdev = simplebus_add_device(dev, child, 0, NULL, -1, NULL);
		if (cdev != NULL)
			device_probe_and_attach(cdev);
	}

	return (bus_generic_attach(dev));
}

static int
aw_de2_detach(device_t dev)
{

	bus_generic_detach(dev);
	return (0);
}

static device_method_t aw_de2_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		aw_de2_probe),
	DEVMETHOD(device_attach,	aw_de2_attach),
	DEVMETHOD(device_detach,	aw_de2_detach),

	DEVMETHOD_END
};

DEFINE_CLASS_1(aw_de2, aw_de2_driver, aw_de2_methods,
    sizeof(struct aw_de2_softc), simplebus_driver);

static devclass_t aw_de2_devclass;

EARLY_DRIVER_MODULE(aw_de2, simplebus, aw_de2_driver,
  aw_de2_devclass, 0, 0, BUS_PASS_SUPPORTDEV + BUS_PASS_ORDER_FIRST);
MODULE_VERSION(aw_de2, 1);
