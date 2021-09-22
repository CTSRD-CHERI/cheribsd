/*-
 * Copyright (c) 2021 Ruslan Bukin <br@bsdpad.com>
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
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/malloc.h>
#include <sys/rman.h>
#include <sys/taskqueue.h>
#include <sys/timeet.h>
#include <sys/timetc.h>
#include <sys/tree.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/endian.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>

#include <machine/bus.h>
#include <machine/cpu.h>
#include <machine/intr.h>
#include <machine/sbi.h>
#include <machine/vmparam.h>

#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#include <dev/ofw/ofw_subr.h>

#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>
#include <dev/iommu/iommu.h>
#include <riscv/iommu/iommu.h>

#include "iommu.h"
#include "iommu_if.h"

struct dm_iommu_softc {
	struct iommu_unit	iommu;
	struct resource		*res[3];
	device_t		dev;
	bus_space_tag_t		bst_data;
	bus_space_handle_t	bsh_data;
};

static struct resource_spec dm_iommu_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ -1, 0 }
};

static int
dm_iommu_find(device_t dev, device_t child)
{
	struct dm_iommu_softc *sc;
	uint16_t rid;
	int seg;

	sc = device_get_softc(dev);

	rid = pci_get_rid(child);
	seg = pci_get_domain(child);

	printf("%s: rid %d seg %d\n", __func__, rid, seg);

	return (0);
}

static int
dm_iommu_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (!ofw_bus_is_compatible(dev, "dm,iommu"))
		return (ENXIO);

	device_set_desc(dev, "Device-Model IOMMU Engine");

	return (BUS_PROBE_DEFAULT);
}

static int
dm_iommu_attach(device_t dev)
{
	struct dm_iommu_softc *sc;
	struct iommu_unit *iommu;
	int err;

	sc = device_get_softc(dev);
	sc->dev = dev;

	if (bus_alloc_resources(dev, dm_iommu_spec, sc->res)) {
		device_printf(dev, "could not allocate resources\n");
		return (ENXIO);
	}

	/* Memory interface */
	sc->bst_data = rman_get_bustag(sc->res[0]);
	sc->bsh_data = rman_get_bushandle(sc->res[0]);

	iommu = &sc->iommu;
	iommu->dev = dev;

	err = iommu_register(iommu);
	if (err) {
		device_printf(dev, "Failed to register IOMMU.\n");
		return (ENXIO);
	}

	return (0);
}

static int
dm_iommu_read_ivar(device_t dev, device_t child, int which, uintptr_t *result)
{
	struct dm_iommu_softc *sc;

	sc = device_get_softc(dev);

	device_printf(sc->dev, "%s\n", __func__);

	return (ENOENT);
}

static device_method_t dm_iommu_methods[] = {
	DEVMETHOD(device_probe,		dm_iommu_probe),
	DEVMETHOD(device_attach,	dm_iommu_attach),

	/* SMMU interface */
	DEVMETHOD(iommu_find,		dm_iommu_find),

#if 0
	DEVMETHOD(iommu_map,		dm_iommu_map),
	DEVMETHOD(iommu_unmap,		dm_iommu_unmap),
	DEVMETHOD(iommu_domain_alloc,	dm_iommu_domain_alloc),
	DEVMETHOD(iommu_domain_free,	dm_iommu_domain_free),
	DEVMETHOD(iommu_ctx_alloc,	dm_iommu_ctx_alloc),
	DEVMETHOD(iommu_ctx_free,	dm_iommu_ctx_free),
	DEVMETHOD(iommu_ctx_lookup,	dm_iommu_ctx_lookup),
#endif

	/* Bus interface */
	DEVMETHOD(bus_read_ivar,	dm_iommu_read_ivar),

	{ 0, 0 }
};

static driver_t dm_iommu_driver = {
	"dm_iommu",
	dm_iommu_methods,
	sizeof(struct dm_iommu_softc),
};

static devclass_t dm_iommu_devclass;

DRIVER_MODULE(dm_iommu, simplebus, dm_iommu_driver, dm_iommu_devclass, 0, 0);
