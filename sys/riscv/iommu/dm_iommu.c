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
#include <vm/vm_page.h>

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
#include <riscv/iommu/iommu_pmap.h>

#include "iommu.h"
#include "iommu_if.h"

MALLOC_DEFINE(M_DM_IOMMU, "DM_IOMMU", "Device-Model IOMMU");

#define	DM_DEBUG
#undef	DM_DEBUG

#ifdef	DM_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

struct dm_iommu_unit {
	struct iommu_unit		iommu;
	LIST_HEAD(, dm_iommu_domain)	domain_list;
	LIST_ENTRY(dm_iommu_unit)	next;
	device_t			dev;
};

struct dm_iommu_domain {
	struct iommu_domain		iodom;
	LIST_HEAD(, dm_iommu_ctx)	ctx_list;
	LIST_ENTRY(dm_iommu_domain)	next;
	u_int				entries_cnt;
	struct pmap			p;
};

struct dm_iommu_ctx {
	struct iommu_ctx		ioctx;
	struct dm_iommu_domain		*domain;
	LIST_ENTRY(dm_iommu_ctx)	next;
	device_t			dev;
	bool				bypass;
	int				sid;
	uint16_t			vendor;
	uint16_t			device;
};

struct dm_iommu_softc {
	struct dm_iommu_unit	unit;
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
dm_iommu_map(device_t dev, struct iommu_domain *iodom,
    vm_offset_t va, vm_page_t *ma, vm_size_t size,
    vm_prot_t prot)
{
	struct dm_iommu_domain *domain;
	vm_paddr_t pa;
	int error;
	int i;

	domain = (struct dm_iommu_domain *)iodom;

	dprintf("%s\n", __func__);

	if (prot & VM_PROT_READ)
		prot |= VM_PROT_READ_CAP;

	if (prot & VM_PROT_WRITE)
		prot |= VM_PROT_WRITE_CAP;

	for (i = 0; size > 0; size -= PAGE_SIZE, i++) {
		pa = VM_PAGE_TO_PHYS(ma[i]);
		dprintf("%s: %lx -> %lx\n", __func__, va, pa);
		error = pmap_dm_enter(&domain->p, va, pa, prot);
		if (error)
			return (error);
		va += PAGE_SIZE;
	}

	return (0);
}

static int
dm_iommu_unmap(device_t dev, struct iommu_domain *iodom,
    vm_offset_t va, bus_size_t size)
{
	struct dm_iommu_domain *domain;
	int error;
	int i;

	domain = (struct dm_iommu_domain *)iodom;

	dprintf("%s: va %lx size %lx\n", __func__, va, size);

	error = 0;

	for (i = 0; i < size; i += PAGE_SIZE) {
		if (pmap_dm_remove(&domain->p, va) != 0) {
			error = ENOENT;
			break;
		}
		va += PAGE_SIZE;
	}

	return (error);
}

static struct iommu_domain *
dm_iommu_domain_alloc(device_t dev, struct iommu_unit *iommu, bool *new)
{
	struct dm_iommu_domain *domain;
	struct dm_iommu_unit *unit;
	struct dm_iommu_softc *sc;
	struct pmap *p;

	sc = device_get_softc(dev);

	printf("%s\n", __func__);

	unit = (struct dm_iommu_unit *)iommu;

	/* TODO. Hack: use the same domain for all devices. */
	LIST_FOREACH(domain, &unit->domain_list, next) {
		*new = false;
		return (&domain->iodom);
	}

	domain = malloc(sizeof(*domain), M_DM_IOMMU, M_WAITOK | M_ZERO);
	*new = true;

#if 0
	int error;
	int new_asid;
	error = dm_iommu_asid_alloc(sc, &new_asid);
	if (error) {
		free(domain, M_DM_IOMMU);
		device_printf(sc->dev,
		    "Could not allocate ASID for a new domain.\n");
		return (NULL);
	}

	domain->asid = (uint16_t)new_asid;
#endif

	uint32_t satp;
	uint32_t addr;

	satp = bus_read_4(sc->res[0], 0x00);

	addr = satp & SATP_PPN_M;
	addr <<= PAGE_SHIFT;

	printf("%s: satp is %x, addr %lx\n", __func__, satp,
	    (uint64_t)PHYS_TO_DMAP(addr));

	/* Initialize pmap. */
	p = &domain->p;
	p->pm_l1 = (pd_entry_t *)PHYS_TO_DMAP(addr);
	p->pm_satp = satp;
	bzero(&p->pm_stats, sizeof(p->pm_stats));
	dprintf("%s: pm_l1 is %#lp\n", __func__, p->pm_l1);
	PMAP_LOCK_INIT(p);

	LIST_INIT(&domain->ctx_list);

	IOMMU_LOCK(iommu);
	LIST_INSERT_HEAD(&unit->domain_list, domain, next);
	IOMMU_UNLOCK(iommu);

	return (&domain->iodom);
}

static void
dm_iommu_domain_free(device_t dev, struct iommu_domain *iodom)
{
	struct dm_iommu_domain *domain;
	struct dm_iommu_softc *sc;

	sc = device_get_softc(dev);

	printf("%s\n", __func__);

	domain = (struct dm_iommu_domain *)iodom;

	LIST_REMOVE(domain, next);

	iommu_pmap_remove_pages(&domain->p);
	iommu_pmap_release(&domain->p);

	free(domain, M_DM_IOMMU);
}

static struct iommu_ctx *
dm_iommu_ctx_alloc(device_t dev, struct iommu_domain *iodom, device_t child,
    bool disabled)
{
	struct dm_iommu_domain *domain;
	struct dm_iommu_softc *sc;
	struct dm_iommu_ctx *ctx;
	uint16_t rid;
#if 0
	u_int xref, sid;
	int err;
#endif
	int seg;

	sc = device_get_softc(dev);
	domain = (struct dm_iommu_domain *)iodom;

	seg = pci_get_domain(child);
	rid = pci_get_rid(child);

#if 0
	err = acpi_iort_map_pci_dm_iommuv3(seg, rid, &xref, &sid);
	if (err)
		return (NULL);

	if (sc->features & SMMU_FEATURE_2_LVL_STREAM_TABLE) {
		err = dm_iommu_init_l1_entry(sc, sid);
		if (err)
			return (NULL);
	}
#endif

	ctx = malloc(sizeof(struct dm_iommu_ctx), M_DM_IOMMU,
	    M_WAITOK | M_ZERO);
	ctx->vendor = pci_get_vendor(child);
	ctx->device = pci_get_device(child);
	ctx->dev = child;
#if 0
	ctx->sid = sid;
#endif
	ctx->domain = domain;
	if (disabled)
		ctx->bypass = true;

#if 0
	/*
	 * Neoverse N1 SDP:
	 * 0x800 xhci
	 * 0x700 re
	 * 0x600 sata
	 */

	dm_iommu_init_ste(sc, domain->cd, ctx->sid, ctx->bypass);

	if (iommu_is_buswide_ctx(iodom->iommu, pci_get_bus(ctx->dev)))
		dm_iommu_set_buswide(dev, domain, ctx);
#endif

	IOMMU_DOMAIN_LOCK(iodom);
	LIST_INSERT_HEAD(&domain->ctx_list, ctx, next);
	IOMMU_DOMAIN_UNLOCK(iodom);

	return (&ctx->ioctx);
}

static void
dm_iommu_ctx_free(device_t dev, struct iommu_ctx *ioctx)
{
	struct dm_iommu_softc *sc;
	struct dm_iommu_ctx *ctx;

	IOMMU_ASSERT_LOCKED(ioctx->domain->iommu);

	printf("%s\n", __func__);

	sc = device_get_softc(dev);
	ctx = (struct dm_iommu_ctx *)ioctx;

	//dm_iommu_deinit_l1_entry(sc, ctx->sid);

	LIST_REMOVE(ctx, next);

	free(ctx, M_DM_IOMMU);
}

static struct iommu_ctx *
dm_iommu_ctx_lookup(device_t dev, device_t child)
{
	struct iommu_unit *iommu;
	struct dm_iommu_softc *sc;
	struct dm_iommu_domain *domain;
	struct dm_iommu_unit *unit;
	struct dm_iommu_ctx *ctx;

	sc = device_get_softc(dev);

	printf("%s\n", __func__);

	unit = &sc->unit;
	iommu = &unit->iommu;

	IOMMU_ASSERT_LOCKED(iommu);

	LIST_FOREACH(domain, &unit->domain_list, next) {
		IOMMU_DOMAIN_LOCK(&domain->iodom);
		LIST_FOREACH(ctx, &domain->ctx_list, next) {
			if (ctx->dev == child) {
				IOMMU_DOMAIN_UNLOCK(&domain->iodom);
				return (&ctx->ioctx);
			}
		}
		IOMMU_DOMAIN_UNLOCK(&domain->iodom);
	}

	return (NULL);
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
	struct dm_iommu_unit *unit;
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

	unit = &sc->unit;
	unit->dev = dev;

	iommu = &unit->iommu;
	iommu->dev = dev;

	LIST_INIT(&unit->domain_list);

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

	/* RISC-V IOMMU interface. */
	DEVMETHOD(iommu_find,		dm_iommu_find),
	DEVMETHOD(iommu_map,		dm_iommu_map),
	DEVMETHOD(iommu_unmap,		dm_iommu_unmap),
	DEVMETHOD(iommu_domain_alloc,	dm_iommu_domain_alloc),
	DEVMETHOD(iommu_domain_free,	dm_iommu_domain_free),
	DEVMETHOD(iommu_ctx_alloc,	dm_iommu_ctx_alloc),
	DEVMETHOD(iommu_ctx_free,	dm_iommu_ctx_free),
	DEVMETHOD(iommu_ctx_lookup,	dm_iommu_ctx_lookup),

	/* Bus interface. */
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
