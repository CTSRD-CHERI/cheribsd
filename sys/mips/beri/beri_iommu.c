/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Ruslan Bukin <br@bsdpad.com>
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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

#include "opt_platform.h"
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/malloc.h>
#include <sys/rman.h>
#include <sys/timeet.h>
#include <sys/timetc.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/endian.h>

#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#include <dev/xdma/xdma.h>

#ifdef FDT
#include <dev/fdt/fdt_common.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#include <dev/ofw/openfirm.h>
#endif

#include <machine/cache.h>
#include <machine/bus.h>
#include <machine/cpu.h>
#include <machine/intr.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>
#include <vm/vm_page.h>

#include "xdma_if.h"
#include "iommu_if.h"

#define	IOMMU_INVALIDATE	0x00
#define	IOMMU_SET_BASE		0x08

#define	FDT_REG_CELLS		4

struct beri_iommu_softc {
	struct resource		*res[1];
	device_t		dev;
	bus_space_tag_t		bst_data;
	bus_space_handle_t	bsh_data;
	uint32_t		offs;
	struct pmap		p;
	vmem_t *vmem;		/* VA space */
};

static struct resource_spec beri_iommu_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ -1, 0 }
};

static int
beri_handle_mem_node(vmem_t *vmem, phandle_t memory)
{
	pcell_t reg[FDT_REG_CELLS * FDT_MEM_REGIONS];
	pcell_t *regp;
	int addr_cells, size_cells;
	int i, reg_len, ret, tuple_size, tuples;
	u_long mem_start, mem_size;

	if ((ret = fdt_addrsize_cells(OF_parent(memory), &addr_cells,
	    &size_cells)) != 0)
		return (ret);

	if (addr_cells > 2)
		return (ERANGE);

	tuple_size = sizeof(pcell_t) * (addr_cells + size_cells);
	reg_len = OF_getproplen(memory, "reg");
	if (reg_len <= 0 || reg_len > sizeof(reg))
		return (ERANGE);

	if (OF_getprop(memory, "reg", reg, reg_len) <= 0)
		return (ENXIO);

	tuples = reg_len / tuple_size;
	regp = (pcell_t *)&reg;
	for (i = 0; i < tuples; i++) {
		ret = fdt_data_to_res(regp, addr_cells, size_cells,
		    &mem_start, &mem_size);
		if (ret != 0)
			return (ret);

		vmem_add(vmem, mem_start, mem_size, 0);
		regp += addr_cells + size_cells;
	}

	return (0);
}

static int
beri_iommu_parse_fdt(struct beri_iommu_softc *sc)
{
#ifdef FDT
	phandle_t mem_node, node;
	pcell_t mem_handle;
#endif

	printf("%s\n", __func__);

	pmap_pinit(&sc->p);

#ifdef FDT
	node = ofw_bus_get_node(sc->dev);
	if (!OF_hasprop(node, "va-region"))
		return (ENXIO);

	if (OF_getencprop(node, "va-region", (void *)&mem_handle,
	    sizeof(mem_handle)) <= 0)
		return (ENXIO);
#endif

	sc->vmem = vmem_create("beri iommu", 0, 0, PAGE_SIZE,
	    PAGE_SIZE, M_FIRSTFIT | M_WAITOK);
	if (sc->vmem == NULL)
		return (ENXIO);

#ifdef FDT
	mem_node = OF_node_from_xref(mem_handle);
	if (beri_handle_mem_node(sc->vmem, mem_node) != 0) {
		vmem_destroy(sc->vmem);
		return (ENXIO);
	}
#endif

	return (0);
}

static void
beri_iommu_invalidate(struct beri_iommu_softc *sc, vm_offset_t addr)
{

	bus_write_8(sc->res[0], IOMMU_INVALIDATE, htole64(addr));
}

static void
beri_iommu_set_base(struct beri_iommu_softc *sc, vm_offset_t addr)
{

	bus_write_8(sc->res[0], IOMMU_SET_BASE, htole64(addr));
}

static int
beri_iommu_release(device_t dev, pmap_t p)
{
	struct beri_iommu_softc *sc;

	printf("%s\n", __func__);

	sc = device_get_softc(dev);

	//beri_iommu_set_base(sc, 0);

	return (0);
}

static int
beri_iommu_init(device_t dev, pmap_t p)
{
	struct beri_iommu_softc *sc;

	printf("%s: setting segtab %lx\n", __func__, (uintptr_t)p->pm_segtab);

	sc = device_get_softc(dev);

	beri_iommu_set_base(sc, (uintptr_t)p->pm_segtab);

	return (0);
}

static int
beri_iommu_remove(device_t dev, pmap_t p, vm_offset_t va)
{
	struct beri_iommu_softc *sc;

	printf("%s\n", __func__);

	sc = device_get_softc(dev);

	beri_iommu_invalidate(sc, va);

	return (0);
}

static int
beri_iommu_enter(device_t dev, pmap_t p, vm_offset_t va,
    vm_paddr_t pa)
{
	struct beri_iommu_softc *sc;
	pt_entry_t opte, npte;
	pt_entry_t *pte;

	printf("%s: pa %lx va %lx\n", __func__, pa, va);

	sc = device_get_softc(dev);

	pte = pmap_pte(p, va);
	if (pte == NULL)
		panic("pte is NULL\n");

	/* Make pte uncacheable. */
	opte = *pte;
	npte = opte & ~PTE_C_MASK;
	npte |= PTE_C(VM_MEMATTR_UNCACHEABLE);
	*pte = npte;

	/* Write back, invalidate pte. */
	mips_dcache_wbinv_range((vm_offset_t)pte, sizeof(vm_offset_t));

	/* Invalidate the entry. */
	if (pte_test(&opte, PTE_V) && opte != npte)
		beri_iommu_invalidate(sc, va);

	return (0);
}

#if 0
int
beri_busdma_iommu_release(struct beri_iommu_softc *sc)
{

	pmap_release(&sc->p);

	vmem_destroy(sc->vmem);

	beri_iommu_release(sc->dev, &sc->p);

	return (0);
}
#endif

static int
beri_iommu_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (!ofw_bus_is_compatible(dev, "beri,iommu"))
		return (ENXIO);

	device_set_desc(dev, "BERI IOMMU");

	return (BUS_PROBE_DEFAULT);
}

static int
beri_iommu_attach(device_t dev)
{
	struct beri_iommu_softc *sc;
	phandle_t xref, node;

	sc = device_get_softc(dev);
	sc->dev = dev;

	if (bus_alloc_resources(dev, beri_iommu_spec, sc->res)) {
		device_printf(dev, "could not allocate resources\n");
		return (ENXIO);
	}

	/* Memory interface */
	sc->bst_data = rman_get_bustag(sc->res[0]);
	sc->bsh_data = rman_get_bushandle(sc->res[0]);

	beri_iommu_parse_fdt(sc);
	beri_iommu_init(sc->dev, &sc->p);

	node = ofw_bus_get_node(dev);
	xref = OF_xref_from_node(node);
	OF_device_register_xref(xref, dev);

	return (0);
}

static int
beri_iommu_detach(device_t dev)
{
	struct beri_iommu_softc *sc;

	sc = device_get_softc(dev);

	bus_release_resources(dev, beri_iommu_spec, sc->res);

	return (0);
}

/* busdma interface */

static void
beri_busdma_iommu_enter(struct beri_iommu_softc *sc, vm_offset_t va,
    vm_paddr_t pa, vm_size_t size, vm_prot_t prot)
{
	vm_page_t m;
	pmap_t p;

	p = &sc->p;

	KASSERT((size & PAGE_MASK) == 0,
	    ("%s: device mapping not page-sized", __func__));

	for (; size > 0; size -= PAGE_SIZE) {
		m = PHYS_TO_VM_PAGE(pa);
		pmap_enter(p, va, m, prot, prot | PMAP_ENTER_WIRED, 0);

		beri_iommu_enter(sc->dev, p, va, pa);

		va += PAGE_SIZE;
		pa += PAGE_SIZE;
	}
}

/* xDMA interface */

static int
beri_xdma_iommu_release(device_t dev, struct xdma_iommu *xio)
{
	int ret;

	ret = beri_iommu_release(dev, &xio->p);

	return (ret);
}

static int
beri_xdma_iommu_init(device_t dev, struct xdma_iommu *xio)
{
	int ret;

	ret = beri_iommu_init(dev, &xio->p);

	return (ret);
}

static int
beri_xdma_iommu_remove(device_t dev, struct xdma_iommu *xio, vm_offset_t va)
{
	int ret;

	ret = beri_iommu_remove(dev, &xio->p, va);

	return (ret);
}

static int
beri_xdma_iommu_enter(device_t dev, struct xdma_iommu *xio, vm_offset_t va,
    vm_paddr_t pa)
{
	int ret;

	ret = beri_iommu_enter(dev, &xio->p, va, pa);

	return (ret);
}

static void
beri_iommu_add_entry(struct beri_iommu_softc *sc, vm_offset_t *va,
    vm_paddr_t pa, vm_size_t size, vm_prot_t prot)
{
	vm_offset_t addr;

	size = roundup2(size, PAGE_SIZE * 2);

	if (vmem_alloc(sc->vmem, size,
	    M_FIRSTFIT | M_NOWAIT, &addr)) {
		panic("Could not allocate virtual address.\n");
	}

	addr |= pa & (PAGE_SIZE - 1);

	if (va)
		*va = addr;

	beri_busdma_iommu_enter(sc, addr, pa, size, prot);
}

static int
beri_iommu_map(device_t dev, bus_dma_segment_t *segs, int *nsegs,
    bus_addr_t min, bus_addr_t max, bus_size_t alignment, bus_addr_t boundary,
    void *cookie)
{
	struct beri_iommu_softc *sc;
	bus_dma_segment_t *seg;
	vm_offset_t va;
	int i;

	sc = device_get_softc(dev);

	printf("%s: nsegs %d\n", __func__, *nsegs);

	for (i = 0; i < *nsegs; i++) {
		seg = &segs[i];

		beri_iommu_add_entry(sc, &va, seg->ds_addr,
		    seg->ds_len, VM_PROT_WRITE | VM_PROT_READ);

		printf("  seg%d: ds_addr %lx ds_len %ld, va %lx\n",
		    i, seg->ds_addr, seg->ds_len, va);

		seg->ds_addr = va;
	}

	return (0);
}

static void
beri_busdma_iommu_remove_entry(struct beri_iommu_softc *sc, vm_offset_t va)
{

	va &= ~(PAGE_SIZE - 1);
	pmap_remove(&sc->p, va, va + PAGE_SIZE);

	beri_iommu_remove(sc->dev, &sc->p, va);

	vmem_free(sc->vmem, va, PAGE_SIZE);
}

static int
beri_iommu_unmap(device_t dev, bus_dma_segment_t *segs, int nsegs,
    void *cookie)
{
	struct beri_iommu_softc *sc;
	vm_offset_t va;
	int i;

	sc = device_get_softc(dev);

	printf("%s: nsegs %d\n", __func__, nsegs);

	for (i = 0; i < nsegs; i++) {
		va = segs[i].ds_addr;
		beri_busdma_iommu_remove_entry(sc, va);
	}

	return (0);
}

static device_method_t beri_iommu_methods[] = {

	/* xDMA IOMMU interface */
	DEVMETHOD(xdma_iommu_init,	beri_xdma_iommu_init),
	DEVMETHOD(xdma_iommu_release,	beri_xdma_iommu_release),
	DEVMETHOD(xdma_iommu_enter,	beri_xdma_iommu_enter),
	DEVMETHOD(xdma_iommu_remove,	beri_xdma_iommu_remove),

	/* busdma IOMMU interface */
	DEVMETHOD(iommu_map,		beri_iommu_map),
	DEVMETHOD(iommu_unmap,		beri_iommu_unmap),

	/* Device interface */
	DEVMETHOD(device_probe,		beri_iommu_probe),
	DEVMETHOD(device_attach,	beri_iommu_attach),
	DEVMETHOD(device_detach,	beri_iommu_detach),

	{ 0, 0 }
};

static driver_t beri_iommu_driver = {
	"beri_iommu",
	beri_iommu_methods,
	sizeof(struct beri_iommu_softc),
};

static devclass_t beri_iommu_devclass;

DRIVER_MODULE(beri_iommu, simplebus, beri_iommu_driver,
    beri_iommu_devclass, 0, 0);
