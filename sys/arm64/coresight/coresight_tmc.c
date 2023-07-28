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

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/pmap.h>

#include <arm64/coresight/coresight.h>
#include <arm64/coresight/coresight_tmc.h>

#include "coresight_if.h"

#define	TMC_DEBUG
#undef TMC_DEBUG

#ifdef TMC_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

#define	SG_PT_ENTIRES_PER_PAGE	(PAGE_SIZE / sizeof(sgte_t))
#define	ETR_SG_ET_MASK			0x3
#define	ETR_SG_ET_LAST			0x1
#define	ETR_SG_ET_NORMAL		0x2
#define	ETR_SG_ET_LINK			0x3

#define	ETR_SG_PAGE_SHIFT		12
#define	ETR_SG_ADDR_SHIFT		4

#define	ETR_SG_ENTRY(addr, type) \
	(sgte_t)((((addr) >> ETR_SG_PAGE_SHIFT) << ETR_SG_ADDR_SHIFT) | \
	    (type & ETR_SG_ET_MASK))

static struct resource_spec tmc_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ SYS_RES_IRQ,		0,	RF_ACTIVE | RF_OPTIONAL },
	{ -1, 0 }
};

static int
tmc_alloc_pages(struct tmc_softc *sc, vm_page_t *pages, int npages)
{
	vm_paddr_t low, high, boundary;
	vm_memattr_t memattr;
	int alignment;
	vm_pointer_t va;
	int pflags;
	vm_page_t m;
	int tries;
	int i;

	alignment = PAGE_SIZE;
	low = 0;
	high = -1UL;
	boundary = 0;
	pflags = VM_ALLOC_NORMAL | VM_ALLOC_NOBUSY | VM_ALLOC_WIRED |
	    VM_ALLOC_ZERO;
	memattr = VM_MEMATTR_DEFAULT;

	for (i = 0; i < npages; i++) {
		tries = 0;
retry:
		m = vm_page_alloc_noobj_contig(pflags, 1, low, high,
		    alignment, boundary, memattr);
		if (m == NULL) {
			if (tries < 3) {
				if (!vm_page_reclaim_contig(pflags, 1, low,
				    high, alignment, boundary))
					vm_wait(NULL);
				tries++;
				goto retry;
			}

			return (ENOMEM);
		}

		if ((m->flags & PG_ZERO) == 0)
			pmap_zero_page(m);

		va = PHYS_TO_DMAP(VM_PAGE_TO_PHYS(m));
		cpu_dcache_wb_range(va, PAGE_SIZE);
		cpu_dcache_inv_range(va, PAGE_SIZE);
		m->valid = VM_PAGE_BITS_ALL;
		m->oflags &= ~VPO_UNMANAGED;
		m->flags |= PG_FICTITIOUS;

		pages[i] = m;
	}

	return (0);
}

static int
tmc_enable(device_t dev)
{
	struct tmc_softc *sc;
	uint32_t reg;

	sc = device_get_softc(dev);

	if (sc->dev_type == CORESIGHT_ETR) {
		dprintf("%s%d\n", __func__, device_get_unit(dev));
	}

	if (bus_read_4(sc->res[0], TMC_CTL) & CTL_TRACECAPTEN)
		return (-1);

	/* Enable TMC */
	bus_write_4(sc->res[0], TMC_CTL, CTL_TRACECAPTEN);
	if ((bus_read_4(sc->res[0], TMC_CTL) & CTL_TRACECAPTEN) == 0)
		panic("Not enabled\n");

	do {
		reg = bus_read_4(sc->res[0], TMC_STS);
	} while ((reg & STS_TMCREADY) == 1);

	if ((bus_read_4(sc->res[0], TMC_CTL) & CTL_TRACECAPTEN) == 0)
		panic("Not enabled\n");

	dprintf("%s: enabled\n", __func__);

	return (0);
}

static int
tmc_disable(device_t dev)
{
	struct tmc_softc *sc;
	uint32_t reg;

	sc = device_get_softc(dev);

	dprintf("%s\n", __func__);

	reg = bus_read_4(sc->res[0], TMC_CTL);
	reg &= ~CTL_TRACECAPTEN;
	bus_write_4(sc->res[0], TMC_CTL, reg);

	do {
		reg = bus_read_4(sc->res[0], TMC_STS);
	} while ((reg & STS_TMCREADY) == 1);

	return (0);
}

static void
tmc_dump(device_t dev)
{
	struct tmc_softc *sc;
	uint32_t reg;
	size_t hi, lo;
	size_t rrp, rwp;

	sc = device_get_softc(dev);

	lo = bus_read_4(sc->res[0], TMC_RRP);
	hi = bus_read_4(sc->res[0], TMC_RRPHI);
	rrp = lo | (hi << 32);

	lo = bus_read_4(sc->res[0], TMC_RWP);
	hi = bus_read_4(sc->res[0], TMC_RWPHI);
	rwp = lo | (hi << 32);

	reg = bus_read_4(sc->res[0], TMC_DEVID);
	if ((reg & DEVID_CONFIGTYPE_M) == DEVID_CONFIGTYPE_ETR)
		printf("%s%d: STS %x CTL %x RSZ %x RRP %lx RWP %lx AXICTL %x\n",
		    __func__,
		    device_get_unit(dev),
		    bus_read_4(sc->res[0], TMC_STS),
		    bus_read_4(sc->res[0], TMC_CTL),
		    bus_read_4(sc->res[0], TMC_RSZ),
		    rrp, rwp,
		    bus_read_4(sc->res[0], TMC_AXICTL));
}

static int
tmc_configure_etf(device_t dev)
{
	struct tmc_softc *sc;
	uint32_t reg;

	sc = device_get_softc(dev);

	do {
		reg = bus_read_4(sc->res[0], TMC_STS);
	} while ((reg & STS_TMCREADY) == 0);

	bus_write_4(sc->res[0], TMC_MODE, MODE_HW_FIFO);
	bus_write_4(sc->res[0], TMC_FFCR, FFCR_EN_FMT | FFCR_EN_TI);

	tmc_enable(dev);

	return (0);
}

static int
tmc_configure_etr(device_t dev, struct endpoint *endp,
    struct coresight_event *event)
{
	struct tmc_softc *sc;
	uint32_t reg;

	sc = device_get_softc(dev);

	do {
		reg = bus_read_4(sc->res[0], TMC_STS);
	} while ((reg & STS_TMCREADY) == 0);

	/* Configure TMC */
	bus_write_4(sc->res[0], TMC_MODE, MODE_CIRCULAR_BUFFER);

	reg = AXICTL_PROT_CTRL_BIT1;
	reg |= AXICTL_WRBURSTLEN_16;
	if (sc->scatter_gather)
		reg |= AXICTL_SG_MODE;
	/* reg |= AXICTL_AXCACHE_OS; */
	bus_write_4(sc->res[0], TMC_AXICTL, reg);

	reg = FFCR_EN_FMT | FFCR_EN_TI | FFCR_FON_FLIN |
	    FFCR_FON_TRIG_EVT | FFCR_TRIGON_TRIGIN;
	bus_write_4(sc->res[0], TMC_FFCR, reg);

	bus_write_4(sc->res[0], TMC_TRG, 0x3ff);

	if (sc->scatter_gather) {
		dprintf("%s: event->etr.pages %p\n", __func__,
		    event->etr.pages);
		dprintf("%s: event->etr.npages %d\n", __func__,
		    event->etr.npages);
	} else {
		bus_write_4(sc->res[0], TMC_DBALO, event->etr.low);
		bus_write_4(sc->res[0], TMC_DBAHI, event->etr.high);
		bus_write_4(sc->res[0], TMC_RSZ, event->etr.bufsize / 4);
		bus_write_4(sc->res[0], TMC_RRP, event->etr.low);
		bus_write_4(sc->res[0], TMC_RWP, event->etr.low);
	}

	reg = bus_read_4(sc->res[0], TMC_STS);
	reg &= ~STS_FULL;
	bus_write_4(sc->res[0], TMC_STS, reg);

	return (0);
}

static vm_page_t *
tmc_allocate_pgdir(struct tmc_softc *sc, vm_page_t *pages, int nentries,
    int npt)
{
	vm_page_t *pt_dir;
	vm_paddr_t paddr;
	int sgtentry;
	sgte_t *ptr;
	uint32_t dirpg;
	int curpg;
	int type;
	int error;
	int i;

	pt_dir = malloc(sizeof(struct vm_page *) * npt, M_DEVBUF,
	    M_WAITOK | M_ZERO);
	error = tmc_alloc_pages(sc, pt_dir, npt);
	if (error) {
		printf("%s: could not allocate pages\n", __func__);
		return (NULL);
	}

	sgtentry = 0;
	curpg = 0;
	ptr = (sgte_t *)PHYS_TO_DMAP(VM_PAGE_TO_PHYS(pt_dir[0]));
	dirpg = 1;

	for (i = 0; i < nentries - 1; i++) {
		dprintf("entry %d dirpg %d\n", i, dirpg);

		if (sgtentry == (SG_PT_ENTIRES_PER_PAGE - 1)) {
			type = ETR_SG_ET_LINK;
			paddr = VM_PAGE_TO_PHYS(pt_dir[dirpg]);
		} else {
			type = ETR_SG_ET_NORMAL;
			paddr = VM_PAGE_TO_PHYS(pages[curpg]);

#ifdef TMC_DEBUG
			if ((i % 100) == 0)
				dprintf("%s: entry (%d/%d) type %d dirpg %d "
				    "curpg %d paddr %lx\n", __func__, i,
				    nentries, type, dirpg, curpg, paddr);
#endif

			curpg++;
		}

		*ptr = ETR_SG_ENTRY(paddr, type);
		cpu_dcache_wb_range((vm_pointer_t)ptr, sizeof(sgte_t));
		ptr++;

		/* Take next directory page. */
		if (type == ETR_SG_ET_LINK) {
			ptr = (sgte_t *)PHYS_TO_DMAP(
				VM_PAGE_TO_PHYS(pt_dir[dirpg]));
			dirpg++;
		}

		sgtentry = (sgtentry + 1) % SG_PT_ENTIRES_PER_PAGE;
	}

	/* Last entry. */
	paddr = VM_PAGE_TO_PHYS(pages[curpg]);
	*ptr = ETR_SG_ENTRY(paddr, ETR_SG_ET_LAST);
	cpu_dcache_wb_range((vm_pointer_t)ptr, sizeof(sgte_t));

	return (pt_dir);
}

static int
tmc_configure(device_t dev, struct endpoint *endp,
    struct coresight_event *event, struct hwt_context *ctx)
{

	return (0);
}

static int
tmc_setup(device_t dev, struct endpoint *endp, struct coresight_event *event)
{
	struct tmc_softc *sc;
	vm_page_t *pt_dir;
	vm_page_t *pages;
	uint64_t pbase;
	uint32_t reg;
	int nentries;
	int nlinks;
	int npages;
	int npt;

	sc = device_get_softc(dev);

	reg = bus_read_4(sc->res[0], TMC_DEVID);
	if ((reg & DEVID_CONFIGTYPE_M) != DEVID_CONFIGTYPE_ETR)
		return (0);

	if (!sc->scatter_gather)
		return (0);

	npages = event->etr.npages;
	pages = event->etr.pages;

	if (npages == 0 || pages == NULL)
		return (EINVAL);

	nlinks = npages / (SG_PT_ENTIRES_PER_PAGE - 1);
	if (nlinks && ((npages % (SG_PT_ENTIRES_PER_PAGE - 1)) < 2))
		nlinks--;
	nentries = nlinks + npages;

	npt = howmany(nentries, SG_PT_ENTIRES_PER_PAGE);

	dprintf("%s: nentries %d, npt %d\n", __func__, nentries, npt);

	pt_dir = tmc_allocate_pgdir(sc, pages, nentries, npt);
	if (pt_dir == NULL)
		return (ENOMEM);

#ifdef TMC_DEBUG
	ptr = (sgte_t *)PHYS_TO_DMAP(VM_PAGE_TO_PHYS(pt_dir[0]));
	for (i = 0; i < nentries; i++)
		dprintf("%s: entry %x\n", __func__, *ptr++);
#endif

	dprintf("%s: event->etr.pages %p\n", __func__, event->etr.pages);
	dprintf("%s: event->etr.npages %d\n", __func__, event->etr.npages);

	pbase = (uint64_t)VM_PAGE_TO_PHYS(pt_dir[0]);

	dprintf("%s: pbase %lx\n", __func__, pbase);

	bus_write_4(sc->res[0], TMC_DBALO, pbase & 0xffffffff);
	bus_write_4(sc->res[0], TMC_DBAHI, pbase >> 32);
	bus_write_4(sc->res[0], TMC_RSZ, (event->etr.npages * 4096) / 4);

	return (0);
}

static int
tmc_init(device_t dev)
{
	struct tmc_softc *sc;
	uint32_t reg;

	sc = device_get_softc(dev);

	/* Unlock Coresight */
	bus_write_4(sc->res[0], CORESIGHT_LAR, CORESIGHT_UNLOCK);

	/* Unlock TMC */
	bus_write_4(sc->res[0], TMC_LAR, CORESIGHT_UNLOCK);

	reg = bus_read_4(sc->res[0], TMC_DEVID);
	reg &= DEVID_CONFIGTYPE_M;
	switch (reg) {
	case DEVID_CONFIGTYPE_ETR:
		sc->dev_type = CORESIGHT_ETR;
		dprintf(dev, "ETR configuration found\n");
		break;
	case DEVID_CONFIGTYPE_ETF:
		sc->dev_type = CORESIGHT_ETF;
		dprintf(dev, "ETF configuration found\n");
		if (sc->etf_configured == false) {
			tmc_configure_etf(dev);
			sc->etf_configured = true;
		}
		break;
	default:
		sc->dev_type = CORESIGHT_UNKNOWN;
		break;
	}

	return (0);
}

static int
tmc_start(device_t dev, struct endpoint *endp, struct coresight_event *event)
{
	struct tmc_softc *sc;

	sc = device_get_softc(dev);

	if (sc->dev_type == CORESIGHT_ETF)
		return (0);

	KASSERT(sc->dev_type == CORESIGHT_ETR, ("Wrong dev_type"));

	tmc_configure_etr(dev, endp, event);
	tmc_enable(dev);

	return (0);
}

static int
tmc_read(device_t dev, struct endpoint *endp, struct coresight_event *event)
{
	struct tmc_softc *sc;
	vm_page_t page;
	bool found;
	uint64_t lo, hi;
	uint64_t ptr;
	int i;

	sc = device_get_softc(dev);
	if (sc->dev_type == CORESIGHT_ETF)
		return (ENXIO);

	lo = bus_read_4(sc->res[0], TMC_RWP);
	hi = bus_read_4(sc->res[0], TMC_RWPHI);
	ptr = lo | (hi << 32);

	page = PHYS_TO_VM_PAGE(ptr);

	found = false;

	for (i = 0; i < event->etr.npages; i++) {
		if (event->etr.pages[i] == page) {
			found = true;
			break;
		}
	}

	if (found) {
		event->etr.curpage = i;
		event->etr.curpage_offset = ptr & 0xfff;
		dprintf("CUR_PTR %lx, page %d of %d, offset %ld\n",
		    ptr, i, event->etr.npages, event->etr.curpage_offset);

		return (0);
	}

	return (ENOENT);
}

static void
tmc_stop(device_t dev, struct endpoint *endp, struct coresight_event *event)
{
	struct tmc_softc *sc;

	sc = device_get_softc(dev);

	/* ETF configuration is static */
	if (sc->dev_type == CORESIGHT_ETF)
		return;

	KASSERT(sc->dev_type == CORESIGHT_ETR, ("Wrong dev_type"));

	/* Make final readings before stopping TMC. */
	tmc_read(dev, endp, event);

	tmc_disable(dev);
}

static void
tmc_intr(void *arg)
{

	/* TODO */

	panic("unhandled interrupt");
}

int
tmc_attach(device_t dev)
{
	struct coresight_desc desc;
	struct tmc_softc *sc;
	uint32_t reg;

	sc = device_get_softc(dev);
	sc->dev = dev;

	if (bus_alloc_resources(dev, tmc_spec, sc->res) != 0) {
		device_printf(dev, "cannot allocate resources for device\n");
		return (ENXIO);
	}

	if (sc->res[1] != NULL) {
		if (bus_setup_intr(dev, sc->res[1],
		    INTR_TYPE_MISC | INTR_MPSAFE, NULL, tmc_intr, sc,
		    &sc->intrhand)) {
			bus_release_resources(dev, tmc_spec, sc->res);
			device_printf(dev, "cannot setup interrupt handler\n");
			return (ENXIO);
		}
	}

	desc.pdata = sc->pdata;
	desc.dev = dev;

	reg = bus_read_4(sc->res[0], TMC_DEVID);
	reg &= DEVID_CONFIGTYPE_M;
	if (reg == DEVID_CONFIGTYPE_ETR)
		desc.dev_type = CORESIGHT_TMC_ETR;
	else
		desc.dev_type = CORESIGHT_TMC_ETF;

	coresight_register(&desc);

	return (0);
}

int
tmc_detach(device_t dev)
{
	struct tmc_softc *sc;
	int error;

	sc = device_get_softc(dev);

	error = coresight_unregister(dev);

	if (sc->intrhand != NULL)
		bus_teardown_intr(dev, sc->res[1], sc->intrhand);

	bus_release_resources(dev, tmc_spec, sc->res);

	return (error);
}

static device_method_t tmc_methods[] = {
	/* Device interface */
	DEVMETHOD(device_attach,	tmc_attach),
	DEVMETHOD(device_detach,	tmc_detach),

	/* Coresight interface */
	DEVMETHOD(coresight_init,	tmc_init),
	DEVMETHOD(coresight_setup,	tmc_setup),
	DEVMETHOD(coresight_configure,	tmc_configure),
	DEVMETHOD(coresight_start,	tmc_start),
	DEVMETHOD(coresight_stop,	tmc_stop),
	DEVMETHOD(coresight_dump,	tmc_dump),
	DEVMETHOD(coresight_read,	tmc_read),
	DEVMETHOD_END
};

DEFINE_CLASS_0(tmc, tmc_driver, tmc_methods, sizeof(struct tmc_softc));
