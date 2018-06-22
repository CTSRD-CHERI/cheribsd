/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2005 Olivier Houchard.  All rights reserved.
 * Copyright (c) 2010 Greg Ansley.  All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "opt_platform.h"

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/devmap.h>

#include <vm/vm.h>
#include <vm/vm_kern.h>
#include <vm/pmap.h>
#include <vm/vm_page.h>
#include <vm/vm_extern.h>

#include <machine/armreg.h>
#define	_ARM32_BUS_DMA_PRIVATE
#include <machine/bus.h>
#include <machine/intr.h>

#include <arm/at91/at91var.h>
#include <arm/at91/at91_pmcvar.h>
#include <arm/at91/at91_aicreg.h>

uint32_t at91_master_clock;

struct arm32_dma_range *
bus_dma_get_range(void)
{

	return (NULL);
}

int
bus_dma_get_range_nb(void)
{
	return (0);
}

#ifndef FDT

static struct at91_softc *at91_softc;

static void at91_eoi(void *);

static int
at91_probe(device_t dev)
{

	device_set_desc(dev, soc_info.name);
	return (BUS_PROBE_NOWILDCARD);
}

static void
at91_identify(driver_t *drv, device_t parent)
{
	
	BUS_ADD_CHILD(parent, 0, "atmelarm", 0);
}

static void
at91_cpu_add_builtin_children(device_t dev, const struct cpu_devs *walker)
{
	int i;

	for (i = 0; walker->name; i++, walker++) {
		at91_add_child(dev, i, walker->name, walker->unit,
		    walker->mem_base, walker->mem_len, walker->irq0,
		    walker->irq1, walker->irq2);
	}
}

static int
at91_attach(device_t dev)
{
	struct at91_softc *sc = device_get_softc(dev);

	arm_post_filter = at91_eoi;

	at91_softc = sc;
	sc->sc_st = arm_base_bs_tag;
	sc->sc_sh = AT91_BASE;
	sc->sc_aic_sh = AT91_BASE + AT91_SYS_BASE;
	sc->dev = dev;

	sc->sc_irq_rman.rm_type = RMAN_ARRAY;
	sc->sc_irq_rman.rm_descr = "AT91 IRQs";
	if (rman_init(&sc->sc_irq_rman) != 0 ||
	    rman_manage_region(&sc->sc_irq_rman, 1, 31) != 0)
		panic("at91_attach: failed to set up IRQ rman");

	sc->sc_mem_rman.rm_type = RMAN_ARRAY;
	sc->sc_mem_rman.rm_descr = "AT91 Memory";
	if (rman_init(&sc->sc_mem_rman) != 0)
		panic("at91_attach: failed to set up memory rman");
	/*
	 * Manage the physical space, defined as being everything that isn't
	 * DRAM.
	 */
	if (rman_manage_region(&sc->sc_mem_rman, 0, PHYSADDR - 1) != 0)
		panic("at91_attach: failed to set up memory rman");
	if (rman_manage_region(&sc->sc_mem_rman, PHYSADDR + (256 << 20),
	    0xfffffffful) != 0)
		panic("at91_attach: failed to set up memory rman");

        /*
         * Add this device's children...
         */
	at91_cpu_add_builtin_children(dev, soc_info.soc_data->soc_children);
	soc_info.soc_data->soc_clock_init();

	bus_generic_probe(dev);
	bus_generic_attach(dev);
	enable_interrupts(PSR_I | PSR_F);
	return (0);
}

static struct resource *
at91_alloc_resource(device_t dev, device_t child, int type, int *rid,
    rman_res_t start, rman_res_t end, rman_res_t count, u_int flags)
{
	struct at91_softc *sc = device_get_softc(dev);
	struct resource_list_entry *rle;
	struct at91_ivar *ivar = device_get_ivars(child);
	struct resource_list *rl = &ivar->resources;
	bus_space_handle_t bsh;

	if (device_get_parent(child) != dev)
		return (BUS_ALLOC_RESOURCE(device_get_parent(dev), child,
		    type, rid, start, end, count, flags));
	
	rle = resource_list_find(rl, type, *rid);
	if (rle == NULL)
		return (NULL);
	if (rle->res)
		panic("Resource rid %d type %d already in use", *rid, type);
	if (RMAN_IS_DEFAULT_RANGE(start, end)) {
		start = rle->start;
		count = ulmax(count, rle->count);
		end = ulmax(rle->end, start + count - 1);
	}
	switch (type)
	{
	case SYS_RES_IRQ:
		rle->res = rman_reserve_resource(&sc->sc_irq_rman,
		    start, end, count, flags, child);
		break;
	case SYS_RES_MEMORY:
		rle->res = rman_reserve_resource(&sc->sc_mem_rman,
		    start, end, count, flags, child);
		if (rle->res != NULL) {
			bus_space_map(arm_base_bs_tag, start,
			    rman_get_size(rle->res), 0, &bsh);
			rman_set_bustag(rle->res, arm_base_bs_tag);
			rman_set_bushandle(rle->res, bsh);
		}
		break;
	}
	if (rle->res) {
		rle->start = rman_get_start(rle->res);
		rle->end = rman_get_end(rle->res);
		rle->count = count;
		rman_set_rid(rle->res, *rid);
	}
	return (rle->res);
}

static struct resource_list *
at91_get_resource_list(device_t dev, device_t child)
{
	struct at91_ivar *ivar;

	ivar = device_get_ivars(child);
	return (&(ivar->resources));
}

static int
at91_release_resource(device_t dev, device_t child, int type,
    int rid, struct resource *r)
{
	struct resource_list *rl;
	struct resource_list_entry *rle;

	rl = at91_get_resource_list(dev, child);
	if (rl == NULL)
		return (EINVAL);
	rle = resource_list_find(rl, type, rid);
	if (rle == NULL)
		return (EINVAL);
	rman_release_resource(r);
	rle->res = NULL;
	return (0);
}

static int
at91_setup_intr(device_t dev, device_t child,
    struct resource *ires, int flags, driver_filter_t *filt,
    driver_intr_t *intr, void *arg, void **cookiep)
{
	int error;

	if (rman_get_start(ires) == AT91_IRQ_SYSTEM && filt == NULL)
		panic("All system interrupt ISRs must be FILTER");
	error = BUS_SETUP_INTR(device_get_parent(dev), child, ires, flags,
	    filt, intr, arg, cookiep);
	if (error)
		return (error);

	return (0);
}

static int
at91_teardown_intr(device_t dev, device_t child, struct resource *res,
    void *cookie)
{
	struct at91_softc *sc = device_get_softc(dev);

	bus_space_write_4(sc->sc_st, sc->sc_aic_sh, IC_IDCR,
	    1 << rman_get_start(res));
	return (BUS_TEARDOWN_INTR(device_get_parent(dev), child, res, cookie));
}

static int
at91_activate_resource(device_t bus, device_t child, int type, int rid,
    struct resource *r)
{
#if 0
	rman_res_t p;
	int error;
	
	if (type == SYS_RES_MEMORY) {
		error = bus_space_map(rman_get_bustag(r),
		    rman_get_bushandle(r), rman_get_size(r), 0, &p);
		if (error)
			return (error);
		rman_set_bushandle(r, p);
	}
#endif	
	return (rman_activate_resource(r));
}

static int
at91_print_child(device_t dev, device_t child)
{
	struct at91_ivar *ivars;
	struct resource_list *rl;
	int retval = 0;

	ivars = device_get_ivars(child);
	rl = &ivars->resources;

	retval += bus_print_child_header(dev, child);

	retval += resource_list_print_type(rl, "port", SYS_RES_IOPORT, "%#jx");
	retval += resource_list_print_type(rl, "mem", SYS_RES_MEMORY, "%#jx");
	retval += resource_list_print_type(rl, "irq", SYS_RES_IRQ, "%jd");
	if (device_get_flags(dev))
		retval += printf(" flags %#x", device_get_flags(dev));

	retval += bus_print_child_footer(dev, child);

	return (retval);
}

static void
at91_eoi(void *unused)
{
	bus_space_write_4(at91_softc->sc_st, at91_softc->sc_aic_sh,
	    IC_EOICR, 0);
}

void
at91_add_child(device_t dev, int prio, const char *name, int unit,
    bus_addr_t addr, bus_size_t size, int irq0, int irq1, int irq2)
{
	device_t kid;
	struct at91_ivar *ivar;

	kid = device_add_child_ordered(dev, prio, name, unit);
	if (kid == NULL) {
	    printf("Can't add child %s%d ordered\n", name, unit);
	    return;
	}
	ivar = malloc(sizeof(*ivar), M_DEVBUF, M_NOWAIT | M_ZERO);
	if (ivar == NULL) {
		device_delete_child(dev, kid);
		printf("Can't add alloc ivar\n");
		return;
	}
	device_set_ivars(kid, ivar);
	resource_list_init(&ivar->resources);
	if (irq0 != -1) {
		bus_set_resource(kid, SYS_RES_IRQ, 0, irq0, 1);
		if (irq0 != AT91_IRQ_SYSTEM)
			at91_pmc_clock_add(device_get_nameunit(kid), irq0, 0);
	}
	if (irq1 != 0)
		bus_set_resource(kid, SYS_RES_IRQ, 1, irq1, 1);
	if (irq2 != 0)
		bus_set_resource(kid, SYS_RES_IRQ, 2, irq2, 1);
	/*
	 * Special case for on-board devices. These have their address
	 * defined relative to AT91_PA_BASE in all the register files we
	 * have. We could change this, but that's a lot of effort which
	 * will be obsoleted when FDT arrives.
	 */
	if (addr != 0 && addr < 0x10000000 && addr >= 0x0f000000) 
		addr += AT91_PA_BASE;
	if (addr != 0)
		bus_set_resource(kid, SYS_RES_MEMORY, 0, addr, size);
}

static device_method_t at91_methods[] = {
	DEVMETHOD(device_probe, at91_probe),
	DEVMETHOD(device_attach, at91_attach),
	DEVMETHOD(device_identify, at91_identify),

	DEVMETHOD(bus_alloc_resource, at91_alloc_resource),
	DEVMETHOD(bus_setup_intr, at91_setup_intr),
	DEVMETHOD(bus_teardown_intr, at91_teardown_intr),
	DEVMETHOD(bus_activate_resource, at91_activate_resource),
	DEVMETHOD(bus_deactivate_resource, bus_generic_deactivate_resource),
	DEVMETHOD(bus_get_resource_list,at91_get_resource_list),
	DEVMETHOD(bus_set_resource,	bus_generic_rl_set_resource),
	DEVMETHOD(bus_get_resource,	bus_generic_rl_get_resource),
	DEVMETHOD(bus_release_resource,	at91_release_resource),
	DEVMETHOD(bus_print_child,	at91_print_child),

	{0, 0},
};

static driver_t at91_driver = {
	"atmelarm",
	at91_methods,
	sizeof(struct at91_softc),
};

static devclass_t at91_devclass;

DRIVER_MODULE(atmelarm, nexus, at91_driver, at91_devclass, 0, 0);
#endif
