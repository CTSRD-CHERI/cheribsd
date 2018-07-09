/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright 2011 Nathan Whitehorn
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_platform.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/module.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/smp.h>

#include <vm/vm.h>
#include <vm/pmap.h>

#include <machine/bus.h>
#include <machine/intr_machdep.h>
#include <machine/md_var.h>
#include <machine/rtas.h>

#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#ifdef POWERNV
#include <powerpc/powernv/opal.h>
#endif

#include "phyp-hvcall.h"
#include "pic_if.h"

#define XICP_PRIORITY	5	/* Random non-zero number */
#define XICP_IPI	2
#define MAX_XICP_IRQS	(1<<24)	/* 24-bit XIRR field */

static int	xicp_probe(device_t);
static int	xicp_attach(device_t);
static int	xics_probe(device_t);
static int	xics_attach(device_t);

static void	xicp_bind(device_t dev, u_int irq, cpuset_t cpumask);
static void	xicp_dispatch(device_t, struct trapframe *);
static void	xicp_enable(device_t, u_int, u_int);
static void	xicp_eoi(device_t, u_int);
static void	xicp_ipi(device_t, u_int);
static void	xicp_mask(device_t, u_int);
static void	xicp_unmask(device_t, u_int);

static device_method_t  xicp_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		xicp_probe),
	DEVMETHOD(device_attach,	xicp_attach),

	/* PIC interface */
	DEVMETHOD(pic_bind,		xicp_bind),
	DEVMETHOD(pic_dispatch,		xicp_dispatch),
	DEVMETHOD(pic_enable,		xicp_enable),
	DEVMETHOD(pic_eoi,		xicp_eoi),
	DEVMETHOD(pic_ipi,		xicp_ipi),
	DEVMETHOD(pic_mask,		xicp_mask),
	DEVMETHOD(pic_unmask,		xicp_unmask),

	DEVMETHOD_END
};

static device_method_t  xics_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		xics_probe),
	DEVMETHOD(device_attach,	xics_attach),

	DEVMETHOD_END
};

struct xicp_softc {
	struct mtx sc_mtx;
	struct resource *mem[MAXCPU];

	int cpu_range[2];

	int ibm_int_on;
	int ibm_int_off;
	int ibm_get_xive;
	int ibm_set_xive;

	/* XXX: inefficient -- hash table? tree? */
	struct {
		int irq;
		int vector;
		int cpu;
	} intvecs[256];
	int nintvecs;
};

static driver_t xicp_driver = {
	"xicp",
	xicp_methods,
	sizeof(struct xicp_softc)
};

static driver_t xics_driver = {
	"xics",
	xics_methods,
	0
};

static devclass_t xicp_devclass;
static devclass_t xics_devclass;

EARLY_DRIVER_MODULE(xicp, ofwbus, xicp_driver, xicp_devclass, 0, 0,
    BUS_PASS_INTERRUPT-1);
EARLY_DRIVER_MODULE(xics, ofwbus, xics_driver, xics_devclass, 0, 0,
    BUS_PASS_INTERRUPT);

#ifdef POWERNV
static struct resource *
xicp_mem_for_cpu(int cpu)
{
	device_t dev;
	struct xicp_softc *sc;
	int i;

	for (i = 0; (dev = devclass_get_device(xicp_devclass, i)) != NULL; i++){
		sc = device_get_softc(dev);
		if (cpu >= sc->cpu_range[0] && cpu < sc->cpu_range[1])
			return (sc->mem[cpu - sc->cpu_range[0]]);
	}

	return (NULL);
}
#endif

static int
xicp_probe(device_t dev)
{

	if (!ofw_bus_is_compatible(dev, "ibm,ppc-xicp"))
		return (ENXIO);

	device_set_desc(dev, "External Interrupt Presentation Controller");
	return (BUS_PROBE_GENERIC);
}

static int
xics_probe(device_t dev)
{

	if (!ofw_bus_is_compatible(dev, "ibm,ppc-xics"))
		return (ENXIO);

	device_set_desc(dev, "External Interrupt Source Controller");
	return (BUS_PROBE_GENERIC);
}

static int
xicp_attach(device_t dev)
{
	struct xicp_softc *sc = device_get_softc(dev);
	phandle_t phandle = ofw_bus_get_node(dev);

	if (rtas_exists()) {
		sc->ibm_int_on = rtas_token_lookup("ibm,int-on");
		sc->ibm_int_off = rtas_token_lookup("ibm,int-off");
		sc->ibm_set_xive = rtas_token_lookup("ibm,set-xive");
		sc->ibm_get_xive = rtas_token_lookup("ibm,get-xive");
#ifdef POWERNV
	} else if (opal_check() == 0) {
		/* No init needed */
#endif
	} else {
		device_printf(dev, "Cannot attach without RTAS or OPAL\n");
		return (ENXIO);
	}

	if (OF_hasprop(phandle, "ibm,interrupt-server-ranges")) {
		OF_getencprop(phandle, "ibm,interrupt-server-ranges",
		    sc->cpu_range, sizeof(sc->cpu_range));
		sc->cpu_range[1] += sc->cpu_range[0];
		device_printf(dev, "Handling CPUs %d-%d\n", sc->cpu_range[0],
		    sc->cpu_range[1]-1);
	} else {
		sc->cpu_range[0] = 0;
		sc->cpu_range[1] = mp_ncpus;
	}

#ifdef POWERNV
	if (mfmsr() & PSL_HV) {
		int i;

		for (i = 0; i < sc->cpu_range[1] - sc->cpu_range[0]; i++) {
			sc->mem[i] = bus_alloc_resource_any(dev, SYS_RES_MEMORY,
			    &i, RF_ACTIVE);
			if (sc->mem[i] == NULL) {
				device_printf(dev, "Could not alloc mem "
				    "resource %d\n", i);
				return (ENXIO);
			}

			/* Unmask interrupts on all cores */
			bus_write_1(sc->mem[i], 4, 0xff);
			bus_write_1(sc->mem[i], 12, 0xff);
		}
	}
#endif

	mtx_init(&sc->sc_mtx, "XICP", NULL, MTX_DEF);
	sc->nintvecs = 0;

	powerpc_register_pic(dev, OF_xref_from_node(phandle), MAX_XICP_IRQS,
	    1 /* Number of IPIs */, FALSE);
	root_pic = dev;

	return (0);
}

static int
xics_attach(device_t dev)
{
	phandle_t phandle = ofw_bus_get_node(dev);

	/* The XICP (root PIC) will handle all our interrupts */
	powerpc_register_pic(root_pic, OF_xref_from_node(phandle),
	    MAX_XICP_IRQS, 1 /* Number of IPIs */, FALSE);

	return (0);
}

/*
 * PIC I/F methods.
 */

static void
xicp_bind(device_t dev, u_int irq, cpuset_t cpumask)
{
	struct xicp_softc *sc = device_get_softc(dev);
	cell_t status, cpu;
	int ncpus, i, error;

	/*
	 * This doesn't appear to actually support affinity groups, so pick a
	 * random CPU.
	 */
	ncpus = 0;
	CPU_FOREACH(cpu)
		if (CPU_ISSET(cpu, &cpumask)) ncpus++;

	i = mftb() % ncpus;
	ncpus = 0;
	CPU_FOREACH(cpu) {
		if (!CPU_ISSET(cpu, &cpumask))
			continue;
		if (ncpus == i)
			break;
		ncpus++;
	}
	
	/* XXX: super inefficient */
	for (i = 0; i < sc->nintvecs; i++) {
		if (sc->intvecs[i].irq == irq) {
			sc->intvecs[i].cpu = cpu;
			break;
		}
	}
	KASSERT(i < sc->nintvecs, ("Binding non-configured interrupt"));

	if (rtas_exists())
		error = rtas_call_method(sc->ibm_set_xive, 3, 1, irq, cpu,
		    XICP_PRIORITY, &status);
#ifdef POWERNV
	else
		error = opal_call(OPAL_SET_XIVE, irq, cpu << 2, XICP_PRIORITY);
#endif

	if (error < 0)
		panic("Cannot bind interrupt %d to CPU %d", irq, cpu);
}

static void
xicp_dispatch(device_t dev, struct trapframe *tf)
{
	struct xicp_softc *sc;
	struct resource *regs = NULL;
	uint64_t xirr, junk;
	int i;

#ifdef POWERNV
	if (mfmsr() & PSL_HV) {
		regs = xicp_mem_for_cpu(PCPU_GET(cpuid));
		KASSERT(regs != NULL,
		    ("Can't find regs for CPU %d", PCPU_GET(cpuid)));
	}
#endif

	sc = device_get_softc(dev);
	for (;;) {
		/* Return value in R4, use the PFT call */
		if (regs) {
			xirr = bus_read_4(regs, 4);
		} else {
			/* Return value in R4, use the PFT call */
			phyp_pft_hcall(H_XIRR, 0, 0, 0, 0, &xirr, &junk, &junk);
		}
		xirr &= 0x00ffffff;

		if (xirr == 0) { /* No more pending interrupts? */
			if (regs)
				bus_write_1(regs, 4, 0xff);
			else
				phyp_hcall(H_CPPR, (uint64_t)0xff);
			break;
		}
		if (xirr == XICP_IPI) {		/* Magic number for IPIs */
			xirr = MAX_XICP_IRQS;	/* Map to FreeBSD magic */

			/* Clear IPI */
			if (regs)
				bus_write_1(regs, 12, 0xff);
			else
				phyp_hcall(H_IPI, (uint64_t)(PCPU_GET(cpuid)),
				    0xff);
		}

		/* XXX: super inefficient */
		for (i = 0; i < sc->nintvecs; i++) {
			if (sc->intvecs[i].irq == xirr)
				break;
		}

		KASSERT(i < sc->nintvecs, ("Unmapped XIRR"));
		powerpc_dispatch_intr(sc->intvecs[i].vector, tf);
	}
}

static void
xicp_enable(device_t dev, u_int irq, u_int vector)
{
	struct xicp_softc *sc;
	cell_t status, cpu;

	sc = device_get_softc(dev);

	KASSERT(sc->nintvecs + 1 < nitems(sc->intvecs),
		("Too many XICP interrupts"));

	/* Bind to this CPU to start: distrib. ID is last entry in gserver# */
	cpu = PCPU_GET(cpuid);

	mtx_lock(&sc->sc_mtx);
	sc->intvecs[sc->nintvecs].irq = irq;
	sc->intvecs[sc->nintvecs].vector = vector;
	sc->intvecs[sc->nintvecs].cpu = cpu;
	mb();
	sc->nintvecs++;
	mtx_unlock(&sc->sc_mtx);

	/* IPIs are also enabled */
	if (irq == MAX_XICP_IRQS)
		return;

	if (rtas_exists()) {
		rtas_call_method(sc->ibm_set_xive, 3, 1, irq, cpu,
		    XICP_PRIORITY, &status);
		xicp_unmask(dev, irq);
#ifdef POWERNV
	} else {
		status = opal_call(OPAL_SET_XIVE, irq, cpu << 2, XICP_PRIORITY);
		/* Unmask implicit for OPAL */

		if (status != 0)
			panic("OPAL_SET_XIVE IRQ %d -> cpu %d failed: %d", irq,
			    cpu, status);
#endif
	}
}

static void
xicp_eoi(device_t dev, u_int irq)
{
	uint64_t xirr;

	if (irq == MAX_XICP_IRQS) /* Remap IPI interrupt to internal value */
		irq = XICP_IPI;
	xirr = irq | (XICP_PRIORITY << 24);

#ifdef POWERNV
	if (mfmsr() & PSL_HV)
		bus_write_4(xicp_mem_for_cpu(PCPU_GET(cpuid)), 4, xirr);
	else
#endif
		phyp_hcall(H_EOI, xirr);
}

static void
xicp_ipi(device_t dev, u_int cpu)
{

#ifdef POWERNV
	if (mfmsr() & PSL_HV)
		bus_write_1(xicp_mem_for_cpu(cpu), 12, XICP_PRIORITY);
	else
#endif
		phyp_hcall(H_IPI, (uint64_t)cpu, XICP_PRIORITY);
}

static void
xicp_mask(device_t dev, u_int irq)
{
	struct xicp_softc *sc = device_get_softc(dev);
	cell_t status;

	if (irq == MAX_XICP_IRQS)
		return;

	if (rtas_exists()) {
		rtas_call_method(sc->ibm_int_off, 1, 1, irq, &status);
#ifdef POWERNV
	} else {
		int i;

		for (i = 0; i < sc->nintvecs; i++) {
			if (sc->intvecs[i].irq == irq) {
				break;
			}
		}
		KASSERT(i < sc->nintvecs, ("Masking unconfigured interrupt"));
		opal_call(OPAL_SET_XIVE, irq, sc->intvecs[i].cpu << 2, 0xff);
#endif
	}
}

static void
xicp_unmask(device_t dev, u_int irq)
{
	struct xicp_softc *sc = device_get_softc(dev);
	cell_t status;

	if (irq == MAX_XICP_IRQS)
		return;

	if (rtas_exists()) {
		rtas_call_method(sc->ibm_int_on, 1, 1, irq, &status);
#ifdef POWERNV
	} else {
		int i;

		for (i = 0; i < sc->nintvecs; i++) {
			if (sc->intvecs[i].irq == irq) {
				break;
			}
		}
		KASSERT(i < sc->nintvecs, ("Unmasking unconfigured interrupt"));
		opal_call(OPAL_SET_XIVE, irq, sc->intvecs[i].cpu << 2,
		    XICP_PRIORITY);
#endif
	}
}

