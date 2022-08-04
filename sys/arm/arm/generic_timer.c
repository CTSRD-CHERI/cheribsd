/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2011 The FreeBSD Foundation
 * Copyright (c) 2013 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * Based on mpcore_timer.c developed by Ben Gray <ben.r.gray@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the company nor the name of the author may be used to
 *    endorse or promote products derived from this software without specific
 *    prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/**
 *      Cortex-A7, Cortex-A15, ARMv8 and later Generic Timer
 */

#include "opt_acpi.h"
#include "opt_platform.h"

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/rman.h>
#include <sys/timeet.h>
#include <sys/timetc.h>
#include <sys/smp.h>
#include <sys/vdso.h>
#include <sys/watchdog.h>
#include <machine/bus.h>
#include <machine/cpu.h>
#include <machine/intr.h>
#include <machine/md_var.h>
#include <machine/machdep.h> /* For arm_set_delay */

#if defined(__aarch64__)
#include <machine/undefined.h>
#endif

#ifdef FDT
#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#endif

#ifdef DEV_ACPI
#include <contrib/dev/acpica/include/acpi.h>
#include <dev/acpica/acpivar.h>
#endif

#include "pic_if.h"

#define	GT_PHYS_SECURE		0
#define	GT_PHYS_NONSECURE	1
#define	GT_VIRT			2
#define	GT_HYP			3
#define	GT_IRQ_COUNT		4

#define	GT_CTRL_ENABLE		(1 << 0)
#define	GT_CTRL_INT_MASK	(1 << 1)
#define	GT_CTRL_INT_STAT	(1 << 2)
#define	GT_REG_CTRL		0
#define	GT_REG_TVAL		1

#define	GT_CNTKCTL_PL0PTEN	(1 << 9) /* PL0 Physical timer reg access */
#define	GT_CNTKCTL_PL0VTEN	(1 << 8) /* PL0 Virtual timer reg access */
#define	GT_CNTKCTL_EVNTI	(0xf << 4) /* Virtual counter event bits */
#define	GT_CNTKCTL_EVNTDIR	(1 << 3) /* Virtual counter event transition */
#define	GT_CNTKCTL_EVNTEN	(1 << 2) /* Enables virtual counter events */
#define	GT_CNTKCTL_PL0VCTEN	(1 << 1) /* PL0 CNTVCT and CNTFRQ access */
#define	GT_CNTKCTL_PL0PCTEN	(1 << 0) /* PL0 CNTPCT and CNTFRQ access */

#ifdef __arm__
extern char hypmode_enabled[];
#endif

struct arm_tmr_softc;

struct arm_tmr_irq {
	struct resource		*res;
	void			*ihl;
	struct arm_tmr_softc	*sc;
#if defined(__aarch64__)
	struct intr_irqsrc	isrc;
#endif
	u_int			flags;
#define	TMR_IRQ_PHYS	(1 << 0)
#define	TMR_IRQ_ET	(1 << 1)
#define	TMR_IRQ_CHILD	(1 << 2)
	u_int			irq;
};

struct arm_tmr_softc {
	struct arm_tmr_irq	irqs[GT_IRQ_COUNT];
	uint64_t		(*get_cntxct)(bool);
	uint32_t		clkfreq;
	struct eventtimer	et;
	bool			physical;
#if defined(__aarch64__)
	struct rman		intr_rman;
#endif
};

static struct arm_tmr_softc *arm_tmr_sc = NULL;

static struct resource_spec timer_spec[] = {
	{ SYS_RES_IRQ,	GT_PHYS_SECURE,		RF_ACTIVE },
	{ SYS_RES_IRQ,	GT_PHYS_NONSECURE,	RF_ACTIVE },
	{ SYS_RES_IRQ,	GT_VIRT,		RF_ACTIVE | RF_OPTIONAL },
	{ SYS_RES_IRQ,	GT_HYP,			RF_ACTIVE | RF_OPTIONAL	},
	{ -1, 0 }
};

struct arm_tmr_ivar {
	struct resource_list	rl;
};

static uint32_t arm_tmr_fill_vdso_timehands(struct vdso_timehands *vdso_th,
    struct timecounter *tc);
static void arm_tmr_do_delay(int usec, void *);

static timecounter_get_t arm_tmr_get_timecount;

static struct timecounter arm_tmr_timecount = {
	.tc_name           = "ARM MPCore Timecounter",
	.tc_get_timecount  = arm_tmr_get_timecount,
	.tc_poll_pps       = NULL,
	.tc_counter_mask   = ~0u,
	.tc_frequency      = 0,
	.tc_quality        = 1000,
	.tc_fill_vdso_timehands = arm_tmr_fill_vdso_timehands,
};

static device_t arm_tmr_dev;

#ifdef __arm__
#define	get_el0(x)	cp15_## x ##_get()
#define	get_el1(x)	cp15_## x ##_get()
#define	set_el0(x, val)	cp15_## x ##_set(val)
#define	set_el1(x, val)	cp15_## x ##_set(val)
#else /* __aarch64__ */
#define	get_el0(x)	READ_SPECIALREG(x ##_el0)
#define	get_el1(x)	READ_SPECIALREG(x ##_el1)
#define	set_el0(x, val)	WRITE_SPECIALREG(x ##_el0, val)
#define	set_el1(x, val)	WRITE_SPECIALREG(x ##_el1, val)
#endif

static int
get_freq(void)
{
	return (get_el0(cntfrq));
}

static uint64_t
get_cntxct_a64_unstable(bool physical)
{
	uint64_t val
;
	isb();
	if (physical) {
		do {
			val = get_el0(cntpct);
		}
		while (((val + 1) & 0x7FF) <= 1);
	}
	else {
		do {
			val = get_el0(cntvct);
		}
		while (((val + 1) & 0x7FF) <= 1);
	}

	return (val);
}

static uint64_t
get_cntxct(bool physical)
{
	uint64_t val;

	isb();
	if (physical)
		val = get_el0(cntpct);
	else
		val = get_el0(cntvct);

	return (val);
}

static int
set_ctrl(uint32_t val, bool physical)
{

	if (physical)
		set_el0(cntp_ctl, val);
	else
		set_el0(cntv_ctl, val);
	isb();

	return (0);
}

static int
set_tval(uint32_t val, bool physical)
{

	if (physical)
		set_el0(cntp_tval, val);
	else
		set_el0(cntv_tval, val);
	isb();

	return (0);
}

static int
get_ctrl(bool physical)
{
	uint32_t val;

	if (physical)
		val = get_el0(cntp_ctl);
	else
		val = get_el0(cntv_ctl);

	return (val);
}

static void
setup_user_access(void *arg __unused)
{
	uint32_t cntkctl;

	cntkctl = get_el1(cntkctl);
	cntkctl &= ~(GT_CNTKCTL_PL0PTEN | GT_CNTKCTL_PL0VTEN |
	    GT_CNTKCTL_EVNTEN);
	if (arm_tmr_sc->physical) {
		cntkctl |= GT_CNTKCTL_PL0PCTEN;
		cntkctl &= ~GT_CNTKCTL_PL0VCTEN;
	} else {
		cntkctl |= GT_CNTKCTL_PL0VCTEN;
		cntkctl &= ~GT_CNTKCTL_PL0PCTEN;
	}
	set_el1(cntkctl, cntkctl);
	isb();
}

#ifdef __aarch64__
static int
cntpct_handler(vm_offset_t va, uint32_t insn, struct trapframe *frame,
    uint32_t esr)
{
	uint64_t val;
	int reg;

	if ((insn & MRS_MASK) != MRS_VALUE)
		return (0);

	if (MRS_SPECIAL(insn) != MRS_SPECIAL(CNTPCT_EL0))
		return (0);

	reg = MRS_REGISTER(insn);
	val = READ_SPECIALREG(cntvct_el0);
	if (reg < nitems(frame->tf_x)) {
		frame->tf_x[reg] = val;
	} else if (reg == 30) {
		frame->tf_lr = val;
	}

	/*
	 * We will handle this instruction, move to the next so we
	 * don't trap here again.
	 */
	frame->tf_elr += INSN_SIZE;

	return (1);
}
#endif

static void
tmr_setup_user_access(void *arg __unused)
{
#ifdef __aarch64__
	int emulate;
#endif

	if (arm_tmr_sc != NULL) {
		smp_rendezvous(NULL, setup_user_access, NULL, NULL);
#ifdef __aarch64__
		if (TUNABLE_INT_FETCH("hw.emulate_phys_counter", &emulate) &&
		    emulate != 0) {
			install_undef_handler(true, cntpct_handler);
		}
#endif
	}
}
SYSINIT(tmr_ua, SI_SUB_SMP, SI_ORDER_ANY, tmr_setup_user_access, NULL);

static unsigned
arm_tmr_get_timecount(struct timecounter *tc)
{

	return (arm_tmr_sc->get_cntxct(arm_tmr_sc->physical));
}

static int
arm_tmr_start(struct eventtimer *et, sbintime_t first,
    sbintime_t period __unused)
{
	struct arm_tmr_softc *sc;
	int counts, ctrl;

	sc = (struct arm_tmr_softc *)et->et_priv;

	if (first != 0) {
		counts = ((uint32_t)et->et_frequency * first) >> 32;
		ctrl = get_ctrl(sc->physical);
		ctrl &= ~GT_CTRL_INT_MASK;
		ctrl |= GT_CTRL_ENABLE;
		set_tval(counts, sc->physical);
		set_ctrl(ctrl, sc->physical);
		return (0);
	}

	return (EINVAL);

}

static void
arm_tmr_disable(bool physical)
{
	int ctrl;

	ctrl = get_ctrl(physical);
	ctrl &= ~GT_CTRL_ENABLE;
	set_ctrl(ctrl, physical);
}

static int
arm_tmr_stop(struct eventtimer *et)
{
	struct arm_tmr_softc *sc;

	sc = (struct arm_tmr_softc *)et->et_priv;
	arm_tmr_disable(sc->physical);

	return (0);
}

static int
arm_tmr_intr(void *arg)
{
	struct arm_tmr_softc *sc;
	struct arm_tmr_irq *irq;
	struct trapframe *tf;
	int ctrl;
	bool physical, mask;

	irq = (struct arm_tmr_irq *)arg;

	if ((irq->flags & TMR_IRQ_CHILD) != 0) {
		/* The child should manage masking the interrupt */
		mask = false;
		tf = curthread->td_intr_frame;
		if (intr_isrc_dispatch(&irq->isrc, tf) != 0) {
			printf("Stray timer irq %u\n", irq->irq);
			mask = true;
		}
	} else {
		mask = true;
	}

	if (mask) {
		physical = (irq->flags & TMR_IRQ_PHYS) != 0;

		ctrl = get_ctrl(physical);
		if (ctrl & GT_CTRL_INT_STAT) {
			ctrl |= GT_CTRL_INT_MASK;
			set_ctrl(ctrl, physical);
		}
	}

	if ((irq->flags & TMR_IRQ_ET) != 0) {
		sc = irq->sc;
		if (sc->et.et_active)
			sc->et.et_event_cb(&sc->et, sc->et.et_arg);
	}

	return (FILTER_HANDLED);
}

#ifdef FDT
static int
arm_tmr_fdt_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_is_compatible(dev, "arm,armv8-timer")) {
		device_set_desc(dev, "ARMv8 Generic Timer");
		return (BUS_PROBE_DEFAULT);
	} else if (ofw_bus_is_compatible(dev, "arm,armv7-timer")) {
		device_set_desc(dev, "ARMv7 Generic Timer");
		return (BUS_PROBE_DEFAULT);
	}

	return (ENXIO);
}
#endif

#ifdef DEV_ACPI
static void
arm_tmr_acpi_add_irq(device_t parent, device_t dev, int rid, u_int irq)
{

	BUS_SET_RESOURCE(parent, dev, SYS_RES_IRQ, rid, irq, 1);
}

static void
arm_tmr_acpi_identify(driver_t *driver, device_t parent)
{
	ACPI_TABLE_GTDT *gtdt;
	vm_paddr_t physaddr;
	device_t dev;

	physaddr = acpi_find_table(ACPI_SIG_GTDT);
	if (physaddr == 0)
		return;

	gtdt = acpi_map_table(physaddr, ACPI_SIG_GTDT);
	if (gtdt == NULL) {
		device_printf(parent, "gic: Unable to map the GTDT\n");
		return;
	}

	dev = BUS_ADD_CHILD(parent, BUS_PASS_TIMER + BUS_PASS_ORDER_MIDDLE,
	    "generic_timer", -1);
	if (dev == NULL) {
		device_printf(parent, "add gic child failed\n");
		goto out;
	}

	arm_tmr_acpi_add_irq(parent, dev, GT_PHYS_SECURE,
	    gtdt->SecureEl1Interrupt);
	arm_tmr_acpi_add_irq(parent, dev, GT_PHYS_NONSECURE,
	    gtdt->NonSecureEl1Interrupt);
	arm_tmr_acpi_add_irq(parent, dev, GT_VIRT,
	    gtdt->VirtualTimerInterrupt);

out:
	acpi_unmap_table(gtdt);
}

static int
arm_tmr_acpi_probe(device_t dev)
{

	device_set_desc(dev, "ARM Generic Timer");
	return (BUS_PROBE_NOWILDCARD);
}
#endif

#if defined(__aarch64__)
static void
arm_tmr_add_vtimer(device_t dev)
{
	struct arm_tmr_ivar *devi;
	device_t child;

	child = device_add_child(dev, "vtimer", -1);
	if (child == NULL) {
		device_printf(dev, "Could not add vtimer child\n");
		return;
	}

	devi = malloc(sizeof(*devi), M_DEVBUF, M_WAITOK | M_ZERO);
	resource_list_init(&devi->rl);
	device_set_ivars(child, devi);

	BUS_SET_RESOURCE(dev, child, SYS_RES_IRQ, 0, GT_VIRT, 1);
}
#endif

static int
arm_tmr_attach(device_t dev)
{
	struct arm_tmr_softc *sc;
	struct resource *res[GT_IRQ_COUNT];
	const char *name;
#ifdef FDT
	phandle_t node;
	pcell_t clock;
#endif
	int error;
	int i;

	sc = device_get_softc(dev);
	if (arm_tmr_sc)
		return (ENXIO);

	sc->get_cntxct = &get_cntxct;
#ifdef FDT
	/* Get the base clock frequency */
	node = ofw_bus_get_node(dev);
	if (node > 0) {
		error = OF_getencprop(node, "clock-frequency", &clock,
		    sizeof(clock));
		if (error > 0)
			sc->clkfreq = clock;

		if (OF_hasprop(node, "allwinner,sun50i-a64-unstable-timer")) {
			sc->get_cntxct = &get_cntxct_a64_unstable;
			if (bootverbose)
				device_printf(dev,
				    "Enabling allwinner unstable timer workaround\n");
		}
	}
#endif

	if (sc->clkfreq == 0) {
		/* Try to get clock frequency from timer */
		sc->clkfreq = get_freq();
	}

	if (sc->clkfreq == 0) {
		device_printf(dev, "No clock frequency specified\n");
		return (ENXIO);
	}

	if (bus_alloc_resources(dev, timer_spec, res)) {
		device_printf(dev, "could not allocate resources\n");
		return (ENXIO);
	}
	for (i = 0; i < GT_IRQ_COUNT; i++) {
		sc->irqs[i].res = res[i];
		sc->irqs[i].sc = sc;
		sc->irqs[i].irq = i;
	}

#ifdef __aarch64__
	/* Use the virtual timer if we have one. */
	if (sc->irqs[GT_VIRT].res != NULL && !has_hyp()) {
		sc->physical = false;
	} else
#endif
	/* Otherwise set up the secure and non-secure physical timers. */
	{
		sc->physical = true;
	}

	arm_tmr_sc = sc;

	sc->irqs[GT_PHYS_SECURE].flags |= TMR_IRQ_PHYS;
	sc->irqs[GT_PHYS_NONSECURE].flags |= TMR_IRQ_PHYS;

	if (sc->physical)
		sc->irqs[GT_PHYS_NONSECURE].flags |= TMR_IRQ_ET;
	else
		sc->irqs[GT_VIRT].flags |= TMR_IRQ_ET;

	/* Setup secure, non-secure and virtual IRQs handler */
	for (i = 0; i < GT_IRQ_COUNT; i++) {
		/* If we do not have the interrupt, skip it. */
		if (sc->irqs[i].res == NULL)
			continue;
		error = bus_setup_intr(dev, sc->irqs[i].res, INTR_TYPE_CLK,
		    arm_tmr_intr, NULL, &sc->irqs[i], &sc->irqs[i].ihl);
		if (error) {
			device_printf(dev, "Unable to alloc int resource.\n");
			return (ENXIO);
		}
	}

#if defined(__aarch64__)
	name = device_get_nameunit(dev);
	for (i = 0; i < GT_IRQ_COUNT; i++) {
		intr_isrc_register(&sc->irqs[i].isrc, dev, 0, "%st%u", name, i);
	}
	intr_pic_register(dev, 0);
	sc->intr_rman.rm_type = RMAN_ARRAY;
	sc->intr_rman.rm_descr = "Timer Interrupts";
	if (rman_init(&sc->intr_rman) != 0 ||
	    rman_manage_region(&sc->intr_rman, 0, ~0) != 0)
		panic("%s: failed to set up rman.", __func__);

	/* Add a vtimer child */
	if (sc->physical)
		arm_tmr_add_vtimer(dev);
	bus_generic_attach(dev);
#endif

	/* Disable the virtual timer until we are ready */
	if (sc->irqs[GT_VIRT].res != NULL)
		arm_tmr_disable(false);
	/* And the physical */
	if (sc->physical)
		arm_tmr_disable(true);

	arm_tmr_timecount.tc_frequency = sc->clkfreq;
	tc_init(&arm_tmr_timecount);

	sc->et.et_name = "ARM MPCore Eventtimer";
	sc->et.et_flags = ET_FLAGS_ONESHOT | ET_FLAGS_PERCPU;
	sc->et.et_quality = 1000;

	sc->et.et_frequency = sc->clkfreq;
	sc->et.et_min_period = (0x00000010LLU << 32) / sc->et.et_frequency;
	sc->et.et_max_period = (0xfffffffeLLU << 32) / sc->et.et_frequency;
	sc->et.et_start = arm_tmr_start;
	sc->et.et_stop = arm_tmr_stop;
	sc->et.et_priv = sc;
	et_register(&sc->et);

#if defined(__arm__)
	arm_set_delay(arm_tmr_do_delay, sc);
#endif

	arm_tmr_dev = dev;

	return (0);
}

#if defined(__aarch64__)
struct intr_map_data_timer {
	struct intr_map_data	hdr;
	u_int			irq;
};

static int
arm_tmr_set_resource(device_t dev, device_t child, int type, int rid,
    rman_res_t start, rman_res_t count)
{
	struct intr_map_data_timer *irq_data;
	struct arm_tmr_ivar *devi;
	struct resource_list_entry *rle;
	u_int irq;

	if (type != SYS_RES_IRQ)
		return (EINVAL);
	if (count != 1)
		return (EINVAL);

	irq_data = (struct intr_map_data_timer *)intr_alloc_map_data(
	    INTR_MAP_DATA_PLAT_1, sizeof(*irq_data), M_WAITOK | M_ZERO);
	irq_data->irq = start;
	irq = intr_map_irq(dev, 0, (struct intr_map_data *)irq_data);

	devi = device_get_ivars(child);
	rle = resource_list_add(&devi->rl, type, rid, irq,
	    irq + count - 1, count);
	if (rle == NULL)
		return (ENXIO);

	return (0);
}

static struct resource *
arm_tmr_alloc_resource(device_t bus, device_t child, int type, int *rid,
    rman_res_t start, rman_res_t end, rman_res_t count, u_int flags)
{
	struct arm_tmr_softc *sc;
	struct resource_list_entry *rle;
	struct resource_list *rl;
	struct resource *rv;
	int isdefault;

	if (type != SYS_RES_IRQ)
		return (NULL);
	if (device_get_parent(child) != bus)
		return (NULL);

	rle = NULL;
	isdefault = (RMAN_IS_DEFAULT_RANGE(start, end) && count == 1);
	if (isdefault) {
		rl = BUS_GET_RESOURCE_LIST(bus, child);
		if (rl == NULL)
			return (NULL);
		rle = resource_list_find(rl, type, *rid);
		if (rle == NULL)
			return (NULL);
		if (rle->res != NULL)
			panic("%s: resource entry is busy", __func__);
		start = rle->start;
		count = rle->count;
		end = rle->end;
	}
	sc = device_get_softc(bus);
	rv = rman_reserve_resource(&sc->intr_rman, start, end, count, flags,
	    child);
	if (rv == NULL)
		return (NULL);
	rman_set_rid(rv, *rid);
	if ((flags & RF_ACTIVE) != 0 &&
	    bus_activate_resource(child, type, *rid, rv) != 0) {
		rman_release_resource(rv);
		return (NULL);
	}

	return (rv);
}

static struct resource_list *
arm_tmr_get_resource_list(device_t bus __unused, device_t child)
{
	struct arm_tmr_ivar *devi;

	devi = device_get_ivars(child);
	return (&devi->rl);
}

static int
arm_tmr_print_child(device_t dev, device_t child)
{
	struct arm_tmr_ivar *devi;
	int retval;

	devi = device_get_ivars(child);

	retval = bus_print_child_header(dev, child);
	resource_list_print_type(&devi->rl, "irq", SYS_RES_IRQ, "%jd");
	retval += bus_print_child_footer(dev, child);

	return (retval);
}

static void
arm_tmr_disable_intr(device_t dev, struct intr_irqsrc *isrc)
{
	struct arm_tmr_softc *sc;
	int i;

	printf("%s\n", __func__);
	sc = device_get_softc(dev);
	for (i = 0; i < nitems(sc->irqs); i++) {
		if (isrc == &sc->irqs[i].isrc) {
			sc->irqs[i].flags &= ~TMR_IRQ_CHILD;
			return;
		}
	}

	panic("%s: Invalid interrupt", __func__);
}

static void
arm_tmr_enable_intr(device_t dev, struct intr_irqsrc *isrc)
{
	struct arm_tmr_softc *sc;
	int i;

	printf("%s\n", __func__);
	sc = device_get_softc(dev);
	for (i = 0; i < nitems(sc->irqs); i++) {
		if (isrc == &sc->irqs[i].isrc) {
			sc->irqs[i].flags |= TMR_IRQ_CHILD;
			return;
		}
	}

	panic("%s: Invalid interrupt", __func__);
}

static int
arm_tmr_map_intr(device_t dev, struct intr_map_data *data,
    struct intr_irqsrc **isrcp)
{
	struct intr_map_data_timer *irq_data;
	struct arm_tmr_softc *sc;

	if (data->type != INTR_MAP_DATA_PLAT_1)
		return (EINVAL);

	sc = device_get_softc(dev);
	irq_data = (struct intr_map_data_timer *)data;
	MPASS(irq_data->irq < nitems(sc->irqs));

	*isrcp = &sc->irqs[irq_data->irq].isrc;
	return (0);
}
#endif

static device_method_t arm_tmr_methods[] = {
	DEVMETHOD(device_attach,	arm_tmr_attach),

#if defined(__aarch64__)
	/* Bus interface */
	DEVMETHOD(bus_setup_intr,	bus_generic_setup_intr),
	DEVMETHOD(bus_config_intr,	bus_generic_config_intr),
	DEVMETHOD(bus_teardown_intr,	bus_generic_teardown_intr),
	DEVMETHOD(bus_set_resource,	arm_tmr_set_resource),
	DEVMETHOD(bus_alloc_resource,	arm_tmr_alloc_resource),
	DEVMETHOD(bus_activate_resource,	bus_generic_activate_resource),
	DEVMETHOD(bus_get_resource_list,	arm_tmr_get_resource_list),
	DEVMETHOD(bus_print_child,	arm_tmr_print_child),

	/* Interrupt controller interface */
	DEVMETHOD(pic_disable_intr,	arm_tmr_disable_intr),
	DEVMETHOD(pic_enable_intr,	arm_tmr_enable_intr),
	DEVMETHOD(pic_map_intr,		arm_tmr_map_intr),
#endif
	DEVMETHOD_END,
};

DEFINE_CLASS_0(generic_timer, arm_tmr_driver, arm_tmr_methods, 0);

#ifdef FDT
static device_method_t arm_tmr_fdt_methods[] = {
	DEVMETHOD(device_probe,		arm_tmr_fdt_probe),

	{ 0, 0 }
};

#define generic_timer_baseclasses generic_timer_fdt_baseclasses
DEFINE_CLASS_1(generic_timer, arm_tmr_fdt_driver, arm_tmr_fdt_methods,
    sizeof(struct arm_tmr_softc), arm_tmr_driver);
#undef generic_timer_baseclasses

EARLY_DRIVER_MODULE(timer, simplebus, arm_tmr_fdt_driver, 0, 0,
    BUS_PASS_TIMER + BUS_PASS_ORDER_MIDDLE);
EARLY_DRIVER_MODULE(timer, ofwbus, arm_tmr_fdt_driver, 0, 0,
    BUS_PASS_TIMER + BUS_PASS_ORDER_MIDDLE);
#endif

#ifdef DEV_ACPI
static device_method_t arm_tmr_acpi_methods[] = {
	DEVMETHOD(device_identify,	arm_tmr_acpi_identify),
	DEVMETHOD(device_probe,		arm_tmr_acpi_probe),
	{ 0, 0 }
};

#define generic_timer_baseclasses generic_timer_acpi_baseclasses
DEFINE_CLASS_1(generic_timer, arm_tmr_acpi_driver, arm_tmr_acpi_methods,
    sizeof(struct arm_tmr_softc), arm_tmr_driver);
#undef generic_timer_baseclasses

EARLY_DRIVER_MODULE(timer, acpi, arm_tmr_acpi_driver, 0, 0,
    BUS_PASS_TIMER + BUS_PASS_ORDER_MIDDLE);
#endif

static void
arm_tmr_do_delay(int usec, void *arg)
{
	struct arm_tmr_softc *sc = arg;
	int32_t counts, counts_per_usec;
	uint32_t first, last;

	/* Get the number of times to count */
	counts_per_usec = ((arm_tmr_timecount.tc_frequency / 1000000) + 1);

	/*
	 * Clamp the timeout at a maximum value (about 32 seconds with
	 * a 66MHz clock). *Nobody* should be delay()ing for anywhere
	 * near that length of time and if they are, they should be hung
	 * out to dry.
	 */
	if (usec >= (0x80000000U / counts_per_usec))
		counts = (0x80000000U / counts_per_usec) - 1;
	else
		counts = usec * counts_per_usec;

	first = sc->get_cntxct(sc->physical);

	while (counts > 0) {
		last = sc->get_cntxct(sc->physical);
		counts -= (int32_t)(last - first);
		first = last;
	}
}

#if defined(__aarch64__)
void
DELAY(int usec)
{
	int32_t counts;

	TSENTER();
	/*
	 * Check the timers are setup, if not just
	 * use a for loop for the meantime
	 */
	if (arm_tmr_sc == NULL) {
		for (; usec > 0; usec--)
			for (counts = 200; counts > 0; counts--)
				/*
				 * Prevent the compiler from optimizing
				 * out the loop
				 */
				cpufunc_nullop();
	} else
		arm_tmr_do_delay(usec, arm_tmr_sc);
	TSEXIT();
}
#endif

static uint32_t
arm_tmr_fill_vdso_timehands(struct vdso_timehands *vdso_th,
    struct timecounter *tc)
{

	vdso_th->th_algo = 0; //VDSO_TH_ALGO_ARM_GENTIM;
	vdso_th->th_physical = arm_tmr_sc->physical;
	bzero(vdso_th->th_res, sizeof(vdso_th->th_res));
	return (1);
}
