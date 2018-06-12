/*-
 * Copyright (c) 2014 Robin Randhawa
 * All rights reserved.
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
 *
 */

/*
 * This implements support for ARM's Power State Co-ordination Interface
 * [PSCI]. The implementation adheres to version 0.2 of the PSCI specification
 * but also supports v0.1. PSCI standardizes operations such as system reset, CPU
 * on/off/suspend. PSCI requires a compliant firmware implementation.
 *
 * The PSCI specification used for this implementation is available at:
 *
 * <http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.den0022b/index.html>.
 *
 * TODO:
 * - Add support for remaining PSCI calls [this implementation only
 *   supports get_version, system_reset and cpu_on].
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_acpi.h"
#include "opt_platform.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/eventhandler.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/reboot.h>

#include <machine/bus.h>
#include <machine/machdep.h>

#ifdef DEV_ACPI
#include <contrib/dev/acpica/include/acpi.h>
#include <dev/acpica/acpivar.h>
#endif

#ifdef FDT
#include <dev/fdt/fdt_common.h>
#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#endif

#include <dev/psci/psci.h>

struct psci_softc {
	device_t        dev;

	psci_callfn_t	psci_call;
	uint32_t	psci_fnids[PSCI_FN_MAX];
};

#ifdef FDT
static int psci_v0_1_init(device_t dev);
#endif
static int psci_v0_2_init(device_t dev);

struct psci_softc *psci_softc = NULL;

#ifdef __arm__
#define	USE_ACPI	0
#define	USE_FDT		1
#elif defined(__aarch64__)
#define	USE_ACPI	(arm64_bus_method == ARM64_BUS_ACPI)
#define	USE_FDT		(arm64_bus_method == ARM64_BUS_FDT)
#else
#error Unknown architecture
#endif

#ifdef FDT
static struct ofw_compat_data compat_data[] = {
	{"arm,psci-1.0",        (uintptr_t)psci_v0_2_init},
	{"arm,psci-0.2",        (uintptr_t)psci_v0_2_init},
	{"arm,psci",            (uintptr_t)psci_v0_1_init},
	{NULL,                  0}
};
#endif

static int psci_attach(device_t, psci_initfn_t);
static void psci_shutdown(void *, int);

#ifdef FDT
static int psci_fdt_probe(device_t dev);
static int psci_fdt_attach(device_t dev);

static device_method_t psci_fdt_methods[] = {
	DEVMETHOD(device_probe,     psci_fdt_probe),
	DEVMETHOD(device_attach,    psci_fdt_attach),

	DEVMETHOD_END
};

static driver_t psci_fdt_driver = {
	"psci",
	psci_fdt_methods,
	sizeof(struct psci_softc),
};

static devclass_t psci_fdt_devclass;

EARLY_DRIVER_MODULE(psci, simplebus, psci_fdt_driver, psci_fdt_devclass, 0, 0,
    BUS_PASS_CPU + BUS_PASS_ORDER_FIRST);
EARLY_DRIVER_MODULE(psci, ofwbus, psci_fdt_driver, psci_fdt_devclass, 0, 0,
    BUS_PASS_CPU + BUS_PASS_ORDER_FIRST);

static psci_callfn_t
psci_fdt_get_callfn(phandle_t node)
{
	char method[16];

	if ((OF_getprop(node, "method", method, sizeof(method))) > 0) {
		if (strcmp(method, "hvc") == 0)
			return (psci_hvc_despatch);
		else if (strcmp(method, "smc") == 0)
			return (psci_smc_despatch);
		else
			printf("psci: PSCI conduit \"%s\" invalid\n", method);
	} else
		printf("psci: PSCI conduit not supplied in the device tree\n");

	return (NULL);
}

static int
psci_fdt_probe(device_t dev)
{
	const struct ofw_compat_data *ocd;

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	ocd = ofw_bus_search_compatible(dev, compat_data);
	if (ocd->ocd_str == NULL)
		return (ENXIO);

	device_set_desc(dev, "ARM Power State Co-ordination Interface Driver");

	return (BUS_PROBE_SPECIFIC);
}

static int
psci_fdt_attach(device_t dev)
{
	struct psci_softc *sc = device_get_softc(dev);
	const struct ofw_compat_data *ocd;
	psci_initfn_t psci_init;
	phandle_t node;

	ocd = ofw_bus_search_compatible(dev, compat_data);
	psci_init = (psci_initfn_t)ocd->ocd_data;

	node = ofw_bus_get_node(dev);
	sc->psci_call = psci_fdt_get_callfn(node);

	return (psci_attach(dev, psci_init));
}
#endif

#ifdef DEV_ACPI
static void psci_acpi_identify(driver_t *, device_t);
static int psci_acpi_probe(device_t);
static int psci_acpi_attach(device_t);

static device_method_t psci_acpi_methods[] = {
	/* Device interface */
	DEVMETHOD(device_identify,	psci_acpi_identify),
	DEVMETHOD(device_probe,		psci_acpi_probe),
	DEVMETHOD(device_attach,	psci_acpi_attach),

	DEVMETHOD_END
};

static driver_t psci_acpi_driver = {
	"psci",
	psci_acpi_methods,
	sizeof(struct psci_softc),
};

static devclass_t psci_acpi_devclass;

EARLY_DRIVER_MODULE(psci, acpi, psci_acpi_driver, psci_acpi_devclass, 0, 0,
    BUS_PASS_CPU + BUS_PASS_ORDER_FIRST);

static int
psci_acpi_bootflags(void)
{
	ACPI_TABLE_FADT *fadt;
	vm_paddr_t physaddr;
	int flags;

	physaddr = acpi_find_table(ACPI_SIG_FADT);
	if (physaddr == 0)
		return (0);

	fadt = acpi_map_table(physaddr, ACPI_SIG_FADT);
	if (fadt == NULL) {
		printf("psci: Unable to map the FADT\n");
		return (0);
	}

	flags = fadt->ArmBootFlags;

	acpi_unmap_table(fadt);
	return (flags);
}

static psci_callfn_t
psci_acpi_get_callfn(int flags)
{

	if ((flags & ACPI_FADT_PSCI_COMPLIANT) != 0) {
		if ((flags & ACPI_FADT_PSCI_USE_HVC) != 0)
			return (psci_hvc_despatch);
		else
			return (psci_smc_despatch);
	} else {
		printf("psci: PSCI conduit not supplied in the device tree\n");
	}

	return (NULL);
}

static void
psci_acpi_identify(driver_t *driver, device_t parent)
{
	device_t dev;
	int flags;

	flags = psci_acpi_bootflags();
	if ((flags & ACPI_FADT_PSCI_COMPLIANT) != 0) {
		dev = BUS_ADD_CHILD(parent,
		    BUS_PASS_CPU + BUS_PASS_ORDER_FIRST, "psci", -1);

		if (dev != NULL)
			acpi_set_private(dev, (void *)(uintptr_t)flags);
	}
}

static int
psci_acpi_probe(device_t dev)
{
	uintptr_t flags;

	flags = (uintptr_t)acpi_get_private(dev);
	if ((flags & ACPI_FADT_PSCI_COMPLIANT) == 0)
		return (ENXIO);

	device_set_desc(dev, "ARM Power State Co-ordination Interface Driver");
	return (BUS_PROBE_SPECIFIC);
}

static int
psci_acpi_attach(device_t dev)
{
	struct psci_softc *sc = device_get_softc(dev);
	uintptr_t flags;

	flags = (uintptr_t)acpi_get_private(dev);
	if ((flags & ACPI_FADT_PSCI_USE_HVC) != 0)
		sc->psci_call = psci_hvc_despatch;
	else
		sc->psci_call = psci_smc_despatch;

	return (psci_attach(dev, psci_v0_2_init));
}
#endif

static int
psci_attach(device_t dev, psci_initfn_t psci_init)
{
	struct psci_softc *sc = device_get_softc(dev);

	if (psci_softc != NULL)
		return (ENXIO);

	if (sc->psci_call == NULL)
		return (ENXIO);

	KASSERT(psci_init != NULL, ("PSCI init function cannot be NULL"));
	if (psci_init(dev))
		return (ENXIO);

	psci_softc = sc;

	return (0);
}

static int
psci_get_version(struct psci_softc *sc)
{
	uint32_t fnid;

	/* PSCI version wasn't supported in v0.1. */
	fnid = sc->psci_fnids[PSCI_FN_VERSION];
	if (fnid)
		return (sc->psci_call(fnid, 0, 0, 0));

	return (PSCI_RETVAL_NOT_SUPPORTED);
}

#ifdef FDT
static int
psci_fdt_callfn(psci_callfn_t *callfn)
{
	phandle_t node;

	node = ofw_bus_find_compatible(OF_peer(0), "arm,psci-0.2");
	if (node == 0) {
		node = ofw_bus_find_compatible(OF_peer(0), "arm,psci-1.0");
		if (node == 0)
			return (PSCI_MISSING);
	}

	*callfn = psci_fdt_get_callfn(node);
	return (0);
}
#endif

#ifdef DEV_ACPI
static int
psci_acpi_callfn(psci_callfn_t *callfn)
{
	int flags;

	flags = psci_acpi_bootflags();
	if ((flags & ACPI_FADT_PSCI_COMPLIANT) == 0)
		return (PSCI_MISSING);

	*callfn = psci_acpi_get_callfn(flags);
	return (0);
}
#endif

int
psci_cpu_on(unsigned long cpu, unsigned long entry, unsigned long context_id)
{
	psci_callfn_t callfn;
	uint32_t fnid;
	int error;

	if (psci_softc == NULL) {
		fnid = PSCI_FNID_CPU_ON;
		callfn = NULL;
#ifdef FDT
		if (USE_FDT) {
			error = psci_fdt_callfn(&callfn);
			if (error != 0)
				return (error);
		}
#endif
#ifdef DEV_ACPI
		if (callfn == NULL && USE_ACPI) {
			error = psci_acpi_callfn(&callfn);
			if (error != 0)
				return (error);
		}
#endif

		if (callfn == NULL)
			return (PSCI_MISSING);
	} else {
		callfn = psci_softc->psci_call;
		fnid = psci_softc->psci_fnids[PSCI_FN_CPU_ON];
	}

	/* PSCI v0.1 and v0.2 both support cpu_on. */
	return (callfn(fnid, cpu, entry, context_id));
}

static void
psci_shutdown(void *xsc, int howto)
{
	uint32_t fn = 0;

	if (psci_softc == NULL)
		return;

	/* PSCI system_off and system_reset werent't supported in v0.1. */
	if ((howto & RB_POWEROFF) != 0)
		fn = psci_softc->psci_fnids[PSCI_FN_SYSTEM_OFF];
	else if ((howto & RB_HALT) == 0)
		fn = psci_softc->psci_fnids[PSCI_FN_SYSTEM_RESET];

	if (fn)
		psci_softc->psci_call(fn, 0, 0, 0);

	/* System reset and off do not return. */
}

void
psci_reset(void)
{

	psci_shutdown(NULL, 0);
}

#ifdef FDT
/* Only support PSCI 0.1 on FDT */
static int
psci_v0_1_init(device_t dev)
{
	struct psci_softc *sc = device_get_softc(dev);
	int psci_fn;
	uint32_t psci_fnid;
	phandle_t node;
	int len;


	/* Zero out the function ID table - Is this needed ? */
	for (psci_fn = PSCI_FN_VERSION, psci_fnid = PSCI_FNID_VERSION;
	    psci_fn < PSCI_FN_MAX; psci_fn++, psci_fnid++)
		sc->psci_fnids[psci_fn] = 0;

	/* PSCI v0.1 doesn't specify function IDs. Get them from DT */
	node = ofw_bus_get_node(dev);

	if ((len = OF_getproplen(node, "cpu_suspend")) > 0) {
		OF_getencprop(node, "cpu_suspend", &psci_fnid, len);
		sc->psci_fnids[PSCI_FN_CPU_SUSPEND] = psci_fnid;
	}

	if ((len = OF_getproplen(node, "cpu_on")) > 0) {
		OF_getencprop(node, "cpu_on", &psci_fnid, len);
		sc->psci_fnids[PSCI_FN_CPU_ON] = psci_fnid;
	}

	if ((len = OF_getproplen(node, "cpu_off")) > 0) {
		OF_getencprop(node, "cpu_off", &psci_fnid, len);
		sc->psci_fnids[PSCI_FN_CPU_OFF] = psci_fnid;
	}

	if ((len = OF_getproplen(node, "migrate")) > 0) {
		OF_getencprop(node, "migrate", &psci_fnid, len);
		sc->psci_fnids[PSCI_FN_MIGRATE] = psci_fnid;
	}

	if (bootverbose)
		device_printf(dev, "PSCI version 0.1 available\n");

	return(0);
}
#endif

static int
psci_v0_2_init(device_t dev)
{
	struct psci_softc *sc = device_get_softc(dev);
	int version;

	/* PSCI v0.2 specifies explicit function IDs. */
	sc->psci_fnids[PSCI_FN_VERSION]		    = PSCI_FNID_VERSION;
	sc->psci_fnids[PSCI_FN_CPU_SUSPEND]	    = PSCI_FNID_CPU_SUSPEND;
	sc->psci_fnids[PSCI_FN_CPU_OFF]		    = PSCI_FNID_CPU_OFF;
	sc->psci_fnids[PSCI_FN_CPU_ON]		    = PSCI_FNID_CPU_ON;
	sc->psci_fnids[PSCI_FN_AFFINITY_INFO]	    = PSCI_FNID_AFFINITY_INFO;
	sc->psci_fnids[PSCI_FN_MIGRATE]		    = PSCI_FNID_MIGRATE;
	sc->psci_fnids[PSCI_FN_MIGRATE_INFO_TYPE]   = PSCI_FNID_MIGRATE_INFO_TYPE;
	sc->psci_fnids[PSCI_FN_MIGRATE_INFO_UP_CPU] = PSCI_FNID_MIGRATE_INFO_UP_CPU;
	sc->psci_fnids[PSCI_FN_SYSTEM_OFF]	    = PSCI_FNID_SYSTEM_OFF;
	sc->psci_fnids[PSCI_FN_SYSTEM_RESET]	    = PSCI_FNID_SYSTEM_RESET;

	version = psci_get_version(sc);

	if (version == PSCI_RETVAL_NOT_SUPPORTED)
		return (1);

	if ((PSCI_VER_MAJOR(version) == 0 && PSCI_VER_MINOR(version) == 2) ||
	    PSCI_VER_MAJOR(version) == 1) {
		if (bootverbose)
			device_printf(dev, "PSCI version 0.2 compatible\n");

		/*
		 * We only register this for v0.2 since v0.1 doesn't support
		 * system_reset.
		 */
		EVENTHANDLER_REGISTER(shutdown_final, psci_shutdown, sc,
		    SHUTDOWN_PRI_LAST);

		return (0);
	}

	device_printf(dev, "PSCI version number mismatched with DT\n");
	return (1);
}
