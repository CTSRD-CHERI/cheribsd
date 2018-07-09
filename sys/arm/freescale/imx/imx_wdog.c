/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2012, 2013 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed by Oleksandr Rybalko under sponsorship
 * from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1.	Redistributions of source code must retain the above copyright
 *	notice, this list of conditions and the following disclaimer.
 * 2.	Redistributions in binary form must reproduce the above copyright
 *	notice, this list of conditions and the following disclaimer in the
 *	documentation and/or other materials provided with the distribution.
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/time.h>
#include <sys/bus.h>
#include <sys/resource.h>
#include <sys/rman.h>
#include <sys/watchdog.h>

#include <machine/bus.h>
#include <machine/intr.h>

#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <arm/freescale/imx/imx_wdogreg.h>

struct imx_wdog_softc {
	struct mtx		sc_mtx;
	device_t		sc_dev;
	bus_space_tag_t		sc_bst;
	bus_space_handle_t	sc_bsh;
	struct resource		*sc_res[2];
	uint32_t		sc_timeout;
};

static struct resource_spec imx_wdog_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ SYS_RES_IRQ,		0,	RF_ACTIVE },
	{ -1, 0 }
};

static struct ofw_compat_data compat_data[] = {
	{"fsl,imx6sx-wdt", 1},
	{"fsl,imx6sl-wdt", 1},
	{"fsl,imx6q-wdt",  1},
	{"fsl,imx53-wdt",  1},
	{"fsl,imx51-wdt",  1},
	{"fsl,imx50-wdt",  1},
	{"fsl,imx35-wdt",  1},
	{"fsl,imx27-wdt",  1},
	{"fsl,imx25-wdt",  1},
	{"fsl,imx21-wdt",  1},
	{NULL,             0}
};

static void	imx_watchdog(void *, u_int, int *);
static int	imx_wdog_probe(device_t);
static int	imx_wdog_attach(device_t);

static device_method_t imx_wdog_methods[] = {
	DEVMETHOD(device_probe,		imx_wdog_probe),
	DEVMETHOD(device_attach,	imx_wdog_attach),
	DEVMETHOD_END
};

static driver_t imx_wdog_driver = {
	"imx_wdog",
	imx_wdog_methods,
	sizeof(struct imx_wdog_softc),
};
static devclass_t imx_wdog_devclass;
DRIVER_MODULE(imx_wdog, simplebus, imx_wdog_driver, imx_wdog_devclass, 0, 0);

#define	RD2(_sc, _r)							\
		bus_space_read_2((_sc)->sc_bst, (_sc)->sc_bsh, (_r))
#define	WR2(_sc, _r, _v)						\
		bus_space_write_2((_sc)->sc_bst, (_sc)->sc_bsh, (_r), (_v))

static void
imx_watchdog(void *arg, u_int cmd, int *error)
{
	struct imx_wdog_softc *sc;
	uint16_t reg;
	u_int timeout;

	sc = arg;
	mtx_lock(&sc->sc_mtx);
	if (cmd == 0) {
		if (bootverbose)
			device_printf(sc->sc_dev, "Can not be disabled.\n");
		*error = EOPNOTSUPP;
	} else {
		timeout = (u_int)((1ULL << (cmd & WD_INTERVAL)) / 1000000000U);
		if (timeout > 1 && timeout < 128) {
			if (timeout != sc->sc_timeout) {
				sc->sc_timeout = timeout;
				reg = RD2(sc, WDOG_CR_REG);
				reg &= ~WDOG_CR_WT_MASK;
				reg |= (timeout << (WDOG_CR_WT_SHIFT + 1)) &
				    WDOG_CR_WT_MASK;
				WR2(sc, WDOG_CR_REG, reg | WDOG_CR_WDE);
			}
			/* Refresh counter */
			WR2(sc, WDOG_SR_REG, WDOG_SR_STEP1);
			WR2(sc, WDOG_SR_REG, WDOG_SR_STEP2);
			*error = 0;
		}
	}
	mtx_unlock(&sc->sc_mtx);
}

static int
imx_wdog_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_search_compatible(dev, compat_data)->ocd_data == 0)
		return (ENXIO);

	device_set_desc(dev, "Freescale i.MX Watchdog");
	return (0);
}

static int
imx_wdog_attach(device_t dev)
{
	struct imx_wdog_softc *sc;

	sc = device_get_softc(dev);
	sc->sc_dev = dev;

	if (bus_alloc_resources(dev, imx_wdog_spec, sc->sc_res)) {
		device_printf(dev, "could not allocate resources\n");
		return (ENXIO);
	}

	mtx_init(&sc->sc_mtx, device_get_nameunit(dev), "imx_wdt", MTX_DEF);

	sc->sc_dev = dev;
	sc->sc_bst = rman_get_bustag(sc->sc_res[0]);
	sc->sc_bsh = rman_get_bushandle(sc->sc_res[0]);

	/* TODO: handle interrupt */

	EVENTHANDLER_REGISTER(watchdog_list, imx_watchdog, sc, 0);
	return (0);
}
