/*-
 * Copyright (c) 1998 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Lennart Augustsson (augustss@carlstedt.se) at
 * Carlstedt Research & Technology.
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_bus.h"

#include <sys/stdint.h>
#include <sys/stddef.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/module.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/condvar.h>
#include <sys/sysctl.h>
#include <sys/sx.h>
#include <sys/unistd.h>
#include <sys/callout.h>
#include <sys/malloc.h>
#include <sys/priv.h>

#include <sys/rman.h>
#include <machine/resource.h>

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>

#include <dev/usb/usb_core.h>
#include <dev/usb/usb_busdma.h>
#include <dev/usb/usb_process.h>
#include <dev/usb/usb_util.h>

#include <dev/usb/usb_controller.h>
#include <dev/usb/usb_bus.h>
#include <dev/usb/controller/ehci.h>
#include <dev/usb/controller/ehcireg.h>
#include <mips/rmi/pic.h>

static device_attach_t ehci_xls_attach;
static device_detach_t ehci_xls_detach;

static const char *xlr_usb_dev_desc = "RMI XLR USB 2.0 controller";
static const char *xlr_vendor_desc = "RMI Corp";

static int
ehci_xls_probe(device_t self)
{
	/* TODO see if usb is enabled on the board */
	device_set_desc(self, xlr_usb_dev_desc);
	return BUS_PROBE_DEFAULT;
}

static int
ehci_xls_attach(device_t self)
{
	ehci_softc_t *sc = device_get_softc(self);
	int err;
	int rid;

	sc->sc_bus.parent = self;
	sc->sc_bus.devices = sc->sc_devices;
	sc->sc_bus.devices_max = EHCI_MAX_DEVICES;
	sc->sc_bus.dma_bits = 32;

	/* get all DMA memory */
	if (usb_bus_mem_alloc_all(&sc->sc_bus,
	    USB_GET_DMA_TAG(self), &ehci_iterate_hw_softc)) {
		return (ENOMEM);
	}

	rid = 0;
	sc->sc_io_res = bus_alloc_resource_any(self, SYS_RES_MEMORY, &rid,
	    RF_ACTIVE);
	if (!sc->sc_io_res) {
		device_printf(self, "Could not map memory\n");
		goto error;
	}
	sc->sc_io_tag = rman_get_bustag(sc->sc_io_res);
	sc->sc_io_hdl = rman_get_bushandle(sc->sc_io_res);
	printf("IO Resource tag %lx, hdl %lx, size %lx\n",
	       (u_long)sc->sc_io_tag, (u_long)sc->sc_io_hdl, 
	       (u_long)sc->sc_io_size);

	rid = 0;
	sc->sc_irq_res = bus_alloc_resource(self, SYS_RES_IRQ, &rid,
	    PIC_USB_IRQ, PIC_USB_IRQ, 1, RF_SHAREABLE | RF_ACTIVE);
	if (sc->sc_irq_res == NULL) {
		device_printf(self, "Could not allocate irq\n");
		goto error;
	}

	sc->sc_bus.bdev = device_add_child(self, "usbus", -1);
	if (!sc->sc_bus.bdev) {
		device_printf(self, "Could not add USB device\n");
		goto error;
	}
	device_set_ivars(sc->sc_bus.bdev, &sc->sc_bus);
	device_set_desc(sc->sc_bus.bdev, xlr_usb_dev_desc);

	strlcpy(sc->sc_vendor, xlr_vendor_desc, sizeof(sc->sc_vendor));

	err = bus_setup_intr(self, sc->sc_irq_res,
	    INTR_TYPE_BIO | INTR_MPSAFE, NULL,
	    (driver_intr_t *) ehci_interrupt, sc, &sc->sc_intr_hdl);
	if (err) {
		device_printf(self, "Could not setup irq, %d\n", err);
		sc->sc_intr_hdl = NULL;
		goto error;
	}

	err = ehci_init(sc);
	if (err) {
		device_printf(self, "USB init failed err=%d\n", err);
		goto error;
	}

	err = device_probe_and_attach(sc->sc_bus.bdev);
	if (err) {
		device_printf(self, "USB probe and attach failed err=%d\n", err);
		goto error;
	}

	return (0);

error:
	ehci_xls_detach(self);
	return (ENXIO);
}

static int
ehci_xls_detach(device_t self)
{
	ehci_softc_t *sc = device_get_softc(self);
	int err;

	/* during module unload there are lots of children leftover */
	device_delete_children(self);

	if (sc->sc_irq_res && sc->sc_intr_hdl) {
		ehci_detach(sc);

		err = bus_teardown_intr(self, sc->sc_irq_res, sc->sc_intr_hdl);
		if (err)
			device_printf(self, "Could not tear down irq, %d\n",
			    err);
		sc->sc_intr_hdl = 0;
	}

	if (sc->sc_irq_res) {
		bus_release_resource(self, SYS_RES_IRQ, 0, sc->sc_irq_res);
		sc->sc_irq_res = NULL;
	}
	if (sc->sc_io_res) {
		bus_release_resource(self, SYS_RES_MEMORY, 0,
		    sc->sc_io_res);
		sc->sc_io_res = NULL;
		sc->sc_io_tag = 0;
		sc->sc_io_hdl = 0;
	}

	usb_bus_mem_free_all(&sc->sc_bus, &ehci_iterate_hw_softc);

	return (0);
}

static device_method_t ehci_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe, ehci_xls_probe),
	DEVMETHOD(device_attach, ehci_xls_attach),
	DEVMETHOD(device_detach, ehci_xls_detach),
	DEVMETHOD(device_suspend, bus_generic_suspend),
	DEVMETHOD(device_resume, bus_generic_resume),
	DEVMETHOD(device_shutdown, bus_generic_shutdown),

	DEVMETHOD_END
};

static driver_t ehci_driver = {
	.name = "ehci",
	.methods = ehci_methods,
	.size = sizeof(struct ehci_softc),
};

static devclass_t ehci_devclass;

DRIVER_MODULE(ehci, iodi, ehci_driver, ehci_devclass, 0, 0);
MODULE_DEPEND(ehci, usb, 1, 1, 1);
