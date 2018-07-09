/*-
 * Product specific probe and attach routines for:
 *      Buslogic BT946, BT948, BT956, BT958 SCSI controllers
 *
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 1995, 1997, 1998 Justin T. Gibbs
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification, immediately at the beginning of the file.
 * 2. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
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
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/bus.h>

#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>

#include <machine/bus.h>
#include <machine/resource.h>
#include <sys/rman.h>

#include <dev/buslogic/btreg.h>

#define BT_PCI_IOADDR	PCIR_BAR(0)
#define BT_PCI_MEMADDR	PCIR_BAR(1)

#define PCI_DEVICE_ID_BUSLOGIC_MULTIMASTER	0x1040104Bul
#define PCI_DEVICE_ID_BUSLOGIC_MULTIMASTER_NC	0x0140104Bul
#define PCI_DEVICE_ID_BUSLOGIC_FLASHPOINT	0x8130104Bul

static int
bt_pci_alloc_resources(device_t dev)
{
	int		type = 0, rid, zero;
	struct resource *regs = NULL;
	struct resource *irq = NULL;

#if 0
	/* XXX Memory Mapped I/O seems to cause problems */
	type = SYS_RES_MEMORY;
	rid = BT_PCI_MEMADDR;
	regs = bus_alloc_resource_any(dev, type, &rid, RF_ACTIVE);
#else
	type = SYS_RES_IOPORT;
	rid = BT_PCI_IOADDR;
	regs = bus_alloc_resource_any(dev, type, &rid, RF_ACTIVE);
#endif
	if (!regs)
		return (ENOMEM);
	
	zero = 0;
	irq = bus_alloc_resource_any(dev, SYS_RES_IRQ, &zero,
				     RF_ACTIVE | RF_SHAREABLE);
	if (!irq) {
		bus_release_resource(dev, type, rid, regs);
		return (ENOMEM);
	}

	bt_init_softc(dev, regs, irq, 0);

	return (0);
}

static void
bt_pci_release_resources(device_t dev)
{
	struct bt_softc *bt = device_get_softc(dev);

	if (bt->port)
		/* XXX can't cope with memory registers anyway */
		bus_release_resource(dev, SYS_RES_IOPORT,
				     BT_PCI_IOADDR, bt->port);
	if (bt->irq)
		bus_release_resource(dev, SYS_RES_IRQ, 0, bt->irq);
	bt_free_softc(dev);
}

static int
bt_pci_probe(device_t dev)
{
	switch (pci_get_devid(dev)) {
		case PCI_DEVICE_ID_BUSLOGIC_MULTIMASTER:
		case PCI_DEVICE_ID_BUSLOGIC_MULTIMASTER_NC:
		{
			struct bt_softc   *bt = device_get_softc(dev);
			pci_info_data_t pci_info;
			int error;

			error = bt_pci_alloc_resources(dev);
			if (error)
				return (error);

			/*
			 * Determine if an ISA compatible I/O port has been
			 * enabled.  If so, record the port so it will not
			 * be probed by our ISA probe.  If the PCI I/O port
			 * was not set to the compatibility port, disable it.
			 */
			error = bt_cmd(bt, BOP_INQUIRE_PCI_INFO,
				       /*param*/NULL, /*paramlen*/0,
				       (u_int8_t*)&pci_info, sizeof(pci_info),
				       DEFAULT_CMD_TIMEOUT);
			if (error == 0
			 && pci_info.io_port < BIO_DISABLED) {
				bt_mark_probed_bio(pci_info.io_port);
				if (rman_get_start(bt->port) !=
				    bt_iop_from_bio(pci_info.io_port)) {
					u_int8_t new_addr;

					new_addr = BIO_DISABLED;
					bt_cmd(bt, BOP_MODIFY_IO_ADDR,
					       /*param*/&new_addr,
					       /*paramlen*/1, /*reply_buf*/NULL,
					       /*reply_len*/0,
					       DEFAULT_CMD_TIMEOUT);
				}
			}
			bt_pci_release_resources(dev);
			device_set_desc(dev, "Buslogic Multi-Master SCSI Host Adapter");
			return (BUS_PROBE_DEFAULT);
		}
		default:
			break;
	}

	return (ENXIO);
}

static int
bt_pci_attach(device_t dev)
{
	struct bt_softc   *bt = device_get_softc(dev);
	int		   error;

	/* Initialize softc */
	error = bt_pci_alloc_resources(dev);
	if (error) {
		device_printf(dev, "can't allocate resources in bt_pci_attach\n");
		return error;
	}

	/* Allocate a dmatag for our CCB DMA maps */
	if (bus_dma_tag_create(	/* PCI parent	*/ bus_get_dma_tag(dev),
				/* alignemnt	*/ 1,
				/* boundary	*/ 0,
				/* lowaddr	*/ BUS_SPACE_MAXADDR_32BIT,
				/* highaddr	*/ BUS_SPACE_MAXADDR,
				/* filter	*/ NULL,
				/* filterarg	*/ NULL,
				/* maxsize	*/ BUS_SPACE_MAXSIZE_32BIT,
				/* nsegments	*/ ~0,
				/* maxsegsz	*/ BUS_SPACE_MAXSIZE_32BIT,
				/* flags	*/ 0,
				/* lockfunc	*/ NULL,
				/* lockarg	*/ NULL,
				&bt->parent_dmat) != 0) {
		bt_pci_release_resources(dev);
		return (ENOMEM);
	}

	if (bt_probe(dev) || bt_fetch_adapter_info(dev) || bt_init(dev)) {
		bt_pci_release_resources(dev);
		return (ENXIO);
	}

	error = bt_attach(dev);

	if (error) {
		bt_pci_release_resources(dev);
		return (error);
	}

	return (0);
}

static device_method_t bt_pci_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		bt_pci_probe),
	DEVMETHOD(device_attach,	bt_pci_attach),

	{ 0, 0 }
};

static driver_t bt_pci_driver = {
	"bt",
	bt_pci_methods,
	sizeof(struct bt_softc),
};

static devclass_t bt_devclass;

DRIVER_MODULE(bt, pci, bt_pci_driver, bt_devclass, 0, 0);
MODULE_DEPEND(bt, pci, 1, 1, 1);
