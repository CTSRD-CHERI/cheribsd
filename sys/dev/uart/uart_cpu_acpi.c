/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2016 The FreeBSD Foundation
 * Copyright (c) 2019 Colin Percival
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
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
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>

#include <machine/bus.h>

#include <dev/uart/uart.h>
#include <dev/uart/uart_bus.h>
#include <dev/uart/uart_cpu.h>
#include <dev/uart/uart_cpu_acpi.h>

#include <contrib/dev/acpica/include/acpi.h>
#include <contrib/dev/acpica/include/accommon.h>
#include <contrib/dev/acpica/include/actables.h>

static struct acpi_uart_compat_data *
uart_cpu_acpi_scan(uint8_t interface_type)
{
	struct acpi_uart_compat_data **cd, *curcd;
	int i;

	SET_FOREACH(cd, uart_acpi_class_and_device_set) {
		curcd = *cd;
		for (i = 0; curcd[i].cd_hid != NULL; i++) {
			if (curcd[i].cd_port_subtype == interface_type)
				return (&curcd[i]);
		}
	}

	SET_FOREACH(cd, uart_acpi_class_set) {
		curcd = *cd;
		for (i = 0; curcd[i].cd_hid != NULL; i++) {
			if (curcd[i].cd_port_subtype == interface_type)
				return (&curcd[i]);
		}
	}

	return (NULL);
}

int
uart_cpu_acpi_spcr(int devtype, struct uart_devinfo *di)
{
	vm_paddr_t spcr_physaddr;
	ACPI_TABLE_SPCR *spcr;
	struct acpi_uart_compat_data *cd;
	struct uart_class *class;
	int error = ENXIO;

	/* SPCR only tells us about consoles. */
	if (devtype != UART_DEV_CONSOLE)
		return (error);

	/* Look for the SPCR table. */
	spcr_physaddr = acpi_find_table(ACPI_SIG_SPCR);
	if (spcr_physaddr == 0)
		return (error);
	spcr = acpi_map_table(spcr_physaddr, ACPI_SIG_SPCR);
	if (spcr == NULL) {
		printf("Unable to map the SPCR table!\n");
		return (error);
	}

	/* Search for information about this SPCR interface type. */
	cd = uart_cpu_acpi_scan(spcr->InterfaceType);
	if (cd == NULL)
		goto out;
	class = cd->cd_class;

	/* Fill in some fixed details. */
	di->bas.chan = 0;
	di->bas.rclk = 0;
	di->databits = 8;
	di->stopbits = 1;
	di->parity = UART_PARITY_NONE;
	di->ops = uart_getops(class);

	/* Fill in details from SPCR table. */
	switch (spcr->SerialPort.SpaceId) {
	case 0:
		di->bas.bst = uart_bus_space_mem;
		break;
	case 1:
		di->bas.bst = uart_bus_space_io;
		break;
	default:
		printf("UART in unrecognized address space: %d!\n",
		    (int)spcr->SerialPort.SpaceId);
		goto out;
	}
	if (spcr->SerialPort.AccessWidth == 0)
		di->bas.regshft = 0;
	else
		di->bas.regshft = spcr->SerialPort.AccessWidth - 1;
	di->bas.regiowidth = spcr->SerialPort.BitWidth / 8;
	switch (spcr->BaudRate) {
	case 0:
		/* Special value; means "keep current value unchanged". */
		di->baudrate = 0;
		break;
	case 3:
		di->baudrate = 9600;
		break;
	case 4:
		di->baudrate = 19200;
		break;
	case 6:
		di->baudrate = 57600;
		break;
	case 7:
		di->baudrate = 115200;
		break;
	default:
		printf("SPCR has reserved BaudRate value: %d!\n",
		    (int)spcr->BaudRate);
		goto out;
	}

	/* Apply device tweaks. */
	if ((cd->cd_quirks & UART_F_IGNORE_SPCR_REGSHFT) ==
	    UART_F_IGNORE_SPCR_REGSHFT) {
		di->bas.regshft = cd->cd_regshft;
	}

	/* Create a bus space handle. */
	error = bus_space_map(di->bas.bst, spcr->SerialPort.Address,
	    uart_getrange(class), 0, &di->bas.bsh);

out:
	acpi_unmap_table(spcr);
	return (error);
}
