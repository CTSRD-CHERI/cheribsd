/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2005-2008 Olivier Houchard.  All rights reserved.
 * Copyright (c) 2005-2012 Warner Losh.  All rights reserved.
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");
#include <sys/param.h>
#include <sys/systm.h>

#include <machine/board.h>
#include <arm/at91/at91board.h>
#include <arm/at91/at91var.h>
#include <arm/at91/at91rm9200var.h>

BOARD_INIT long
board_init(void)
{

	at91rm9200_set_subtype(AT91_ST_RM9200_BGA);

	/*
	 * Setup the serial ports.
	 * DBGU and USART0 are DB9 ports.
	 * USART2 is IrDA.
	 */
	at91rm9200_config_uart(AT91_ID_DBGU, 0, 0);   /* DBGU just Tx and Rx */
	at91rm9200_config_uart(AT91RM9200_ID_USART0, 1,
	    AT91_UART_CTS | AT91_UART_RTS | AT91_UART_DTR | AT91_UART_DSR |
	    AT91_UART_DCD | AT91_UART_RI);
	at91rm9200_config_uart(AT91RM9200_ID_USART1, 2, 0);

	at91rm9200_config_mci(1);

	/* CFE interface */
	/* SPI interface */
	/* ethernet interface */
	/* USB host */
	/* USB device (gadget) */
	/* TWI */
	/* CF interface */
	/* SmartMedia Interface */

	return (at91_ramsize());
}

ARM_BOARD(ATEB9200, "Embest ATEB9200")
