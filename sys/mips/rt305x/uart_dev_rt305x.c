/* $NetBSD: uart.c,v 1.2 2007/03/23 20:05:47 dogcow Exp $ */

/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2010 Aleksandr Rybalko.
 * Copyright (c) 2007 Ruslan Ermilov and Vsevolod Lobko.
 * Copyright (c) 2007 Oleksandr Tymoshenko.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_ddb.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/kdb.h>
#include <sys/reboot.h>
#include <sys/sysctl.h>
#include <sys/kernel.h>
#include <machine/bus.h>

#include <dev/uart/uart.h>
#include <dev/uart/uart_cpu.h>
#include <dev/uart/uart_bus.h>

#include <mips/rt305x/uart_dev_rt305x.h>
#include <mips/rt305x/rt305xreg.h>

#include "uart_if.h"
/*
 * Low-level UART interface.
 */
static int rt305x_uart_probe(struct uart_bas *bas);
static void rt305x_uart_init(struct uart_bas *bas, int, int, int, int);
static void rt305x_uart_term(struct uart_bas *bas);
static void rt305x_uart_putc(struct uart_bas *bas, int);
static int rt305x_uart_rxready(struct uart_bas *bas);
static int rt305x_uart_getc(struct uart_bas *bas, struct mtx *);

static struct uart_ops uart_rt305x_uart_ops = {
	.probe = rt305x_uart_probe,
	.init = rt305x_uart_init,
	.term = rt305x_uart_term,
	.putc = rt305x_uart_putc,
	.rxready = rt305x_uart_rxready,
	.getc = rt305x_uart_getc,
};

static int	uart_output = 1;
SYSCTL_INT(_kern, OID_AUTO, uart_output, CTLFLAG_RWTUN,
    &uart_output, 0, "UART output enabled.");

static int
rt305x_uart_probe(struct uart_bas *bas)
{

	return (0);
}

static void
rt305x_uart_init(struct uart_bas *bas, int baudrate, int databits, 
    int stopbits, int parity)
{
#ifdef notyet
        /* CLKDIV  = 384000000/ 3/ 16/ br */
        /* for 384MHz CLKDIV = 8000000 / baudrate; */
        switch (databits) {
        case 5:
    		databits = UART_LCR_5B;
    		break;
        case 6:
    		databits = UART_LCR_6B;
    		break;
        case 7:
    		databits = UART_LCR_7B;
    		break;
        case 8:
    		databits = UART_LCR_8B;
    		break;
    	default:
    		/* Unsupported */
    		return;
        }
	switch (parity) {
	case UART_PARITY_EVEN:	parity = (UART_LCR_PEN|UART_LCR_EVEN); break;
	case UART_PARITY_NONE:	parity = (UART_LCR_PEN); break;
	case UART_PARITY_ODD:	parity = 0; break;
	/* Unsupported */
	default:		return;
	}
        uart_setreg(bas, UART_CDDL_REG, 8000000/baudrate);
	uart_barrier(bas);
        uart_setreg(bas, UART_LCR_REG, databits | (stopbits==1?0:4) | parity);
	uart_barrier(bas);
#endif
}

static void
rt305x_uart_term(struct uart_bas *bas)
{
        uart_setreg(bas, UART_MCR_REG, 0);
	uart_barrier(bas);
}

static void
rt305x_uart_putc(struct uart_bas *bas, int c)
{
	char chr;
	if (!uart_output) return;
	chr = c;
	while (!(uart_getreg(bas, UART_LSR_REG) & UART_LSR_THRE));
	uart_setreg(bas, UART_TX_REG, c);
	uart_barrier(bas);
	while (!(uart_getreg(bas, UART_LSR_REG) & UART_LSR_THRE));
}

static int
rt305x_uart_rxready(struct uart_bas *bas)
{
#ifdef notyet
	if (uart_getreg(bas, UART_LSR_REG) & UART_LSR_DR)
		return (1);

	return (0);
#else
	return (1);
#endif
}

static int
rt305x_uart_getc(struct uart_bas *bas, struct mtx *hwmtx)
{
	int c;

	uart_lock(hwmtx);

	while (!(uart_getreg(bas, UART_LSR_REG) & UART_LSR_DR)) {
		uart_unlock(hwmtx);
		DELAY(10);
		uart_lock(hwmtx);
	}

	c = uart_getreg(bas, UART_RX_REG);

	uart_unlock(hwmtx);

	return (c);
}

/*
 * High-level UART interface.
 */
struct rt305x_uart_softc {
	struct uart_softc base;
};

static int rt305x_uart_bus_attach(struct uart_softc *);
static int rt305x_uart_bus_detach(struct uart_softc *);
static int rt305x_uart_bus_flush(struct uart_softc *, int);
static int rt305x_uart_bus_getsig(struct uart_softc *);
static int rt305x_uart_bus_ioctl(struct uart_softc *, int, intptr_t);
static int rt305x_uart_bus_ipend(struct uart_softc *);
static int rt305x_uart_bus_param(struct uart_softc *, int, int, int, int);
static int rt305x_uart_bus_probe(struct uart_softc *);
static int rt305x_uart_bus_receive(struct uart_softc *);
static int rt305x_uart_bus_setsig(struct uart_softc *, int);
static int rt305x_uart_bus_transmit(struct uart_softc *);
static void rt305x_uart_bus_grab(struct uart_softc *);
static void rt305x_uart_bus_ungrab(struct uart_softc *);

static kobj_method_t rt305x_uart_methods[] = {
	KOBJMETHOD(uart_attach,		rt305x_uart_bus_attach),
	KOBJMETHOD(uart_detach,		rt305x_uart_bus_detach),
	KOBJMETHOD(uart_flush,		rt305x_uart_bus_flush),
	KOBJMETHOD(uart_getsig,		rt305x_uart_bus_getsig),
	KOBJMETHOD(uart_ioctl,		rt305x_uart_bus_ioctl),
	KOBJMETHOD(uart_ipend,		rt305x_uart_bus_ipend),
	KOBJMETHOD(uart_param,		rt305x_uart_bus_param),
	KOBJMETHOD(uart_probe,		rt305x_uart_bus_probe),
	KOBJMETHOD(uart_receive,	rt305x_uart_bus_receive),
	KOBJMETHOD(uart_setsig,		rt305x_uart_bus_setsig),
	KOBJMETHOD(uart_transmit,	rt305x_uart_bus_transmit),
	KOBJMETHOD(uart_grab,		rt305x_uart_bus_grab),
	KOBJMETHOD(uart_ungrab,		rt305x_uart_bus_ungrab),
	{ 0, 0 }
};

struct uart_class uart_rt305x_uart_class = {
	"rt305x",
	rt305x_uart_methods,
	sizeof(struct rt305x_uart_softc),
	.uc_ops = &uart_rt305x_uart_ops,
	.uc_range = 1, /* use hinted range */
	.uc_rclk = SYSTEM_CLOCK,
	.uc_rshift = 0
};

#define	SIGCHG(c, i, s, d)				\
	if (c) {					\
		i |= (i & s) ? s : s | d;		\
	} else {					\
		i = (i & s) ? (i & ~s) | d : i;		\
	}

/*
 * Disable TX interrupt. uart should be locked 
 */ 
static __inline void
rt305x_uart_disable_txintr(struct uart_softc *sc)
{
	struct uart_bas *bas = &sc->sc_bas;
	uint8_t cr;

	cr = uart_getreg(bas, UART_IER_REG);
	cr &= ~UART_IER_ETBEI;
	uart_setreg(bas, UART_IER_REG, cr);
	uart_barrier(bas);
}

/*
 * Enable TX interrupt. uart should be locked 
 */ 
static __inline void
rt305x_uart_enable_txintr(struct uart_softc *sc)
{
	struct uart_bas *bas = &sc->sc_bas;
	uint8_t cr;

	cr = uart_getreg(bas, UART_IER_REG);
	cr |= UART_IER_ETBEI;
	uart_setreg(bas, UART_IER_REG, cr);
	uart_barrier(bas);
}

static int
rt305x_uart_bus_attach(struct uart_softc *sc)
{
	struct uart_bas *bas;
	struct uart_devinfo *di;

	bas = &sc->sc_bas;
	if (sc->sc_sysdev != NULL) {
		di = sc->sc_sysdev;
		rt305x_uart_init(bas, di->baudrate, di->databits, di->stopbits,
		    di->parity);
	} else {
		rt305x_uart_init(bas, 115200, 8, 1, 0);
	}

	(void)rt305x_uart_bus_getsig(sc);

	/* Enable FIFO */
	uart_setreg(bas, UART_FCR_REG, 
	    uart_getreg(bas, UART_FCR_REG) | 
	    UART_FCR_FIFOEN | UART_FCR_TXTGR_1 | UART_FCR_RXTGR_1);
 	uart_barrier(bas);
	/* Enable interrupts */
	uart_setreg(bas, UART_IER_REG,
	    UART_IER_EDSSI | UART_IER_ELSI | UART_IER_ERBFI);
	uart_barrier(bas);

	return (0);
}

static int
rt305x_uart_bus_detach(struct uart_softc *sc)
{

	return (0);
}

static int
rt305x_uart_bus_flush(struct uart_softc *sc, int what)
{
	struct uart_bas *bas = &sc->sc_bas;
	uint32_t fcr = uart_getreg(bas, UART_FCR_REG);
	if (what & UART_FLUSH_TRANSMITTER) {
		uart_setreg(bas, UART_FCR_REG, fcr|UART_FCR_TXRST);
		uart_barrier(bas);
	}
	if (what & UART_FLUSH_RECEIVER) {
		uart_setreg(bas, UART_FCR_REG, fcr|UART_FCR_RXRST);
		uart_barrier(bas);
	}
	uart_setreg(bas, UART_FCR_REG, fcr);
	uart_barrier(bas);
	return (0);
}

static int
rt305x_uart_bus_getsig(struct uart_softc *sc)
{
	uint32_t new, old, sig;
	uint8_t bes;

	do {
		old = sc->sc_hwsig;
		sig = old;
		uart_lock(sc->sc_hwmtx);
		bes = uart_getreg(&sc->sc_bas, UART_MSR_REG);
		uart_unlock(sc->sc_hwmtx);
		/* XXX: chip can show delta */
		SIGCHG(bes & UART_MSR_CTS, sig, SER_CTS, SER_DCTS);
		SIGCHG(bes & UART_MSR_DCD, sig, SER_DCD, SER_DDCD);
		SIGCHG(bes & UART_MSR_DSR, sig, SER_DSR, SER_DDSR);
		new = sig & ~SER_MASK_DELTA;
	} while (!atomic_cmpset_32(&sc->sc_hwsig, old, new));

	return (sig);
}

static int
rt305x_uart_bus_ioctl(struct uart_softc *sc, int request, intptr_t data)
{
	struct uart_bas *bas;
	int baudrate, divisor, error;

	bas = &sc->sc_bas;
	error = 0;
	uart_lock(sc->sc_hwmtx);
	switch (request) {
	case UART_IOCTL_BREAK:
		/* TODO: Send BREAK */
		break;
	case UART_IOCTL_BAUD:
		divisor = uart_getreg(bas, UART_CDDL_REG);
		baudrate = bas->rclk / (divisor * 16);
		*(int*)data = baudrate;
		break;
	default:
		error = EINVAL;
		break;
	}
	uart_unlock(sc->sc_hwmtx);
	return (error);
}

static int
rt305x_uart_bus_ipend(struct uart_softc *sc)
{
	struct uart_bas *bas;
	int ipend;
	uint8_t iir, lsr, msr;

	bas = &sc->sc_bas;
	ipend = 0;

	uart_lock(sc->sc_hwmtx);
	iir = uart_getreg(&sc->sc_bas, UART_IIR_REG);
	lsr = uart_getreg(&sc->sc_bas, UART_LSR_REG);
	uart_setreg(&sc->sc_bas, UART_LSR_REG, lsr);
	msr = uart_getreg(&sc->sc_bas, UART_MSR_REG);
	uart_setreg(&sc->sc_bas, UART_MSR_REG, msr);
	if (iir & UART_IIR_INTP) {
		uart_unlock(sc->sc_hwmtx);
		return (0);
	}


	switch ((iir >> 1) & 0x07) {
	case UART_IIR_ID_THRE:
		ipend |= SER_INT_TXIDLE;
		break;
	case UART_IIR_ID_DR2:
		rt305x_uart_bus_flush(sc, UART_FLUSH_RECEIVER);
		/* passthrough */
	case UART_IIR_ID_DR:
		ipend |= SER_INT_RXREADY;
		break;
	case UART_IIR_ID_MST:
	case UART_IIR_ID_LINESTATUS:
		ipend |= SER_INT_SIGCHG;
		if (lsr & UART_LSR_BI)
		{
			ipend |= SER_INT_BREAK;
#ifdef KDB
			breakpoint();
#endif
		}
		if (lsr & UART_LSR_OE)
			ipend |= SER_INT_OVERRUN;
		break;
	default:
		/* XXX: maybe return error here */
		break;
	}

	uart_unlock(sc->sc_hwmtx);

	return (ipend);
}

static int
rt305x_uart_bus_param(struct uart_softc *sc, int baudrate, int databits,
    int stopbits, int parity)
{
	uart_lock(sc->sc_hwmtx);
	rt305x_uart_init(&sc->sc_bas, baudrate, databits, stopbits, parity);
	uart_unlock(sc->sc_hwmtx);
	return (0);
}

static int
rt305x_uart_bus_probe(struct uart_softc *sc)
{
	char buf[80];
	int error;

	error = rt305x_uart_probe(&sc->sc_bas);
	if (error)
		return (error);

	sc->sc_rxfifosz = 16;
	sc->sc_txfifosz = 16;

	snprintf(buf, sizeof(buf), "rt305x_uart");
	device_set_desc_copy(sc->sc_dev, buf);

	return (0);
}

static int
rt305x_uart_bus_receive(struct uart_softc *sc)
{
	struct uart_bas *bas;
	int xc;
	uint8_t lsr;

	bas = &sc->sc_bas;
	uart_lock(sc->sc_hwmtx);
	lsr = uart_getreg(bas, UART_LSR_REG);
	while ((lsr & UART_LSR_DR)) {
		if (uart_rx_full(sc)) {
			sc->sc_rxbuf[sc->sc_rxput] = UART_STAT_OVERRUN;
			break;
		}
		xc = 0;
		xc = uart_getreg(bas, UART_RX_REG);
		if (lsr & UART_LSR_FE)
			xc |= UART_STAT_FRAMERR;
		if (lsr & UART_LSR_PE)
			xc |= UART_STAT_PARERR;
		if (lsr & UART_LSR_OE)
			xc |= UART_STAT_OVERRUN;
		uart_barrier(bas);
		uart_rx_put(sc, xc);
		lsr = uart_getreg(bas, UART_LSR_REG);
	}

	uart_unlock(sc->sc_hwmtx);
	return (0);
}

static int
rt305x_uart_bus_setsig(struct uart_softc *sc, int sig)
{

	/* TODO: implement (?) */
	return (0);
}

static int
rt305x_uart_bus_transmit(struct uart_softc *sc)
{
	struct uart_bas *bas = &sc->sc_bas;
	int i;

	if (!uart_output) return (0);

	bas = &sc->sc_bas;
	uart_lock(sc->sc_hwmtx);
	while ((uart_getreg(bas, UART_LSR_REG) & UART_LSR_THRE) == 0)
		;
	rt305x_uart_enable_txintr(sc);
	for (i = 0; i < sc->sc_txdatasz; i++) {
		uart_setreg(bas, UART_TX_REG, sc->sc_txbuf[i]);
		uart_barrier(bas);
	}
	sc->sc_txbusy = 1;
	uart_unlock(sc->sc_hwmtx);
	return (0);
}

static void
rt305x_uart_bus_grab(struct uart_softc *sc)
{
	struct uart_bas *bas = &sc->sc_bas;

	/* disable interrupts -- XXX not sure which one is RX, so kill them all */
	uart_lock(sc->sc_hwmtx);
	uart_setreg(bas, UART_IER_REG, 0);
	uart_barrier(bas);
	uart_unlock(sc->sc_hwmtx);
}

static void
rt305x_uart_bus_ungrab(struct uart_softc *sc)
{
	struct uart_bas *bas = &sc->sc_bas;

	/* Enable interrupts */
	uart_lock(sc->sc_hwmtx);
	uart_setreg(bas, UART_IER_REG,
	    UART_IER_EDSSI | UART_IER_ELSI | UART_IER_ERBFI);
	uart_barrier(bas);
	uart_unlock(sc->sc_hwmtx);
}
