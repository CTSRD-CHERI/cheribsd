/*	$NetBSD: ixp425var.h,v 1.12 2009/10/21 14:15:51 rmind Exp $ */

/*-
 * SPDX-License-Identifier: BSD-2-Clause-NetBSD
 *
 * Copyright (c) 2003
 *	Ichiro FUKUHARA <ichiro@ichiro.org>.
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
 * THIS SOFTWARE IS PROVIDED BY ICHIRO FUKUHARA ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL ICHIRO FUKUHARA OR THE VOICES IN HIS HEAD BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 *
 */

#ifndef _IXP425VAR_H_
#define _IXP425VAR_H_

#include <sys/conf.h>
#include <sys/queue.h>

#include <machine/bus.h>

#include <sys/rman.h>

/* NB: cputype is setup by set_cpufuncs */
#define	cpu_is_ixp42x()	(cputype == CPU_ID_IXP425)
#define	cpu_is_ixp43x()	(cputype == CPU_ID_IXP435)
#define	cpu_is_ixp46x()	(cputype == CPU_ID_IXP465)

struct ixp425_softc {
	device_t sc_dev;
	bus_space_tag_t sc_iot;
	bus_space_handle_t sc_gpio_ioh;
	bus_space_handle_t sc_exp_ioh;

	u_int32_t sc_intrmask;

	struct rman sc_irq_rman;
	struct rman sc_mem_rman;
	bus_dma_tag_t sc_dmat;
};

void	ixp425_set_gpio(struct ixp425_softc *sc, int pin, int type);

struct ixppcib_softc {
	device_t                sc_dev;
	
	u_int                   sc_bus;
	
	struct resource         *sc_csr;
	struct resource         *sc_mem;
	
	struct rman             sc_io_rman;
	struct rman             sc_mem_rman;
	struct rman             sc_irq_rman;
	
	struct bus_space        sc_pci_memt;
	struct bus_space        sc_pci_iot;
	bus_dma_tag_t 		sc_dmat;
};

#define EXP_BUS_WRITE_4(sc, reg, data) \
	bus_space_write_4(sc->sc_iot, sc->sc_exp_ioh, reg, data)
#define EXP_BUS_READ_4(sc, reg) \
	bus_space_read_4(sc->sc_iot, sc->sc_exp_ioh, reg)

#define	GPIO_CONF_WRITE_4(sc, reg, data)	\
	bus_space_write_4(sc->sc_iot, sc->sc_gpio_ioh, reg, data)
#define	GPIO_CONF_READ_4(sc, reg) \
	bus_space_read_4(sc->sc_iot, sc->sc_gpio_ioh, reg)
#define	IXP4XX_GPIO_LOCK()	mtx_lock(&ixp425_gpio_mtx)
#define	IXP4XX_GPIO_UNLOCK()	mtx_unlock(&ixp425_gpio_mtx)
extern struct mtx ixp425_gpio_mtx;

extern struct bus_space ixp425_bs_tag;
extern struct bus_space ixp425_a4x_bs_tag;

extern struct bus_space cambria_exp_bs_tag;
void	cambria_exp_bus_init(struct ixp425_softc *);

void	ixp425_io_bs_init(bus_space_tag_t, void *);
void	ixp425_mem_bs_init(bus_space_tag_t, void *);

uint32_t ixp425_sdram_size(void);
uint32_t ixp435_ddram_size(void);
uint32_t ixp4xx_read_feature_bits(void);
void	ixp4xx_write_feature_bits(uint32_t);

int	ixp425_md_route_interrupt(device_t, device_t, int);
void	ixp425_md_attach(device_t);

int	getvbase(uint32_t, uint32_t, uint32_t *);

struct ixp425_ivar {
	uint32_t	addr;
	int		irq;
};
#define	IXP425_IVAR(d)	((struct ixp425_ivar *) device_get_ivars(d))

enum {
	IXP425_IVAR_ADDR,		/* base physical address */
	IXP425_IVAR_IRQ			/* irq/gpio pin assignment */
};
#endif /* _IXP425VAR_H_ */
