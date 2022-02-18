/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2022 Ruslan Bukin <br@bsdpad.com>
 *
 * This work was supported by Innovate UK project 105694, "Digital Security
 * by Design (DSbD) Technology Platform Prototype".
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
 * $FreeBSD$
 */

#ifndef	_DEV_CADENCE_CDNS_I2C_H_
#define	_DEV_CADENCE_CDNS_I2C_H_

#define	CDNS_I2C_CR		0x00	/* Control Register */
#define	 I2C_CR_DIVA_S		14
#define	 I2C_CR_DIVA_M		(0x3 << I2C_CR_DIVA_S)
#define	 I2C_CR_DIVB_S		8
#define	 I2C_CR_DIVB_M		(0x3f << I2C_CR_DIVB_S)
#define	 I2C_CR_CLR_FIFO	(1 << 6)
#define	 I2C_CR_HOLD		(1 << 4)
#define	 I2C_CR_ACK_EN		(1 << 3)
#define	 I2C_CR_NEA		(1 << 2)
#define	 I2C_CR_MS		(1 << 1)
#define	 I2C_CR_RW		(1 << 0) /* 0 = Transmitter, 1 = Receiver */
#define	CDNS_I2C_SR		0x04	/* (ro) Status Register */
#define	 I2C_SR_BA		(1 << 8)
#define	 I2C_SR_TXDV		(1 << 6)
#define	 I2C_SR_RXDV		(1 << 5)
#define	 I2C_SR_RXRW		(1 << 3)
#define	CDNS_I2C_ADDR		0x08	/* Address Register */
#define	 I2C_ADDR_M		(0x3ff)
#define	CDNS_I2C_DATA		0x0C	/* Data Register */
#define	CDNS_I2C_ISR		0x10	/* Interrupt Status Register */
#define	 I2C_ISR_COMP		(1 << 0)
#define	 I2C_ISR_DATA		(1 << 1)
#define	 I2C_ISR_NACK		(1 << 2)
#define	 I2C_ISR_TO		(1 << 3)
#define	 I2C_ISR_SLVRDY		(1 << 4)
#define	 I2C_ISR_RXOVF		(1 << 5)
#define	 I2C_ISR_TXOVF		(1 << 6)
#define	 I2C_ISR_RXUNF		(1 << 7)
#define	 I2C_ISR_ARBLOST	(1 << 9)
#define	CDNS_I2C_TRANS_SIZE	0x14	/* (8) Transfer Size Register */
#define	CDNS_I2C_SLV_PAUSE	0x18	/* (8) Slave Monitor Pause Register */
#define	CDNS_I2C_TIME_OUT	0x1C	/* (8) Time Out Register */
#define	CDNS_I2C_IMR		0x20	/* (ro) Interrupt Mask Register */
#define	CDNS_I2C_IER		0x24	/* Interrupt Enable Register */
#define	CDNS_I2C_IDR		0x28	/* Interrupt Disable Register */
#define	 I2C_IMR_ARB_LOST	(1 << 9)
#define	 I2C_IMR_RX_UNF		(1 << 7)
#define	 I2C_IMR_TX_OVF		(1 << 6)
#define	 I2C_IMR_RX_OVF		(1 << 5)
#define	 I2C_IMR_SLV_RDY	(1 << 4)
#define	 I2C_IMR_TO		(1 << 3)
#define	 I2C_IMR_NACK		(1 << 2)
#define	 I2C_IMR_DATA		(1 << 1)
#define	 I2C_IMR_COMP		(1 << 0)

#define	CDNS_I2C_FIFO_DEPTH		16
#define	CDNS_I2C_TRANSFER_SIZE		16

#endif /* !_DEV_CADENCE_CDNS_I2C_H_ */
