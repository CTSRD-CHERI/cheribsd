/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2013 Ganbold Tsagaankhuu <ganbold@freebsd.org>
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
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef _RK30_GRF_H_
#define	_RK30_GRF_H_

#define	RK30_GRF_BASE		0xF0008000

#define	GRF_GPIO0L_DIR		0x0000
#define	GRF_GPIO0H_DIR		0x0004
#define	GRF_GPIO1L_DIR		0x0008
#define	GRF_GPIO1H_DIR		0x000c
#define	GRF_GPIO2L_DIR		0x0010
#define	GRF_GPIO2H_DIR		0x0014
#define	GRF_GPIO3L_DIR		0x0018
#define	GRF_GPIO3H_DIR		0x001c
#define	GRF_GPIO0L_DO		0x0020
#define	GRF_GPIO0H_DO		0x0024
#define	GRF_GPIO1L_DO		0x0028
#define	GRF_GPIO1H_DO		0x002c
#define	GRF_GPIO2L_DO		0x0030
#define	GRF_GPIO2H_DO		0x0034
#define	GRF_GPIO3L_DO		0x0038
#define	GRF_GPIO3H_DO		0x003c
#define	GRF_GPIO0L_EN		0x0040
#define	GRF_GPIO0H_EN		0x0044
#define	GRF_GPIO1L_EN		0x0048
#define	GRF_GPIO1H_EN		0x004c
#define	GRF_GPIO2L_EN		0x0050
#define	GRF_GPIO2H_EN		0x0054
#define	GRF_GPIO3L_EN		0x0058
#define	GRF_GPIO3H_EN		0x005c

#define	GRF_GPIO0C_IOMUX	0x0068
#define	GRF_GPIO0D_IOMUX	0x006c
#define	GRF_GPIO1A_IOMUX	0x0070
#define	GRF_GPIO1B_IOMUX	0x0074
#define	GRF_GPIO1C_IOMUX	0x0078
#define	GRF_GPIO1D_IOMUX	0x007c
#define	GRF_GPIO2A_IOMUX	0x0080
#define	GRF_GPIO2B_IOMUX	0x0084
#define	GRF_GPIO2C_IOMUX	0x0088
#define	GRF_GPIO2D_IOMUX	0x008c
#define	GRF_GPIO3A_IOMUX	0x0090
#define	GRF_GPIO3B_IOMUX	0x0094
#define	GRF_GPIO3C_IOMUX	0x0098
#define	GRF_GPIO3D_IOMUX	0x009c
#define	GRF_SOC_CON0		0x00a0
#define	GRF_SOC_CON1		0x00a4
#define	GRF_SOC_CON2		0x00a8
#define	GRF_SOC_STATUS0		0x00ac
#define	GRF_DMAC1_CON0		0x00b0
#define	GRF_DMAC1_CON1		0x00b4
#define	GRF_DMAC1_CON2		0x00b8
#define	GRF_DMAC2_CON0		0x00bc
#define	GRF_DMAC2_CON1		0x00c0
#define	GRF_DMAC2_CON2		0x00c4
#define	GRF_DMAC2_CON3		0x00c8
#define	GRF_CPU_CON0		0x00cc
#define	GRF_CPU_CON1		0x00d0
#define	GRF_CPU_CON2		0x00d4
#define	GRF_CPU_CON3		0x00d8
#define	GRF_CPU_CON4		0x00dc
#define	GRF_CPU_CON5		0x00e0

#define	GRF_DDRC_CON0		0x00ec
#define	GRF_DDRC_STAT		0x00f0
#define	GRF_IO_CON0		0x00f4
#define	GRF_IO_CON1		0x00f8
#define	GRF_IO_CON2		0x00fc
#define	GRF_IO_CON3		0x0100
#define	GRF_IO_CON4		0x0104
#define	GRF_SOC_STATUS1		0x0108
#define	GRF_UOC0_CON0		0x010c
#define	GRF_UOC0_CON1		0x0110
#define	GRF_UOC0_CON2		0x0114
#define	GRF_UOC0_CON3		0x0118
#define	GRF_UOC1_CON0		0x011c
#define	GRF_UOC1_CON1		0x0120
#define	GRF_UOC1_CON2		0x0124
#define	GRF_UOC1_CON3		0x0128
#define	GRF_UOC2_CON0		0x012c
#define	GRF_UOC2_CON1		0x0130

#define	GRF_UOC3_CON0		0x0138
#define	GRF_UOC3_CON1		0x013c
#define	GRF_HSIC_STAT		0x0140
#define	GRF_OS_REG0		0x0144
#define	GRF_OS_REG1		0x0148
#define	GRF_OS_REG2		0x014c
#define	GRF_OS_REG3		0x0150
#define	GRF_OS_REG4		0x0154
#define	GRF_OS_REG5		0x0158
#define	GRF_OS_REG6		0x015c
#define	GRF_OS_REG7		0x0160
#define	GRF_GPIO0B_PULL		0x0164
#define	GRF_GPIO0C_PULL		0x0168
#define	GRF_GPIO0D_PULL		0x016c
#define	GRF_GPIO1A_PULL		0x0170
#define	GRF_GPIO1B_PULL		0x0174
#define	GRF_GPIO1C_PULL		0x0178
#define	GRF_GPIO1D_PULL		0x017c
#define	GRF_GPIO2A_PULL		0x0180
#define	GRF_GPIO2B_PULL		0x0184
#define	GRF_GPIO2C_PULL		0x0188
#define	GRF_GPIO2D_PULL		0x018c
#define	GRF_GPIO3A_PULL		0x0190
#define	GRF_GPIO3B_PULL		0x0194
#define	GRF_GPIO3C_PULL		0x0198
#define	GRF_GPIO3D_PULL		0x019c
#define	GRF_FLASH_DATA_PULL	0x01a0
#define	GRF_FLASH_CMD_PULL	0x01a4

void rk30_grf_gpio_pud(uint32_t bank, uint32_t pin, uint32_t state);

#endif /* _RK30_GRF_H_ */
