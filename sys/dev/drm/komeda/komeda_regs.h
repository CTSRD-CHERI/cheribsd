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

#ifndef	_DEV_DRM_KOMEDA_KOMEDA_REGS_H_
#define	_DEV_DRM_KOMEDA_KOMEDA_REGS_H_

/* Global Control Unit. */
#define	GLB_ARCH_ID		0x0000
#define	GLB_CORE_ID		0x0004
#define	GLB_CORE_INFO		0x0008
#define	GLB_IRQ_STATUS		0x0010
#define	 GLB_IRQ_DOU0		(1 << 24)
#define	 GLB_IRQ_CU0		(1 << 16)
#define	 GLB_IRQ_LPU0		(1 << 8)
#define	 GLB_IRQ_GCU		(1 << 0)

#define	GCU_IRQ_RAW_STATUS	0x00A0
#define	GCU_IRQ_CLEAR		0x00A4
#define	GCU_IRQ_MASK		0x00A8
#define	 GCU_IRQ_ERR		(1 << 11)
#define	 GCU_IRQ_MODE		(1 << 4)
#define	 GCU_IRQ_CVAL0		(1 << 0)
#define	GCU_IRQ_STATUS		0x00AC
#define	GCU_STATUS		0x00B0
#define	GCU_CONTROL		0x00D0
#define	 CONTROL_MODE_S			0
#define	 CONTROL_MODE_M			(0x7 << CONTROL_MODE_S)
#define	 CONTROL_MODE_DO0_ACTIVE	(0x3 << CONTROL_MODE_S)
#define	GCU_CONFIG_VALID0	0x00D4
#define	 CONFIG_VALID0_CVAL	(1 << 0)
#define	GCU_CONFIGURATION_ID0	0x0100
#define	 CONFIG_ID0_MAX_LINE_SIZE_S	0
#define	 CONFIG_ID0_MAX_LINE_SIZE_M	(0xffff << CONFIG_ID0_MAX_LINE_SIZE_S)
#define	 CONFIG_ID0_MAX_NUM_LINES_S	15
#define	 CONFIG_ID0_MAX_NUM_LINES_M	(0xffff << CONFIG_ID0_MAX_NUM_LINES_S)
#define	GCU_CONFIGURATION_ID1	0x0104
#define	 CONFIG_ID1_NUM_RICH_LAYERS_S	0
#define	 CONFIG_ID1_NUM_RICH_LAYERS_M	(0x7 << CONFIG_ID1_NUM_RICH_LAYERS_S)
#define	 CONFIG_ID1_DISPLAY_SPLIT_EN	(1 << 16)
#define	 CONFIG_ID1_DISPLAY_TBU_EN	(1 << 17)

/* DOU0 Backend Subsystem. */
#define	BS_INFO			0x1EC0
#define	BS_CONTROL		0x1ED0
#define	 BS_CONTROL_DL		(1 << 16) /* Dual link (1:2 display split) */
#define	 BS_CONTROL_TM		(1 << 12) /* Test mode (color bars) enable */
#define	 BS_CONTROL_VM		(1 << 1) /* Video Mode enable */
#define	 BS_CONTROL_EN		(1 << 0) /* Display backend timing enable */
#define	BS_PROG_LINE		0x1ED4
#define	BS_PREFETCH_LINE	0x1ED8
#define	BS_BG_COLOR		0x1EDC
#define	BS_ACTIVESIZE		0x1EE0
#define	 ACTIVESIZE_VACTIVE_S	16
#define	 ACTIVESIZE_HACTIVE_S	0
#define	BS_HINTERVALS		0x1EE4
#define	 HINTERVALS_HBACKPORCH_S	16
#define	 HINTERVALS_HFRONTPORCH_S	0
#define	BS_VINTERVALS		0x1EE8
#define	 VINTERVALS_VBACKPORCH_S	16
#define	 VINTERVALS_VFRONTPORCH_S	0
#define	BS_SYNC			0x1EEC
#define	 SYNC_VSYNCWIDTH_S	16
#define	 SYNC_HSYNCWIDTH_S	0
#define	 SYNC_HSP		(1 << 12)
#define	 SYNC_VSP		(1 << 28)
#define	BS_DRIFT_TO		0x1F00
#define	BS_FRAME_TO		0x1F04
#define	BS_TE_TO		0x1F08
#define	BS_T0_INTERVAL		0x1F10
#define	BS_T1_INTERVAL		0x1F14
#define	BS_T2_INTERVAL		0x1F18
#define	BS_CRC0_LOW		0x1F20
#define	BS_CRC0_HIGH		0x1F24
#define	BS_CRC1_LOW		0x1F28
#define	BS_CRC1_HIGH		0x1F2C
#define	BS_USER			0x1F30

/* DOU0 IPS Image Processing Unit */
#define	DOU0_IPS_INPUT_ID0	0x1A80
#define	DOU0_IPS_CONTROL	0x1AD0
#define	 IPS_CONTROL_YUV	(1 << 8)
#define	DOU0_IPS_SIZE		0x1AD4
#define	 IPS_SIZE_VSIZE_S	16
#define	 IPS_SIZE_HSIZE_S	0
#define	DOU0_IPS_DEPTH		0x1AD8
#define	 IPS_OUT_DEPTH_S	0
#define	 IPS_OUT_DEPTH_10	(10 << IPS_OUT_DEPTH_S)

/* DOU0 */
#define	DOU0_IRQ_CLEAR		0x18A4
#define	DOU0_IRQ_MASK		0x18A8
#define	 DOU_IRQ_PL1		(1 << 14)
#define	 DOU_IRQ_PL0		(1 << 13)
#define	 DOU_IRQ_ERR		(1 << 11)
#define	 DOU_IRQ_UND		(1 << 8) /* Underrun interrupt */
#define	DOU0_IRQ_STATUS		0x18AC
#define	DOU0_STATUS		0x18B0

#define	PERIPH_BLOCK_INFO	0xFE00
#define	PERIPH_PIPELINE_INFO	0xFE04

enum d71_block_type {
	D71_BLK_TYPE_GCU		= 0x00,
	D71_BLK_TYPE_LPU		= 0x01,
	D71_BLK_TYPE_CU			= 0x02,
	D71_BLK_TYPE_DOU		= 0x03,
	D71_BLK_TYPE_AEU		= 0x04,
	D71_BLK_TYPE_GLB_LT_COEFF	= 0x05,
	D71_BLK_TYPE_GLB_SCL_COEFF	= 0x06,
	D71_BLK_TYPE_GLB_SC_COEFF	= 0x07,
	D71_BLK_TYPE_PERIPH		= 0x08,
	D71_BLK_TYPE_LPU_TRUSTED	= 0x09,
	D71_BLK_TYPE_AEU_TRUSTED	= 0x0A,
	D71_BLK_TYPE_LPU_LAYER		= 0x10,
	D71_BLK_TYPE_LPU_WB_LAYER	= 0x11,
	D71_BLK_TYPE_CU_SPLITTER	= 0x20,
	D71_BLK_TYPE_CU_SCALER		= 0x21,
	D71_BLK_TYPE_CU_MERGER		= 0x22,
	D71_BLK_TYPE_DOU_IPS		= 0x30,
	D71_BLK_TYPE_DOU_BS		= 0x31,
	D71_BLK_TYPE_DOU_FT_COEFF	= 0x32,
	D71_BLK_TYPE_AEU_DS		= 0x40,
	D71_BLK_TYPE_AEU_AES		= 0x41,
	D71_BLK_TYPE_RESERVED		= 0xFF
};

#define	BLOCK_INFO_BLOCK_TYPE_S		8
#define	BLOCK_INFO_BLOCK_TYPE_M		(0xff << BLOCK_INFO_BLOCK_TYPE_S)
#define	BLOCK_INFO_BLOCK_TYPE(reg)	\
	((reg & BLOCK_INFO_BLOCK_TYPE_M) >> BLOCK_INFO_BLOCK_TYPE_S)
#define	BLOCK_INFO_BLOCK_ID_S		4
#define	BLOCK_INFO_BLOCK_ID_M		(0xf << BLOCK_INFO_BLOCK_ID_S)

#define	LPU0_IRQ_RAW_STATUS	0x02A0
#define	LPU0_IRQ_CLEAR		0x02A4
#define	LPU0_IRQ_MASK		0x02A8
#define	 LPU_IRQ_MASK_PL0	(1 << 13)
#define	 LPU_IRQ_MASK_EOW	(1 << 12)
#define	 LPU_IRQ_MASK_ERR	(1 << 11)
#define	 LPU_IRQ_MASK_IBSY	(1 << 10)
#define	LPU0_IRQ_STATUS		0x02AC
#define	LPU0_STATUS		0x02B0

#define	LR_BLOCK_INFO(n)	(0x0400 + 0x200 * (n))
#define	LR_OUTPUT_ID0(n)	(0x0460 + 0x200 * (n))
#define	LR_CONTROL(n)		(0x04D0 + 0x200 * (n))
#define	 CONTROL_ARCACHE_S	28
#define	 CONTROL_ARCACHE_AXIC_BUF_CACHE	(0x3 << CONTROL_ARCACHE_S)
		/* Cacheable and bufferable, but do not allocate */
#define	 CONTROL_EN		(1 << 0)	/* Layer enable */
#define	LR_FORMAT(n)		(0x04D8 + 0x200 * (n))
#define	LR_IN_SIZE(n)		(0x04E0 + 0x200 * (n))
#define	 IN_SIZE_HSIZE_S	0
#define	 IN_SIZE_HSIZE_M	(0xfff << IN_SIZE_HSIZE_S)
#define	 IN_SIZE_VSIZE_S	16
#define	 IN_SIZE_VSIZE_M	(0xfff << IN_SIZE_VSIZE_S)
#define	LR_PALPHA(n)		(0x04E4 + 0x200 * (n))
#define	LR_P0_PTR_LOW(n)	(0x0500 + 0x200 * (n))
#define	LR_P0_PTR_HIGH(n)	(0x0504 + 0x200 * (n))
#define	LR_P0_STRIDE(n)		(0x0508 + 0x200 * (n))
#define	LR_P1_PTR_LOW(n)	(0x0510 + 0x200 * (n))
#define	LR_P1_STRIDE(n)		(0x0518 + 0x200 * (n))
#define	LR_P2_PTR_LOW(n)	(0x0520 + 0x200 * (n))
#define	LR_AD_CONTROL(n)	(0x0560 + 0x200 * (n))

#define	CU0_BLOCK_INFO			0x0E00
#define	CU0_OUTPUT_ID0			0x0E60
#define	CU0_CU_INPUT_ID0		0x0E80
#define	CU0_CU_INPUT_ID1		0x0E84
#define	CU0_CU_INPUT_ID(n)		(0x0E80 + 0x4 * (n))
#define	CU0_CU_IRQ_CLEAR		0x0EA4
#define	CU0_CU_IRQ_MASK			0x0EA8
#define	 CU_IRQ_MASK_OVR		(1 << 9)
#define	 CU_IRQ_MASK_ERR		(1 << 11)
#define	CU0_CU_IRQ_STATUS		0x0EAC
#define	CU0_CU_STATUS			0x0EB0
#define	CU0_CU_CONTROL			0x0ED0
#define	 CU_CONTROL_COPR	(1 << 0) /* Coprocessor interface enable */
#define	CU0_CU_SIZE			0x0ED4
#define	 CU_SIZE_VSIZE_S		16
#define	 CU_SIZE_HSIZE_S		0
#define	CU0_INPUT0_SIZE			0x0EE0
#define	 INPUT0_SIZE_HSIZE_S		0
#define	 INPUT0_SIZE_VSIZE_S		16
#define	CU0_INPUT0_OFFSET		0x0EE4
#define	 INPUT0_OFFSET_HOFFSET_S	0
#define	 INPUT0_OFFSET_VOFFSET_S	16
#define	CU0_INPUT0_CONTROL		0x0EE8
#define	 INPUT0_CONTROL_EN		(1 << 0)
#define	 INPUT0_CONTROL_LALPHA_S	8
#define	 INPUT0_CONTROL_LALPHA(n)	((n) << INPUT0_CONTROL_LALPHA_S)
#define	 INPUT0_CONTROL_LALPHA_MAX	INPUT0_CONTROL_LALPHA(255)
#define	CU0_INPUT1_SIZE			0x0EF0
#define	CU0_INPUT1_OFFSET		0x0EF4
#define	CU0_INPUT1_CONTROL		0x0EF8

#define	D71_DEFAULT_PREPRETCH_LINE	5
#define	D71_PALPHA_DEF_MAP		0xFFAA5500

#endif /* !_DEV_DRM_KOMEDA_KOMEDA_REGS_H_ */
