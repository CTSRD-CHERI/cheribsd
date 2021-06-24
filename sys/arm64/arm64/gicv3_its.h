/*-
 * Copyright (c) 2015-2016 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed by Andrew Turner under
 * the sponsorship of the FreeBSD Foundation.
 *
 * This software was developed by Semihalf under
 * the sponsorship of the FreeBSD Foundation.
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
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
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

#ifndef _GICV3_ITS_H_
#define	_GICV3_ITS_H_

/* ITS command. Each command is 32 bytes long */
struct its_cmd {
	uint64_t	cmd_dword[4];	/* ITS command double word */
};

/* ITS commands encoding */
#define	ITS_CMD_MOVI		0x01
#define	ITS_CMD_SYNC		0x05
#define	ITS_CMD_MAPD		0x08
#define	ITS_CMD_MAPC		0x09
#define	ITS_CMD_MAPTI		0x0a
#define	ITS_CMD_MAPI		0x0b
#define	ITS_CMD_INV		0x0c
#define	ITS_CMD_INVALL		0x0d

/* Command */
#define	CMD_COMMAND_SHIFT	0
#define	CMD_COMMAND_MASK	(0xFFUL << CMD_COMMAND_SHIFT)
#define	CMD_COMMAND_GET(x)	\
    (((x)->cmd_dword[0] & CMD_COMMAND_MASK) >> CMD_COMMAND_SHIFT)

/* PCI device ID */
#define	CMD_DEVID_SHIFT		32
#define	CMD_DEVID_MASK		(0xFFFFFFFFUL << CMD_DEVID_SHIFT)
#define	CMD_DEVID_GET(x)	\
    (((x)->cmd_dword[0] & CMD_DEVID_MASK) >> CMD_DEVID_SHIFT)

/* PCI event ID */
#define	CMD_ID_SHIFT		0
#define	CMD_ID_MASK		(0xfffffffful << CMD_ID_SHIFT)
#define	CMD_ID_GET(x)	\
    (((x)->cmd_dword[1] & CMD_ID_MASK) >> CMD_ID_SHIFT)

/* Size of IRQ ID bitfield */
#define	CMD_SIZE_SHIFT		0
#define	CMD_SIZE_MASK		(0xFFUL << CMD_SIZE_SHIFT)
#define	CMD_SIZE_GET(x)		\
    (((x)->cmd_dword[1] & CMD_SIZE_MASK) >> CMD_SIZE_SHIFT)

/* Physical LPI ID */
#define	CMD_PID_SHIFT		32
#define	CMD_PID_MASK		(0xFFFFFFFFUL << CMD_PID_SHIFT)
#define	CMD_PID_GET(x)		\
    (((x)->cmd_dword[1] & CMD_PID_MASK) >> CMD_PID_SHIFT)

/* Collection */
#define	CMD_COL_SHIFT		0
#define	CMD_COL_MASK		(0xFFFFUL << CMD_COL_SHIFT)
#define	CMD_COL_GET(x)		\
    (((x)->cmd_dword[2] & CMD_COL_MASK) >> CMD_COL_SHIFT)

/* Interrupt Translation Table address */
#define	CMD_ITT_MASK		0xFFFFFFFFFF00UL
#define	CMD_ITT_GET(x)		\
    ((x)->cmd_dword[2] & CMD_ITT_MASK)

/* Target (CPU or Re-Distributor) */
#define	CMD_TARGET_SHIFT	16
#define	CMD_TARGET_MASK		(0xFFFFFFFFUL << CMD_TARGET_SHIFT)
#define	CMD_TARGET_GET(x)	\
    (((x)->cmd_dword[2] & CMD_TARGET_MASK) >> CMD_TARGET_SHIFT)

/* Valid command bit */
#define	CMD_VALID_SHIFT		63
#define	CMD_VALID_MASK		(1UL << CMD_VALID_SHIFT)
#define	CMD_VALID_GET(x)	\
    (((x)->cmd_dword[2] & CMD_VALID_MASK) >> CMD_VALID_SHIFT)

#endif /* _GICV3_ITS_H_ */
