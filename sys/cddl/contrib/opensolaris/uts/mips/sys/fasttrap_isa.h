/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_FASTTRAP_ISA_H
#define	_FASTTRAP_ISA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	FASTTRAP_SUNWDTRACE_SIZE	64

// break
#define FASTTRAP_INSTR			MIPS_BREAK_PID_BKPT

typedef	uint32_t	fasttrap_instr_t;

/* This mips implementation will only support to put a probe on the entrypoint
 * of a userpsace function, and not at an offset or return.
 */
// This struct is a field of fasttrap_tracepoint
typedef struct fasttrap_machtp_t {
	fasttrap_instr_t	ftmt_instr		/* original instruction */
	fasttrap_instr_t	ftmt_next_instr;	/* used to single step */
	uint64_t		ftmt_next_instr_addr;
	uint8_t			single_stepping;

} fasttrap_machtp_t;

#define	ftt_instr		ftt_mtp.ftmt_instr
#define	ftt_next_instr		ftt_mtp.ftmt_next_instr
#define	ftt_next_instr_addr	ftt_mtp.ftmt_next_instr_addr
#define	single_stepping		ftt_mtp.single_stepping


#define	FASTTRAP_AFRAMES		3
#define	FASTTRAP_RETURN_AFRAMES		4
#define	FASTTRAP_ENTRY_AFRAMES		3
#define	FASTTRAP_OFFSET_AFRAMES		3

#ifdef	__cplusplus
}
#endif

#endif	/* _FASTTRAP_ISA_H */
