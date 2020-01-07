/*	$OpenBSD: cpu.h,v 1.4 1998/09/15 10:50:12 pefo Exp $	*/

/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Ralph Campbell and Rick Macklem.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	Copyright (C) 1989 Digital Equipment Corporation.
 *	Permission to use, copy, modify, and distribute this software and
 *	its documentation for any purpose and without fee is hereby granted,
 *	provided that the above copyright notice appears in all copies.
 *	Digital Equipment Corporation makes no representations about the
 *	suitability of this software for any purpose.  It is provided "as is"
 *	without express or implied warranty.
 *
 *	from: @(#)cpu.h	8.4 (Berkeley) 1/4/94
 *	JNPR: cpu.h,v 1.9.2.2 2007/09/10 08:23:46 girish
 * $FreeBSD$
 */

#ifndef _MACHINE_CPU_H_
#define	_MACHINE_CPU_H_

#include <machine/endian.h>

/* BEGIN: these are going away */

#define	soft_int_mask(softintr)	(1 << ((softintr) + 8))
#define	hard_int_mask(hardintr)	(1 << ((hardintr) + 10))

/* END: These are going away */

/*
 * Exported definitions unique to mips cpu support.
 */

#ifndef _LOCORE
#include <machine/cpufunc.h>
#include <machine/frame.h>
#include <cheri/cheric.h>

#define	TRAPF_USERMODE(framep)  (((framep)->sr & MIPS_SR_KSU_USER) != 0)
#define	TRAPF_PC(framep)	((__cheri_addr vaddr_t)(framep)->pc)
#define	TRAPF_PC_OFFSET(framep)	((__cheri_offset vaddr_t)(framep)->pc)
#if __has_feature(capabilities)
#define	TRAPF_PC_SET_ADDR(framep, addr)	do {				\
    (framep)->pc = __builtin_cheri_address_set((framep)->pc, addr);	\
    KASSERT(cheri_gettag((framep)->pc), 				\
        ("created untagged pcc: " _CHERI_PRINT_PTR_FMT((framep)->pc)));	\
    } while(0)
#else
#define	TRAPF_PC_SET_ADDR(framep, addr)	\
    ((framep)->pc) = (trapf_pc_t)(uintptr_t)addr
#endif
/*
 * Note: No if __has_feature(capabilities) needed as uintcap_t is uintptr_t for
 * !has_feature(capabilities). Also no unrepresentable assert here since the
 * value is only ever incremented by four which is unlikely to cause an
 * unrepresentable capability.
 */
#define	TRAPF_PC_INCREMENT(framep, offset)	\
    (framep)->pc = (trapf_pc_t)((uintcap_t)((framep)->pc) + offset)
#define	cpu_getstack(td)	((td)->td_frame->sp)
#define	cpu_setstack(td, nsp)	((td)->td_frame->sp = (nsp))
#define	cpu_spinwait()		/* nothing */
#define	cpu_lock_delay()	DELAY(1)

/*
 * A machine-independent interface to the CPU's counter.
 */
#define get_cyclecount()	mips_rd_count()
#endif				/* !_LOCORE */

#if defined(_KERNEL) && !defined(_LOCORE)

extern char btext[];
extern char etext[];

void swi_vm(void *);
void cpu_halt(void);
void cpu_reset(void);

#endif				/* _KERNEL */
#endif				/* !_MACHINE_CPU_H_ */
