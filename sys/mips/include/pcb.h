
/*	$OpenBSD: pcb.h,v 1.3 1998/09/15 10:50:12 pefo Exp $	*/

/*-
 * SPDX-License-Identifier: BSD-3-Clause AND BSD-2-Clause
 *
 * Copyright (c) 2017 Robert N. M. Watson
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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
 * Copyright (c) 1988 University of Utah.
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department and Ralph Campbell.
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
 *	from: Utah Hdr: pcb.h 1.13 89/04/23
 *	from: @(#)pcb.h 8.1 (Berkeley) 6/10/93
 *	JNPR: pcb.h,v 1.2 2006/08/07 11:51:17 katta
 * $FreeBSD$
 */

#ifndef _MACHINE_PCB_H_
#define	_MACHINE_PCB_H_

/*
 * used by switch.S
 */
#define	PCB_REG_S0	0
#define	PCB_REG_S1	1
#define	PCB_REG_S2	2
#define	PCB_REG_S3	3
#define	PCB_REG_S4	4
#define	PCB_REG_S5	5
#define	PCB_REG_S6	6
#define	PCB_REG_S7	7
#define	PCB_REG_SP	8
#define	PCB_REG_S8	9
#define	PCB_REG_RA	10
#define	PCB_REG_SR	11
#define	PCB_REG_GP	12
#define	PCB_REG_PC	13

/*
 * Call ast if required
 *
 * XXX Do we really need to disable interrupts?
 */
#define DO_AST				             \
44:				                     \
	mfc0	t0, MIPS_COP_0_STATUS               ;\
	and	a0, t0, MIPS_SR_INT_IE              ;\
	xor	t0, a0, t0                          ;\
	mtc0	t0, MIPS_COP_0_STATUS               ;\
	COP0_SYNC                                   ;\
	GET_CPU_PCPU(s1)                            ;\
	PTR_L	s3, PC_CURPCB(s1)                   ;\
	PTR_L	s1, PC_CURTHREAD(s1)                ;\
	lw	s2, TD_FLAGS(s1)                    ;\
	li	s0, TDF_ASTPENDING | TDF_NEEDRESCHED;\
	and	s2, s0                              ;\
	mfc0	t0, MIPS_COP_0_STATUS               ;\
	or	t0, a0, t0                          ;\
	mtc0	t0, MIPS_COP_0_STATUS               ;\
	COP0_SYNC                                   ;\
	beq	s2, zero, 4f                        ;\
	nop                                         ;\
	PTR_LA	t9, _C_LABEL(ast)                   ;\
	jalr	t9                                  ;\
	PTR_ADDU a0, s3, U_PCB_REGS                 ;\
	j	44b		                    ;\
        nop                                         ;\
4:

#define	SAVE_U_PCB_REG(reg, offs, base) \
	REG_S	reg, (U_PCB_REGS + (SZREG * offs)) (base)

#define	RESTORE_U_PCB_REG(reg, offs, base) \
	REG_L	reg, (U_PCB_REGS + (SZREG * offs)) (base)

#ifdef CPU_CHERI
#define	SAVE_U_PCB_CREG(creg, offs, base) \
	csc	creg, base, (U_PCB_REGS + (SZREG * offs)) ($ddc)

#define	RESTORE_U_PCB_CREG(creg, offs, base) \
	clc	creg, base, (U_PCB_REGS + (SZREG * offs)) ($ddc)

/*
 * Note: Updating EPCC will also update CP0_EPC. Therefore we should not be
 * setting CP0_EPC to the value of PC (which is an absolute pc address).
 * The kernel has been adjusted to use $pcc instead of $pc everywhere so we
 * can simply write that to $epcc.
 */
#define RESTORE_U_PCB_PC(unused_pc_vaddr_tmpreg, pcb)			\
	/* EPCC is no longer a GPR so load it into C27 first. */	\
	csetkr1c	CHERI_REG_KSCRATCH; /* Save $c27 in $kr1c. */	\
	RESTORE_U_PCB_CREG(CHERI_REG_KSCRATCH, PCC, pcb);		\
	CSetEPCC CHERI_REG_KSCRATCH;					\
	/* Restore $c27 since we clobbered it to set EPCC */		\
	cgetkr1c	CHERI_REG_KSCRATCH;				\
	/* Clear kr1c again */						\
	csetkr1c	$cnull

#else
/* Non-CHERI case: just update CP0_EPC with the saved pc virtual address. */
#define RESTORE_U_PCB_PC(pc_vaddr_tmpreg, pcb)	\
	RESTORE_U_PCB_REG(pc_vaddr_tmpreg, PC, pcb);		\
	MTC0	pc_vaddr_tmpreg, MIPS_COP_0_EXC_PC
#endif

#define	SAVE_U_PCB_FPREG(reg, offs, base) \
	FP_S	reg, (U_PCB_FPREGS + (SZFPREG * offs)) (base)

#define	RESTORE_U_PCB_FPREG(reg, offs, base) \
	FP_L	reg, (U_PCB_FPREGS + (SZFPREG * offs)) (base)

#define	SAVE_U_PCB_FPSR(reg, offs, base) \
	REG_S	reg, (U_PCB_FPREGS + (SZFPREG * offs)) (base)

#define	RESTORE_U_PCB_FPSR(reg, offs, base) \
	REG_L	reg, (U_PCB_FPREGS + (SZFPREG * offs)) (base)

#define	SAVE_U_PCB_CONTEXT(reg, offs, base) \
	REG_S	reg, (U_PCB_CONTEXT + (SZREG * offs)) (base)

#define	RESTORE_U_PCB_CONTEXT(reg, offs, base) \
	REG_L	reg, (U_PCB_CONTEXT + (SZREG * offs)) (base)

#ifndef LOCORE
#include <machine/frame.h>
#ifdef CPU_CHERI
#include <cheri/cheri.h>
#endif

/*
 * MIPS process control block
 */
struct pcb
{
	struct trapframe pcb_regs;	/* saved CPU and registers */
	__register_t pcb_context[14];	/* kernel context for resume */
	void *pcb_onfault;		/* for copyin/copyout faults */
	trapf_pc_t pcb_tpc;
#ifdef CPU_CHERI
	struct cheri_signal pcb_cherisignal;	/* CHERI signal-related state. */
	struct cheri_kframe pcb_cherikframe;	/* kernel caller-save state. */
#endif
};

#ifdef _KERNEL
extern struct pcb *curpcb;		/* the current running pcb */

void makectx(struct trapframe *, struct pcb *);
int savectx(struct pcb *) __returns_twice;

#endif
#endif

#endif	/* !_MACHINE_PCB_H_ */
// CHERI CHANGES START
// {
//   "updated": 20181114,
//   "target_type": "header",
//   "changes": [
//     "support"
//   ]
// }
// CHERI CHANGES END
