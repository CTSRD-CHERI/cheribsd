/*	$OpenBSD: regnum.h,v 1.3 1999/01/27 04:46:06 imp Exp $	*/

/*-
 * SPDX-License-Identifier: BSD-3-Clause AND BSD-2-Clause
 *
 * Copyright (c) 2011-2016 Robert N. M. Watson
 * Copyright (c) 2015 SRI International
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
 *	from: Utah Hdr: reg.h 1.1 90/07/09
 *	@(#)reg.h	8.2 (Berkeley) 1/11/94
 *	JNPR: regnum.h,v 1.6 2007/08/09 11:23:32 katta
 * $FreeBSD$
 */

#ifndef _MACHINE_REGNUM_H_
#define	_MACHINE_REGNUM_H_

#define	NUMSAVEREGS	40
#define	NUMFPREGS	34

#define	NUMCHERISAVEREGS	34	/* Plenty of alignment already. */

/*
 * Location of the saved registers relative to ZERO.
 * This must match struct trapframe defined in frame.h exactly.
 * This must also match regdef.h.
 */
#if defined(_KERNEL) || defined(_WANT_MIPS_REGNUM)
#define	ZERO	0
#define	AST	1
#define	V0	2
#define	V1	3
#define	A0	4
#define	A1	5
#define	A2	6
#define	A3	7
#if defined(__mips_n32) || defined(__mips_n64)
#define	A4	8
#define	A5	9
#define	A6	10
#define	A7	11
#define	T0	12
#define	T1	13
#define	T2	14
#define	T3	15
#else
#define	T0	8
#define	T1	9
#define	T2	10
#define	T3	11
#define	T4	12
#define	T5	13
#define	T6	14
#define	T7	15
#endif
#define	S0	16
#define	S1	17
#define	S2	18
#define	S3	19
#define	S4	20
#define	S5	21
#define	S6	22
#define	S7	23
#define	T8	24
#define	T9	25
#define	K0	26
#define	K1	27
#define	GP	28
#define	SP	29
#define	S8	30
#define	RA	31
#define	SR	32
#define	PS	SR	/* alias for SR */
#define	MULLO	33
#define	MULHI	34
#define	BADVADDR 35
#define	CAUSE	36
#if __has_feature(capabilities) && defined(_KERNEL)
/*
 * Ensure that we don't use the PC macro for CHERI, use PCC instead.
 * However, we do need to expose it to userland since it is used e.g. by ASAN.
 */
#pragma GCC poison PC
/* Define a macro that can be used for the PT_GETREGS/PT_SETREGS implementation. */
#define	PT_REGS_PC	37
#else
#define	PC	37
#endif

/* XXXAR: These two seem unused so I repurposed them for BadInstr + BadInstrP */
#if 0
/*
 * IC is valid only on RM7K and RM9K processors. Access to this is
 * controlled by IC_INT_REG which defined in kernel config
 */
#define	IC	38
#define	DUMMY	39	/* for 8 byte alignment */
#else
#define	BADINSTR	38
#define	BADINSTR_P	39
#endif

/*
 * Pseudo registers so we save a complete set of registers regardless of
 * the ABI. See regdef.h for a more complete explanation.
 */
#if defined(__mips_n32) || defined(__mips_n64)
#define	TA0	8
#define	TA1	9
#define	TA2	10
#define	TA3	11
#else
#define	TA0	12
#define	TA1	13
#define	TA2	14
#define	TA3	15
#endif

/*
 * Load/store offsets for saved registers are with respect to the basic
 * register size (8 bytes on CHERI), not the CHERI capability register size
 * (16 or 32 bytes).  Adjust all values by CHERIREGOFFSIZE so that SZREG can
 * be used in all such calculations.
 */
#define	CHERIREGOFFSIZE	(CHERICAP_SIZE / SZREG)	/* Capability / register_t */
#define	CHERIBASE	NUMSAVEREGS

#define	DDC		(CHERIBASE + 0)
#define	C1		(CHERIBASE + 1 * CHERIREGOFFSIZE)
#define	C2		(CHERIBASE + 2 * CHERIREGOFFSIZE)
#define	C3		(CHERIBASE + 3 * CHERIREGOFFSIZE)
#define	C4		(CHERIBASE + 4 * CHERIREGOFFSIZE)
#define	C5		(CHERIBASE + 5 * CHERIREGOFFSIZE)
#define	C6		(CHERIBASE + 6 * CHERIREGOFFSIZE)
#define	C7		(CHERIBASE + 7 * CHERIREGOFFSIZE)
#define	C8		(CHERIBASE + 8 * CHERIREGOFFSIZE)
#define	C9		(CHERIBASE + 9 * CHERIREGOFFSIZE)
#define	C10		(CHERIBASE + 10 * CHERIREGOFFSIZE)
#define	STC		(CHERIBASE + 11 * CHERIREGOFFSIZE)
#define	C12		(CHERIBASE + 12 * CHERIREGOFFSIZE)
#define	C13		(CHERIBASE + 13 * CHERIREGOFFSIZE)
#define	C14		(CHERIBASE + 14 * CHERIREGOFFSIZE)
#define	C15		(CHERIBASE + 15 * CHERIREGOFFSIZE)
#define	C16		(CHERIBASE + 16 * CHERIREGOFFSIZE)
#define	C17		(CHERIBASE + 17 * CHERIREGOFFSIZE)
#define	C18		(CHERIBASE + 18 * CHERIREGOFFSIZE)
#define	C19		(CHERIBASE + 19 * CHERIREGOFFSIZE)
#define	C20		(CHERIBASE + 20 * CHERIREGOFFSIZE)
#define	C21		(CHERIBASE + 21 * CHERIREGOFFSIZE)
#define	C22		(CHERIBASE + 22 * CHERIREGOFFSIZE)
#define	C23		(CHERIBASE + 23 * CHERIREGOFFSIZE)
#define	C24		(CHERIBASE + 24 * CHERIREGOFFSIZE)
#define	C25		(CHERIBASE + 25 * CHERIREGOFFSIZE)
#define	IDC		(CHERIBASE + 26 * CHERIREGOFFSIZE)
#define	C27		(CHERIBASE + 27 * CHERIREGOFFSIZE)
#define	C28		(CHERIBASE + 28 * CHERIREGOFFSIZE)
#define	C29		(CHERIBASE + 29 * CHERIREGOFFSIZE)
#define	C30		(CHERIBASE + 30 * CHERIREGOFFSIZE)
#define	C31		(CHERIBASE + 31 * CHERIREGOFFSIZE)
#define	PCC		(CHERIBASE + 32 * CHERIREGOFFSIZE)
#define	CAPCAUSE	(CHERIBASE + 33 * CHERIREGOFFSIZE)

/*
 * Index of FP registers in 'struct frame', counting from the beginning
 * of the frame (i.e., including the general registers).
 */
#ifdef CPU_CHERI
/* NB: rounded up to nearest capability size over capcause; see frame.h. */
#define	FPBASE	(NUMSAVEREGS + NUMCHERISAVEREGS * CHERIREGOFFSIZE)
#else
#define	FPBASE	NUMSAVEREGS
#endif

#define	F0	(FPBASE+0)
#define	F1	(FPBASE+1)
#define	F2	(FPBASE+2)
#define	F3	(FPBASE+3)
#define	F4	(FPBASE+4)
#define	F5	(FPBASE+5)
#define	F6	(FPBASE+6)
#define	F7	(FPBASE+7)
#define	F8	(FPBASE+8)
#define	F9	(FPBASE+9)
#define	F10	(FPBASE+10)
#define	F11	(FPBASE+11)
#define	F12	(FPBASE+12)
#define	F13	(FPBASE+13)
#define	F14	(FPBASE+14)
#define	F15	(FPBASE+15)
#define	F16	(FPBASE+16)
#define	F17	(FPBASE+17)
#define	F18	(FPBASE+18)
#define	F19	(FPBASE+19)
#define	F20	(FPBASE+20)
#define	F21	(FPBASE+21)
#define	F22	(FPBASE+22)
#define	F23	(FPBASE+23)
#define	F24	(FPBASE+24)
#define	F25	(FPBASE+25)
#define	F26	(FPBASE+26)
#define	F27	(FPBASE+27)
#define	F28	(FPBASE+28)
#define	F29	(FPBASE+29)
#define	F30	(FPBASE+30)
#define	F31	(FPBASE+31)
#define	FSR	(FPBASE+32)
#define FIR	(FPBASE+33)

/*
 * Index of FP registers in 'struct frame', relative to the base
 * of the FP registers in frame (i.e., *not* including the general
 * registers).
 */
#define	F0_NUM	(0)
#define	F1_NUM	(1)
#define	F2_NUM	(2)
#define	F3_NUM	(3)
#define	F4_NUM	(4)
#define	F5_NUM	(5)
#define	F6_NUM	(6)
#define	F7_NUM	(7)
#define	F8_NUM	(8)
#define	F9_NUM	(9)
#define	F10_NUM	(10)
#define	F11_NUM	(11)
#define	F12_NUM	(12)
#define	F13_NUM	(13)
#define	F14_NUM	(14)
#define	F15_NUM	(15)
#define	F16_NUM	(16)
#define	F17_NUM	(17)
#define	F18_NUM	(18)
#define	F19_NUM	(19)
#define	F20_NUM	(20)
#define	F21_NUM	(21)
#define	F22_NUM	(22)
#define	F23_NUM	(23)
#define	F24_NUM	(24)
#define	F25_NUM	(25)
#define	F26_NUM	(26)
#define	F27_NUM	(27)
#define	F28_NUM	(28)
#define	F29_NUM	(29)
#define	F30_NUM	(30)
#define	F31_NUM	(31)
#define	FSR_NUM	(32)
#define	FIR_NUM	(33)

#endif	/* _KERNEL || _WANT_MIPS_REGNUM */

#endif /* !_MACHINE_REGNUM_H_ */
