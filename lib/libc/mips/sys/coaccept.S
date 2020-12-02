/*-
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.
 * Copyright (c) 2015 SRI International
 * Copyright (c) 2017 Robert N. M. Watson
 * Copyright (c) 2018, 2020 Edward Tomasz Napierala <trasz@FreeBSD.org>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * This code is derived from software contributed to Berkeley by
 * Ralph Campbell.
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
 */

.set noreorder
.set noat

#include <machine/asm.h>
__FBSDID("$FreeBSD$");
#include "SYS.h"

#ifdef __ABICALLS__
	.abicalls
#endif

#define	JUMP_BUFFER_SIZE	(64 * _MIPS_SZCAP / 8)

LEAF(coaccept)
	/*
	 * Save the CPU context before calling into switcher.
	 * This mostly mimics setjmp(3).
	 */
	cincoffsetimm	$csp, $csp, -JUMP_BUFFER_SIZE

	/*
	 * From "MIPSpro N32 ABI Handbook", Table 2-1:
	 * Registers s0..s7 are callee-saved.
	 * The sp register is callee-saved.
	 * The fp (or s8) register is callee-saved.
	 * The gp register is callee-saved (for n32/n64).
	 *
	 * NB: The pure-capability ABI roughly retains the n32/n64 MIPS ABI in
	 * terms of caller/callee-save registers, despite some registers
	 * seeing different use.
	 *
	 * NB: In the pure-capability ABI, we need to neither save nore restore
	 * $ra and $sp, which are caller-save and not used for control flow.
	 */
	csd		s0, zero, (_JB_REG_S0 * SZREG)($csp)
	csd		s1, zero, (_JB_REG_S1 * SZREG)($csp)
	csd		s2, zero, (_JB_REG_S2 * SZREG)($csp)
	csd		s3, zero, (_JB_REG_S3 * SZREG)($csp)
	csd		s4, zero, (_JB_REG_S4 * SZREG)($csp)
	csd		s5, zero, (_JB_REG_S5 * SZREG)($csp)
	csd		s6, zero, (_JB_REG_S6 * SZREG)($csp)
	csd		s7, zero, (_JB_REG_S7 * SZREG)($csp)
	csd		s8, zero, (_JB_REG_S8 * SZREG)($csp)
	csd		gp, zero, (_JB_REG_GP * SZREG)($csp)
#ifndef __mips_soft_float
	/*
	 * From "MIPSpro N32 ABI Handbook", Table 2-1:
	 * In N64, FP registers F24 .. F31 are callee-saved.
	 */
#if 0
	/*
	 * XXX: Not needed here, I suppose?
	 */
	cfc1	v0, $31
	csw	v0, zero, (_JB_FPREG_FCSR * SZREG)($csp)
#endif
	csdc1	$f24, zero, (_JB_FPREG_F24 * SZREG)($csp)
	csdc1	$f25, zero, (_JB_FPREG_F25 * SZREG)($csp)
	csdc1	$f26, zero, (_JB_FPREG_F26 * SZREG)($csp)
	csdc1	$f27, zero, (_JB_FPREG_F27 * SZREG)($csp)
	csdc1	$f28, zero, (_JB_FPREG_F28 * SZREG)($csp)
	csdc1	$f29, zero, (_JB_FPREG_F29 * SZREG)($csp)
	csdc1	$f30, zero, (_JB_FPREG_F30 * SZREG)($csp)
	csdc1	$f31, zero, (_JB_FPREG_F31 * SZREG)($csp)
#endif	/* ! __mips_soft_float */
	csc		$c11, zero, _JB_CHERI_OFFSET(C11)($csp)
	csc		$c12, zero, _JB_CHERI_OFFSET(C12)($csp)
	csc		$c13, zero, _JB_CHERI_OFFSET(C13)($csp)
	csc		$c14, zero, _JB_CHERI_OFFSET(C14)($csp)
	csc		$c15, zero, _JB_CHERI_OFFSET(C15)($csp)
	csc		$c16, zero, _JB_CHERI_OFFSET(C16)($csp)
	csc		$c17, zero, _JB_CHERI_OFFSET(C17)($csp)
	csc		$c18, zero, _JB_CHERI_OFFSET(C18)($csp)
	csc		$c19, zero, _JB_CHERI_OFFSET(C19)($csp)
	csc		$c20, zero, _JB_CHERI_OFFSET(C20)($csp)
	csc		$c21, zero, _JB_CHERI_OFFSET(C21)($csp)
	csc		$c22, zero, _JB_CHERI_OFFSET(C22)($csp)
	csc		$c23, zero, _JB_CHERI_OFFSET(C23)($csp)
	csc		$c24, zero, _JB_CHERI_OFFSET(C24)($csp)
	csc		$c25, zero, _JB_CHERI_OFFSET(C25)($csp)

	/*
	 * Enter the switcher.
	 */

	cgetpcc		$c13
	cincoffset	$c13, $c13, 12
	ccall		$c3, $c4, 1
	nop

	/*
	 * Back from the switcher; restore the CPU context.
	 */

	/*
	 * From "MIPSpro N32 ABI Handbook", Table 2-1:
	 * Registers s0..s7 are callee-saved.
	 * The sp register is callee-saved.
	 * The fp (or s8) register is callee-saved.
	 * The gp register is callee-saved (for n32/n64).
	 *
	 * NB: In the pure-capability ABI, we need to neither save nore restore
	 * $ra and $sp, which are caller-save and not used for control flow.
	 */
	cld		s0, zero, (_JB_REG_S0 * SZREG)($csp)
	cld		s1, zero, (_JB_REG_S1 * SZREG)($csp)
	cld		s2, zero, (_JB_REG_S2 * SZREG)($csp)
	cld		s3, zero, (_JB_REG_S3 * SZREG)($csp)
	cld		s4, zero, (_JB_REG_S4 * SZREG)($csp)
	cld		s5, zero, (_JB_REG_S5 * SZREG)($csp)
	cld		s6, zero, (_JB_REG_S6 * SZREG)($csp)
	cld		s7, zero, (_JB_REG_S7 * SZREG)($csp)
	cld		s8, zero, (_JB_REG_S8 * SZREG)($csp)
	cld		gp, zero, (_JB_REG_GP * SZREG)($csp)
#ifndef __mips_soft_float
	/*
	 * From "MIPSpro N32 ABI Handbook", Table 2-1:
	 * In N32, FP registers F20, F22, F24, F26, F28, F30 are callee-saved.
	 * In N64, FP registers F23 .. F31 are callee-saved.
	 * In O32, FP registers F20 .. F23 are callee-saved.
	 */
#if 0
	/*
	 * XXX: Not needed here, I suppose?
	 */
        clw		v0, zero, (_JB_FPREG_FCSR * SZREG)($csp)
        ctc1		v0, $31
#endif
	cldc1		$f24, zero, (_JB_FPREG_F24 * SZREG)($csp)
	cldc1		$f25, zero, (_JB_FPREG_F25 * SZREG)($csp)
	cldc1		$f26, zero, (_JB_FPREG_F26 * SZREG)($csp)
	cldc1		$f27, zero, (_JB_FPREG_F27 * SZREG)($csp)
	cldc1		$f28, zero, (_JB_FPREG_F28 * SZREG)($csp)
	cldc1		$f29, zero, (_JB_FPREG_F29 * SZREG)($csp)
	cldc1		$f30, zero, (_JB_FPREG_F30 * SZREG)($csp)
	cldc1		$f31, zero, (_JB_FPREG_F31 * SZREG)($csp)
#endif	/* ! __mips_soft_float */
	clc		$c11, zero, _JB_CHERI_OFFSET(C11)($csp)
	clc		$c12, zero, _JB_CHERI_OFFSET(C12)($csp)
	clc		$c13, zero, _JB_CHERI_OFFSET(C13)($csp)
	clc		$c14, zero, _JB_CHERI_OFFSET(C14)($csp)
	clc		$c15, zero, _JB_CHERI_OFFSET(C15)($csp)
	clc		$c16, zero, _JB_CHERI_OFFSET(C16)($csp)
	clc		$c17, zero, _JB_CHERI_OFFSET(C17)($csp)
	clc		$c18, zero, _JB_CHERI_OFFSET(C18)($csp)
	clc		$c19, zero, _JB_CHERI_OFFSET(C19)($csp)
	clc		$c20, zero, _JB_CHERI_OFFSET(C20)($csp)
	clc		$c21, zero, _JB_CHERI_OFFSET(C21)($csp)
	clc		$c22, zero, _JB_CHERI_OFFSET(C22)($csp)
	clc		$c23, zero, _JB_CHERI_OFFSET(C23)($csp)
	clc		$c24, zero, _JB_CHERI_OFFSET(C24)($csp)
	clc		$c25, zero, _JB_CHERI_OFFSET(C25)($csp)

	addi		t0, zero, JUMP_BUFFER_SIZE
	cincoffset	$csp, $csp, t0
	bnez		v0, 1f
	nop
	cjr		$c17
	nop
1:
	/*
	 * XXX: I don't understand what it does, except that PIC_TAILCALL()
	 *      depends on $c26 being loaded by PIC_PROLOGUE(). I don't really
	 *      want to save $c26, so let's just call it here, all in one place.
	 *      Without it, stuff will crash if v0 != 0.
	 */
	PIC_PROLOGUE(coaccept)
	PIC_TAILCALL(__cerror)
	nop
END(coaccept)
