/*-
 * Copyright (c) 2015-2018 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * Portions of this software were developed by SRI International and the
 * University of Cambridge Computer Laboratory under DARPA/AFRL contract
 * FA8750-10-C-0237 ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Portions of this software were developed by the University of Cambridge
 * Computer Laboratory as part of the CTSRD Project, with support from the
 * UK Higher Education Innovation Fund (HEIF).
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
 */

#include <machine/asm.h>
__FBSDID("$FreeBSD$");

#include "assym.inc"

#include <machine/trap.h>
#include <machine/riscvreg.h>

.macro save_registers mode
#if __has_feature(capabilities)
.option push
#ifndef __CHERI_PURE_CAPABILITY__
.option capmode
.if \mode == 1
	/*
	 * Build a capability for 'csp' using 'sp' as an address
	 * in the kernel DDC.  We haven't saved any registers yet,
	 * so store 'ct0' in 'scratchc' temporarily.
	 *
	 * XXX: Bounds?  Maybe could use TF_SIZE + 16 as length?
	 * A purecap kernel would have proper bounds on csp already.
	 */
	cspecialw sscratchc, ct0
	cspecialr ct0, stdc
	csetaddr ct0, ct0, sp
	cmove	csp, ct0
	cspecialr ct0, sscratchc
.endif
#endif
	cincoffset csp, csp, -(TF_SIZE)

	csc	cra, (TF_RA)(csp)
#else
	addi	sp, sp, -(TF_SIZE)

	sd	ra, (TF_RA)(sp)
#endif

.if \mode == 0	/* We came from userspace. */
#if __has_feature(capabilities)
	csc	cgp, (TF_GP)(csp)

	/* Load our pcpu */
	csc	ctp, (TF_TP)(csp)
	clc	ctp, (TF_SIZE)(csp)
#else
	sd	gp, (TF_GP)(sp)

	/* Load our pcpu */
	sd	tp, (TF_TP)(sp)
	ld	tp, (TF_SIZE)(sp)
#endif
.endif

#if __has_feature(capabilities)
	csc	ct0, (TF_T + 0 * 16)(csp)
	csc	ct1, (TF_T + 1 * 16)(csp)
	csc	ct2, (TF_T + 2 * 16)(csp)
	csc	ct3, (TF_T + 3 * 16)(csp)
	csc	ct4, (TF_T + 4 * 16)(csp)
	csc	ct5, (TF_T + 5 * 16)(csp)
	csc	ct6, (TF_T + 6 * 16)(csp)

	csc	cs0, (TF_S + 0 * 16)(csp)
	csc	cs1, (TF_S + 1 * 16)(csp)
	csc	cs2, (TF_S + 2 * 16)(csp)
	csc	cs3, (TF_S + 3 * 16)(csp)
	csc	cs4, (TF_S + 4 * 16)(csp)
	csc	cs5, (TF_S + 5 * 16)(csp)
	csc	cs6, (TF_S + 6 * 16)(csp)
	csc	cs7, (TF_S + 7 * 16)(csp)
	csc	cs8, (TF_S + 8 * 16)(csp)
	csc	cs9, (TF_S + 9 * 16)(csp)
	csc	cs10, (TF_S + 10 * 16)(csp)
	csc	cs11, (TF_S + 11 * 16)(csp)

	csc	ca0, (TF_A + 0 * 16)(csp)
	csc	ca1, (TF_A + 1 * 16)(csp)
	csc	ca2, (TF_A + 2 * 16)(csp)
	csc	ca3, (TF_A + 3 * 16)(csp)
	csc	ca4, (TF_A + 4 * 16)(csp)
	csc	ca5, (TF_A + 5 * 16)(csp)
	csc	ca6, (TF_A + 6 * 16)(csp)
	csc	ca7, (TF_A + 7 * 16)(csp)

.if \mode == 1
	/* Store kernel sp */
	li	t1, TF_SIZE
	cincoffset ct0, csp, t1
	csc	ct0, (TF_SP)(csp)
.else
	/* Store user sp */
	cspecialr ct0, sscratchc
	csc	ct0, (TF_SP)(csp)
.endif
	cmove	ct0, cnull
	cspecialw sscratchc, ct0
	cspecialr ct0, sepcc
	csc	ct0, (TF_SEPC)(csp)
	cspecialr ct0, ddc
	csc	ct0, (TF_DDC)(csp)

#ifdef __CHERI_PURE_CAPABILITY__
	cmove	ct0, cnull
#else
	cspecialr ct0, stdc
#endif
	cspecialw ddc, ct0

#ifndef __CHERI_PURE_CAPABILITY__
	/* Switch to non-capmode PCC. */
	cllc	ct1, 1f
	csetflags ct1, ct1, x0
	cjr	ct1
1:
#endif
.option pop
#else
	sd	t0, (TF_T + 0 * 8)(sp)
	sd	t1, (TF_T + 1 * 8)(sp)
	sd	t2, (TF_T + 2 * 8)(sp)
	sd	t3, (TF_T + 3 * 8)(sp)
	sd	t4, (TF_T + 4 * 8)(sp)
	sd	t5, (TF_T + 5 * 8)(sp)
	sd	t6, (TF_T + 6 * 8)(sp)

	sd	s0, (TF_S + 0 * 8)(sp)
	sd	s1, (TF_S + 1 * 8)(sp)
	sd	s2, (TF_S + 2 * 8)(sp)
	sd	s3, (TF_S + 3 * 8)(sp)
	sd	s4, (TF_S + 4 * 8)(sp)
	sd	s5, (TF_S + 5 * 8)(sp)
	sd	s6, (TF_S + 6 * 8)(sp)
	sd	s7, (TF_S + 7 * 8)(sp)
	sd	s8, (TF_S + 8 * 8)(sp)
	sd	s9, (TF_S + 9 * 8)(sp)
	sd	s10, (TF_S + 10 * 8)(sp)
	sd	s11, (TF_S + 11 * 8)(sp)

	sd	a0, (TF_A + 0 * 8)(sp)
	sd	a1, (TF_A + 1 * 8)(sp)
	sd	a2, (TF_A + 2 * 8)(sp)
	sd	a3, (TF_A + 3 * 8)(sp)
	sd	a4, (TF_A + 4 * 8)(sp)
	sd	a5, (TF_A + 5 * 8)(sp)
	sd	a6, (TF_A + 6 * 8)(sp)
	sd	a7, (TF_A + 7 * 8)(sp)

.if \mode == 1
	/* Store kernel sp */
	li	t1, TF_SIZE
	add	t0, sp, t1
	sd	t0, (TF_SP)(sp)
.else
	/* Store user sp */
	csrr	t0, sscratch
	sd	t0, (TF_SP)(sp)
.endif
	li	t0, 0
	csrw	sscratch, t0
	csrr	t0, sepc
	sd	t0, (TF_SEPC)(sp)
#endif
#ifdef __CHERI_PURE_CAPABILITY__
	csrr	t0, sstatus
	csd	t0, (TF_SSTATUS)(csp)
	csrr	t0, stval
	csd	t0, (TF_STVAL)(csp)
	csrr	t0, scause
	csd	t0, (TF_SCAUSE)(csp)
#else
	csrr	t0, sstatus
	sd	t0, (TF_SSTATUS)(sp)
	csrr	t0, stval
	sd	t0, (TF_STVAL)(sp)
	csrr	t0, scause
	sd	t0, (TF_SCAUSE)(sp)
#endif
.if \mode == 1
	/* Disable user address access for supervisor mode exceptions. */
	li	t0, SSTATUS_SUM
	csrc	sstatus, t0
.endif

.if \mode == 0
#ifdef __CHERI_PURE_CAPABILITY__
	cspecialr ct0, stdc
	cmove	cgp, ct0
#else
.option push
.option norelax
	/* Load the kernel's global pointer */
	lla	gp, __global_pointer$
.option pop
#endif
.endif
.endm

.macro load_registers mode
#ifdef __CHERI_PURE_CAPABILITY__
	cld	t0, (TF_SSTATUS)(csp)
#else
	ld	t0, (TF_SSTATUS)(sp)
#endif
.if \mode == 0
	/* Ensure user interrupts will be enabled on eret */
	li	t1, SSTATUS_SPIE
	or	t0, t0, t1
.else
	/*
	 * Disable interrupts for supervisor mode exceptions.
	 * For user mode exceptions we have already done this
	 * in do_ast.
	 */
	li	t1, ~SSTATUS_SIE
	and	t0, t0, t1
.endif
	csrw	sstatus, t0

.option push
#if __has_feature(capabilities)
#ifndef __CHERI_PURE_CAPABILITY__
	/* Switch to capmode PCC. */
	lla	t0, 1f
	cspecialr ct1, pcc
	csetaddr ct1, ct1, t0
	li	t0, 1
	csetflags ct1, ct1, t0
#ifdef __riscv_xcheri_mode_dependent_jumps
	jr.cap	ct1
#else
	cjr	ct1
#endif
.option capmode
1:
	/*
	 * Build a capability for 'csp' using 'sp' as an address
	 * in the kernel DDC.
	 *
	 * XXX: Bounds?  Maybe could use TF_SIZE + 16 as length?
	 * A purecap kernel would have proper bounds on csp already.
	 */
	cspecialr ct0, ddc
	csetaddr ct0, ct0, sp
	cmove	csp, ct0
#endif

	/*
	 * Switch to user DDC.  After this point, all stack accesses
	 * must use 'csp' instead of 'sp'.
	 */
	clc	ct0, (TF_DDC)(csp)
	cspecialw ddc, ct0
	clc	ct0, (TF_SEPC)(csp)
	cspecialw sepcc, ct0

.if \mode == 0
	/* We go to userspace. Load user csp */
	clc	ct0, (TF_SP)(csp)
	cspecialw sscratchc, ct0

	/* Store our pcpu */
	csc	ctp, (TF_SIZE)(csp)
	clc	ctp, (TF_TP)(csp)

	/* And restore the user's global pointer */
	clc	cgp, (TF_GP)(csp)
.endif

	clc	cra, (TF_RA)(csp)

	clc	ct0, (TF_T + 0 * 16)(csp)
	clc	ct1, (TF_T + 1 * 16)(csp)
	clc	ct2, (TF_T + 2 * 16)(csp)
	clc	ct3, (TF_T + 3 * 16)(csp)
	clc	ct4, (TF_T + 4 * 16)(csp)
	clc	ct5, (TF_T + 5 * 16)(csp)
	clc	ct6, (TF_T + 6 * 16)(csp)

	clc	cs0, (TF_S + 0 * 16)(csp)
	clc	cs1, (TF_S + 1 * 16)(csp)
	clc	cs2, (TF_S + 2 * 16)(csp)
	clc	cs3, (TF_S + 3 * 16)(csp)
	clc	cs4, (TF_S + 4 * 16)(csp)
	clc	cs5, (TF_S + 5 * 16)(csp)
	clc	cs6, (TF_S + 6 * 16)(csp)
	clc	cs7, (TF_S + 7 * 16)(csp)
	clc	cs8, (TF_S + 8 * 16)(csp)
	clc	cs9, (TF_S + 9 * 16)(csp)
	clc	cs10, (TF_S + 10 * 16)(csp)
	clc	cs11, (TF_S + 11 * 16)(csp)

	clc	ca0, (TF_A + 0 * 16)(csp)
	clc	ca1, (TF_A + 1 * 16)(csp)
	clc	ca2, (TF_A + 2 * 16)(csp)
	clc	ca3, (TF_A + 3 * 16)(csp)
	clc	ca4, (TF_A + 4 * 16)(csp)
	clc	ca5, (TF_A + 5 * 16)(csp)
	clc	ca6, (TF_A + 6 * 16)(csp)
	clc	ca7, (TF_A + 7 * 16)(csp)

	cincoffset csp, csp, (TF_SIZE)
#else
	ld	t0, (TF_SEPC)(sp)
	csrw	sepc, t0

.if \mode == 0
	/* We go to userspace. Load user sp */
	ld	t0, (TF_SP)(sp)
	csrw	sscratch, t0

	/* Store our pcpu */
	sd	tp, (TF_SIZE)(sp)
	ld	tp, (TF_TP)(sp)

	/* And restore the user's global pointer */
	ld	gp, (TF_GP)(sp)
.endif

	ld	ra, (TF_RA)(sp)

	ld	t0, (TF_T + 0 * 8)(sp)
	ld	t1, (TF_T + 1 * 8)(sp)
	ld	t2, (TF_T + 2 * 8)(sp)
	ld	t3, (TF_T + 3 * 8)(sp)
	ld	t4, (TF_T + 4 * 8)(sp)
	ld	t5, (TF_T + 5 * 8)(sp)
	ld	t6, (TF_T + 6 * 8)(sp)

	ld	s0, (TF_S + 0 * 8)(sp)
	ld	s1, (TF_S + 1 * 8)(sp)
	ld	s2, (TF_S + 2 * 8)(sp)
	ld	s3, (TF_S + 3 * 8)(sp)
	ld	s4, (TF_S + 4 * 8)(sp)
	ld	s5, (TF_S + 5 * 8)(sp)
	ld	s6, (TF_S + 6 * 8)(sp)
	ld	s7, (TF_S + 7 * 8)(sp)
	ld	s8, (TF_S + 8 * 8)(sp)
	ld	s9, (TF_S + 9 * 8)(sp)
	ld	s10, (TF_S + 10 * 8)(sp)
	ld	s11, (TF_S + 11 * 8)(sp)

	ld	a0, (TF_A + 0 * 8)(sp)
	ld	a1, (TF_A + 1 * 8)(sp)
	ld	a2, (TF_A + 2 * 8)(sp)
	ld	a3, (TF_A + 3 * 8)(sp)
	ld	a4, (TF_A + 4 * 8)(sp)
	ld	a5, (TF_A + 5 * 8)(sp)
	ld	a6, (TF_A + 6 * 8)(sp)
	ld	a7, (TF_A + 7 * 8)(sp)

	addi	sp, sp, (TF_SIZE)
#endif
.option pop
.endm

.macro	do_ast
	/* Disable interrupts */
	csrr	a4, sstatus
1:
	csrci	sstatus, (SSTATUS_SIE)

#ifdef __CHERI_PURE_CAPABILITY__
	clc	ca1, PC_CURTHREAD(ctp)
	clw	a2, TD_AST(ca1)
#else
	ld	a1, PC_CURTHREAD(tp)
	lw	a2, TD_AST(a1)
#endif

	beqz	a2, 2f

	/* Restore interrupts */
	andi	a4, a4, (SSTATUS_SIE)
	csrs	sstatus, a4

	/* Handle the ast */
#ifdef __CHERI_PURE_CAPABILITY__
	cmove	ca0, csp
	clgc	cra, _C_LABEL(ast)
	cjalr	cra
#else
	mv	a0, sp
	call	_C_LABEL(ast)
#endif

	/* Re-check for new ast scheduled */
	j	1b
2:
.endm

ENTRY(cpu_exception_handler)
#if __has_feature(capabilities)
	cspecialrw csp, sscratchc, csp
#else
	csrrw	sp, sscratch, sp
#endif
	beqz	sp, 1f
	/* User mode detected */
	j	cpu_exception_handler_user
1:
	/* Supervisor mode detected */
#if __has_feature(capabilities)
	cspecialrw csp, sscratchc, csp
#else
	csrrw	sp, sscratch, sp
#endif
	j	cpu_exception_handler_supervisor
END(cpu_exception_handler)

ENTRY(cpu_exception_handler_supervisor)
	save_registers 1
#ifdef __CHERI_PURE_CAPABILITY__
	cmove	ca0, csp
	clgc	cra, _C_LABEL(do_trap_supervisor)
	cjalr	cra
#else
	mv	a0, sp
	call	_C_LABEL(do_trap_supervisor)
#endif
	load_registers 1
	sret
END(cpu_exception_handler_supervisor)

ENTRY(cpu_exception_handler_user)
	save_registers 0
#ifdef __CHERI_PURE_CAPABILITY__
	cmove	ca0, csp
	clgc	cra, _C_LABEL(do_trap_user)
	cjalr	cra
#else
	mv	a0, sp
	call	_C_LABEL(do_trap_user)
#endif
	do_ast
	load_registers 0
#if __has_feature(capabilities)
	cspecialrw csp, sscratchc, csp
#else
	csrrw	sp, sscratch, sp
#endif
	sret
END(cpu_exception_handler_user)

/*-
 * CHERI CHANGES START
 * {
 *   "updated": 20200804,
 *   "target_type": "kernel",
 *   "changes_purecap": [
 *     "support"
 *   ]
 * }
 * CHERI CHANGES END
 */
