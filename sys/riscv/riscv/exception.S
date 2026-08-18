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
#include "assym.inc"

#include <machine/trap.h>
#include <machine/riscvreg.h>

.macro save_registers mode
#if __has_feature(capabilities)
.option push
#ifndef __CHERI__
.option capmode
	/*
	 * If coming from userspace, load_registers 0 leaves 'csp' as a
	 * capability, which is then stored in 'sscratchc' whilst in
	 * userspace, and similarly for fork_trampoline, so no derivation is
	 * needed on re-entering the kernel.
	 */
.if \mode == 1
	/*
	 * Build a capability for 'csp' using 'sp' as an address
	 * in the kernel DDC.  We haven't saved any registers yet,
	 * so store 'ct0' in 'sscratchc' temporarily.
	 *
	 * XXX: Bounds?  Maybe could use TF_SIZE + KF_SIZE as length?
	 * A purecap kernel would have proper bounds on csp already.
	*/
	CSRW_CAP(sscratch, t0)
	GET_DDC(t0)
	yaddrw	t0, t0, sp
	ymv	sp, t0
	CSRR_CAP(t0, sscratch)
.endif
#endif
#endif
	ADDI_CAP sp, sp, -(TF_SIZE)

	S_CAP	ra, (TF_RA)(sp)
	S_CAP	tp, (TF_TP)(sp)
	S_CAP	gp, (TF_GP)(sp)

.if \mode == 0	/* We came from userspace. */
	/* Load our pcpu */
	L_CAP	tp, (TF_SIZE + KF_TP)(sp)
.endif

	S_CAP	t0, (TF_T + 0 * CAP_WIDTH)(sp)
	S_CAP	t1, (TF_T + 1 * CAP_WIDTH)(sp)
	S_CAP	t2, (TF_T + 2 * CAP_WIDTH)(sp)
	S_CAP	t3, (TF_T + 3 * CAP_WIDTH)(sp)
	S_CAP	t4, (TF_T + 4 * CAP_WIDTH)(sp)
	S_CAP	t5, (TF_T + 5 * CAP_WIDTH)(sp)
	S_CAP	t6, (TF_T + 6 * CAP_WIDTH)(sp)

	S_CAP	s0, (TF_S + 0 * CAP_WIDTH)(sp)
	S_CAP	s1, (TF_S + 1 * CAP_WIDTH)(sp)
	S_CAP	s2, (TF_S + 2 * CAP_WIDTH)(sp)
	S_CAP	s3, (TF_S + 3 * CAP_WIDTH)(sp)
	S_CAP	s4, (TF_S + 4 * CAP_WIDTH)(sp)
	S_CAP	s5, (TF_S + 5 * CAP_WIDTH)(sp)
	S_CAP	s6, (TF_S + 6 * CAP_WIDTH)(sp)
	S_CAP	s7, (TF_S + 7 * CAP_WIDTH)(sp)
	S_CAP	s8, (TF_S + 8 * CAP_WIDTH)(sp)
	S_CAP	s9, (TF_S + 9 * CAP_WIDTH)(sp)
	S_CAP	s10, (TF_S + 10 * CAP_WIDTH)(sp)
	S_CAP	s11, (TF_S + 11 * CAP_WIDTH)(sp)

	S_CAP	a0, (TF_A + 0 * CAP_WIDTH)(sp)
	S_CAP	a1, (TF_A + 1 * CAP_WIDTH)(sp)
	S_CAP	a2, (TF_A + 2 * CAP_WIDTH)(sp)
	S_CAP	a3, (TF_A + 3 * CAP_WIDTH)(sp)
	S_CAP	a4, (TF_A + 4 * CAP_WIDTH)(sp)
	S_CAP	a5, (TF_A + 5 * CAP_WIDTH)(sp)
	S_CAP	a6, (TF_A + 6 * CAP_WIDTH)(sp)
	S_CAP	a7, (TF_A + 7 * CAP_WIDTH)(sp)

.if \mode == 1
	/* Store kernel sp */
	li	t1, TF_SIZE
	ADD_CAP	t0, sp, t1
	S_CAP	t0, (TF_SP)(sp)
.else
	/* Store user sp */
	CSRR_CAP(t0, sscratch)
	S_CAP	t0, (TF_SP)(sp)
.endif
	MV_CAP	t0, zero
	CSRW_CAP(sscratch, t0)
	CSRR_CAP(t0, sepc)
	S_CAP	t0, (TF_SEPC)(sp)
#if __has_feature(capabilities)
	GET_DDC(t0)
	S_CAP	t0, (TF_DDC)(sp)
#endif

#if __has_feature(capabilities)
.if \mode == 0
	/* Load our DDC */
#ifdef __CHERI__
	MV_PTR	t0, zero
#else
	L_CAP	t0, (TF_SIZE + KF_DDC)(sp)
#endif
	SET_DDC(t0)
.endif

#ifndef __CHERI__
	/* Switch to non-capmode PCC. */
	MODESW_INT(t1)
#endif
.option pop
#endif

	csrr	t0, sstatus
	sd	t0, (TF_SSTATUS)(sp)
	csrr	t0, stval
	sd	t0, (TF_STVAL)(sp)
	csrr	t0, scause
	sd	t0, (TF_SCAUSE)(sp)
.if \mode == 1
	/* Disable user address access for supervisor mode exceptions. */
	li	t0, SSTATUS_SUM
	csrc	sstatus, t0
.endif

.if \mode == 0
#ifdef __CHERI__
	/* CHERI-RISC-V purecap doesn't currently use cgp. */
	MV_PTR	gp, zero
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
	ld	t0, (TF_SSTATUS)(sp)
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
#ifndef __CHERI__
	/* Switch to capmode PCC. */
	MODESW_CAP(t0, t1)
.option capmode

	/*
	 * Build a capability for 'csp' using 'sp' as an address
	 * in the kernel DDC.
	 *
	 * XXX: Bounds?  Maybe could use TF_SIZE + KF_SIZE as length?
	 * A purecap kernel would have proper bounds on csp already.
	 */
	GET_DDC(t0)
	yaddrw	t0, t0, sp
	MV_CAP	sp, t0

.if \mode == 0
	/* Store our DDC */
	GET_DDC(t0)
	S_CAP	t0, (TF_SIZE + KF_DDC)(sp)
.endif
#endif

	/*
	 * Switch to user DDC.  After this point, all stack accesses
	 * must use 'csp' instead of 'sp'.
	 */
	L_CAP	t0, (TF_DDC)(sp)
	SET_DDC(t0)
#endif

	L_CAP	t0, (TF_SEPC)(sp)
	CSRW_CAP(sepc, t0)

.if \mode == 0
	/* We go to userspace. Load user csp */
	L_CAP	t0, (TF_SP)(sp)
	CSRW_CAP(sscratch, t0)

	/* Store our pcpu */
	S_CAP	tp, (TF_SIZE + KF_TP)(sp)
	L_CAP	tp, (TF_TP)(sp)

	/* And restore the user's global pointer */
	L_CAP	gp, (TF_GP)(sp)
.endif

	L_CAP	ra, (TF_RA)(sp)

	L_CAP	t0, (TF_T + 0 * CAP_WIDTH)(sp)
	L_CAP	t1, (TF_T + 1 * CAP_WIDTH)(sp)
	L_CAP	t2, (TF_T + 2 * CAP_WIDTH)(sp)
	L_CAP	t3, (TF_T + 3 * CAP_WIDTH)(sp)
	L_CAP	t4, (TF_T + 4 * CAP_WIDTH)(sp)
	L_CAP	t5, (TF_T + 5 * CAP_WIDTH)(sp)
	L_CAP	t6, (TF_T + 6 * CAP_WIDTH)(sp)

	L_CAP	s0, (TF_S + 0 * CAP_WIDTH)(sp)
	L_CAP	s1, (TF_S + 1 * CAP_WIDTH)(sp)
	L_CAP	s2, (TF_S + 2 * CAP_WIDTH)(sp)
	L_CAP	s3, (TF_S + 3 * CAP_WIDTH)(sp)
	L_CAP	s4, (TF_S + 4 * CAP_WIDTH)(sp)
	L_CAP	s5, (TF_S + 5 * CAP_WIDTH)(sp)
	L_CAP	s6, (TF_S + 6 * CAP_WIDTH)(sp)
	L_CAP	s7, (TF_S + 7 * CAP_WIDTH)(sp)
	L_CAP	s8, (TF_S + 8 * CAP_WIDTH)(sp)
	L_CAP	s9, (TF_S + 9 * CAP_WIDTH)(sp)
	L_CAP	s10, (TF_S + 10 * CAP_WIDTH)(sp)
	L_CAP	s11, (TF_S + 11 * CAP_WIDTH)(sp)

	L_CAP	a0, (TF_A + 0 * CAP_WIDTH)(sp)
	L_CAP	a1, (TF_A + 1 * CAP_WIDTH)(sp)
	L_CAP	a2, (TF_A + 2 * CAP_WIDTH)(sp)
	L_CAP	a3, (TF_A + 3 * CAP_WIDTH)(sp)
	L_CAP	a4, (TF_A + 4 * CAP_WIDTH)(sp)
	L_CAP	a5, (TF_A + 5 * CAP_WIDTH)(sp)
	L_CAP	a6, (TF_A + 6 * CAP_WIDTH)(sp)
	L_CAP	a7, (TF_A + 7 * CAP_WIDTH)(sp)

	ADDI_CAP	sp, sp, (TF_SIZE)

.option pop
.endm

.macro	do_ast
	/* Disable interrupts */
	csrr	a4, sstatus
1:
	csrci	sstatus, (SSTATUS_SIE)

	L_PTR	a1, PC_CURTHREAD(tp)
	lw	a2, TD_AST(a1)

	beqz	a2, 2f

	/* Restore interrupts */
	andi	a4, a4, (SSTATUS_SIE)
	csrs	sstatus, a4

	/* Handle the ast */
	MV_PTR	a0, sp
	call	_C_LABEL(ast)

	/* Re-check for new ast scheduled */
	j	1b
2:
.endm

ENTRY(cpu_exception_handler)
	CSRRW_CAP(sp, sscratch, sp)
	beqz	sp, 1f
	/* User mode detected */
	j	cpu_exception_handler_user
1:
	/* Supervisor mode detected */
	CSRRW_CAP(sp, sscratch, sp)
	j	cpu_exception_handler_supervisor
END(cpu_exception_handler)

ENTRY(cpu_exception_handler_supervisor)
	save_registers 1
	MV_PTR	a0, sp
	call	_C_LABEL(do_trap_supervisor)
	load_registers 1
	sret
END(cpu_exception_handler_supervisor)

ENTRY(cpu_exception_handler_user)
	save_registers 0
	MV_PTR	a0, sp
	call	_C_LABEL(do_trap_user)
	do_ast
	load_registers 0
	CSRRW_CAP(sp, sscratch, sp)
	sret
END(cpu_exception_handler_user)

/*-
 * CHERI CHANGES START
 * {
 *   "updated": 20230509,
 *   "target_type": "kernel",
 *   "changes_purecap": [
 *     "support"
 *   ]
 * }
 * CHERI CHANGES END
 */
