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
#ifndef __CHERI_PURE_CAPABILITY__
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
	CSRW_CAP	sscratchc, CAP(t0)
	CSRR_CAP	CAP(t0), ddc
	_SCADDR		CAP(t0), CAP(t0), sp
	CMV_CAP		CAP(sp), CAP(t0)
	CSRR_CAP	CAP(t0), sscratchc
.endif
#endif
	CADDI_CAP	CAP(sp), CAP(sp), -(TF_SIZE)

	_SC	CAP(ra), (TF_RA)(CAP(sp))
	_SC	CAP(tp), (TF_TP)(CAP(sp))
	_SC	CAP(gp), (TF_GP)(CAP(sp))
#else
	addi	sp, sp, -(TF_SIZE)

	sd	ra, (TF_RA)(sp)
	sd	tp, (TF_TP)(sp)
	sd	gp, (TF_GP)(sp)
#endif

.if \mode == 0	/* We came from userspace. */
	/* Load our pcpu */
	_LC	CAP(tp), (TF_SIZE + KF_TP)(CAP(sp))
.endif

#if __has_feature(capabilities)
	_SC	CAP(t0), (TF_T + 0 * 16)(CAP(sp))
	_SC	CAP(t1), (TF_T + 1 * 16)(CAP(sp))
	_SC	CAP(t2), (TF_T + 2 * 16)(CAP(sp))
	_SC	CAP(t3), (TF_T + 3 * 16)(CAP(sp))
	_SC	CAP(t4), (TF_T + 4 * 16)(CAP(sp))
	_SC	CAP(t5), (TF_T + 5 * 16)(CAP(sp))
	_SC	CAP(t6), (TF_T + 6 * 16)(CAP(sp))

	_SC	CAP(s0), (TF_S + 0 * 16)(CAP(sp))
	_SC	CAP(s1), (TF_S + 1 * 16)(CAP(sp))
	_SC	CAP(s2), (TF_S + 2 * 16)(CAP(sp))
	_SC	CAP(s3), (TF_S + 3 * 16)(CAP(sp))
	_SC	CAP(s4), (TF_S + 4 * 16)(CAP(sp))
	_SC	CAP(s5), (TF_S + 5 * 16)(CAP(sp))
	_SC	CAP(s6), (TF_S + 6 * 16)(CAP(sp))
	_SC	CAP(s7), (TF_S + 7 * 16)(CAP(sp))
	_SC	CAP(s8), (TF_S + 8 * 16)(CAP(sp))
	_SC	CAP(s9), (TF_S + 9 * 16)(CAP(sp))
	_SC	CAP(s10), (TF_S + 10 * 16)(CAP(sp))
	_SC	CAP(s11), (TF_S + 11 * 16)(CAP(sp))

	_SC	CAP(a0), (TF_A + 0 * 16)(CAP(sp))
	_SC	CAP(a1), (TF_A + 1 * 16)(CAP(sp))
	_SC	CAP(a2), (TF_A + 2 * 16)(CAP(sp))
	_SC	CAP(a3), (TF_A + 3 * 16)(CAP(sp))
	_SC	CAP(a4), (TF_A + 4 * 16)(CAP(sp))
	_SC	CAP(a5), (TF_A + 5 * 16)(CAP(sp))
	_SC	CAP(a6), (TF_A + 6 * 16)(CAP(sp))
	_SC	CAP(a7), (TF_A + 7 * 16)(CAP(sp))

.if \mode == 1
	/* Store kernel sp */
	li	t1, TF_SIZE
	CADD_CAP CAP(t0), CAP(sp), t1
	_SC	CAP(t0), (TF_SP)(CAP(sp))
.else
	/* Store user sp */
	CSRR_CAP	CAP(t0), sscratchc
	_SC		CAP(t0), (TF_SP)(CAP(sp))
.endif
	CMV_CAP		CAP(t0), CAP(null)
	CSRW_CAP	sscratchc, CAP(t0)
	CSRR_CAP	CAP(t0), sepcc
	_SC		CAP(t0), (TF_SEPC)(CAP(sp))
	CSRR_CAP	CAP(t0), ddc
	_SC		CAP(t0), (TF_DDC)(CAP(sp))

.if \mode == 0
	/* Load our DDC */
#ifdef __CHERI_PURE_CAPABILITY__
	_CMV	CAP(t0), CAP(null)
#else
	_LC	CAP(t0), (TF_SIZE + KF_DDC)(CAP(sp))
#endif
	CSRW_CAP	ddc, CAP(t0)
.endif

#ifndef __CHERI_PURE_CAPABILITY__
	/* Switch to non-capmode PCC. */
#ifdef __riscv_xcheri
	cllc	CAP(t1), 1f
	csetflags CAP(t1), CAP(t1), x0
	cjr	CAP(t1)
1:
#else
	modesw.int
#endif
#endif
.option pop
#else /* !__has_feature(capabilities) */
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
#endif /* !__has_feature(capabilities) */
	csrr	t0, sstatus
	_SD	t0, (TF_SSTATUS)(PTR(sp))
	csrr	t0, stval
	_SD	t0, (TF_STVAL)(PTR(sp))
	csrr	t0, scause
	_SD	t0, (TF_SCAUSE)(PTR(sp))
#ifdef __riscv_zcheripurecap
	csrr	t0, stval2
	sd	t0, (TF_STVAL2)(PTR(sp))
#endif
.if \mode == 1
	/* Disable user address access for supervisor mode exceptions. */
	li	t0, SSTATUS_SUM
	csrc	sstatus, t0
.endif

.if \mode == 0
#ifdef __CHERI_PURE_CAPABILITY__
	/* CHERI-RISC-V purecap doesn't currently use cgp. */
	_CMV	PTR(gp), PTR(null)
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
	_LD	t0, (TF_SSTATUS)(PTR(sp))
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
#ifdef __riscv_xcheri
	lla	t0, 1f
	cspecialr ct1, pcc
	scaddr	ct1, ct1, t0
	li	t0, 1
	csetflags ct1, ct1, t0
#ifdef __riscv_xcheri_mode_dependent_jumps
	jr.cap	ct1
#else
	jr	ct1
#endif
#else /* !defiend(__riscv_xcheri) */
	modesw.cap
#endif  /* !defiend(__riscv_xcheri) */
.option capmode
1:
	/*
	 * Build a capability for 'csp' using 'sp' as an address
	 * in the kernel DDC.
	 *
	 * XXX: Bounds?  Maybe could use TF_SIZE + KF_SIZE as length?
	 * A purecap kernel would have proper bounds on csp already.
	 */
	CSRR_CAP	CAP(t0), ddc
	_SCADDR	CAP(t0), CAP(t0), sp
	CMV_CAP	CAP(sp), CAP(t0)
#endif

#ifndef __CHERI_PURE_CAPABILITY__
.if \mode == 0
	/* Store our DDC */
	CSRR_CAP	CAP(t0), ddc
	_SC		CAP(t0), (TF_SIZE + KF_DDC)(CAP(sp))
.endif
#endif

	/*
	 * Switch to user DDC.  After this point, all stack accesses
	 * must use 'csp' instead of 'sp'.
	 */
	_LC		CAP(t0), (TF_DDC)(CAP(sp))
	CSRW_CAP	ddc, CAP(t0)
	_LC		CAP(t0), (TF_SEPC)(CAP(sp))
	CSRW_CAP	sepcc, CAP(t0)

.if \mode == 0
	/* We go to userspace. Load user csp */
	_LC		CAP(t0), (TF_SP)(CAP(sp))
	CSRW_CAP	sscratchc, CAP(t0)

	/* Store our pcpu */
	_SC	CAP(tp), (TF_SIZE + KF_TP)(CAP(sp))
	_LC	CAP(tp), (TF_TP)(CAP(sp))

	/* And restore the user's global pointer */
	_LC	CAP(gp), (TF_GP)(CAP(sp))
.endif

	_LC	CAP(ra), (TF_RA)(CAP(sp))

	_LC	ct0, (TF_T + 0 * 16)(CAP(sp))
	_LC	ct1, (TF_T + 1 * 16)(CAP(sp))
	_LC	ct2, (TF_T + 2 * 16)(CAP(sp))
	_LC	ct3, (TF_T + 3 * 16)(CAP(sp))
	_LC	ct4, (TF_T + 4 * 16)(CAP(sp))
	_LC	ct5, (TF_T + 5 * 16)(CAP(sp))
	_LC	ct6, (TF_T + 6 * 16)(CAP(sp))

	_LC	cs0, (TF_S + 0 * 16)(CAP(sp))
	_LC	cs1, (TF_S + 1 * 16)(CAP(sp))
	_LC	cs2, (TF_S + 2 * 16)(CAP(sp))
	_LC	cs3, (TF_S + 3 * 16)(CAP(sp))
	_LC	cs4, (TF_S + 4 * 16)(CAP(sp))
	_LC	cs5, (TF_S + 5 * 16)(CAP(sp))
	_LC	cs6, (TF_S + 6 * 16)(CAP(sp))
	_LC	cs7, (TF_S + 7 * 16)(CAP(sp))
	_LC	cs8, (TF_S + 8 * 16)(CAP(sp))
	_LC	cs9, (TF_S + 9 * 16)(CAP(sp))
	_LC	cs10, (TF_S + 10 * 16)(CAP(sp))
	_LC	cs11, (TF_S + 11 * 16)(CAP(sp))

	_LC	ca0, (TF_A + 0 * 16)(CAP(sp))
	_LC	ca1, (TF_A + 1 * 16)(CAP(sp))
	_LC	ca2, (TF_A + 2 * 16)(CAP(sp))
	_LC	ca3, (TF_A + 3 * 16)(CAP(sp))
	_LC	ca4, (TF_A + 4 * 16)(CAP(sp))
	_LC	ca5, (TF_A + 5 * 16)(CAP(sp))
	_LC	ca6, (TF_A + 6 * 16)(CAP(sp))
	_LC	ca7, (TF_A + 7 * 16)(CAP(sp))

	CADDI_CAP	CAP(sp), CAP(sp), (TF_SIZE)
#else /* !__has_feature(capabilities) */
	ld	t0, (TF_SEPC)(sp)
	csrw	sepc, t0

.if \mode == 0
	/* We go to userspace. Load user sp */
	ld	t0, (TF_SP)(sp)
	csrw	sscratch, t0

	/* Store our pcpu */
	sd	tp, (TF_SIZE + KF_TP)(sp)
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
#endif /* !__has_feature(capabilities) */
.option pop
.endm

.macro	do_ast
	/* Disable interrupts */
	csrr	a4, sstatus
1:
	csrci	sstatus, (SSTATUS_SIE)

#ifdef __CHERI_PURE_CAPABILITY__
	L_PTR	PTR(a1), PC_CURTHREAD(PTR(tp))
	_LW	a2, TD_AST(PTR(a1))
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
	_CMV	PTR(a0), PTR(sp)
	_LGC	PTR(ra), _C_LABEL(ast)
	_JALR	PTR(ra)
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
	CSRRW_CAP	CAP(sp), sscratchc, CAP(sp)
#else
	csrrw	sp, sscratch, sp
#endif
	beqz	sp, 1f
	/* User mode detected */
	j	cpu_exception_handler_user
1:
	/* Supervisor mode detected */
#if __has_feature(capabilities)
	CSRRW_CAP	CAP(sp), sscratchc, CAP(sp)
#else
	csrrw	sp, sscratch, sp
#endif
	j	cpu_exception_handler_supervisor
END(cpu_exception_handler)

ENTRY(cpu_exception_handler_supervisor)
	save_registers 1
#ifdef __CHERI_PURE_CAPABILITY__
	_CMV	PTR(a0), PTR(sp)
	_LGC	PTR(ra), _C_LABEL(do_trap_supervisor)
	_JALR	PTR(ra)
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
	_CMV	PTR(a0), PTR(sp)
	_LGC	PTR(ra), _C_LABEL(do_trap_user)
	_JALR	PTR(ra)
#else
	mv	a0, sp
	call	_C_LABEL(do_trap_user)
#endif
	do_ast
	load_registers 0
#if __has_feature(capabilities)
	CSRRW_CAP	CAP(sp), sscratchc, CAP(sp)
#else
	csrrw	sp, sscratch, sp
#endif
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
