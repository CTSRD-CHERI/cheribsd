/*-
 * Copyright (c) 2015-2017 Ruslan Bukin <br@bsdpad.com>
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

#include "assym.inc"
#include "opt_sched.h"

#include <machine/param.h>
#include <machine/asm.h>
#include <machine/riscvreg.h>
#include <machine/pte.h>

__FBSDID("$FreeBSD$");

#ifdef FPE
.macro __fpe_state_save p
	/*
	 * Enable FPE usage in supervisor mode,
	 * so we can access registers.
	 */
	li	t0, SSTATUS_FS_INITIAL
	csrs	sstatus, t0

	/* Store registers */
	frcsr	t0
	sd	t0, (PCB_FCSR)(\p)
	fsd	f0, (PCB_X + 0 * 16)(\p)
	fsd	f1, (PCB_X + 1 * 16)(\p)
	fsd	f2, (PCB_X + 2 * 16)(\p)
	fsd	f3, (PCB_X + 3 * 16)(\p)
	fsd	f4, (PCB_X + 4 * 16)(\p)
	fsd	f5, (PCB_X + 5 * 16)(\p)
	fsd	f6, (PCB_X + 6 * 16)(\p)
	fsd	f7, (PCB_X + 7 * 16)(\p)
	fsd	f8, (PCB_X + 8 * 16)(\p)
	fsd	f9, (PCB_X + 9 * 16)(\p)
	fsd	f10, (PCB_X + 10 * 16)(\p)
	fsd	f11, (PCB_X + 11 * 16)(\p)
	fsd	f12, (PCB_X + 12 * 16)(\p)
	fsd	f13, (PCB_X + 13 * 16)(\p)
	fsd	f14, (PCB_X + 14 * 16)(\p)
	fsd	f15, (PCB_X + 15 * 16)(\p)
	fsd	f16, (PCB_X + 16 * 16)(\p)
	fsd	f17, (PCB_X + 17 * 16)(\p)
	fsd	f18, (PCB_X + 18 * 16)(\p)
	fsd	f19, (PCB_X + 19 * 16)(\p)
	fsd	f20, (PCB_X + 20 * 16)(\p)
	fsd	f21, (PCB_X + 21 * 16)(\p)
	fsd	f22, (PCB_X + 22 * 16)(\p)
	fsd	f23, (PCB_X + 23 * 16)(\p)
	fsd	f24, (PCB_X + 24 * 16)(\p)
	fsd	f25, (PCB_X + 25 * 16)(\p)
	fsd	f26, (PCB_X + 26 * 16)(\p)
	fsd	f27, (PCB_X + 27 * 16)(\p)
	fsd	f28, (PCB_X + 28 * 16)(\p)
	fsd	f29, (PCB_X + 29 * 16)(\p)
	fsd	f30, (PCB_X + 30 * 16)(\p)
	fsd	f31, (PCB_X + 31 * 16)(\p)

	/* Disable FPE usage in supervisor mode. */
	li	t0, SSTATUS_FS_MASK
	csrc	sstatus, t0
.endm

.macro __fpe_state_load p
	/*
	 * Enable FPE usage in supervisor mode,
	 * so we can access registers.
	 */
	li	t0, SSTATUS_FS_INITIAL
	csrs	sstatus, t0

	/* Restore registers */
	ld	t0, (PCB_FCSR)(\p)
	fscsr	t0
	fld	f0, (PCB_X + 0 * 16)(\p)
	fld	f1, (PCB_X + 1 * 16)(\p)
	fld	f2, (PCB_X + 2 * 16)(\p)
	fld	f3, (PCB_X + 3 * 16)(\p)
	fld	f4, (PCB_X + 4 * 16)(\p)
	fld	f5, (PCB_X + 5 * 16)(\p)
	fld	f6, (PCB_X + 6 * 16)(\p)
	fld	f7, (PCB_X + 7 * 16)(\p)
	fld	f8, (PCB_X + 8 * 16)(\p)
	fld	f9, (PCB_X + 9 * 16)(\p)
	fld	f10, (PCB_X + 10 * 16)(\p)
	fld	f11, (PCB_X + 11 * 16)(\p)
	fld	f12, (PCB_X + 12 * 16)(\p)
	fld	f13, (PCB_X + 13 * 16)(\p)
	fld	f14, (PCB_X + 14 * 16)(\p)
	fld	f15, (PCB_X + 15 * 16)(\p)
	fld	f16, (PCB_X + 16 * 16)(\p)
	fld	f17, (PCB_X + 17 * 16)(\p)
	fld	f18, (PCB_X + 18 * 16)(\p)
	fld	f19, (PCB_X + 19 * 16)(\p)
	fld	f20, (PCB_X + 20 * 16)(\p)
	fld	f21, (PCB_X + 21 * 16)(\p)
	fld	f22, (PCB_X + 22 * 16)(\p)
	fld	f23, (PCB_X + 23 * 16)(\p)
	fld	f24, (PCB_X + 24 * 16)(\p)
	fld	f25, (PCB_X + 25 * 16)(\p)
	fld	f26, (PCB_X + 26 * 16)(\p)
	fld	f27, (PCB_X + 27 * 16)(\p)
	fld	f28, (PCB_X + 28 * 16)(\p)
	fld	f29, (PCB_X + 29 * 16)(\p)
	fld	f30, (PCB_X + 30 * 16)(\p)
	fld	f31, (PCB_X + 31 * 16)(\p)

	/* Disable FPE usage in supervisor mode. */
	li	t0, SSTATUS_FS_MASK
	csrc	sstatus, t0
.endm

/*
 * void
 * fpe_state_save(struct thread *td)
 */
ENTRY(fpe_state_save)
	/* Get pointer to PCB */
	ld	a0, TD_PCB(a0)
	__fpe_state_save a0
	ret
END(fpe_state_save)

/*
 * void
 * fpe_state_clear(void)
 */
ENTRY(fpe_state_clear)
	/*
	 * Enable FPE usage in supervisor mode,
	 * so we can access registers.
	 */
	li	t0, SSTATUS_FS_INITIAL
	csrs	sstatus, t0

	fscsr	zero
	fcvt.d.l f0, zero
	fcvt.d.l f1, zero
	fcvt.d.l f2, zero
	fcvt.d.l f3, zero
	fcvt.d.l f4, zero
	fcvt.d.l f5, zero
	fcvt.d.l f6, zero
	fcvt.d.l f7, zero
	fcvt.d.l f8, zero
	fcvt.d.l f9, zero
	fcvt.d.l f10, zero
	fcvt.d.l f11, zero
	fcvt.d.l f12, zero
	fcvt.d.l f13, zero
	fcvt.d.l f14, zero
	fcvt.d.l f15, zero
	fcvt.d.l f16, zero
	fcvt.d.l f17, zero
	fcvt.d.l f18, zero
	fcvt.d.l f19, zero
	fcvt.d.l f20, zero
	fcvt.d.l f21, zero
	fcvt.d.l f22, zero
	fcvt.d.l f23, zero
	fcvt.d.l f24, zero
	fcvt.d.l f25, zero
	fcvt.d.l f26, zero
	fcvt.d.l f27, zero
	fcvt.d.l f28, zero
	fcvt.d.l f29, zero
	fcvt.d.l f30, zero
	fcvt.d.l f31, zero

	/* Disable FPE usage in supervisor mode. */
	li	t0, SSTATUS_FS_MASK
	csrc	sstatus, t0

	ret
END(fpe_state_clear)
#endif /* FPE */
	
/*
 * void cpu_throw(struct thread *old __unused, struct thread *new)
 */
ENTRY(cpu_throw)
	/* Activate the new thread's pmap. */
	mv	s0, a1
	mv	a0, a1
	call	_C_LABEL(pmap_activate_sw)
	mv	a0, s0

	/* Store the new curthread */
	sd	a0, PC_CURTHREAD(tp)
	/* And the new pcb */
	ld	x13, TD_PCB(a0)
	sd	x13, PC_CURPCB(tp)

#if __has_feature(capabilities)
	/* Load registers */
	lc	cra, (PCB_RA)(x13)
	lc	csp, (PCB_SP)(x13)

	/* s[0-11] */
	lc	cs0, (PCB_S + 0 * 16)(x13)
	lc	cs1, (PCB_S + 1 * 16)(x13)
	lc	cs2, (PCB_S + 2 * 16)(x13)
	lc	cs3, (PCB_S + 3 * 16)(x13)
	lc	cs4, (PCB_S + 4 * 16)(x13)
	lc	cs5, (PCB_S + 5 * 16)(x13)
	lc	cs6, (PCB_S + 6 * 16)(x13)
	lc	cs7, (PCB_S + 7 * 16)(x13)
	lc	cs8, (PCB_S + 8 * 16)(x13)
	lc	cs9, (PCB_S + 9 * 16)(x13)
	lc	cs10, (PCB_S + 10 * 16)(x13)
	lc	cs11, (PCB_S + 11 * 16)(x13)
#else
	/* Load registers */
	ld	ra, (PCB_RA)(x13)
	ld	sp, (PCB_SP)(x13)

	/* s[0-11] */
	ld	s0, (PCB_S + 0 * 8)(x13)
	ld	s1, (PCB_S + 1 * 8)(x13)
	ld	s2, (PCB_S + 2 * 8)(x13)
	ld	s3, (PCB_S + 3 * 8)(x13)
	ld	s4, (PCB_S + 4 * 8)(x13)
	ld	s5, (PCB_S + 5 * 8)(x13)
	ld	s6, (PCB_S + 6 * 8)(x13)
	ld	s7, (PCB_S + 7 * 8)(x13)
	ld	s8, (PCB_S + 8 * 8)(x13)
	ld	s9, (PCB_S + 9 * 8)(x13)
	ld	s10, (PCB_S + 10 * 8)(x13)
	ld	s11, (PCB_S + 11 * 8)(x13)
#endif

#ifdef FPE
	/* Is FPE enabled for new thread? */
	ld	t0, TD_FRAME(a0)
	ld	t1, (TF_SSTATUS)(t0)
	li	t2, SSTATUS_FS_MASK
	and	t3, t1, t2
	beqz	t3, 1f		/* No, skip. */

	/* Restore registers. */
	__fpe_state_load x13
1:
#endif

	ret
END(cpu_throw)

/*
 * void cpu_switch(struct thread *old, struct thread *new, struct mtx *mtx)
 *
 * a0 = old
 * a1 = new
 * a2 = mtx
 * x3 to x7, x16 and x17 are caller saved
 */
ENTRY(cpu_switch)
	/* Store the new curthread */
	sd	a1, PC_CURTHREAD(tp)
	/* And the new pcb */
	ld	x13, TD_PCB(a1)
	sd	x13, PC_CURPCB(tp)

	/* Save the old context. */
	ld	x13, TD_PCB(a0)

#if __has_feature(capabilities)
	/* Store ra, sp and the callee-saved registers */
	sc	cra, (PCB_RA)(x13)
	sc	csp, (PCB_SP)(x13)

	/* s[0-11] */
	sc	cs0, (PCB_S + 0 * 16)(x13)
	sc	cs1, (PCB_S + 1 * 16)(x13)
	sc	cs2, (PCB_S + 2 * 16)(x13)
	sc	cs3, (PCB_S + 3 * 16)(x13)
	sc	cs4, (PCB_S + 4 * 16)(x13)
	sc	cs5, (PCB_S + 5 * 16)(x13)
	sc	cs6, (PCB_S + 6 * 16)(x13)
	sc	cs7, (PCB_S + 7 * 16)(x13)
	sc	cs8, (PCB_S + 8 * 16)(x13)
	sc	cs9, (PCB_S + 9 * 16)(x13)
	sc	cs10, (PCB_S + 10 * 16)(x13)
	sc	cs11, (PCB_S + 11 * 16)(x13)
#else
	/* Store ra, sp and the callee-saved registers */
	sd	ra, (PCB_RA)(x13)
	sd	sp, (PCB_SP)(x13)

	/* s[0-11] */
	sd	s0, (PCB_S + 0 * 8)(x13)
	sd	s1, (PCB_S + 1 * 8)(x13)
	sd	s2, (PCB_S + 2 * 8)(x13)
	sd	s3, (PCB_S + 3 * 8)(x13)
	sd	s4, (PCB_S + 4 * 8)(x13)
	sd	s5, (PCB_S + 5 * 8)(x13)
	sd	s6, (PCB_S + 6 * 8)(x13)
	sd	s7, (PCB_S + 7 * 8)(x13)
	sd	s8, (PCB_S + 8 * 8)(x13)
	sd	s9, (PCB_S + 9 * 8)(x13)
	sd	s10, (PCB_S + 10 * 8)(x13)
	sd	s11, (PCB_S + 11 * 8)(x13)
#endif

#ifdef FPE
	/*
	 * Is FPE enabled and is it in dirty state
	 * for the old thread?
	 */
	ld	t0, TD_FRAME(a0)
	ld	t1, (TF_SSTATUS)(t0)
	li	t2, SSTATUS_FS_MASK
	and	t3, t1, t2
	li	t2, SSTATUS_FS_DIRTY
	bne	t3, t2, 1f		/* No, skip. */

	/* Yes, mark FPE state clean and save registers. */
	li	t2, ~SSTATUS_FS_MASK
	and	t3, t1, t2
	li	t2, SSTATUS_FS_CLEAN
	or	t3, t3, t2
	sd	t3, (TF_SSTATUS)(t0)

	__fpe_state_save x13
1:
#endif

	/* Activate the new thread's pmap */
	mv	s0, a0
	mv	s1, a1
	mv	s2, a2
	mv	a0, a1
	call	_C_LABEL(pmap_activate_sw)
	mv	a1, s1

	/* Release the old thread */
	sd	s2, TD_LOCK(s0)
#if defined(SCHED_ULE) && defined(SMP)
	/* Spin if TD_LOCK points to a blocked_lock */
	la	s2, _C_LABEL(blocked_lock)
1:
	ld	t0, TD_LOCK(a1)
	beq	t0, s2, 1b
#endif

#ifdef CPU_QEMU_RISCV
	/*
	 * Check if per-thread tracing is enabled, if so pause/resume
	 * QEMU instruction tracing to reflect the new thread tracing
	 * flag.
	 */
	lw	t0, _C_LABEL(qemu_trace_perthread)
	beqz	t0, .Lout_qemu_tracing

	lw	t0, TD_MDFLAGS(a1)
	andi	t0, t0, MDTD_QTRACE
	beqz	t0, .Ldisable_qemu_tracing
.Lenable_qemu_tracing:
	slti	x0, x0, 0x1b
	j	.Lout_qemu_tracing
.Ldisable_qemu_tracing:
	slti	x0, x0, 0x1e
.Lout_qemu_tracing:
#endif

	/*
	 * Restore the saved context.
	 */
	ld	x13, TD_PCB(a1)

#if __has_feature(capabilities)
	/* Restore the registers */
	lc	cra, (PCB_RA)(x13)
	lc	csp, (PCB_SP)(x13)

	/* s[0-11] */
	lc	cs0, (PCB_S + 0 * 16)(x13)
	lc	cs1, (PCB_S + 1 * 16)(x13)
	lc	cs2, (PCB_S + 2 * 16)(x13)
	lc	cs3, (PCB_S + 3 * 16)(x13)
	lc	cs4, (PCB_S + 4 * 16)(x13)
	lc	cs5, (PCB_S + 5 * 16)(x13)
	lc	cs6, (PCB_S + 6 * 16)(x13)
	lc	cs7, (PCB_S + 7 * 16)(x13)
	lc	cs8, (PCB_S + 8 * 16)(x13)
	lc	cs9, (PCB_S + 9 * 16)(x13)
	lc	cs10, (PCB_S + 10 * 16)(x13)
	lc	cs11, (PCB_S + 11 * 16)(x13)
#else
	/* Restore the registers */
	ld	ra, (PCB_RA)(x13)
	ld	sp, (PCB_SP)(x13)

	/* s[0-11] */
	ld	s0, (PCB_S + 0 * 8)(x13)
	ld	s1, (PCB_S + 1 * 8)(x13)
	ld	s2, (PCB_S + 2 * 8)(x13)
	ld	s3, (PCB_S + 3 * 8)(x13)
	ld	s4, (PCB_S + 4 * 8)(x13)
	ld	s5, (PCB_S + 5 * 8)(x13)
	ld	s6, (PCB_S + 6 * 8)(x13)
	ld	s7, (PCB_S + 7 * 8)(x13)
	ld	s8, (PCB_S + 8 * 8)(x13)
	ld	s9, (PCB_S + 9 * 8)(x13)
	ld	s10, (PCB_S + 10 * 8)(x13)
	ld	s11, (PCB_S + 11 * 8)(x13)
#endif

#ifdef FPE
	/* Is FPE enabled for new thread? */
	ld	t0, TD_FRAME(a1)
	ld	t1, (TF_SSTATUS)(t0)
	li	t2, SSTATUS_FS_MASK
	and	t3, t1, t2
	beqz	t3, 1f		/* No, skip. */

	/* Restore registers. */
	__fpe_state_load x13
1:
#endif

	ret
.Lcpu_switch_panic_str:
	.asciz "cpu_switch: %p\0"
END(cpu_switch)

/*
 * fork_exit(void (*callout)(void *, struct trapframe *), void *arg,
 *  struct trapframe *frame)
 */

ENTRY(fork_trampoline)
	mv	a0, s0
	mv	a1, s1
	mv	a2, sp
	call	_C_LABEL(fork_exit)

	/* Restore sstatus */
	ld	t0, (TF_SSTATUS)(sp)
	/* Ensure interrupts disabled */
	li	t1, ~SSTATUS_SIE
	and	t0, t0, t1
	csrw	sstatus, t0

#if __has_feature(capabilities)
	/* Switch to capmode PCC. */
	lla	t1, 1f
	cspecialr ct0, pcc
	csetaddr ct0, ct0, t1
	li	t1, 1
	csetflags ct0, ct0, t1
	cjr	ct0
.option push
.option capmode
1:
	/*
	 * Build a capability for 'csp' using 'sp' as an address
	 * in the kernel DDC.
	 *
	 * XXX: Bounds?  Maybe could use TF_SIZE + 8 as length?
	 * A purecap kernel would have proper bounds on csp already.
	 */
	cspecialr ct0, ddc
	csetaddr ct0, ct0, sp
	cmove	csp, ct0

	/*
	 * Switch to user DDC.  After this point, all stack accesses
	 * must use 'csp' instead of 'sp'.
	 */
	clc	ct0, (TF_DDC)(csp)
	cspecialw ddc, ct0

	/* Restore exception program counter */
	clc	ct0, (TF_SEPC)(csp)
	cspecialw sepcc, ct0

	/* Restore the registers */
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

	/* Load user ra and gp */
	clc	cra, (TF_RA)(csp)
	clc	cgp, (TF_GP)(csp)

	/*
	 * Store our pcpup on stack, we will load it back
	 * on kernel mode trap.
	 */
	csc	ctp, (TF_SIZE)(csp)
	clc	ctp, (TF_TP)(csp)

	/* Save kernel stack so we can use it doing a user trap */
	cincoffset csp, csp, TF_SIZE
	cspecialw sscratchc, csp

	/* Load user stack */
	clc	csp, (TF_SP - TF_SIZE)(csp)
.option pop
#else
	/* Restore exception program counter */
	ld	t0, (TF_SEPC)(sp)
	csrw	sepc, t0

	/* Restore the registers */
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

	/* Load user ra and gp */
	ld	ra, (TF_RA)(sp)
	ld	gp, (TF_GP)(sp)

	/*
	 * Store our pcpup on stack, we will load it back
	 * on kernel mode trap.
	 */
	sd	tp, (TF_SIZE)(sp)
	ld	tp, (TF_TP)(sp)

	/* Save kernel stack so we can use it doing a user trap */
	addi	sp, sp, TF_SIZE
	csrw	sscratch, sp

	/* Load user stack */
	ld	sp, (TF_SP - TF_SIZE)(sp)
#endif

	sret
END(fork_trampoline)

ENTRY(savectx)
#if __has_feature(capabilities)
	/* Store ra, sp and the callee-saved registers */
	sc	cra, (PCB_RA)(a0)
	sc	csp, (PCB_SP)(a0)
	sc	ctp, (PCB_TP)(a0)
	sc	cgp, (PCB_GP)(a0)

	/* s[0-11] */
	sc	cs0, (PCB_S + 0 * 16)(a0)
	sc	cs1, (PCB_S + 1 * 16)(a0)
	sc	cs2, (PCB_S + 2 * 16)(a0)
	sc	cs3, (PCB_S + 3 * 16)(a0)
	sc	cs4, (PCB_S + 4 * 16)(a0)
	sc	cs5, (PCB_S + 5 * 16)(a0)
	sc	cs6, (PCB_S + 6 * 16)(a0)
	sc	cs7, (PCB_S + 7 * 16)(a0)
	sc	cs8, (PCB_S + 8 * 16)(a0)
	sc	cs9, (PCB_S + 9 * 16)(a0)
	sc	cs10, (PCB_S + 10 * 16)(a0)
	sc	cs11, (PCB_S + 11 * 16)(a0)
#else
	/* Store ra, sp and the callee-saved registers */
	sd	ra, (PCB_RA)(a0)
	sd	sp, (PCB_SP)(a0)
	sd	tp, (PCB_TP)(a0)
	sd	gp, (PCB_GP)(a0)

	/* s[0-11] */
	sd	s0, (PCB_S + 0 * 8)(a0)
	sd	s1, (PCB_S + 1 * 8)(a0)
	sd	s2, (PCB_S + 2 * 8)(a0)
	sd	s3, (PCB_S + 3 * 8)(a0)
	sd	s4, (PCB_S + 4 * 8)(a0)
	sd	s5, (PCB_S + 5 * 8)(a0)
	sd	s6, (PCB_S + 6 * 8)(a0)
	sd	s7, (PCB_S + 7 * 8)(a0)
	sd	s8, (PCB_S + 8 * 8)(a0)
	sd	s9, (PCB_S + 9 * 8)(a0)
	sd	s10, (PCB_S + 10 * 8)(a0)
	sd	s11, (PCB_S + 11 * 8)(a0)
#endif

#ifdef FPE
	__fpe_state_save a0
#endif
	ret
END(savectx)
