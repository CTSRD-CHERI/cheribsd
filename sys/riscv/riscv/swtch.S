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
#ifdef __CHERI_PURE_CAPABILITY__
	csd	t0, (PCB_FCSR)(\p)
	cfsd	f0, (PCB_X + 0 * 16)(\p)
	cfsd	f1, (PCB_X + 1 * 16)(\p)
	cfsd	f2, (PCB_X + 2 * 16)(\p)
	cfsd	f3, (PCB_X + 3 * 16)(\p)
	cfsd	f4, (PCB_X + 4 * 16)(\p)
	cfsd	f5, (PCB_X + 5 * 16)(\p)
	cfsd	f6, (PCB_X + 6 * 16)(\p)
	cfsd	f7, (PCB_X + 7 * 16)(\p)
	cfsd	f8, (PCB_X + 8 * 16)(\p)
	cfsd	f9, (PCB_X + 9 * 16)(\p)
	cfsd	f10, (PCB_X + 10 * 16)(\p)
	cfsd	f11, (PCB_X + 11 * 16)(\p)
	cfsd	f12, (PCB_X + 12 * 16)(\p)
	cfsd	f13, (PCB_X + 13 * 16)(\p)
	cfsd	f14, (PCB_X + 14 * 16)(\p)
	cfsd	f15, (PCB_X + 15 * 16)(\p)
	cfsd	f16, (PCB_X + 16 * 16)(\p)
	cfsd	f17, (PCB_X + 17 * 16)(\p)
	cfsd	f18, (PCB_X + 18 * 16)(\p)
	cfsd	f19, (PCB_X + 19 * 16)(\p)
	cfsd	f20, (PCB_X + 20 * 16)(\p)
	cfsd	f21, (PCB_X + 21 * 16)(\p)
	cfsd	f22, (PCB_X + 22 * 16)(\p)
	cfsd	f23, (PCB_X + 23 * 16)(\p)
	cfsd	f24, (PCB_X + 24 * 16)(\p)
	cfsd	f25, (PCB_X + 25 * 16)(\p)
	cfsd	f26, (PCB_X + 26 * 16)(\p)
	cfsd	f27, (PCB_X + 27 * 16)(\p)
	cfsd	f28, (PCB_X + 28 * 16)(\p)
	cfsd	f29, (PCB_X + 29 * 16)(\p)
	cfsd	f30, (PCB_X + 30 * 16)(\p)
	cfsd	f31, (PCB_X + 31 * 16)(\p)
#else
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
#endif

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
#ifdef __CHERI_PURE_CAPABILITY__
	cld	t0, (PCB_FCSR)(\p)
#else
	ld	t0, (PCB_FCSR)(\p)
#endif
	fscsr	t0
#ifdef __CHERI_PURE_CAPABILITY__
	cfld	f0, (PCB_X + 0 * 16)(\p)
	cfld	f1, (PCB_X + 1 * 16)(\p)
	cfld	f2, (PCB_X + 2 * 16)(\p)
	cfld	f3, (PCB_X + 3 * 16)(\p)
	cfld	f4, (PCB_X + 4 * 16)(\p)
	cfld	f5, (PCB_X + 5 * 16)(\p)
	cfld	f6, (PCB_X + 6 * 16)(\p)
	cfld	f7, (PCB_X + 7 * 16)(\p)
	cfld	f8, (PCB_X + 8 * 16)(\p)
	cfld	f9, (PCB_X + 9 * 16)(\p)
	cfld	f10, (PCB_X + 10 * 16)(\p)
	cfld	f11, (PCB_X + 11 * 16)(\p)
	cfld	f12, (PCB_X + 12 * 16)(\p)
	cfld	f13, (PCB_X + 13 * 16)(\p)
	cfld	f14, (PCB_X + 14 * 16)(\p)
	cfld	f15, (PCB_X + 15 * 16)(\p)
	cfld	f16, (PCB_X + 16 * 16)(\p)
	cfld	f17, (PCB_X + 17 * 16)(\p)
	cfld	f18, (PCB_X + 18 * 16)(\p)
	cfld	f19, (PCB_X + 19 * 16)(\p)
	cfld	f20, (PCB_X + 20 * 16)(\p)
	cfld	f21, (PCB_X + 21 * 16)(\p)
	cfld	f22, (PCB_X + 22 * 16)(\p)
	cfld	f23, (PCB_X + 23 * 16)(\p)
	cfld	f24, (PCB_X + 24 * 16)(\p)
	cfld	f25, (PCB_X + 25 * 16)(\p)
	cfld	f26, (PCB_X + 26 * 16)(\p)
	cfld	f27, (PCB_X + 27 * 16)(\p)
	cfld	f28, (PCB_X + 28 * 16)(\p)
	cfld	f29, (PCB_X + 29 * 16)(\p)
	cfld	f30, (PCB_X + 30 * 16)(\p)
	cfld	f31, (PCB_X + 31 * 16)(\p)
#else
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
#endif

	/* Disable FPE usage in supervisor mode. */
	li	t0, SSTATUS_FS_MASK
	csrc	sstatus, t0
.endm

/*
 * void
 * fpe_state_save(struct thread *td)
 */
ENTRY(fpe_state_save)
#ifdef __CHERI_PURE_CAPABILITY__
	/* Get pointer to PCB */
	clc	ca0, TD_PCB(ca0)
	__fpe_state_save ca0
	cret
#else
	/* Get pointer to PCB */
	ld	a0, TD_PCB(a0)
	__fpe_state_save a0
	ret
#endif
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

	RETURN
END(fpe_state_clear)
#endif /* FPE */
	
/*
 * void cpu_throw(struct thread *old __unused, struct thread *new)
 */
ENTRY(cpu_throw)
#ifdef __CHERI_PURE_CAPABILITY__
	/* Activate the new thread's pmap. */
	cmove	cs0, ca1
	cmove	ca0, ca1
	clgc	cra, _C_LABEL(pmap_activate_sw)
	cjalr	cra
	cmove	ca0, cs0

	/* Store the new curthread */
	csc	ca0, PC_CURTHREAD(ctp)
	/* And the new pcb */
	clc	c13, TD_PCB(ca0)
	csc	c13, PC_CURPCB(ctp)
#else
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
#endif

#ifdef __CHERI_PURE_CAPABILITY__
	/* Load registers */
	clc	cra, (PCB_RA)(c13)
	clc	csp, (PCB_SP)(c13)

	/* s[0-11] */
	clc	cs0, (PCB_S + 0 * 16)(c13)
	clc	cs1, (PCB_S + 1 * 16)(c13)
	clc	cs2, (PCB_S + 2 * 16)(c13)
	clc	cs3, (PCB_S + 3 * 16)(c13)
	clc	cs4, (PCB_S + 4 * 16)(c13)
	clc	cs5, (PCB_S + 5 * 16)(c13)
	clc	cs6, (PCB_S + 6 * 16)(c13)
	clc	cs7, (PCB_S + 7 * 16)(c13)
	clc	cs8, (PCB_S + 8 * 16)(c13)
	clc	cs9, (PCB_S + 9 * 16)(c13)
	clc	cs10, (PCB_S + 10 * 16)(c13)
	clc	cs11, (PCB_S + 11 * 16)(c13)
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
#ifdef __CHERI_PURE_CAPABILITY__
	clc	ct0, TD_FRAME(ca0)
	cld	t1, (TF_SSTATUS)(ct0)
#else
	ld	t0, TD_FRAME(a0)
	ld	t1, (TF_SSTATUS)(t0)
#endif
	li	t2, SSTATUS_FS_MASK
	and	t3, t1, t2
	beqz	t3, 1f		/* No, skip. */

	/* Restore registers. */
#ifdef __CHERI_PURE_CAPABILITY__
	__fpe_state_load c13
#else
	__fpe_state_load x13
#endif
1:
#endif

	RETURN
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
#ifdef __CHERI_PURE_CAPABILITY__
	/* Store the new curthread */
	csc	ca1, PC_CURTHREAD(ctp)
	/* And the new pcb */
	clc	c13, TD_PCB(ca1)
	csc	c13, PC_CURPCB(ctp)

	/* Save the old context. */
	clc	c13, TD_PCB(ca0)
#else
	/* Store the new curthread */
	sd	a1, PC_CURTHREAD(tp)
	/* And the new pcb */
	ld	x13, TD_PCB(a1)
	sd	x13, PC_CURPCB(tp)

	/* Save the old context. */
	ld	x13, TD_PCB(a0)
#endif

#ifdef __CHERI_PURE_CAPABILITY__
	/* Store ra, sp and the callee-saved registers */
	csc	cra, (PCB_RA)(c13)
	csc	csp, (PCB_SP)(c13)

	/* s[0-11] */
	csc	cs0, (PCB_S + 0 * 16)(c13)
	csc	cs1, (PCB_S + 1 * 16)(c13)
	csc	cs2, (PCB_S + 2 * 16)(c13)
	csc	cs3, (PCB_S + 3 * 16)(c13)
	csc	cs4, (PCB_S + 4 * 16)(c13)
	csc	cs5, (PCB_S + 5 * 16)(c13)
	csc	cs6, (PCB_S + 6 * 16)(c13)
	csc	cs7, (PCB_S + 7 * 16)(c13)
	csc	cs8, (PCB_S + 8 * 16)(c13)
	csc	cs9, (PCB_S + 9 * 16)(c13)
	csc	cs10, (PCB_S + 10 * 16)(c13)
	csc	cs11, (PCB_S + 11 * 16)(c13)
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
#ifdef __CHERI_PURE_CAPABILITY__
	clc	ct0, TD_FRAME(ca0)
	cld	t1, (TF_SSTATUS)(ct0)
#else
	ld	t0, TD_FRAME(a0)
	ld	t1, (TF_SSTATUS)(t0)
#endif
	li	t2, SSTATUS_FS_MASK
	and	t3, t1, t2
	li	t2, SSTATUS_FS_DIRTY
	bne	t3, t2, 1f		/* No, skip. */

	/* Yes, mark FPE state clean and save registers. */
	li	t2, ~SSTATUS_FS_MASK
	and	t3, t1, t2
	li	t2, SSTATUS_FS_CLEAN
	or	t3, t3, t2
#ifdef __CHERI_PURE_CAPABILITY__
	csd	t3, (TF_SSTATUS)(ct0)
#else
	sd	t3, (TF_SSTATUS)(t0)
#endif

#ifdef __CHERI_PURE_CAPABILITY__
	__fpe_state_save c13
#else
	__fpe_state_save x13
#endif
1:
#endif

	/* Activate the new thread's pmap */
#ifdef __CHERI_PURE_CAPABILITY__
	cmove	cs0, ca0
	cmove	cs1, ca1
	cmove	cs2, ca2
	cmove	ca0, ca1
	clgc	cra, _C_LABEL(pmap_activate_sw)
	cjalr	cra
	cmove	ca1, cs1
#else
	mv	s0, a0
	mv	s1, a1
	mv	s2, a2
	mv	a0, a1
	call	_C_LABEL(pmap_activate_sw)
	mv	a1, s1
#endif

	/* Release the old thread */
#ifdef __CHERI_PURE_CAPABILITY__
	csc	cs2, TD_LOCK(cs0)
#else
	sd	s2, TD_LOCK(s0)
#endif
#if defined(SCHED_ULE) && defined(SMP)
	/* Spin if TD_LOCK points to a blocked_lock */
#ifdef __CHERI_PURE_CAPABILITY__
	clgc	cs2, _C_LABEL(blocked_lock)
1:
	clc	ct0, TD_LOCK(ca1)
	beq	t0, s2, 1b
#else
	la	s2, _C_LABEL(blocked_lock)
1:
	ld	t0, TD_LOCK(a1)
	beq	t0, s2, 1b
#endif
#endif

#ifdef CPU_QEMU_RISCV
	/*
	 * Check if per-thread tracing is enabled, if so pause/resume
	 * QEMU instruction tracing to reflect the new thread tracing
	 * flag.
	 */
#ifdef __CHERI_PURE_CAPABILITY__
	clgc	ct0, _C_LABEL(qemu_trace_perthread)
	clw	t0, (ct0)
#else
	lw	t0, _C_LABEL(qemu_trace_perthread)
#endif
	beqz	t0, .Lout_qemu_tracing

	/*
	 * When pausing/resuming, take care that the context switch
	 * event is observed.
	 */
#ifdef __CHERI_PURE_CAPABILITY__
	clw	t0, TD_MDFLAGS(cs1)
#else
	lw	t0, TD_MDFLAGS(s1)
#endif
	andi	t1, t0, MDTD_QTRACE
	andi	t0, t0, MDTD_QTRACE_USERMODE
	/* Note: user tracing takes precedence if both have been requested. */
.Ltry_enable_qemu_user_tracing:
	beqz	t0, .Ltry_enable_qemu_tracing
	slti	x0, x0, 0x2b
	/* don't even try to trace context switch as user mode will never see it */
	j	.Lout_qemu_tracing
.Ltry_enable_qemu_tracing:
	beqz	t1, .Lqemu_ctx_switch_event
	slti	x0, x0, 0x1b
	/* fall through */
.Lqemu_ctx_switch_event:
	/* Expect: t1 = enable tracing; t0 = enable user tracing; */
	/* Log context switch */
	li	a0, 0x1 // LOG_EVENT_CTX_UPDATE
	li	a1, 0x1 // LOG_EVENT_CTX_OP_SWITCH
#ifdef __CHERI_PURE_CAPABILITY__
	clc	ca2, TD_PROC(cs1)
	cld	a2, P_PID(ca2)
	cld	a3, TD_TID(cs1)
#else
	ld	a2, TD_PROC(s1)
	ld	a2, P_PID(a2)
	ld	a3, TD_TID(s1)
#endif
	li	a4, -1 // ignore compartment ID for now
	slti	zero, zero, 0x30 // event logging NOP
	/* Check if we need to disable tracing for next thread */
	or	t0, t0, t1
	bnez	t0, .Lout_qemu_tracing
	slti	x0, x0, 0x1e
.Lout_qemu_tracing:
#ifdef __CHERI_PURE_CAPABILITY__
	cmove	ca1, cs1
#else
	mv	a1, s1
#endif
#endif

	/*
	 * Restore the saved context.
	 */
#ifdef __CHERI_PURE_CAPABILITY__
	clc	c13, TD_PCB(ca1)
#else
	ld	x13, TD_PCB(a1)
#endif

#ifdef __CHERI_PURE_CAPABILITY__
	/* Restore the registers */
	clc	cra, (PCB_RA)(c13)
	clc	csp, (PCB_SP)(c13)

	/* s[0-11] */
	clc	cs0, (PCB_S + 0 * 16)(c13)
	clc	cs1, (PCB_S + 1 * 16)(c13)
	clc	cs2, (PCB_S + 2 * 16)(c13)
	clc	cs3, (PCB_S + 3 * 16)(c13)
	clc	cs4, (PCB_S + 4 * 16)(c13)
	clc	cs5, (PCB_S + 5 * 16)(c13)
	clc	cs6, (PCB_S + 6 * 16)(c13)
	clc	cs7, (PCB_S + 7 * 16)(c13)
	clc	cs8, (PCB_S + 8 * 16)(c13)
	clc	cs9, (PCB_S + 9 * 16)(c13)
	clc	cs10, (PCB_S + 10 * 16)(c13)
	clc	cs11, (PCB_S + 11 * 16)(c13)
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
#ifdef __CHERI_PURE_CAPABILITY__
	clc	ct0, TD_FRAME(ca1)
	cld	t1, (TF_SSTATUS)(ct0)
#else
	ld	t0, TD_FRAME(a1)
	ld	t1, (TF_SSTATUS)(t0)
#endif
	li	t2, SSTATUS_FS_MASK
	and	t3, t1, t2
	beqz	t3, 1f		/* No, skip. */

	/* Restore registers. */
#ifdef __CHERI_PURE_CAPABILITY__
	__fpe_state_load c13
#else
	__fpe_state_load x13
#endif
1:
#endif

	RETURN
.Lcpu_switch_panic_str:
	.asciz "cpu_switch: %p\0"
END(cpu_switch)

/*
 * fork_exit(void (*callout)(void *, struct trapframe *), void *arg,
 *  struct trapframe *frame)
 */

ENTRY(fork_trampoline)
#ifdef __CHERI_PURE_CAPABILITY__
	cmove	ca0, cs0
	cmove	ca1, cs1
	cmove	ca2, csp
	clgc	cra, _C_LABEL(fork_exit)
	cjalr	cra
#else
	mv	a0, s0
	mv	a1, s1
	mv	a2, sp
	call	_C_LABEL(fork_exit)
#endif

	/* Restore sstatus */
#ifdef __CHERI_PURE_CAPABILITY__
	cld	t0, (TF_SSTATUS)(csp)
#else
	ld	t0, (TF_SSTATUS)(sp)
#endif
	/* Ensure interrupts disabled */
	li	t1, ~SSTATUS_SIE
	and	t0, t0, t1
	csrw	sstatus, t0

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
#endif

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
#ifndef __CHERI_PURE_CAPABILITY__
.option pop
#endif
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
#ifdef __CHERI_PURE_CAPABILITY__
	/* Store ra, sp and the callee-saved registers */
	csc	cra, (PCB_RA)(ca0)
	csc	csp, (PCB_SP)(ca0)
	csc	ctp, (PCB_TP)(ca0)
	csc	cgp, (PCB_GP)(ca0)

	/* s[0-11] */
	csc	cs0, (PCB_S + 0 * 16)(ca0)
	csc	cs1, (PCB_S + 1 * 16)(ca0)
	csc	cs2, (PCB_S + 2 * 16)(ca0)
	csc	cs3, (PCB_S + 3 * 16)(ca0)
	csc	cs4, (PCB_S + 4 * 16)(ca0)
	csc	cs5, (PCB_S + 5 * 16)(ca0)
	csc	cs6, (PCB_S + 6 * 16)(ca0)
	csc	cs7, (PCB_S + 7 * 16)(ca0)
	csc	cs8, (PCB_S + 8 * 16)(ca0)
	csc	cs9, (PCB_S + 9 * 16)(ca0)
	csc	cs10, (PCB_S + 10 * 16)(ca0)
	csc	cs11, (PCB_S + 11 * 16)(ca0)
#elif __has_feature(capabilities)
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
#ifdef __CHERI_PURE_CAPABILITY__
	__fpe_state_save ca0
#else
	__fpe_state_save a0
#endif
#endif
	RETURN
END(savectx)

/*
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
