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
.macro __fpe_state_save p
	/*
	 * Enable FPE usage in supervisor mode,
	 * so we can access registers.
	 */
	li	t0, SSTATUS_FS_INITIAL
	csrs	sstatus, t0

	/* Store registers */
	frcsr	t0
	_SD	t0, (PCB_FCSR)(\p)
	_FSD	f0, (PCB_X + 0 * 16)(\p)
	_FSD	f1, (PCB_X + 1 * 16)(\p)
	_FSD	f2, (PCB_X + 2 * 16)(\p)
	_FSD	f3, (PCB_X + 3 * 16)(\p)
	_FSD	f4, (PCB_X + 4 * 16)(\p)
	_FSD	f5, (PCB_X + 5 * 16)(\p)
	_FSD	f6, (PCB_X + 6 * 16)(\p)
	_FSD	f7, (PCB_X + 7 * 16)(\p)
	_FSD	f8, (PCB_X + 8 * 16)(\p)
	_FSD	f9, (PCB_X + 9 * 16)(\p)
	_FSD	f10, (PCB_X + 10 * 16)(\p)
	_FSD	f11, (PCB_X + 11 * 16)(\p)
	_FSD	f12, (PCB_X + 12 * 16)(\p)
	_FSD	f13, (PCB_X + 13 * 16)(\p)
	_FSD	f14, (PCB_X + 14 * 16)(\p)
	_FSD	f15, (PCB_X + 15 * 16)(\p)
	_FSD	f16, (PCB_X + 16 * 16)(\p)
	_FSD	f17, (PCB_X + 17 * 16)(\p)
	_FSD	f18, (PCB_X + 18 * 16)(\p)
	_FSD	f19, (PCB_X + 19 * 16)(\p)
	_FSD	f20, (PCB_X + 20 * 16)(\p)
	_FSD	f21, (PCB_X + 21 * 16)(\p)
	_FSD	f22, (PCB_X + 22 * 16)(\p)
	_FSD	f23, (PCB_X + 23 * 16)(\p)
	_FSD	f24, (PCB_X + 24 * 16)(\p)
	_FSD	f25, (PCB_X + 25 * 16)(\p)
	_FSD	f26, (PCB_X + 26 * 16)(\p)
	_FSD	f27, (PCB_X + 27 * 16)(\p)
	_FSD	f28, (PCB_X + 28 * 16)(\p)
	_FSD	f29, (PCB_X + 29 * 16)(\p)
	_FSD	f30, (PCB_X + 30 * 16)(\p)
	_FSD	f31, (PCB_X + 31 * 16)(\p)

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
	_LD	t0, (PCB_FCSR)(\p)

	fscsr	t0
	_FLD	f0, (PCB_X + 0 * 16)(\p)
	_FLD	f1, (PCB_X + 1 * 16)(\p)
	_FLD	f2, (PCB_X + 2 * 16)(\p)
	_FLD	f3, (PCB_X + 3 * 16)(\p)
	_FLD	f4, (PCB_X + 4 * 16)(\p)
	_FLD	f5, (PCB_X + 5 * 16)(\p)
	_FLD	f6, (PCB_X + 6 * 16)(\p)
	_FLD	f7, (PCB_X + 7 * 16)(\p)
	_FLD	f8, (PCB_X + 8 * 16)(\p)
	_FLD	f9, (PCB_X + 9 * 16)(\p)
	_FLD	f10, (PCB_X + 10 * 16)(\p)
	_FLD	f11, (PCB_X + 11 * 16)(\p)
	_FLD	f12, (PCB_X + 12 * 16)(\p)
	_FLD	f13, (PCB_X + 13 * 16)(\p)
	_FLD	f14, (PCB_X + 14 * 16)(\p)
	_FLD	f15, (PCB_X + 15 * 16)(\p)
	_FLD	f16, (PCB_X + 16 * 16)(\p)
	_FLD	f17, (PCB_X + 17 * 16)(\p)
	_FLD	f18, (PCB_X + 18 * 16)(\p)
	_FLD	f19, (PCB_X + 19 * 16)(\p)
	_FLD	f20, (PCB_X + 20 * 16)(\p)
	_FLD	f21, (PCB_X + 21 * 16)(\p)
	_FLD	f22, (PCB_X + 22 * 16)(\p)
	_FLD	f23, (PCB_X + 23 * 16)(\p)
	_FLD	f24, (PCB_X + 24 * 16)(\p)
	_FLD	f25, (PCB_X + 25 * 16)(\p)
	_FLD	f26, (PCB_X + 26 * 16)(\p)
	_FLD	f27, (PCB_X + 27 * 16)(\p)
	_FLD	f28, (PCB_X + 28 * 16)(\p)
	_FLD	f29, (PCB_X + 29 * 16)(\p)
	_FLD	f30, (PCB_X + 30 * 16)(\p)
	_FLD	f31, (PCB_X + 31 * 16)(\p)

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
	L_PTR	PTR(a0), TD_PCB(PTR(a0))
	__fpe_state_save PTR(a0)
	RETURN
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

/*
 * void cpu_throw(struct thread *old __unused, struct thread *new)
 */
ENTRY(cpu_throw)
	/* Activate the new thread's pmap. */
	_CMV	PTR(s0), PTR(a1)
	_CMV	PTR(a0), PTR(a1)
#ifdef __CHERI_PURE_CAPABILITY__
	_LGC	PTR(ra), _C_LABEL(pmap_activate_sw)
	_JALR	PTR(ra)
#else
	call	_C_LABEL(pmap_activate_sw)
#endif
	_CMV	PTR(a0), PTR(s0)

	/* Store the new curthread */
	S_PTR	PTR(a0), PC_CURTHREAD(PTR(tp))
	/* And the new pcb */
	L_PTR	PTRN(13), TD_PCB(PTR(a0))
	S_PTR	PTRN(13), PC_CURPCB(PTR(tp))

	/* Load registers */
	L_PTR	PTR(ra), (PCB_RA)(PTRN(13))
	L_PTR	PTR(sp), (PCB_SP)(PTRN(13))

	/* s[0-11] */
	L_PTR	PTR(s0), (PCB_S + 0 * PTR_WIDTH)(PTRN(13))
	L_PTR	PTR(s1), (PCB_S + 1 * PTR_WIDTH)(PTRN(13))
	L_PTR	PTR(s2), (PCB_S + 2 * PTR_WIDTH)(PTRN(13))
	L_PTR	PTR(s3), (PCB_S + 3 * PTR_WIDTH)(PTRN(13))
	L_PTR	PTR(s4), (PCB_S + 4 * PTR_WIDTH)(PTRN(13))
	L_PTR	PTR(s5), (PCB_S + 5 * PTR_WIDTH)(PTRN(13))
	L_PTR	PTR(s6), (PCB_S + 6 * PTR_WIDTH)(PTRN(13))
	L_PTR	PTR(s7), (PCB_S + 7 * PTR_WIDTH)(PTRN(13))
	L_PTR	PTR(s8), (PCB_S + 8 * PTR_WIDTH)(PTRN(13))
	L_PTR	PTR(s9), (PCB_S + 9 * PTR_WIDTH)(PTRN(13))
	L_PTR	PTR(s10), (PCB_S + 10 * PTR_WIDTH)(PTRN(13))
	L_PTR	PTR(s11), (PCB_S + 11 * PTR_WIDTH)(PTRN(13))

	/* Is FPE enabled for new thread? */
	L_PTR	PTR(t0), TD_FRAME(PTR(a0))
	_LD	t1, (TF_SSTATUS)(PTR(t0))

	li	t2, SSTATUS_FS_MASK
	and	t3, t1, t2
	beqz	t3, 1f		/* No, skip. */

	/* Restore registers. */
	__fpe_state_load PTRN(13)
1:
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
	/* Store the new curthread */
	S_PTR	PTR(a1), PC_CURTHREAD(PTR(tp))
	/* And the new pcb */
	L_PTR	PTRN(13), TD_PCB(PTR(a1))
	S_PTR	PTRN(13), PC_CURPCB(PTR(tp))

	/* Save the old context. */
	L_PTR	PTRN(13), TD_PCB(PTR(a0))

	/* Store ra, sp and the callee-saved registers */
	S_PTR	PTR(ra), (PCB_RA)(PTRN(13))
	S_PTR	PTR(sp), (PCB_SP)(PTRN(13))

	/* s[0-11] */
	S_PTR	PTR(s0), (PCB_S + 0 * PTR_WIDTH)(PTRN(13))
	S_PTR	PTR(s1), (PCB_S + 1 * PTR_WIDTH)(PTRN(13))
	S_PTR	PTR(s2), (PCB_S + 2 * PTR_WIDTH)(PTRN(13))
	S_PTR	PTR(s3), (PCB_S + 3 * PTR_WIDTH)(PTRN(13))
	S_PTR	PTR(s4), (PCB_S + 4 * PTR_WIDTH)(PTRN(13))
	S_PTR	PTR(s5), (PCB_S + 5 * PTR_WIDTH)(PTRN(13))
	S_PTR	PTR(s6), (PCB_S + 6 * PTR_WIDTH)(PTRN(13))
	S_PTR	PTR(s7), (PCB_S + 7 * PTR_WIDTH)(PTRN(13))
	S_PTR	PTR(s8), (PCB_S + 8 * PTR_WIDTH)(PTRN(13))
	S_PTR	PTR(s9), (PCB_S + 9 * PTR_WIDTH)(PTRN(13))
	S_PTR	PTR(s10), (PCB_S + 10 * PTR_WIDTH)(PTRN(13))
	S_PTR	PTR(s11), (PCB_S + 11 * PTR_WIDTH)(PTRN(13))

	/*
	 * Is FPE enabled and is it in dirty state
	 * for the old thread?
	 */
	L_PTR	PTR(t0), TD_FRAME(PTR(a0))
	_LD	t1, (TF_SSTATUS)(PTR(t0))
	li	t2, SSTATUS_FS_MASK
	and	t3, t1, t2
	li	t2, SSTATUS_FS_DIRTY
	bne	t3, t2, 1f		/* No, skip. */

	/* Yes, mark FPE state clean and save registers. */
	li	t2, ~SSTATUS_FS_MASK
	and	t3, t1, t2
	li	t2, SSTATUS_FS_CLEAN
	or	t3, t3, t2
	_SD	t3, (TF_SSTATUS)(PTR(t0))

	__fpe_state_save PTRN(13)
1:

	/* Activate the new thread's pmap */
	_CMV	PTR(s0), PTR(a0)
	_CMV	PTR(s1), PTR(a1)
	_CMV	PTR(s2), PTR(a2)
	_CMV	PTR(a0), PTR(a1)
#ifdef __CHERI_PURE_CAPABILITY__
	_LGC	PTR(ra), _C_LABEL(pmap_activate_sw)
	_JALR	PTR(ra)
#else
	call	_C_LABEL(pmap_activate_sw)
#endif
	_CMV	PTR(a1), PTR(s1)

	/* Release the old thread */
	S_PTR	PTR(s2), TD_LOCK(PTR(s0))

#if defined(SCHED_ULE) && defined(SMP)
	/* Spin if TD_LOCK points to a blocked_lock */
#ifdef __CHERI_PURE_CAPABILITY__
	_LGC	PTR(s2), _C_LABEL(blocked_lock)
1:
	L_PTR	PTR(t0), TD_LOCK(PTR(a1))
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
	_LGC	PTR(t0), _C_LABEL(qemu_trace_perthread)
	_LW	t0, (PTR(t0))
#else
	lw	t0, _C_LABEL(qemu_trace_perthread)
#endif
	beqz	t0, .Lout_qemu_tracing

	_LW	t0, TD_MDFLAGS(PTR(a1))
	andi	t1, t0, MDTD_QTRACE
	beqz	t1, .Ldisable_qemu_tracing
	andi	t0, t0, MDTD_QTRACE_USERMODE
	bnez	t0, .Lenable_qemu_user_tracing
.Lenable_qemu_tracing:
	slti	x0, x0, 0x1b
	j	.Lout_qemu_tracing
.Lenable_qemu_user_tracing:
	slti	x0, x0, 0x2b
	j	.Lout_qemu_tracing
.Ldisable_qemu_tracing:
	slti	x0, x0, 0x1e
.Lout_qemu_tracing:
#endif

	/*
	 * Restore the saved context.
	 */
	L_PTR	PTRN(13), TD_PCB(PTR(a1))

	/* Restore the registers */
	L_PTR	PTR(ra), (PCB_RA)(PTRN(13))
	L_PTR	PTR(sp), (PCB_SP)(PTRN(13))

	/* s[0-11] */
	L_PTR	PTR(s0), (PCB_S + 0 * PTR_WIDTH)(PTRN(13))
	L_PTR	PTR(s1), (PCB_S + 1 * PTR_WIDTH)(PTRN(13))
	L_PTR	PTR(s2), (PCB_S + 2 * PTR_WIDTH)(PTRN(13))
	L_PTR	PTR(s3), (PCB_S + 3 * PTR_WIDTH)(PTRN(13))
	L_PTR	PTR(s4), (PCB_S + 4 * PTR_WIDTH)(PTRN(13))
	L_PTR	PTR(s5), (PCB_S + 5 * PTR_WIDTH)(PTRN(13))
	L_PTR	PTR(s6), (PCB_S + 6 * PTR_WIDTH)(PTRN(13))
	L_PTR	PTR(s7), (PCB_S + 7 * PTR_WIDTH)(PTRN(13))
	L_PTR	PTR(s8), (PCB_S + 8 * PTR_WIDTH)(PTRN(13))
	L_PTR	PTR(s9), (PCB_S + 9 * PTR_WIDTH)(PTRN(13))
	L_PTR	PTR(s10), (PCB_S + 10 * PTR_WIDTH)(PTRN(13))
	L_PTR	PTR(s11), (PCB_S + 11 * PTR_WIDTH)(PTRN(13))

	/* Is FPE enabled for new thread? */
	L_PTR	PTR(t0), TD_FRAME(PTR(a1))
	_LD	t1, (TF_SSTATUS)(PTR(t0))

	li	t2, SSTATUS_FS_MASK
	and	t3, t1, t2
	beqz	t3, 1f		/* No, skip. */

	/* Restore registers. */
	__fpe_state_load PTRN(13)
1:
	RETURN
END(cpu_switch)

/*
 * fork_exit(void (*callout)(void *, struct trapframe *), void *arg,
 *  struct trapframe *frame)
 */

ENTRY(fork_trampoline)
	_CMV	PTR(a0), PTR(s0)
	_CMV	PTR(a1), PTR(s1)
	_CMV	PTR(a2), PTR(sp)
#ifdef __CHERI_PURE_CAPABILITY__
	_LGC	PTR(ra), _C_LABEL(fork_exit)
	_JALR	PTR(ra)
#else
	call	_C_LABEL(fork_exit)
#endif

	/* Restore sstatus */
	_LD	t0, (TF_SSTATUS)(PTR(sp))
	/* Ensure interrupts disabled */
	li	t1, ~SSTATUS_SIE
	and	t0, t0, t1
	csrw	sstatus, t0

#if __has_feature(capabilities)
#ifndef __CHERI_PURE_CAPABILITY__
	/* Switch to capmode PCC. */
#ifdef __riscv_xcheri
	lla	t0, 1f
	cspecialr CAP(t1), pcc
	scaddr CAP(t1), CAP(t1), t0
	li	t0, 1
	csetflags CAP(t1), CAP(t1), t0
#ifdef __riscv_xcheri_mode_dependent_jumps
	jr.cap	CAP(t1)
#else
	jr	CAP(t1)
#endif
#else /* !defined(__riscv_xcheri) */
	modesw.cap
#endif /* !defined(__riscv_xcheri) */
.option push
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

	/*
	 * Store our DDC on stack, we will load it back
	 * on kernel mode trap.
	 */
	CSRR_CAP	CAP(t0), ddc
	_SC	CAP(t0), (TF_SIZE + KF_DDC)(CAP(sp))
#endif /* !defined(__CHERI_PURE_CAPABILITY__) */

	/*
	 * Switch to user DDC.  After this point, all stack accesses
	 * must use 'csp' instead of 'sp'.
	 */
	_LC	CAP(t0), (TF_DDC)(CAP(sp))
	CSRW_CAP	ddc, CAP(t0)
#endif /* __has_feature(capabilities) */

	/* Restore exception program counter */
	_LC	CAP(t0), (TF_SEPC)(CAP(sp))
	CSRW_CAP	CAP_CSR(sepc), CAP(t0)

	/* Restore the registers */
	_LC	CAP(t0), (TF_T + 0 * CAP_WIDTH)(CAP(sp))
	_LC	CAP(t1), (TF_T + 1 * CAP_WIDTH)(CAP(sp))
	_LC	CAP(t2), (TF_T + 2 * CAP_WIDTH)(CAP(sp))
	_LC	CAP(t3), (TF_T + 3 * CAP_WIDTH)(CAP(sp))
	_LC	CAP(t4), (TF_T + 4 * CAP_WIDTH)(CAP(sp))
	_LC	CAP(t5), (TF_T + 5 * CAP_WIDTH)(CAP(sp))
	_LC	CAP(t6), (TF_T + 6 * CAP_WIDTH)(CAP(sp))

	_LC	CAP(s0), (TF_S + 0 * CAP_WIDTH)(CAP(sp))
	_LC	CAP(s1), (TF_S + 1 * CAP_WIDTH)(CAP(sp))
	_LC	CAP(s2), (TF_S + 2 * CAP_WIDTH)(CAP(sp))
	_LC	CAP(s3), (TF_S + 3 * CAP_WIDTH)(CAP(sp))
	_LC	CAP(s4), (TF_S + 4 * CAP_WIDTH)(CAP(sp))
	_LC	CAP(s5), (TF_S + 5 * CAP_WIDTH)(CAP(sp))
	_LC	CAP(s6), (TF_S + 6 * CAP_WIDTH)(CAP(sp))
	_LC	CAP(s7), (TF_S + 7 * CAP_WIDTH)(CAP(sp))
	_LC	CAP(s8), (TF_S + 8 * CAP_WIDTH)(CAP(sp))
	_LC	CAP(s9), (TF_S + 9 * CAP_WIDTH)(CAP(sp))
	_LC	CAP(s10), (TF_S + 10 * CAP_WIDTH)(CAP(sp))
	_LC	CAP(s11), (TF_S + 11 * CAP_WIDTH)(CAP(sp))

	_LC	CAP(a0), (TF_A + 0 * CAP_WIDTH)(CAP(sp))
	_LC	CAP(a1), (TF_A + 1 * CAP_WIDTH)(CAP(sp))
	_LC	CAP(a2), (TF_A + 2 * CAP_WIDTH)(CAP(sp))
	_LC	CAP(a3), (TF_A + 3 * CAP_WIDTH)(CAP(sp))
	_LC	CAP(a4), (TF_A + 4 * CAP_WIDTH)(CAP(sp))
	_LC	CAP(a5), (TF_A + 5 * CAP_WIDTH)(CAP(sp))
	_LC	CAP(a6), (TF_A + 6 * CAP_WIDTH)(CAP(sp))
	_LC	CAP(a7), (TF_A + 7 * CAP_WIDTH)(CAP(sp))

	/* Load user ra and gp */
	_LC	CAP(ra), (TF_RA)(CAP(sp))
	_LC	CAP(gp), (TF_GP)(CAP(sp))

	/*
	 * Store our pcpup on stack, we will load it back
	 * on kernel mode trap.
	 */
	_SC	CAP(tp), (TF_SIZE + KF_TP)(CAP(sp))
	_LC	CAP(tp), (TF_TP)(CAP(sp))

	/* Save kernel stack so we can use it doing a user trap */
	CADDI_CAP	CAP(sp), CAP(sp), TF_SIZE
	CSRW_CAP	CAP_CSR(sscratch), CAP(sp)

	/* Load user stack */
	_LC	CAP(sp), (TF_SP - TF_SIZE)(CAP(sp))
#if __has_feature(capabilities) && !defined(__CHERI_PURE_CAPABILITY__)
.option pop
#endif

	sret
END(fork_trampoline)

ENTRY(savectx)
	/* Store ra, sp and the callee-saved registers */
	_SC	CAP(ra), (PCB_RA)(PTR(a0))
	_SC	CAP(sp), (PCB_SP)(PTR(a0))
	_SC	CAP(tp), (PCB_TP)(PTR(a0))
	_SC	CAP(gp), (PCB_GP)(PTR(a0))

	/* s[0-11] */
	_SC	CAP(s0), (PCB_S + 0 * CAP_WIDTH)(PTR(a0))
	_SC	CAP(s1), (PCB_S + 1 * CAP_WIDTH)(PTR(a0))
	_SC	CAP(s2), (PCB_S + 2 * CAP_WIDTH)(PTR(a0))
	_SC	CAP(s3), (PCB_S + 3 * CAP_WIDTH)(PTR(a0))
	_SC	CAP(s4), (PCB_S + 4 * CAP_WIDTH)(PTR(a0))
	_SC	CAP(s5), (PCB_S + 5 * CAP_WIDTH)(PTR(a0))
	_SC	CAP(s6), (PCB_S + 6 * CAP_WIDTH)(PTR(a0))
	_SC	CAP(s7), (PCB_S + 7 * CAP_WIDTH)(PTR(a0))
	_SC	CAP(s8), (PCB_S + 8 * CAP_WIDTH)(PTR(a0))
	_SC	CAP(s9), (PCB_S + 9 * CAP_WIDTH)(PTR(a0))
	_SC	CAP(s10), (PCB_S + 10 * CAP_WIDTH)(PTR(a0))
	_SC	CAP(s11), (PCB_S + 11 * CAP_WIDTH)(PTR(a0))

	__fpe_state_save PTR(a0)
	RETURN
END(savectx)

/*
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
