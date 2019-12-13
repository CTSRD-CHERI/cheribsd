/*	$OpenBSD: locore.S,v 1.18 1998/09/15 10:58:53 pefo Exp $	*/
/*-
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Digital Equipment Corporation and Ralph Campbell.
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
 * Copyright (C) 1989 Digital Equipment Corporation.
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby granted,
 * provided that the above copyright notice appears in all copies.
 * Digital Equipment Corporation makes no representations about the
 * suitability of this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 *
 * from: Header: /sprite/src/kernel/mach/ds3100.md/RCS/loMem.s,
 *	v 1.1 89/07/11 17:55:04 nelson Exp  SPRITE (DECWRL)
 * from: Header: /sprite/src/kernel/mach/ds3100.md/RCS/machAsm.s,
 *	v 9.2 90/01/29 18:00:39 shirriff Exp  SPRITE (DECWRL)
 * from: Header: /sprite/src/kernel/vm/ds3100.md/vmPmaxAsm.s,
 *	v 1.1 89/07/10 14:27:41 nelson Exp  SPRITE (DECWRL)
 *
 *	from: @(#)locore.s	8.5 (Berkeley) 1/4/94
 *	JNPR: swtch.S,v 1.6.2.1 2007/09/10 10:36:50 girish
 * $FreeBSD$
 */

/* XXX-AM add CTSRD license header? Do we keep the old header? */


/*
 * Pure capability kernel context switching routines.
 *
 */

#ifndef CPU_CHERI
#error "purecap kernel context switching compiled for non-CHERI target!"
#endif
#ifndef CHERI_PURECAP_KERNEL
#error "purecap kernel context switching compiled for non-purecap kernel!"
#endif


#include "opt_compat.h"
#include <sys/syscall.h>
#include <machine/asm.h>
#include <machine/cpu.h>
#include <machine/cpuregs.h>
#include <machine/regnum.h>
#include <machine/pte.h>
#include <machine/pcb.h>

#include <machine/cheriasm.h>
#include <machine/cherireg.h>
.set cheri_sysregs_accessible

#include "assym.inc"

	.set	noreorder			# Noreorder is default style!

/*
 * Setup for and return to user.
 */
LEAF(fork_trampoline)
	/*
	 * Adjust arguments to fork_exit, these are restored
	 * from cherikframe before entering the trampoline.
	 */
	cmove	$c3, $c18
	cmove	$c4, $c19
	CAPCALL_LOAD($c12, fork_exit)
	cjalr	$c12, $c17
	cmove	$c5, $c20

	DO_AST

	mfc0	v0, MIPS_COP_0_STATUS
	and     v0, ~(MIPS_SR_INT_IE)
	mtc0	v0, MIPS_COP_0_STATUS	# disable interrupts
	COP0_SYNC
/*
 * The use of kr1c for storing the PCB pointer must be done only
 * after interrupts are disabled.  Otherwise it will get overwritten
 * by the interrupt code.
 */
	.set	noat
	GET_CPU_PCPU(CHERI_REG_KSCRATCH)
	clc CHERI_REG_KSCRATCH, zero, PC_CURPCB(CHERI_REG_KSCRATCH)

	RESTORE_U_PCB_REG(t0, MULLO, CHERI_REG_KSCRATCH)
	RESTORE_U_PCB_REG(t1, MULHI, CHERI_REG_KSCRATCH)
	mtlo	t0
	mthi	t1
	/* Note: this uses $c1 as scratch register. */
	RESTORE_U_PCB_PC(a0, CHERI_REG_C1, CHERI_REG_KSCRATCH, t2) # set return address
	RESTORE_U_PCB_REG(a0, PC, CHERI_REG_KSCRATCH)
	RESTORE_U_PCB_REG(AT, AST, CHERI_REG_KSCRATCH)
	RESTORE_U_PCB_REG(v0, V0, CHERI_REG_KSCRATCH)

	RESTORE_U_PCB_REG(v1, V1, CHERI_REG_KSCRATCH)
	RESTORE_U_PCB_REG(a0, A0, CHERI_REG_KSCRATCH)
	RESTORE_U_PCB_REG(a1, A1, CHERI_REG_KSCRATCH)
	RESTORE_U_PCB_REG(a2, A2, CHERI_REG_KSCRATCH)
	RESTORE_U_PCB_REG(a3, A3, CHERI_REG_KSCRATCH)
	RESTORE_U_PCB_REG(t0, T0, CHERI_REG_KSCRATCH)
	RESTORE_U_PCB_REG(t1, T1, CHERI_REG_KSCRATCH)
	RESTORE_U_PCB_REG(t2, T2, CHERI_REG_KSCRATCH)
	RESTORE_U_PCB_REG(t3, T3, CHERI_REG_KSCRATCH)
	RESTORE_U_PCB_REG(ta0, TA0, CHERI_REG_KSCRATCH)
	RESTORE_U_PCB_REG(ta1, TA1, CHERI_REG_KSCRATCH)
	RESTORE_U_PCB_REG(ta2, TA2, CHERI_REG_KSCRATCH)
	RESTORE_U_PCB_REG(ta3, TA3, CHERI_REG_KSCRATCH)
	RESTORE_U_PCB_REG(s0, S0, CHERI_REG_KSCRATCH)
	RESTORE_U_PCB_REG(s1, S1, CHERI_REG_KSCRATCH)
	RESTORE_U_PCB_REG(s2, S2, CHERI_REG_KSCRATCH)
	RESTORE_U_PCB_REG(s3, S3, CHERI_REG_KSCRATCH)
	RESTORE_U_PCB_REG(s4, S4, CHERI_REG_KSCRATCH)
	RESTORE_U_PCB_REG(s5, S5, CHERI_REG_KSCRATCH)
	RESTORE_U_PCB_REG(s6, S6, CHERI_REG_KSCRATCH)
	RESTORE_U_PCB_REG(s7, S7, CHERI_REG_KSCRATCH)
	RESTORE_U_PCB_REG(t8, T8, CHERI_REG_KSCRATCH)
	RESTORE_U_PCB_REG(t9, T9, CHERI_REG_KSCRATCH)
	RESTORE_U_PCB_REG(k0, SR, CHERI_REG_KSCRATCH)
	RESTORE_U_PCB_REG(gp, GP, CHERI_REG_KSCRATCH)
	RESTORE_U_PCB_REG(s8, S8, CHERI_REG_KSCRATCH)
	RESTORE_U_PCB_REG(ra, RA, CHERI_REG_KSCRATCH)
	RESTORE_U_PCB_REG(sp, SP, CHERI_REG_KSCRATCH)

	/*
	 * Note: This restores does not restore EPCC, since that is restored
	 * by RESTORE_U_PCB_PC() above.
	 */
	RESTORE_CREGS_FROM_PCB(CHERI_REG_KSCRATCH, k1)

	li	k1, ~MIPS_SR_INT_MASK
	and	k0, k0, k1
	mfc0	k1, MIPS_COP_0_STATUS
	and	k1, k1, MIPS_SR_INT_MASK
	or	k0, k0, k1
	mtc0	k0, MIPS_COP_0_STATUS	# switch to user mode (when eret...)
	HAZARD_DELAY
	sync

	/* Restore KSCRATCH for exception return */
	cgetkr1c	CHERI_REG_KSCRATCH
	CHERI_EXCEPTION_RETURN(k0)

	eret
	.set	at
END(fork_trampoline)

/*
 * Update pcb, saving current processor state.
 * Note: this only works if pcbp != curproc's pcb since
 * cpu_switch() will copy over pcb_context.
 *
 *	savectx(struct pcb *pcbp);
 */
LEAF(savectx)
	SAVE_U_PCB_CONTEXT(s0, PCB_REG_S0, $c3)
	SAVE_U_PCB_CONTEXT(s1, PCB_REG_S1, $c3)
	SAVE_U_PCB_CONTEXT(s2, PCB_REG_S2, $c3)
	SAVE_U_PCB_CONTEXT(s3, PCB_REG_S3, $c3)
	mfc0	v0, MIPS_COP_0_STATUS // XXX-AM: not sure why we are doing this...
	SAVE_U_PCB_CONTEXT(s4, PCB_REG_S4, $c3)
	SAVE_U_PCB_CONTEXT(s5, PCB_REG_S5, $c3)
	SAVE_U_PCB_CONTEXT(s6, PCB_REG_S6, $c3)
	SAVE_U_PCB_CONTEXT(s7, PCB_REG_S7, $c3)
	SAVE_U_PCB_CONTEXT(sp, PCB_REG_SP, $c3)
	SAVE_U_PCB_CONTEXT(s8, PCB_REG_S8, $c3)
	SAVE_U_PCB_CONTEXT(ra, PCB_REG_RA, $c3)
	SAVE_U_PCB_CONTEXT(v0, PCB_REG_SR, $c3)
	SAVE_U_PCB_CONTEXT(gp, PCB_REG_GP, $c3)

	SAVE_U_PCB_CHERIKFRAME($c3);

	/* Save pc and pcc */
	cgetpcc	$c1
	SAVE_U_PCB_CHERIKFRAME_CREG($c1, CHERIKFRAME_OFF_PCC, $c3)
	cgetoffset ra, $c1
	SAVE_U_PCB_CONTEXT(ra, PCB_REG_PC, $c3)

	cjr	$c17
	move	v0, zero
END(savectx)

NESTED(cpu_throw, CALLFRAME_SIZ, ra)
	mfc0	t0, MIPS_COP_0_STATUS		# t0 = saved status register
	nop
	nop
	and     a3, t0, ~(MIPS_SR_INT_IE)
	mtc0	a3, MIPS_COP_0_STATUS		# Disable all interrupts
	ITLBNOPFIX
	j	mips_sw1			# We're not interested in old
						# thread's context, so jump
						# right to action
	nop					# BDSLOT
END(cpu_throw)
/*
 * Force size 0 so that we do not set the capability bounds in relocations.
 * this is needed to allow the branch to mips_sw1.
 * XXX-AM: This could be replaced with an indirect jump through the captable.
 */
.size _C_LABEL(cpu_throw), 0


/*
 * Helper macro that checks whether the TLB contains a mapping to
 * a given address, and invalidates it.
 * This is used by cpu_switch() to set up TLB entry 0 for the new
 * kernel stack.
 * If an entry is found, it is replaced by KSEG0_START + 2 * index * PAGE_SIZE
 * so that it is invalidated.
 */
#define TLB_KSTACK_INVAL(kaddr, tregA, tregB)		\
	MTC0	kaddr, MIPS_COP_0_TLB_HI		;\
	HAZARD_DELAY					;\
	tlbp						;\
	HAZARD_DELAY					;\
	mfc0	tregA, MIPS_COP_0_TLB_INDEX		;\
	HAZARD_DELAY					;\
	bltz	tregA, 1337f				;\
	PTR_LI	tregB, MIPS_KSEG0_START			;\
	sll	tregA, PAGE_SHIFT + 1			;\
	daddu	tregA, tregA, tregB			;\
	MTC0	tregA, MIPS_COP_0_TLB_HI		;\
	PTE_MTC0	zero, MIPS_COP_0_TLB_LO0	;\
	PTE_MTC0	zero, MIPS_COP_0_TLB_LO1	;\
	MTC0	zero, MIPS_COP_0_TLB_PG_MASK		;\
	HAZARD_DELAY					;\
	tlbwi						;\
	HAZARD_DELAY					;\
1337:	# NO matching TLB entry


/*
 * cpu_switch(struct thread *old, struct thread *new, struct mutex *mtx);
 *	c3 - old
 *	c4 - new
 *	c5 - mtx
 * Find the highest priority process and resume it.
 */
NESTED(cpu_switch, CALLFRAME_SIZ, ra)
	mfc0	t1, MIPS_COP_0_STATUS		# t1 = saved status register
	nop
	nop
	and     a3, t1, ~(MIPS_SR_INT_IE)
	mtc0	a3, MIPS_COP_0_STATUS		# Disable all interrupts
	ITLBNOPFIX
	cbez	$c3, mips_sw1
	cmove	$c1, $c3
	clc	$c1, zero, TD_PCB($c1)	# load PCB addr of curproc
	SAVE_U_PCB_CHERIKFRAME_CREG(CHERI_REG_STC, CHERIKFRAME_OFF_STC, $c1)
	/* XXX-AM: Not really using sp so we can not save it? */
	SAVE_U_PCB_CONTEXT(sp, PCB_REG_SP, $c1)		# save old sp
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, -CALLFRAME_SIZ
	csc	$c17, zero, CALLFRAME_RA(CHERI_REG_STC)
	.mask	0x80000000, (CALLFRAME_RA - CALLFRAME_SIZ) // XXX-AM: this is meaningless in purecap...
	/* Do a savectx(), note SAVE_U_PCB_CONTEXT trashes t0 */
	SAVE_U_PCB_CONTEXT(s0, PCB_REG_S0, $c1)
	SAVE_U_PCB_CONTEXT(s1, PCB_REG_S1, $c1)
	SAVE_U_PCB_CONTEXT(s2, PCB_REG_S2, $c1)
	SAVE_U_PCB_CONTEXT(s3, PCB_REG_S3, $c1)
	SAVE_U_PCB_CONTEXT(s4, PCB_REG_S4, $c1)
	SAVE_U_PCB_CONTEXT(s5, PCB_REG_S5, $c1)
	SAVE_U_PCB_CONTEXT(s6, PCB_REG_S6, $c1)
	SAVE_U_PCB_CONTEXT(s7, PCB_REG_S7, $c1)
	SAVE_U_PCB_CONTEXT(s8, PCB_REG_S8, $c1)
	SAVE_U_PCB_CONTEXT(ra, PCB_REG_RA, $c1)		# save return address
	SAVE_U_PCB_CONTEXT(t1, PCB_REG_SR, $c1)		# save status register
	SAVE_U_PCB_CONTEXT(gp, PCB_REG_GP, $c1)

	/* Save pc and pcc to context */
	cgetpcc	$c2
	cgetoffset ra, $c2
	SAVE_U_PCB_CHERIKFRAME_CREG($c2, CHERIKFRAME_OFF_PCC, $c1)
	SAVE_U_PCB_CONTEXT(ra, PCB_REG_PC, $c1)		# save return address

	/* Do cheri savectx() */
	SAVE_U_PCB_CHERIKFRAME($c1);

	/* Reset original thread mutex that we temporarily replaced with sched_lock */
	csc	$c5, zero, TD_LOCK($c3)

mips_sw1:
#ifdef CPU_QEMU_MALTA
	/*
	 * If per-thread tracing is disabled, skip this block and don't muck
	 * with emulator state.
	 */
	CAPTABLE_LOAD($c2, qemu_trace_perthread)	# Load address of var
	clw	t2, zero, 0($c2)			# Load var value
	beqz	t2, done_qemu_tracing			# Skip if value is 0
	nop

	/*
	 * If per-thread tracing is enabled, update Qemu-internal state to
	 * reflect the thread we are switching to.  Don't disable before
	 * checking, so we can ensure that we get a full trace if both the
	 * 'old' and 'new' threads have tracing enabled.
	*/
	REG_LI	t0, TD_MDFLAGS
	clw	t2, t0, 0($c4)				# Get new->md_flags
	andi	t2, t2, MDTD_QTRACE			# Mask Qemu trace bit
	beqz	t2, disable_qemu_tracing		# Branch if not set
	nop

enable_qemu_tracing:
	li	$0, 0xbeef
	b	done_qemu_tracing
	nop

disable_qemu_tracing:
	li	$0, 0xdead

done_qemu_tracing:
#endif

#if defined(SMP) && defined(SCHED_ULE)
	CAPTABLE_LOAD($c2, blocked_lock)
blocked_loop:
	clc	$c1, zero, TD_LOCK($c4)
	ceq	t1, $c2, $c1
	bnez	t1, blocked_loop
	nop
#endif
	/* Save newthr in callee-save reg */
	cmove	$c18, $c4
/*
 * Switch to new context.
 */
	GET_CPU_PCPU($c2)
	csc	$c4, zero, PC_CURTHREAD($c2)
	clc	$c1, zero, TD_PCB($c4)
	csc	$c1, zero, PC_CURPCB($c2)
	clc	$c1, zero, TD_KSTACK($c4)	# va of 1st half of kstack
	/* set the newthread kstack in pcpu for the exception handlers to use. */
	csc	$c1, zero, PC_KSTACK_CAP($c2)
	cgetbase	v0, $c1			# get kstack base
	cgetoffset	t0, $c1			# get kstack offset
	daddu		v0, v0, t0		# get kstack va
	PTR_LI	s0, MIPS_XKSEG_START
	bltu	v0, s0, sw2			# kstack in xkphys? no need to insert in TLB.
	REG_LI	t0, TD_UPTE
	cld	a1, t0, 0($c4)			# a1 = u. pte #0
	REG_LI	t0, (TD_UPTE + PTESIZE)
	cld	a2, t0, 0($c4)			# a2 = u. pte #1
/*
 * Wiredown the USPACE of newproc in TLB entry#0.  Check whether target
 * USPACE is already in another place of TLB before that, and if so
 * invalidate that TLB entry.
 * NOTE: This is hard coded to UPAGES == 2.
 * Also, there should be no TLB faults at this point.
*/
	TLB_KSTACK_INVAL(v0, s0, t1)

#ifdef KSTACK_LARGE_PAGE
/*
 * With a KSTACK large page size it is possible that a second TLB
 * entry is currently mapping the kernel thread stack as a regular
 * 4K sized page(s). Check for this case and, if so, invalidate
 * that TLB entry as well.
 * This can happen only with the following combinations:
 * CHERI-256 KSTACK_PAGE_SIZE == 64K
 * CHERI-128 KSTACK_PAGE_SIZE == 16K
 * non-cheri KSTACK_PAGE_SIZE == 16K
 * all with PAGE_SIZE == 4K
 */
#if (PAGE_SIZE != 4096)
#error PAGE_SIZE is not 4K.
#elif defined(CPU_CHERI128)
#if (KSTACK_PAGE_SIZE != (1 << 14))
#error CHERI128 KSTACK_PAGE_SIZE is not 16K.
#endif
#elif defined(CPU_CHERI)
#if (KSTACK_PAGE_SIZE != (1 << 16))
#error CHERI256 KSTACK_PAGE_SIZE is not 64K.
#endif
#endif
	/*
	 * Number of pairs of 4K pages in the KSTACK_SIZE region
	 * -1 because the first KSTACK_INVAL has already been done above.
	 * On cheri kernels we use a larger stack with no guard page
	 * so we need to perform additional checks depending on KSTACK_SIZE.
	 */
	REG_LI	t2, (KSTACK_SIZE >> (PAGE_SHIFT + 1)) - 1
	move		v1, v0
kstack_inval_loop:
	PTR_ADDU	v1, PAGE_SIZE * 2	# advance by 2 pages and try again
	TLB_KSTACK_INVAL(v1, t0, t1)
	daddi	t2, t2, -1
	bnez t2, kstack_inval_loop
	nop
#endif /* KSTACK_LARGE_PAGE */

	MTC0		v0, MIPS_COP_0_TLB_HI		# set VPN again
	HAZARD_DELAY
/* SMP!! - Works only for  unshared TLB case - i.e. no v-cpus */
	mtc0		zero, MIPS_COP_0_TLB_INDEX	# TLB entry #0
	HAZARD_DELAY
	PTE_MTC0	a1, MIPS_COP_0_TLB_LO0		# upte[0]
	HAZARD_DELAY
	PTE_MTC0	a2, MIPS_COP_0_TLB_LO1		# upte[1]
	HAZARD_DELAY
#ifdef KSTACK_LARGE_PAGE
	li		t1, KSTACK_TLBMASK_MASK
	MTC0		t1, MIPS_COP_0_TLB_PG_MASK
	HAZARD_DELAY
#else /* ! KSTACK_LARGE_PAGE */
	MTC0		zero, MIPS_COP_0_TLB_PG_MASK
	HAZARD_DELAY
#endif /* ! KSTACK_LARGE_PAGE */
	tlbwi					# set TLB entry #0
	HAZARD_DELAY
#ifdef KSTACK_LARGE_PAGE
	MTC0		zero, MIPS_COP_0_TLB_PG_MASK
	HAZARD_DELAY
#endif /* KSTACK_LARGE_PAGE */
/*
 * Now running on new u struct.
 */
sw2:
	clc	$c19, zero, TD_PCB($c18)
	/* grab newthread kstack */
	RESTORE_U_PCB_CHERIKFRAME_CREG(CHERI_REG_STC, CHERIKFRAME_OFF_STC, $c19)
	RESTORE_U_PCB_CONTEXT(sp, PCB_REG_SP, $c19)
	// Note we have newthr in c18
	CAPCALL_LOAD($c12, pmap_activate)
	cjalr	$c12, $c17
	cmove	$c3, $c4
/*
 * Restore registers and return.
 */
	cmove	$c3, $c19	# newthr pcb
	cmove	$c4, $c18	# newthr
	RESTORE_U_PCB_CONTEXT(gp, PCB_REG_GP, $c3)
	RESTORE_U_PCB_CONTEXT(v0, PCB_REG_SR, $c3)	# restore kernel context
	RESTORE_U_PCB_CONTEXT(ra, PCB_REG_RA, $c3)
	RESTORE_U_PCB_CONTEXT(s0, PCB_REG_S0, $c3)
	RESTORE_U_PCB_CONTEXT(s1, PCB_REG_S1, $c3)
	RESTORE_U_PCB_CONTEXT(s2, PCB_REG_S2, $c3)
	RESTORE_U_PCB_CONTEXT(s3, PCB_REG_S3, $c3)
	RESTORE_U_PCB_CONTEXT(s4, PCB_REG_S4, $c3)
	RESTORE_U_PCB_CONTEXT(s5, PCB_REG_S5, $c3)
	RESTORE_U_PCB_CONTEXT(s6, PCB_REG_S6, $c3)
	RESTORE_U_PCB_CONTEXT(s7, PCB_REG_S7, $c3)
	RESTORE_U_PCB_CONTEXT(s8, PCB_REG_S8, $c3)

	RESTORE_U_PCB_CHERIKFRAME($c3);

	mfc0	t0, MIPS_COP_0_STATUS
	and	t0, t0, MIPS_SR_INT_MASK
	and	v0, v0, ~MIPS_SR_INT_MASK
	or	v0, v0, t0
	mtc0	v0, MIPS_COP_0_STATUS
	ITLBNOPFIX

/*
 * Set the new thread's TLS pointer.
 *
 * Note that this code is normally removed if the CPU doesn't support ULRI by
 * remove_userlocal_code() in cpu.c. We assume that CHERI cpu supports the
 * thread's TLS pointer, otherwise the following breaks remove_userlocal_code()
 * in cpu.c.
 */
	clc	$c3, zero, TD_MDTLS($c4)	# Get TLS pointer
	PTR_LI	t0, TD_MDTLS_TCB_OFFSET
	cld	t0, t0, 0($c4)			# Get TLS/TCB offset
	cincoffset $c3, $c3, t0
	cwritehwr $c3, $chwr_userlocal
	cgetaddr t0, $c3
	MTC0	t0, MIPS_COP_0_USERLOCAL, 2	# write it to ULR for rdhwr

	cjr	$c17
	nop
	END(cpu_switch)

/*----------------------------------------------------------------------------
 *
 * MipsSwitchFPState --
 *
 * CHERI do not support hardfloats, the purecap kernel certainly does not
 * since we do not have a way to load/store hardware floats via capabilities
 * unless we emulate it.
 *
 * Panic for now.
 *
 *----------------------------------------------------------------------------
 */
LEAF(MipsSwitchFPState)
	PANIC("purecap kernel has no FPU support")
	nop
END(MipsSwitchFPState)

/*----------------------------------------------------------------------------
 *
 * MipsFPID --
 *
 *	Read and return the floating point implementation register.
 *	Always return zero in this case since the purecap kernel does not
 *	currently support an FPU.
 *
 *	uint32_t
 *	MipsFPID(void)
 *
 * Results:
 *	Floating point implementation register.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------------
 */
LEAF(MipsFPID)
	.set push
	.set hardfloat
#ifdef CHERI_PURECAP_KERNEL
	li	v0, 0
	cjr	$c17
	nop
#else
	mfc0	t1, MIPS_COP_0_STATUS		# Save the status register.
	HAZARD_DELAY
	or	t0, t1, MIPS_SR_COP_1_BIT | MIPS_SR_FR
	mtc0	t0, MIPS_COP_0_STATUS 		# Enable the coprocessor
	HAZARD_DELAY
	ITLBNOPFIX
	cfc1	v0, MIPS_FPU_ID
	mtc0	t1, MIPS_COP_0_STATUS		# Restore the status register.
	ITLBNOPFIX
	cjr	$c17
	nop
#endif
	.set pop
END(MipsFPID)

/*
 * This code is copied the user's stack for returning from signal handlers
 * (see sendsig() and sigreturn()). We have to compute the address
 * of the sigcontext struct for the sigreturn call.
*/
/*
 * XXX-AM: TODO merge cheriabi and normal sigcode for purecap kernel.
 * Now this distinction is useless since cheriABI is the default ABI.
 */
	.globl	_C_LABEL(sigcode)
_C_LABEL(sigcode):
	PTR_ADDU	a0, sp, SIGF_UC		# address of ucontext
	li		v0, SYS_sigreturn
# sigreturn (ucp)
	syscall
	break	0				# just in case sigreturn fails
	.globl	_C_LABEL(esigcode)
_C_LABEL(esigcode):

	.data
	.globl	szsigcode
szsigcode:
	.long	esigcode-sigcode
	.text

#if defined(__mips_n64) && defined(COMPAT_FREEBSD64)
	.globl	_C_LABEL(freebsd64_sigcode)
_C_LABEL(freebsd64_sigcode):
	PTR_ADDU	a0, sp, SIGF_UC		# address of ucontext
	li		v0, SYS_sigreturn
# sigreturn (ucp)
	syscall
	break	0				# just in case sigreturn fails
	.globl	_C_LABEL(freebsd64_esigcode)
_C_LABEL(freebsd64_esigcode):

	.data
	.globl	freebsd64_szsigcode
freebsd64_szsigcode:
	.long	freebsd64_esigcode-freebsd64_sigcode
	.text
#endif

#if (defined(__mips_n32) || defined(__mips_n64)) && defined(COMPAT_FREEBSD32)
	.globl	_C_LABEL(sigcode32)
_C_LABEL(sigcode32):
	addu		a0, sp, SIGF32_UC	# address of ucontext
	li		v0, SYS_sigreturn
# sigreturn (ucp)
	syscall
	break	0				# just in case sigreturn fails
	.globl	_C_LABEL(esigcode32)
_C_LABEL(esigcode32):

	.data
	.globl	szsigcode32
szsigcode32:
	.long	esigcode32-sigcode32
	.text
#endif

/*
 * Always build the CheriABI sigcode symbols since this file is only ever
 * compiled with capability support.
 */
	.globl	_C_LABEL(cheri_sigcode)
_C_LABEL(cheri_sigcode):
	dli		t0, SIGF_UC
	cincoffset	$c3, $c11, t0		# In the hybrid ABI named $c11,
	li		v0, SYS_sigreturn	# but we really mean $csp.
# sigreturn (ucp)
	syscall
	break	0				# just in case sigreturn fails
	.globl	_C_LABEL(echeri_sigcode)
_C_LABEL(echeri_sigcode):

	.data
	.globl	szcheri_sigcode
szcheri_sigcode:
	.long	echeri_sigcode-cheri_sigcode
	.text
// CHERI CHANGES START
// {
//   "updated": 20190514,
//   "target_type": "header",
//   "changes": [
//     "support"
//   ],
//   "change_comment": ""
// }
// CHERI CHANGES END
