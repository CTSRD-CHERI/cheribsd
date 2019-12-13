/*	$OpenBSD: locore.S,v 1.18 1998/09/15 10:58:53 pefo Exp $	*/
/*-
 * Copyright (c) 2016 Robert N. M. Watson
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
 *	from: @(#)locore.s	8.5 (Berkeley) 1/4/94
 *	JNPR: exception.S,v 1.5 2007/01/08 04:58:37 katta
 * $FreeBSD$
 */

/* XXX-AM add CTSRD license header? Do we keep the old header? */


/*
 * Pure capability kernel exception handling routines.
 */

#ifndef CPU_CHERI
#error "purecap kernel exception handlers compiled for non-CHERI target!"
#endif
#ifndef CHERI_PURECAP_KERNEL
#error "purecap kernel exception handlers compiled for non-purecap kernel!"
#endif

/*
 * Contains code that is the first executed at boot time plus
 * assembly language support routines.
 *
 * General MIPS CPU state for exceptions:
 *
 * EPC Register will point to the instruction that caused fault, unless the
 * faulting instruction was in a branch delay slot.  In that case, it will
 * point to the branch before the branch delay slot instruction.
 *
 * The cause register will contain what caused the exception and some state
 * about the interrupt.
 *
 * The status register contains information about the status of the CPU such
 * as: Kernel/User mode bit, interrupt enable bit.
 *
 * The BadVaddr register contains the virtual address that cause the last
 * exception.
 *
 * The Context register contains the lower 22 bits of the VPN (starting at
 * bit 4) that cause the last exception except bit0 and bit1 are zero. The
 * upper bits (bits 23 to 31 for MIPS32 and bits 23 to 63) are set under
 * kernel control (i.e. point to the page table). The Context/XContext
 * registers are not currently used by FreeBSD.
*/

#include "opt_ddb.h"
#include "opt_stack.h"

#include <machine/asm.h>
#include <machine/cpu.h>
#include <machine/exceptionasm.h>
#include <machine/regnum.h>
#include <machine/cpuregs.h>
#include <machine/pte.h>
#include <machine/pcb.h>
#include <machine/trap.h>

#include <machine/cheriasm.h>
#include <machine/cherireg.h>
.set cheri_sysregs_accessible	# Don't warn on access to c27-c30

#include "assym.inc"

	.set	noreorder		# Noreorder is default style!

#ifdef KDTRACE_HOOKS
	.data
	.globl	dtrace_invop_calltrap_addr
	.align	4
	.type	dtrace_invop_calltrap_addr, @object
	.size	dtrace_invop_calltrap_addr, 8
dtrace_invop_calltrap_addr:
	.word	0
	.word	0

	.text
#endif

/*
 *----------------------------------------------------------------------------
 *
 * MipsTLBMiss --
 *
 *	Vector code for the TLB-miss exception vector 0x80000000.
 *
 * This code is copied to the TLB exception vector address to
 * which the CPU jumps in response to an exception or a TLB miss.
 * NOTE: This code must be position independent!!!
 *
 *
 */
VECTOR(MipsTLBMiss, unknown)
	.set push
	.set noat

	CHERI_EXCEPTION_ENTER(k0)
	# Increment exception counter, if enabled.
	INC_EXCEPTION_CNTR(TLB_MISS_CNT)
	csetkr1c CHERI_REG_KSCRATCH
	CAPCALL_LOAD(CHERI_REG_KSCRATCH, _C_LABEL(MipsDoTLBMiss))
	MFC0	k0, MIPS_COP_0_BAD_VADDR	# get the fault address
	cjr	CHERI_REG_KSCRATCH
	cgetkr1c CHERI_REG_KSCRATCH
	.set pop
VECTOR_END(MipsTLBMiss)

/*
 *----------------------------------------------------------------------------
 *
 * MipsDoTLBMiss --  (UTLB miss)
 *
 * This is the real TLB Miss Handler code.  A miss was generated when the
 * access is to kuseg and there was not matching mapping loaded into the TLB.
 * 'segbase' points to the base of the segment table for user processes.
 *
 * The CPU does the following for an UTLB miss:
 * - Sets the EPC register.
 * - Sets the Cause register.
 * - Sets the Status register. Shifts K/U and IE bits over one and clears
 *   the current Kernel/User and Interrupt Enable bits. So the processor
 *   is in kernel mode with the interupts turned off.
 * - Sets BadVaddr register.
 * - Sets the Context/XContext register(s).
 * - Sets the TLB EntryHi register to contain VPN of the faulting address.
 *
 * Don't check for invalid pte's here. We load them as well and
 * let the processor trap to load the correct value after service.
 *
 * XXX This really needs to be changed to a linear page table and use the
 * Context and XContext registers.  That is really what it was designed for.
 *----------------------------------------------------------------------------
 */
	.set push
	.set noat
LEAF(MipsDoTLBMiss)
	/* Save c27 for use as KSCRATCH, this can be either the user or kernel c27. */
	csetkr1c	CHERI_REG_KSCRATCH
	bltz		k0, 1f				#02: k0<0 -> 1f (kernel fault)
	PTR_SRL		k0, k0, SEGSHIFT - PTRSHIFT	#03: k0=seg offset (almost)
	/* CHERI_PURECAP_KERNEL - assumes __mips64 and ! MIPS64_NEW_PMAP */
	GET_CPU_PCPU(CHERI_REG_KSCRATCH)
	clc		CHERI_REG_KSCRATCH, zero, PC_SEGBASE(CHERI_REG_KSCRATCH)
	cbez		CHERI_REG_KSCRATCH, 2f			# == NULL no segbase
	andi		k0, k0, PDEPTRMASK			# k0 = seg offset
	cincoffset	CHERI_REG_KSCRATCH, CHERI_REG_KSCRATCH, k0	# kr1c = seg entry ptr

	clc		CHERI_REG_KSCRATCH, zero, 0(CHERI_REG_KSCRATCH) # kr1c = seg entry
	MFC0		k0, MIPS_COP_0_BAD_VADDR		# XXX we may use k1 and avoid to reload badVaddr
	cbez		CHERI_REG_KSCRATCH, 2f			# == NULL no page table
	PTR_SRL		k0, PDRSHIFT - PTRSHIFT			# k0 = shift to first level page directory
	andi		k0, k0, PDEPTRMASK			# k0 = pde offset
	clc		CHERI_REG_KSCRATCH, k0, 0(CHERI_REG_KSCRATCH)	# kr1c = pde entry
	cbez		CHERI_REG_KSCRATCH, 2f			# == NULL no page table
	nop

	MFC0		k0, MIPS_COP_0_BAD_VADDR	# k0=bad address (again)
	PTR_SRL		k0, PAGE_SHIFT - PTESHIFT	#0b: k0=VPN (second level page table entry)
	andi		k0, k0, PTE2MASK		#0c: k0=page tab offset
	cincoffset	CHERI_REG_KSCRATCH, CHERI_REG_KSCRATCH, k0 # lo0 pte address
	cld		k0, zero, 0(CHERI_REG_KSCRATCH)	# k0 = lo0 pte

	CLEAR_PTE_SWBITS(k0)
	PTE_MTC0	k0, MIPS_COP_0_TLB_LO0		#12: lo0 is loaded
	COP0_SYNC

	cld		k0, zero, PTESIZE(CHERI_REG_KSCRATCH) # k1 = lo1 pte

	CLEAR_PTE_SWBITS(k0)
	PTE_MTC0	k0, MIPS_COP_0_TLB_LO1		#15: lo1 is loaded
	COP0_SYNC
	tlbwr						#1a: write to tlb
	HAZARD_DELAY

	/* Restore c27 used as KSCRATCH */
	cgetkr1c	CHERI_REG_KSCRATCH
	CHERI_EXCEPTION_RETURN(k0)
	eret						#1f: retUrn from exception

1:	/* kernel exception */
	j	MipsTLBMissException
	nop
2:	/* no page table present */
	j	SlowFault
	nop
	.set pop
END(MipsDoTLBMiss)
/* Force size 0 so that we do not set the capability bounds in relocations */
.size _C_LABEL(MipsDoTLBMiss), 0

/*
 * This code is copied to the general exception vector address to
 * handle all execptions except RESET and TLBMiss.
 * NOTE: This code must be position independent!!!
 */
VECTOR(MipsException, unknown)
/*
 * Find out what mode we came from and jump to the proper handler.
 *
 * Note: at turned off here because we cannot trash the at register
 * in this exception code. Only k0, k1 and kr1c may be modified before
 * we save registers. This is true of all functions called through
 * the pointer magic: Mips{User,Kern}Intr, Mips{User,Kern}GenException
 * and MipsTLBInvalidException
 */
	.set	noat

	/*
	 * If this is and user exception, this will also set
	 * kr1c and kr2c.
	 */
	CHERI_EXCEPTION_ENTER(k0)
	mfc0	k0, MIPS_COP_0_STATUS		# Get the status register
	mfc0	k1, MIPS_COP_0_CAUSE		# Get the cause register value.
	and	k0, k0, MIPS_SR_KSU_USER	# test for user mode
						# sneaky but the bits are
						# with us........
	sll	k0, k0, 3			# shift user bit for cause index
	and	k1, k1, MIPS_CR_EXC_CODE	# Mask out the cause bits.
	or	k1, k1, k0			# change index to user table
	PTR_SLL	k1, k1, 1			# shift to get 8-byte offset
1:
	CAPTABLE_LOAD(CHERI_REG_KSCRATCH, _C_LABEL(machExceptionTable))
	PTR_SLL		k1, CHERICAP_SHIFT - 3		# cause is already shifted by 3
	clc		CHERI_REG_KSCRATCH, k1, 0(CHERI_REG_KSCRATCH) # get function address
	cjr		CHERI_REG_KSCRATCH			# Jump to the function
	nop

	.set	at
VECTOR_END(MipsException)

/*
 * We couldn't find a TLB entry.
 * Find out what mode we came from and call the appropriate handler.
 */
SlowFault:
	.set	noat
	mfc0	k0, MIPS_COP_0_STATUS
	nop
	and	k0, k0, MIPS_SR_KSU_USER
	bne	k0, zero, _C_LABEL(MipsUserGenException)
	nop
	.set	at
/*
 * Fall though ...
 */

/*----------------------------------------------------------------------------
 *
 * MipsKernGenException --
 *
 *	Handle an exception from kernel mode.
 *
 * Preconditions:
 *	KSCRATCH can be clobbered.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------------
 */

/*
 * The kernel exception stack contains 40 general-purpose registers, hi/lo
 * registers, and status register.  If CHERI is present, a further 28 CHERI
 * registers are stored there.  We also set up linkage conventions.  The
 * on-stack frame must match the binary layout of 'struct trapframe'.
 *
 * If we store capability registers on the stack, we need to adjust the stack
 * pointer to provide suitable alignment.  We therefore allocate an additional
 * CHERICAP_SIZE/2 to allow for that adjustment.  a0 will be set suitably to
 * include that alignment.
 */
#define	KERN_REG_SIZE		(NUMSAVEREGS * SZREG)
#define	KERN_CREG_SIZE		(NUMCHERISAVEREGS * CHERICAP_SIZE)
#define	KERN_EXC_FRAME_SIZE	(CALLFRAME_SIZ + KERN_REG_SIZE +	\
				KERN_CREG_SIZE)

/*
 * CHERI requires 16- or 32-byte alignment of the trap frame, so adjust sp
 * (or, whatever register is passed in via 'reg') down if required.  The
 * previous value of sp should be saved prior to calling this macro --
 * typically, in k1.  There are no free registers, so we do this using shift
 * instructions.
*/
#define CHERI_ADJUST_STC(reg)						\
	cgetoffset reg, CHERI_REG_STC;					\
	dsrl	reg, reg, CHERICAP_SHIFT ;				\
	dsll	reg, reg, CHERICAP_SHIFT ;				\
	csetoffset CHERI_REG_STC, CHERI_REG_STC, reg

/*
 * Trigger a panic due to a kernel stack overflow in an exception
 * handler.
 * This will switch to the boot stack for the current CPU and call PANIC.
 *
 * Note that this will trash KSCRATCH and assume the current STC is the
 * overflowed stack pointer.
 * Trashing KSCRATCH is fine since we will panic anyway.
 */
#define CHERI_KSTACK_OVERFLOW_PANIC					\
	GET_CPU_PCPU(CHERI_REG_KSCRATCH);				\
	clw	k1, zero, PC_CPUID(CHERI_REG_KSCRATCH);			\
	sll	k1, k1, PAGE_SHIFT + 1 /* curcpu pcpu offset */;	\
	CAPTABLE_LOAD(CHERI_REG_KSCRATCH, _C_LABEL(pcpu_space)) ;	\
	/* go to beginning of curcpu pcpu space */			\
	cincoffset	CHERI_REG_KSCRATCH, CHERI_REG_KSCRATCH, k1;	\
	REG_LI		k1, PCPU_SIZE;					\
	/* skip pcpu data */						\
	cincoffset	CHERI_REG_KSCRATCH, CHERI_REG_KSCRATCH, k1;	\
	REG_LI		k1, (PAGE_SIZE * 2) - PCPU_SIZE;		\
	/* boot kstack bounds */					\
	csetbounds	CHERI_REG_KSCRATCH, CHERI_REG_KSCRATCH, k1;	\
	/* go to the top of kstack */					\
	cincoffset	CHERI_REG_KSCRATCH, CHERI_REG_KSCRATCH, k1;	\
	/* XXX may want to save context before for the debugger */	\
	/* stop the ddb backtrace here */				\
	PTR_SUBU	k0, zero, KERN_EXC_FRAME_SIZE;			\
	cincoffset	CHERI_REG_KSCRATCH, CHERI_REG_KSCRATCH, k0;	\
	/* Save the overflowed STC in KR2C for later use; */		\
	csetkr2c	CHERI_REG_STC;					\
	cmove	CHERI_REG_STC, CHERI_REG_KSCRATCH;			\
	CHERI_NULL(CHERI_REG_KSCRATCH);					\
	csc	CHERI_REG_KSCRATCH, zero, CALLFRAME_RA(CHERI_REG_STC);	\
	csc	CHERI_REG_KSCRATCH, zero, CALLFRAME_SP(CHERI_REG_STC);	\
	/* SAVE_CPU will save KSCRATCH as STC so we put the overflowed STC here */\
	cgetkr2c	CHERI_REG_KSCRATCH;				\
	SAVE_CPU;							\
	PANIC("Kernel stack overflow")

/*
 * If the current exception is a coprocessor 2 exception,
 * and it is a length violation or tag violation on STC
 * then the kernel stack overflowed and we should panic.
 *
 * Note that we move to a valid stack before we call panic.
 * We use the boot stack for this purpose.
 * The boot stack has to be rederived, this code is shared with locore
 * and the TLB exception kernel stack overflow handling and should
 * be merged.
 */
#define CHERI_CHECK_STC_OVERFLOW(tmp)					\
	mfc0	tmp, MIPS_COP_0_CAUSE ;					\
	and	tmp, tmp, MIPS_CR_EXC_CODE ;				\
	srl	tmp, tmp, 2 ;						\
	xori	tmp, tmp, T_C2E ;					\
	bnez	tmp, 99f ;						\
	cgetcause tmp ;							\
	and	tmp, tmp, (CHERI_CAPCAUSE_EXCCODE_MASK | CHERI_CAPCAUSE_REGNUM_MASK) ;\
	xori	tmp, tmp, ((CHERI_EXCCODE_LENGTH << CHERI_CAPCAUSE_EXCCODE_SHIFT) | CHERI_CR_STC) ;\
	beqz	tmp, 98f ;						\
	cgetcause tmp ;							\
	and	tmp, tmp, (CHERI_CAPCAUSE_EXCCODE_MASK | CHERI_CAPCAUSE_REGNUM_MASK) ;\
	xori	tmp, tmp, ((CHERI_EXCCODE_TAG << CHERI_CAPCAUSE_EXCCODE_SHIFT) | CHERI_CR_STC) ;\
	bnez tmp, 99f ;							\
	nop ;								\
98:									\
	CHERI_KSTACK_OVERFLOW_PANIC;					\
99:


/*
 * Save CHERI registers on the stack to construct the kernel trap frame.
 * Suitable alignment should already have been arranged by the caller.
 */
#define	SAVE_CREG(creg, offs)					\
	csc	creg, zero, (CALLFRAME_SIZ + (SZREG * offs))(CHERI_REG_STC)

#define	SAVE_CAPCAUSE(reg, treg, offs)				\
	REG_LI	treg, (CALLFRAME_SIZ + (SZREG * offs));		\
	csd	reg, treg, 0(CHERI_REG_STC)

/*
 * Note that this is used only for kernel-generated exceptions.
 *
 * Assume the following register setup:
 * KSCRATCH holds the preempted STC
 * KR1C holds the saved KSCRATCH
 * KR2C is available
 * These are preserved outside the SAVE/RESTORE macros.
 *
 * We save these here to keep KR1C, KR2C, KSCRATCH and
 * KSCRATCH1 usable, and to keep the trapframe consistent.
 */
#define	SAVE_CHERI(treg0, treg1)		\
	SAVE_CREG(CHERI_REG_C1, C1);		\
	SAVE_CREG(CHERI_REG_C2, C2);		\
	SAVE_CREG(CHERI_REG_C3, C3);		\
	SAVE_CREG(CHERI_REG_C4, C4);		\
	SAVE_CREG(CHERI_REG_C5, C5);		\
	SAVE_CREG(CHERI_REG_C6, C6);		\
	SAVE_CREG(CHERI_REG_C7, C7);		\
	SAVE_CREG(CHERI_REG_C8, C8);		\
	SAVE_CREG(CHERI_REG_C9, C9);		\
	SAVE_CREG(CHERI_REG_C10, C10);		\
	/* Note KSCRATCH is saved here, so later can be used */\
	SAVE_CREG(CHERI_REG_KSCRATCH, STC);	\
	SAVE_CREG(CHERI_REG_C12, C12);		\
	SAVE_CREG(CHERI_REG_C13, C13);		\
	SAVE_CREG(CHERI_REG_C14, C14);		\
	SAVE_CREG(CHERI_REG_C15, C15);		\
	SAVE_CREG(CHERI_REG_C16, C16);		\
	SAVE_CREG(CHERI_REG_C17, C17);		\
	SAVE_CREG(CHERI_REG_C18, C18);		\
	SAVE_CREG(CHERI_REG_C19, C19);		\
	SAVE_CREG(CHERI_REG_C20, C20);		\
	SAVE_CREG(CHERI_REG_C21, C21);		\
	SAVE_CREG(CHERI_REG_C22, C22);		\
	SAVE_CREG(CHERI_REG_C23, C23);		\
	SAVE_CREG(CHERI_REG_C24, C24);		\
	SAVE_CREG(CHERI_REG_C25, C25);		\
	SAVE_CREG(CHERI_REG_C26, IDC);		\
	/* Note preempted c27 is in KR1C */	\
	cgetkr1c	CHERI_REG_KSCRATCH;	\
	SAVE_CREG(CHERI_REG_KSCRATCH, C27);	\
	SAVE_CREG(CHERI_REG_C28, C28);		\
	SAVE_CREG(CHERI_REG_C29, C29);		\
	SAVE_CREG(CHERI_REG_C30, C30);		\
	SAVE_CREG(CHERI_REG_C31, C31);		\
	/* Save special registers after KSCRATCH (C27) */\
	CGetEPCC CHERI_REG_KSCRATCH;		\
	SAVE_CREG(CHERI_REG_KSCRATCH, PCC);	\
	CGetDefault CHERI_REG_KSCRATCH;		\
	SAVE_CREG(CHERI_REG_KSCRATCH, DDC);	\
	cgetcause	treg0;			\
	SAVE_CAPCAUSE(treg0, treg1, CAPCAUSE)

/*
 * Save CPU and CP0 register state when taking an exception in kernel mode.
 * The caller will already have set up a stack pointer with suitable space and
 * alignment.
 *
 * This is straightforward except for saving the exception program
 * counter. The ddb backtrace code looks for the first instruction
 * matching the form "sw ra, (off)sp" to figure out the address of the
 * calling function. So we must make sure that we save the exception
 * PC by staging it through 'ra' as opposed to any other register.
 *
 * sp passes in the pointer to where we should place the call frame and trap
 * frame on the stack.
 * k1 passes in the preempted stack pointer (to be saved at SP).
 * a0 returns a pointer to the trap frame.
 * k0 is used as a temporary to hold the CP0 status register.
 *
 * sp and k1 may differ if we've had to re-align the stack for CHERI.
 *
 * The purecap kernel changes how stack is handled during exceptions.
 *
 * sp is now treated as a normal register
 * KSCRATCH holds the preempted stack pointer, to be saved as REG_STC
 * c3 returns a pointer to the trap frame
 * k0 is used as a temporary to hold CP0 status as before
 * k1 is used as a temporary
 */

#define	SAVE_REG(reg, offs)		\
	csd	reg, zero, (CALLFRAME_SIZ + (SZREG * offs))(CHERI_REG_STC)

#define	SAVE_CPU \
	SAVE_REG(AT, AST)		;\
	.set	at			;\
	SAVE_REG(v0, V0)		;\
	SAVE_REG(v1, V1)		;\
	SAVE_REG(a0, A0)		;\
	SAVE_REG(a1, A1)		;\
	SAVE_REG(a2, A2)		;\
	SAVE_REG(a3, A3)		;\
	SAVE_REG(t0, T0)		;\
	SAVE_REG(t1, T1)		;\
	SAVE_REG(t2, T2)		;\
	SAVE_REG(t3, T3)		;\
	SAVE_REG(ta0, TA0)		;\
	SAVE_REG(ta1, TA1)		;\
	SAVE_REG(ta2, TA2)		;\
	SAVE_REG(ta3, TA3)		;\
	SAVE_REG(t8, T8)		;\
	SAVE_REG(t9, T9)		;\
	SAVE_REG(gp, GP)		;\
	SAVE_REG(s0, S0)		;\
	SAVE_REG(s1, S1)		;\
	SAVE_REG(s2, S2)		;\
	SAVE_REG(s3, S3)		;\
	SAVE_REG(s4, S4)		;\
	SAVE_REG(s5, S5)		;\
	SAVE_REG(s6, S6)		;\
	SAVE_REG(s7, S7)		;\
	SAVE_REG(s8, S8)		;\
	mflo	v0			;\
	mfhi	v1			;\
	mfc0	a0, MIPS_COP_0_STATUS	;\
	mfc0	a1, MIPS_COP_0_CAUSE	;\
	MFC0	a2, MIPS_COP_0_BAD_VADDR;\
	MFC0	a3, MIPS_COP_0_EXC_PC	;\
	SAVE_REG(v0, MULLO)		;\
	SAVE_REG(v1, MULHI)		;\
	SAVE_REG(a0, SR)		;\
	SAVE_REG(a1, CAUSE)		;\
	SAVE_REG(a2, BADVADDR)		;\
	SAVE_CHERI(t0, t1)		;\
	move	t0, ra			;\
	move	ra, a3			;\
	SAVE_REG(ra, PC)		;\
	move	ra, t0			;\
	SAVE_REG(ra, RA)		;\
	SAVE_REG(sp, SP)	/* Notice: store sp as a normal register. */;\
	CLEAR_STATUS			;\
	cincoffset	$c3, CHERI_REG_STC, CALLFRAME_SIZ /* Notice: trap frame ptr in c3 */;\
	ITLBNOPFIX


#define RESTORE_CREG(creg, offs)	\
	clc	creg, zero, (CALLFRAME_SIZ + (SZREG * offs))(CHERI_REG_STC)

/*
 * Restore CHERI registers from the on-stack kernel trap frame.
 * Note that this is only used for kernel-generated exceptions.
 *
 * EPCC is expected to be given in the epcc parameter register with the offset
 * already set.
 * STC must be restored later in the cheri kernel, otherwise we can not
 * restore the the rest of the registers. Here we restore KSCRATCH in KR1C and
 * STC in KSCRATCH for later use. XXX-AM: Could restore capregs last?
 *
 * Notice: the capability cause register is saved, but not restored.
 */
#define	RESTORE_CHERI(epcc_reg)					\
	/* Restore special registers before KSCRATCH (C27) */	\
	csetepcc epcc_reg;			\
	RESTORE_CREG(CHERI_REG_KSCRATCH, DDC);	\
	CSetDefault CHERI_REG_KSCRATCH;		\
	RESTORE_CREG(CHERI_REG_C1, C1);		\
	RESTORE_CREG(CHERI_REG_C2, C2);		\
	RESTORE_CREG(CHERI_REG_C3, C3);		\
	RESTORE_CREG(CHERI_REG_C4, C4);		\
	RESTORE_CREG(CHERI_REG_C5, C5);		\
	RESTORE_CREG(CHERI_REG_C6, C6);		\
	RESTORE_CREG(CHERI_REG_C7, C7);		\
	RESTORE_CREG(CHERI_REG_C8, C8);		\
	RESTORE_CREG(CHERI_REG_C9, C9);		\
	RESTORE_CREG(CHERI_REG_C10, C10);	\
	/* Restore STC later, after EPCC, when KSCRATCH is free to use */\
	RESTORE_CREG(CHERI_REG_C12, C12);	\
	RESTORE_CREG(CHERI_REG_C13, C13);	\
	RESTORE_CREG(CHERI_REG_C14, C14);	\
	RESTORE_CREG(CHERI_REG_C15, C15);	\
	RESTORE_CREG(CHERI_REG_C16, C16);	\
	RESTORE_CREG(CHERI_REG_C17, C17);	\
	RESTORE_CREG(CHERI_REG_C18, C18);	\
	RESTORE_CREG(CHERI_REG_C19, C19);	\
	RESTORE_CREG(CHERI_REG_C20, C20);	\
	RESTORE_CREG(CHERI_REG_C21, C21);	\
	RESTORE_CREG(CHERI_REG_C22, C22);	\
	RESTORE_CREG(CHERI_REG_C23, C23);	\
	RESTORE_CREG(CHERI_REG_C24, C24);	\
	RESTORE_CREG(CHERI_REG_C25, C25);	\
	RESTORE_CREG(CHERI_REG_C26, IDC);	\
	/* Restore c27 in kr1c for later use */	\
	RESTORE_CREG(CHERI_REG_KSCRATCH, C27);	\
	csetkr1c	CHERI_REG_KSCRATCH;	\
	RESTORE_CREG(CHERI_REG_C28, C28);	\
	RESTORE_CREG(CHERI_REG_C29, C29);	\
	RESTORE_CREG(CHERI_REG_C30, C30);	\
	RESTORE_CREG(CHERI_REG_C31, C31) ;	\
	RESTORE_CREG(CHERI_REG_KSCRATCH, STC)

/*
 * Restore preempted kernel state following a kernel exception.  The caller
 * will restore the original sp from k1 after RESTORE_CPU has ended.
 */
#define	RESTORE_REG(reg, offs) \
	cld	reg, zero, (CALLFRAME_SIZ + (SZREG * offs)) (CHERI_REG_STC)

#define	RESTORE_CPU(epcc_reg) \
	CLEAR_STATUS			;\
	RESTORE_CHERI(epcc_reg)		;\
	RESTORE_REG(k0, SR)		;\
	RESTORE_REG(t0, MULLO)	;\
	RESTORE_REG(t1, MULHI)	;\
	mtlo	t0			;\
	mthi	t1			;\
	.set noat			;\
	RESTORE_REG(AT, AST)	;\
	RESTORE_REG(v0, V0)		;\
	RESTORE_REG(v1, V1)		;\
	RESTORE_REG(a0, A0)		;\
	RESTORE_REG(a1, A1)		;\
	RESTORE_REG(a2, A2)		;\
	RESTORE_REG(a3, A3)		;\
	RESTORE_REG(t0, T0)		;\
	RESTORE_REG(t1, T1)		;\
	RESTORE_REG(t2, T2)		;\
	RESTORE_REG(t3, T3)		;\
	RESTORE_REG(ta0, TA0)	;\
	RESTORE_REG(ta1, TA1)	;\
	RESTORE_REG(ta2, TA2)	;\
	RESTORE_REG(ta3, TA3)	;\
	RESTORE_REG(t8, T8)		;\
	RESTORE_REG(t9, T9)		;\
	RESTORE_REG(s0, S0)		;\
	RESTORE_REG(s1, S1)		;\
	RESTORE_REG(s2, S2)		;\
	RESTORE_REG(s3, S3)		;\
	RESTORE_REG(s4, S4)		;\
	RESTORE_REG(s5, S5)		;\
	RESTORE_REG(s6, S6)		;\
	RESTORE_REG(s7, S7)		;\
	RESTORE_REG(s8, S8)		;\
	RESTORE_REG(gp, GP)		;\
	RESTORE_REG(ra, RA)		;\
	RESTORE_REG(sp, SP)		/* Notice: restore sp as a normal register. */ ;\
	mtc0	k0, MIPS_COP_0_STATUS

NESTED_NOPROFILE(MipsKernGenException, KERN_EXC_FRAME_SIZE, ra)
	.set	noat

	/* Save exception stc in kr1c to put on the stack later */
	cmove	CHERI_REG_KSCRATCH, CHERI_REG_STC
	PTR_SUBU	k0, zero, KERN_EXC_FRAME_SIZE
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, k0
	/* Adjust stack alignment if needed */
	CHERI_ADJUST_STC(k0)
	/*
	 * Check for kernel stack overflow before using the stack.
	 * Note that KSCRATCH is the old stc but we do not care since
	 * we will panic if this fails.
	 */
	CHERI_CHECK_STC_OVERFLOW(k0)

	/* XXX-AM: Can we use .mask/.frame in cheriabi? */
	.mask	0x80000000, (CALLFRAME_RA - KERN_EXC_FRAME_SIZE)
	/*
	 * For CHERI_PURECAP_KERNEL, CHERI_REG_STC holds the location of the
	 * trap frame, KSCRATCH holds the value of STC to save in the trap frame.
	 * Will leave the trap frame address in c3.
	 */
	SAVE_CPU

#ifdef STACK
	/*
	 * Inform stack backtrace to continue from the correct place by
	 * simulating function prologue.
	 */
	RESTORE_CREG($c24, STC)
	csc $c24, zero, CALLFRAME_CSP(CHERI_REG_STC)
	RESTORE_CREG($c17, PCC)
	csc $c17, zero, CALLFRAME_CRA(CHERI_REG_STC)
	cmove $c24, CHERI_REG_STC
#endif

	/*
	 * Call the exception handler (c3 set by SAVE_CPU).
	 */
	CAPCALL_LOAD($c12, trap)
	cjalr	$c12, $c17
	nop

	/*
	 * Update interrupt and CPU mask in saved status register
	 * Some of interrupts could be disabled by
	 * intr filters if interrupts are enabled later
	 * in trap handler
	 */
	mfc0	a0, MIPS_COP_0_STATUS
	and	a0, a0, (MIPS_SR_INT_MASK|MIPS_SR_COP_USABILITY)
	RESTORE_REG(a1, SR)
	and	a1, a1, ~(MIPS_SR_INT_MASK|MIPS_SR_COP_USABILITY)
	or	a1, a1, a0
	SAVE_REG(a1, SR)

	/*
	 * c3 holds the trap() return address, RESTORE_CPU will look in c3
	 * for the PCC to be installed in EPCC.
	 */
	RESTORE_CPU($c3)
	/* Restore preempted stc from kr1c now we are done with the stack. */
	cmove	CHERI_REG_STC, CHERI_REG_KSCRATCH
	sync

	/* Restore KSCRATCH for exception return, left in kr1c by RESTORE_CPU */
	cgetkr1c	CHERI_REG_KSCRATCH
	CHERI_EXCEPTION_RETURN(k0)
	eret
	.set	at
END(MipsKernGenException)


/*----------------------------------------------------------------------------
 *
 * MipsUserGenException --
 *
 *	Handle an exception from user mode.
 *
 * Preconditions:
 *	KSCRATCH can be clobbered
 *	KR1C holds the preempted KSCRATCH
 *	KR2C holds the preempted DDC
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------------
 */
NESTED_NOPROFILE(MipsUserGenException, CALLFRAME_SIZ, ra)
	.set	noat
	.mask	0x80000000, (CALLFRAME_RA - CALLFRAME_SIZ)

	GET_CPU_PCPU(CHERI_REG_KSCRATCH)	# get pcpu pointer
	clc	CHERI_REG_KSCRATCH, zero, PC_CURPCB(CHERI_REG_KSCRATCH)
	SAVE_REGS_TO_PCB(CHERI_REG_KSCRATCH)
	SAVE_CREGS_TO_PCB(CHERI_REG_KSCRATCH, t0, t1)
	/* Switch to kernel stack, use c3 as scratch reg */
	GET_CPU_PCPU($c3)
	/* get top of the stack from pcpu */
	clc CHERI_REG_STC, zero, PC_KSTACK_CAP($c3)
	/* start with kstack at bottom */
	REG_LI t0, (CHERI_KSTACK_OFFSET - CALLFRAME_SIZ)
	cincoffset CHERI_REG_STC, CHERI_REG_STC, t0

#ifdef STACK
	/*
	 * Inform kernel stack backtrace to stop by simulating empty prologue.
	 */
	cmove $c24, $cnull
	csc $c24, zero, CALLFRAME_CSP(CHERI_REG_STC)
	cmove $c17, $cnull
	csc $c17, zero, CALLFRAME_CRA(CHERI_REG_STC)
	cmove $c24, CHERI_REG_STC
#endif

	/* Turn off fpu and enter kernel mode */
	and	t0, a0, ~(MIPS_SR_COP_1_BIT | MIPS_SR_EXL | MIPS_SR_KSU_MASK | MIPS_SR_INT_IE)
	mtc0	t0, MIPS_COP_0_STATUS
	ITLBNOPFIX

	/* Assume CURPCB left in KSCRATCH */
	cincoffset	$c3, CHERI_REG_KSCRATCH, U_PCB_REGS
	REG_LI	t0, TRAPFRAME_SIZE
	csetbounds	$c3, $c3, t0
	CAPCALL_LOAD($c12, trap)
	/* Note the return EPCC in c3 is not used for userspace return. */
	cjalr	$c12, $c17
	nop

	/*
	 * Restore user registers and return.
	 * First disable interrupts and set exeption level.
	 */
	DO_AST

	CLEAR_STATUS

	/*
	 * The use of kr1c for storing the PCB pointer must be done only
	 * after interrupts are disabled.  Otherwise it will get overwritten
	 * by the interrupt code.
	 */
	GET_CPU_PCPU(CHERI_REG_KSCRATCH)
	clc	CHERI_REG_KSCRATCH, zero, PC_CURPCB(CHERI_REG_KSCRATCH)

	/*
	 * Update interrupt mask in saved status register
	 * Some of interrupts could be enabled by ithread
	 * scheduled by ast()
	 */
	mfc0	a0, MIPS_COP_0_STATUS
	and	a0, a0, MIPS_SR_INT_MASK
	RESTORE_U_PCB_REG(a1, SR, CHERI_REG_KSCRATCH)
	and	a1, a1, ~MIPS_SR_INT_MASK
	or	a1, a1, a0
	SAVE_U_PCB_REG(a1, SR, CHERI_REG_KSCRATCH)
	/* This also sets k0 from PCB */
	RESTORE_REGS_FROM_PCB(CHERI_REG_KSCRATCH, CHERI_REG_KSCRATCH2)
	/*
	 * Note: This does not restore EPCC, since that is restored by
	 * RESTORE_U_PCB_PC() (inside RESTORE_REGS_FROM_PCB) above.
	 */
	RESTORE_CREGS_FROM_PCB(CHERI_REG_KSCRATCH, k1)

	mtc0	k0, MIPS_COP_0_STATUS	# still exception level
	ITLBNOPFIX
	sync

	/*
	 * Restore KSCRATCH for exception return.
	 * Note: RESTORE_CREGS restored it in kr1c
	 */
	cgetkr1c	CHERI_REG_KSCRATCH
	CHERI_EXCEPTION_RETURN(k0)
	eret
	.set	at
END(MipsUserGenException)

	.set	push
	.set	noat
NESTED(mips_wait, CALLFRAME_SIZ, ra)
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, -CALLFRAME_SIZ
	.mask   0x80000000, (CALLFRAME_RA - CALLFRAME_SIZ) # XXX-AM: is this working in purecap?
	csc	$c17, zero, CALLFRAME_RA(CHERI_REG_STC)

	mfc0	t0, MIPS_COP_0_STATUS
	xori	t1, t0, MIPS_SR_INT_IE
	mtc0	t1, MIPS_COP_0_STATUS
	COP0_SYNC
	CAPCALL_LOAD($c12, sched_runnable)
	cjalr	$c12, $c17
	nop
	clc	$c17, zero, CALLFRAME_RA(CHERI_REG_STC)

	mfc0	t0, MIPS_COP_0_STATUS
	ori	t1, t0, MIPS_SR_INT_IE
	.align 4
GLOBAL(MipsWaitStart)			# this is 16 byte aligned
	mtc0	t1, MIPS_COP_0_STATUS
	bnez	v0, MipsWaitEnd
	nop
#if defined(CPU_XBURST) && defined(SMP)
	nop
#else
	wait
#endif
GLOBAL(MipsWaitEnd)			# MipsWaitStart + 16
	cjr	$c17
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, CALLFRAME_SIZ
END(mips_wait)
	.set	pop

/*----------------------------------------------------------------------------
 *
 * MipsKernIntr --
 *
 *	Handle an interrupt from kernel mode.
 *	Interrupts use the standard kernel stack.
 *	switch_exit sets up a kernel stack after exit so interrupts won't fail.
 *
 * Preconditions:
 *	KSCRATCH can be clobbered
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------------
 */

NESTED_NOPROFILE(MipsKernIntr, KERN_EXC_FRAME_SIZE, ra)
	.set	noat

/*
 * Check for getting interrupts just before wait
 *
 * XXXCHERI: Once we use variable CHERI PCC in the kernel, this check will
 * also need to take that into account.  In the mean time, the fact that we're
 * in the kernel ring is sufficient to imply that PCC matches the kernel
 * address space.
 */
	MFC0	k0, MIPS_COP_0_EXC_PC
	ori	k0, 0xf
	xori	k0, 0xf			# 16 byte align
	CAPTABLE_LOAD(CHERI_REG_KSCRATCH, MipsWaitStart)
	cgetaddr k1, CHERI_REG_KSCRATCH
	bne	k0, k1, 1f
	nop
	PTR_ADDU k1, 16			# skip over wait
	MTC0	k1, MIPS_COP_0_EXC_PC
1:

	/* Save exception sp in kscratch to put on the stack later. */
	cmove	CHERI_REG_KSCRATCH, CHERI_REG_STC
	PTR_SUBU	k0, zero, KERN_EXC_FRAME_SIZE
	cincoffset	CHERI_REG_STC, CHERI_REG_STC, k0
	CHERI_ADJUST_STC(k0)
	.mask	0x80000000, (CALLFRAME_RA - KERN_EXC_FRAME_SIZE)

	/*
	 * Save CPU state, building 'frame'.  sp holds the location to save the trap
	 * frame, whereas k1 holds the value of sp to save in the trap frame.
	 */
	SAVE_CPU

#ifdef STACK
	/*
	 * Inform kernel stack backtrace to stop by simulating empty prologue.
	 */
	cmove $c24, $cnull
	csc $c24, zero, CALLFRAME_CSP(CHERI_REG_STC)
	cmove $c17, $cnull
	csc $c17, zero, CALLFRAME_CRA(CHERI_REG_STC)
	cmove $c24, CHERI_REG_STC
#endif

	/*
	 * Call the interrupt handler. SAVE_CPU has left a0 pointing at the saved
	 * frame.
	 */
#ifdef INTRNG
	CAPCALL_LOAD($c12, intr_irq_handler)
#else
	CAPCALL_LOAD($c12, cpu_intr)
#endif
	/* XXX-AM: we should rely on EPCC instead of COP0_EXC_PC in a3 */
	cjalr	$c12, $c17
	nop

	/*
	 * Update interrupt and CPU mask in saved status register
	 * Some of interrupts could be disabled by
	 * intr filters if interrupts are enabled later
	 * in trap handler
	 */
	mfc0	a0, MIPS_COP_0_STATUS
	and	a0, a0, (MIPS_SR_INT_MASK|MIPS_SR_COP_USABILITY)
	RESTORE_REG(a1, SR)
	and	a1, a1, ~(MIPS_SR_INT_MASK|MIPS_SR_COP_USABILITY)
	or	a1, a1, a0
	SAVE_REG(a1, SR)

	/* Set pc in c3 for RESTORE_CPU */
	RESTORE_CREG($c3, PCC)
	RESTORE_CPU($c3)

	/* Restore preempted stc from kscratch now we are done with the stack. */
	cmove	CHERI_REG_STC, CHERI_REG_KSCRATCH
	sync

	/* Restore KSCRATCH for exception return */
	cgetkr1c	CHERI_REG_KSCRATCH
	CHERI_EXCEPTION_RETURN(k0)
	eret
	.set	at
END(MipsKernIntr)

/*----------------------------------------------------------------------------
 *
 * MipsUserIntr --
 *
 *	Handle an interrupt from user mode.
 *	Note: we save minimal state in the u.u_pcb struct and use the standard
 *	kernel stack since there has to be a u page if we came from user mode.
 *	If there is a pending software interrupt, then save the remaining state
 *	and call softintr(). This is all because if we call switch() inside
 *	interrupt(), not all the user registers have been saved in u.u_pcb.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------------
 */

/*
 * Save registers to U_PCB during an user interrupt.
 * XXX-AM: I am not sure why we can not use SAVE_REGS_TO_PCB()
 * since it does exactly the same things except mfc0 instructions
 * change position.
 *
 * Leaves:
 * a3: exception PC
 */
#define SAVE_UINTR_PCB_REGS(pcb)		\
	SAVE_U_PCB_REG(AT, AST, pcb);		\
	.set	at;				\
	SAVE_U_PCB_REG(v0, V0, pcb);		\
	SAVE_U_PCB_REG(v1, V1, pcb);		\
	SAVE_U_PCB_REG(a0, A0, pcb);		\
	SAVE_U_PCB_REG(a1, A1, pcb);		\
	SAVE_U_PCB_REG(a2, A2, pcb);		\
	SAVE_U_PCB_REG(a3, A3, pcb);		\
	SAVE_U_PCB_REG(t0, T0, pcb);		\
	SAVE_U_PCB_REG(t1, T1, pcb);		\
	SAVE_U_PCB_REG(t2, T2, pcb);		\
	SAVE_U_PCB_REG(t3, T3, pcb);		\
	SAVE_U_PCB_REG(ta0, TA0, pcb);		\
	SAVE_U_PCB_REG(ta1, TA1, pcb);		\
	SAVE_U_PCB_REG(ta2, TA2, pcb);		\
	SAVE_U_PCB_REG(ta3, TA3, pcb);		\
	SAVE_U_PCB_REG(t8, T8, pcb);		\
	SAVE_U_PCB_REG(t9, T9, pcb);		\
	SAVE_U_PCB_REG(gp, GP, pcb);		\
	SAVE_U_PCB_REG(sp, SP, pcb);		\
	SAVE_U_PCB_REG(ra, RA, pcb);		\
	SAVE_U_PCB_REG(s0, S0, pcb);		\
	SAVE_U_PCB_REG(s1, S1, pcb);		\
	SAVE_U_PCB_REG(s2, S2, pcb);		\
	SAVE_U_PCB_REG(s3, S3, pcb);		\
	SAVE_U_PCB_REG(s4, S4, pcb);		\
	SAVE_U_PCB_REG(s5, S5, pcb);		\
	SAVE_U_PCB_REG(s6, S6, pcb);		\
	SAVE_U_PCB_REG(s7, S7, pcb);		\
	SAVE_U_PCB_REG(s8, S8, pcb);		\
	mflo	v0 /* get lo/hi late to avoid stall*/;	\
	mfhi	v1;					\
	mfc0	a0, MIPS_COP_0_STATUS;			\
	mfc0	a1, MIPS_COP_0_CAUSE;			\
	MFC0	a3, MIPS_COP_0_EXC_PC;			\
	SAVE_U_PCB_REG(v0, MULLO, pcb);			\
	SAVE_U_PCB_REG(v1, MULHI, pcb);			\
	SAVE_U_PCB_REG(a0, SR, pcb);			\
	SAVE_U_PCB_REG(a1, CAUSE, pcb);			\
	SAVE_U_PCB_REG(a3, PC, pcb)

/* Note: this trashes KSCRATCH2 */
#define RESTORE_UINTR_PCB_REGS(pcb)			\
	RESTORE_U_PCB_REG(s0, S0, pcb);			\
	RESTORE_U_PCB_REG(s1, S1, pcb);			\
	RESTORE_U_PCB_REG(s2, S2, pcb);			\
	RESTORE_U_PCB_REG(s3, S3, pcb);			\
	RESTORE_U_PCB_REG(s4, S4, pcb);			\
	RESTORE_U_PCB_REG(s5, S5, pcb);			\
	RESTORE_U_PCB_REG(s6, S6, pcb);			\
	RESTORE_U_PCB_REG(s7, S7, pcb);			\
	RESTORE_U_PCB_REG(s8, S8, pcb);			\
	RESTORE_U_PCB_REG(t0, MULLO, pcb);		\
	RESTORE_U_PCB_REG(t1, MULHI, pcb);		\
	RESTORE_U_PCB_REG(t2, PC, pcb);			\
	mtlo	t0;					\
	mthi	t1;					\
	/* set return address */			\
	RESTORE_U_PCB_PC(t2, CHERI_REG_KSCRATCH2, pcb, t3);	\
	RESTORE_U_PCB_REG(v0, V0, pcb);			\
	RESTORE_U_PCB_REG(v1, V1, pcb);			\
	RESTORE_U_PCB_REG(a0, A0, pcb);			\
	RESTORE_U_PCB_REG(a1, A1, pcb);			\
	RESTORE_U_PCB_REG(a2, A2, pcb);			\
	RESTORE_U_PCB_REG(a3, A3, pcb);			\
	RESTORE_U_PCB_REG(t0, T0, pcb);			\
	RESTORE_U_PCB_REG(t1, T1, pcb);			\
	RESTORE_U_PCB_REG(t2, T2, pcb);			\
	RESTORE_U_PCB_REG(t3, T3, pcb);			\
	RESTORE_U_PCB_REG(ta0, TA0, pcb);		\
	RESTORE_U_PCB_REG(ta1, TA1, pcb);		\
	RESTORE_U_PCB_REG(ta2, TA2, pcb);		\
	RESTORE_U_PCB_REG(ta3, TA3, pcb);		\
	RESTORE_U_PCB_REG(t8, T8, pcb);			\
	RESTORE_U_PCB_REG(t9, T9, pcb);			\
	RESTORE_U_PCB_REG(gp, GP, pcb);			\
	RESTORE_U_PCB_REG(k0, SR, pcb);			\
	RESTORE_U_PCB_REG(sp, SP, pcb);			\
	RESTORE_U_PCB_REG(ra, RA, pcb);			\
	.set	noat;					\
	RESTORE_U_PCB_REG(AT, AST, pcb)


NESTED_NOPROFILE(MipsUserIntr, CALLFRAME_SIZ, ra)
	.set	noat
	.mask	0x80000000, (CALLFRAME_RA - CALLFRAME_SIZ)
	/*
	 * Save the relevant user registers into the u.u_pcb struct.
	 * We don't need to save s0 - s8 because the compiler does it for us.
	 */
	GET_CPU_PCPU(CHERI_REG_KSCRATCH)
	clc CHERI_REG_KSCRATCH, zero, PC_CURPCB(CHERI_REG_KSCRATCH)
	SAVE_UINTR_PCB_REGS(CHERI_REG_KSCRATCH)
	SAVE_CREGS_TO_PCB(CHERI_REG_KSCRATCH, t0, t1)
	/* Switch to kernel stack from pcpu, use c3 as scratch reg */
	GET_CPU_PCPU($c3)
	clc CHERI_REG_STC, zero, PC_KSTACK_CAP($c3)
	/* start with kstack at bottom */
	REG_LI t0, (CHERI_KSTACK_OFFSET - CALLFRAME_SIZ)
	cincoffset CHERI_REG_STC, CHERI_REG_STC, t0

	// Turn off fpu, disable interrupts, set kernel mode, clear exception level.
	and	t0, a0, ~(MIPS_SR_COP_1_BIT | MIPS_SR_EXL | MIPS_SR_INT_IE | MIPS_SR_KSU_MASK)
	mtc0	t0, MIPS_COP_0_STATUS
	ITLBNOPFIX

#ifdef STACK
	/*
	 * Stop kernel stack backtrace here by simulating function prologue.
	 */
	cmove $c24, $cnull
	csc $c24, zero, CALLFRAME_CSP(CHERI_REG_STC)
	cmove $c17, $cnull
	csc $c17, zero, CALLFRAME_CRA(CHERI_REG_STC)
	cmove $c24, CHERI_REG_STC
#endif

	/*
	 * Call the interrupt handler.
	 * Assume CURPCB left in KSCRATCH
	 */
	cincoffset $c3, CHERI_REG_KSCRATCH, U_PCB_REGS
#ifdef INTRNG
	CAPCALL_LOAD($c12, intr_irq_handler)
#else
	CAPCALL_LOAD($c12, cpu_intr)
#endif
	cjalr	$c12, $c17
	nop

	/*
	 * Enable interrupts before doing ast().
	 *
	 * On SMP kernels the AST processing might trigger IPI to other processors.
	 * If that processor is also doing AST processing with interrupts disabled
	 * then we may deadlock.
	 */
	mfc0	a0, MIPS_COP_0_STATUS
	or	a0, a0, MIPS_SR_INT_IE
	mtc0	a0, MIPS_COP_0_STATUS
	ITLBNOPFIX

	/*
	 * DO_AST enabled interrupts
	 */
	DO_AST

	/*
	 * Restore user registers and return.
	 */
	CLEAR_STATUS

	GET_CPU_PCPU(CHERI_REG_KSCRATCH)
	clc	CHERI_REG_KSCRATCH, zero, PC_CURPCB(CHERI_REG_KSCRATCH)

	/*
	 * Update interrupt mask in saved status register
	 * Some of interrupts could be disabled by
	 * intr filters
	 */
	mfc0	a0, MIPS_COP_0_STATUS
	and	a0, a0, MIPS_SR_INT_MASK
	RESTORE_U_PCB_REG(a1, SR, CHERI_REG_KSCRATCH)
	and	a1, a1, ~MIPS_SR_INT_MASK
	or	a1, a1, a0

	SAVE_U_PCB_REG(a1, SR, CHERI_REG_KSCRATCH)

	/* This also restores SR in k0 */
	RESTORE_UINTR_PCB_REGS(CHERI_REG_KSCRATCH)
	RESTORE_CREGS_FROM_PCB(CHERI_REG_KSCRATCH, k1)

	mtc0	k0, MIPS_COP_0_STATUS	# SR with EXL set.
	ITLBNOPFIX
	sync

	/*
	 * Restore KSCRATCH for exception return.
	 * Note: RESTORE_CREGS restored it in kr1c
	 */
	cgetkr1c	CHERI_REG_KSCRATCH
	CHERI_EXCEPTION_RETURN(k0)
	eret
	.set	at
END(MipsUserIntr)

#if defined(MIPS_EXC_CNTRS)
/* A stub for counting TLB modification exceptions. */
LEAF_NOPROFILE(MipsTLBModException)
	.set push
	.set noat

	# Increment exception counter, if enabled.
	INC_EXCEPTION_CNTR(TLB_MOD_CNT)
	j	MipsKernGenException
	nop
	.set pop
END(MipsTLBModException)
/* Force size 0 so that we do not set the capability bounds in relocations */
.size _C_LABEL(MipsTLBModException), 0
#endif /* defined(MIPS_EXC_CNTRS) */


LEAF_NOPROFILE(MipsTLBInvalidException)
	.set push
	.set noat
	.set noreorder

	# Increment exception counter, if enabled.
	INC_EXCEPTION_CNTR(TLB_INVALID_CNT)

	/* XXX-AM: Leave this check for now, we should use EPCC later */
	MFC0		k0, MIPS_COP_0_BAD_VADDR
	PTR_LI		k1, VM_MAXUSER_ADDRESS
	sltu		k1, k0, k1
	bnez		k1, 1f
	nop

	/* Kernel address. */
	CAPTABLE_LOAD(CHERI_REG_KSCRATCH, _C_LABEL(kernel_segmap))
	b		2f
	clc		CHERI_REG_KSCRATCH, zero, 0(CHERI_REG_KSCRATCH)		# load from kernel_segmap

1:	/* User address.  */
	GET_CPU_PCPU(CHERI_REG_KSCRATCH)
	clc	CHERI_REG_KSCRATCH, zero, PC_SEGBASE(CHERI_REG_KSCRATCH)

2:	/* Validate page directory pointer. If no seg tab go to exception processing */
	cbez		CHERI_REG_KSCRATCH, 3f
	nop

	PTR_SRL		k0, SEGSHIFT - PTRSHIFT		# k0=seg offset (almost)
	andi		k0, k0, PDEPTRMASK		# k0=seg offset
	cincoffset	CHERI_REG_KSCRATCH, CHERI_REG_KSCRATCH, k0 # kr1c=seg entry address
	clc		CHERI_REG_KSCRATCH, zero, 0(CHERI_REG_KSCRATCH) # kr1c=seg entry

	/* Validate page table pointer.  */
	cbez		CHERI_REG_KSCRATCH, 3f
	nop

	/* Assumes __mips_n64 and ! defined(MIPS64_NEW_PMAP) */

	MFC0		k0, MIPS_COP_0_BAD_VADDR
	PTR_SRL		k0, PDRSHIFT - PTRSHIFT		# k0=pde offset (almost)
	andi		k0, k0, PDEPTRMASK		# k0=pde offset
	cincoffset	CHERI_REG_KSCRATCH, CHERI_REG_KSCRATCH, k0 # kr1c=pde entry address
	clc		CHERI_REG_KSCRATCH, zero, 0(CHERI_REG_KSCRATCH) # kr1c=pde entry

	/* Validate pde table pointer.  */
	cbez		CHERI_REG_KSCRATCH, 3f
	nop

	MFC0		k0, MIPS_COP_0_BAD_VADDR	# k0=bad address (again)
	PTR_SRL		k0, PAGE_SHIFT - PTESHIFT	# k0=VPN
	andi		k0, k0, PTEMASK			# k0=page tab offset
	cincoffset	CHERI_REG_KSCRATCH, CHERI_REG_KSCRATCH, k0 # kr1c=pte address
	cld		k0, zero, 0(CHERI_REG_KSCRATCH)	# k0=this PTE

	/* Validate page table entry.  */
	andi		k1, k0, PTE_V
	beqz		k1, 3f
	nop

	/* Check whether this is an even or odd entry.  */
	cgetoffset	k1, CHERI_REG_KSCRATCH
	andi		k1, k1, PTESIZE
	bnez		k1, odd_page
	nop

	CLEAR_PTE_SWBITS(k0)
	PTE_MTC0	k0, MIPS_COP_0_TLB_LO0
	COP0_SYNC

	cld		k0, zero, PTESIZE(CHERI_REG_KSCRATCH)

	CLEAR_PTE_SWBITS(k0)
	PTE_MTC0	k0, MIPS_COP_0_TLB_LO1
	COP0_SYNC

	b		tlb_insert_entry
	nop

odd_page:
	cld		k0, zero, -PTESIZE(CHERI_REG_KSCRATCH)

	CLEAR_PTE_SWBITS(k0)
	PTE_MTC0	k0, MIPS_COP_0_TLB_LO0
	COP0_SYNC

	cld		k0, zero, 0(CHERI_REG_KSCRATCH)

	CLEAR_PTE_SWBITS(k0)
	PTE_MTC0	k0, MIPS_COP_0_TLB_LO1
	COP0_SYNC

tlb_insert_entry:
	tlbp
	HAZARD_DELAY
	mfc0		k0, MIPS_COP_0_TLB_INDEX
	bltz		k0, tlb_insert_random
	nop
	tlbwi
	PTE_MTC0	zero, MIPS_COP_0_TLB_PG_MASK
	COP0_SYNC
	/* Restore KSCRATCH for exception return */
	cgetkr1c	CHERI_REG_KSCRATCH
	CHERI_EXCEPTION_RETURN(k0)
	eret
	ssnop

tlb_insert_random:
	tlbwr
	PTE_MTC0	zero, MIPS_COP_0_TLB_PG_MASK
	COP0_SYNC
	/* Restore KSCRATCH for exception return */
	cgetkr1c	CHERI_REG_KSCRATCH
	CHERI_EXCEPTION_RETURN(k0)
	eret
	ssnop

3:
	/*
	 * If we come from user mode, branch to the comprehensive
	 * exception processing.
	 */
	mfc0	k1, MIPS_COP_0_STATUS
	andi	k1, k1, MIPS_SR_KSU_USER
	bnez	k1, _C_LABEL(MipsUserGenException)
	nop

	/*
	 * Check for kernel stack overflow.
	 * This can happen if we are using guard pages for our kernel stack.
	 */
	GET_CPU_PCPU(CHERI_REG_KSCRATCH)
	clc	CHERI_REG_KSCRATCH, zero, PC_CURTHREAD(CHERI_REG_KSCRATCH)
	clc	CHERI_REG_KSCRATCH, zero, TD_KSTACK(CHERI_REG_KSCRATCH)
	cltu	k0, CHERI_REG_KSCRATCH, CHERI_REG_STC
	bnez	k0, _C_LABEL(MipsKernGenException)
	nop

	/*
	 * Kernel stack overflow.
	 *
	 * Move to a valid stack before we call panic. We use the boot stack
	 * for this purpose.
	 */
	CHERI_KSTACK_OVERFLOW_PANIC

	/*
	 * This nop is necessary so that the 'ra' remains within the bounds
	 * of this handler. Otherwise the ddb backtrace code will think that
	 * the panic() was called from MipsTLBMissException.
	 */
	.globl	MipsKStackOverflow
MipsKStackOverflow:
	nop

	.set pop
END(MipsTLBInvalidException)
/* Force size 0 so that we do not set the capability bounds in relocations */
.size _C_LABEL(MipsTLBInvalidException), 0

/*----------------------------------------------------------------------------
 *
 * MipsTLBMissException --
 *
 *	Handle a TLB miss exception from kernel mode in kernel space.
 *	The BaddVAddr, Context, and EntryHi registers contain the failed
 *	virtual address.
 *
 * Precoditions:
 *	KSCRATCH can be clobbered
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------------
 */
LEAF_NOPROFILE(MipsTLBMissException)
	.set	noat
	/* assumes __mips64 and ! MIPS64_NEW_PMAP */
	MFC0		k0, MIPS_COP_0_BAD_VADDR	# k0=bad address
	/**
	 * XXX-AM: It would be nice if we could stop using VM_MAX/MIN_KERNEL_ADDRESS
	 * in LOCORE and perform the check against the xkseg capability so we can
	 * the KERNEL_ADDRESS with MIPS_XKSEG() to automatically have it
	 * derived as a capability everywhere. The implications are not obvious
	 * to me so I'll leave it for now.
	 * PTR_LA		k1, _C_LABEL(cheri_xkseg_capability)
	*/
	PTR_LI		k1, VM_MAX_KERNEL_ADDRESS	# check fault address against
	sltu		k1, k1, k0			# upper bound of kernel_segmap
	bnez		k1, MipsKernGenException	# out of bound
	CAPTABLE_LOAD(CHERI_REG_KSCRATCH, _C_LABEL(kernel_segmap)) # k1c = segbase ptr
	PTR_SRL		k0, SEGSHIFT - PTRSHIFT		# k0 = seg offset (almost)
	/* XXX-AM: MUST set bounds on kernel_segmap, also readonly */
	clc		CHERI_REG_KSCRATCH, k1, 0(CHERI_REG_KSCRATCH) # kr1c = segbase
	cbez		CHERI_REG_KSCRATCH, MipsKernGenException  # == NULL -- no seg tab
	andi		k0, k0, PDEPTRMASK		# k0 = seg offset
	clc		CHERI_REG_KSCRATCH, k0, 0(CHERI_REG_KSCRATCH) # kr1c = seg entry
	MFC0		k0, MIPS_COP_0_BAD_VADDR	# k0 = bad address (again)
	cbez		CHERI_REG_KSCRATCH, MipsKernGenException  # === NULL -- no page table

	PTR_SRL		k0, PDRSHIFT - PTRSHIFT		# k0 = VPN
	andi		k0, k0, PDEPTRMASK		# k0=pde offset
	clc		CHERI_REG_KSCRATCH, k0, 0(CHERI_REG_KSCRATCH) # kr1c = pde entry
	MFC0		k0, MIPS_COP_0_BAD_VADDR	# k0 = bad address (again)
	cbez		CHERI_REG_KSCRATCH, MipsKernGenException # == NULL -- no page table

	PTR_SRL		k0, PAGE_SHIFT - PTESHIFT	# k0=VPN
	andi		k0, k0, PTE2MASK		# k0=page tab offset
	cincoffset	CHERI_REG_KSCRATCH, CHERI_REG_KSCRATCH, k0 # kr1c = lo0 pte address
	cld		k0, zero, 0(CHERI_REG_KSCRATCH)	# k0 = lo0 pte
	# XXX Reference bit emulation

	CLEAR_PTE_SWBITS(k0)
	PTE_MTC0	k0, MIPS_COP_0_TLB_LO0		# lo0 is loaded
	COP0_SYNC

	cld		k0, zero, PTESIZE(CHERI_REG_KSCRATCH) # k0 = lo1 pte

	CLEAR_PTE_SWBITS(k0)
	PTE_MTC0	k0, MIPS_COP_0_TLB_LO1		# lo1 is loaded
	COP0_SYNC
	tlbwr					# write to tlb
	HAZARD_DELAY

	/* Restore c27 used as KSCRATCH */
	cgetkr1c	CHERI_REG_KSCRATCH
	CHERI_EXCEPTION_RETURN(k0)
	eret					# return from exception
	.set	at
END(MipsTLBMissException)
/* Force size 0 so that we do not set the capability bounds in relocations */
.size _C_LABEL(MipsTLBMissException), 0

/*----------------------------------------------------------------------------
 *
 * MipsFPTrap --
 *
 *	Handle a floating point Trap.
 *
 *	MipsFPTrap(statusReg, causeReg, pc)
 *		unsigned statusReg;
 *		unsigned causeReg;
 *		unsigned pc;
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------------
 */
#if defined(CPU_HAVEFPU)
#error "Floating point traps not supported in purecap kernel!"
#endif /* CPU_HAVEFPU */

/*
 * Vector to real handler in KSEG1.
 */
	.text
VECTOR(MipsCache, unknown)
	CHERI_EXCEPTION_ENTER(k0)

	CAPCALL_LOAD(CHERI_REG_KSCRATCH, _C_LABEL(MipsCacheException))
	clc	CHERI_REG_KSCRATCH, zero, 0(CHERI_REG_KSCRATCH)
	cgetaddr k0, CHERI_REG_KSCRATCH
	CAPCALL_LOAD(CHERI_REG_KSCRATCH, _C_LABEL(cheri_kseg1_capability))
	clc	CHERI_REG_KSCRATCH, zero, 0(CHERI_REG_KSCRATCH)
	csetaddr CHERI_REG_KSCRATCH, CHERI_REG_KSCRATCH, k0
	cjr	CHERI_REG_KSCRATCH
	nop
VECTOR_END(MipsCache)

	.set	at


/*
 * Panic on cache errors.  A lot more could be done to recover
 * from some types of errors but it is tricky.
 *
 * XXX-AM: Note that variadic functions in CHERI are different and this is
 * partially broken.
 */
NESTED_NOPROFILE(MipsCacheException, KERN_EXC_FRAME_SIZE, ra)
	.set	noat
	.mask	0x80000000, -4
	CAPCALL_LOAD(CHERI_REG_KSCRATCH, _C_LABEL(panic)) # return to panic
	cgetaddr k0, CHERI_REG_KSCRATCH
	CAPTABLE_LOAD($c3, 9f)			# panicstr
	MFC0	a1, MIPS_COP_0_ERROR_PC
	mfc0	a2, MIPS_COP_0_CACHE_ERR	# 3rd arg cache error

	MTC0	k0, MIPS_COP_0_ERROR_PC		# set return address
	/* XXX-AM: It seems that we need to set EXC_PC in CHERI */
	MTC0	k0, MIPS_COP_0_EXC_PC		# set return address

	mfc0	k0, MIPS_COP_0_STATUS		# restore status
	li	k1, MIPS_SR_DIAG_PE		# ignore further errors
	or	k0, k1
	mtc0	k0, MIPS_COP_0_STATUS		# restore status
	COP0_SYNC

	CHERI_EXCEPTION_RETURN(k0)
	eret

	MSG("cache error @ EPC 0x%x CachErr 0x%x");
	.set	at
END(MipsCacheException)
