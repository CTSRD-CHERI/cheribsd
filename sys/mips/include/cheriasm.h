/*-
 * Copyright (c) 2012-2016 Robert N. M. Watson
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
 */

#ifndef _MIPS_INCLUDE_CHERIASM_H_
#define	_MIPS_INCLUDE_CHERIASM_H_

#if !defined(_KERNEL) && !defined(_CHERI_INTERNAL)
#error "no user-serviceable parts inside"
#endif

/*
 * 27 user-context registers -- with names where appropriate.
 */
#define	CHERI_REG_C0	$c0	/* MIPS legacy load/store capability. */
#define	CHERI_REG_DDC	CHERI_REG_C0
#define	CHERI_REG_C1	$c1
#define	CHERI_REG_C2	$c2
#define	CHERI_REG_C3	$c3
#define	CHERI_REG_C4	$c4
#define	CHERI_REG_C5	$c5
#define	CHERI_REG_C6	$c6
#define	CHERI_REG_C7	$c7
#define	CHERI_REG_C8	$c8
#define	CHERI_REG_C9	$c9
#define	CHERI_REG_C10	$c10
#define	CHERI_REG_C11	$c11	/* Stack capability. */
#define	CHERI_REG_STC	CHERI_REG_C11
#define	CHERI_REG_C12	$c12
#define	CHERI_REG_C13	$c13
#define	CHERI_REG_C14	$c14
#define	CHERI_REG_C15	$c15
#define	CHERI_REG_C16	$c16
#define	CHERI_REG_C17	$c17
#define	CHERI_REG_C18	$c18
#define	CHERI_REG_C19	$c19
#define	CHERI_REG_C20	$c20
#define	CHERI_REG_C21	$c21
#define	CHERI_REG_C22	$c22
#define	CHERI_REG_C23	$c23
#define	CHERI_REG_C24	$c24
#define	CHERI_REG_C25	$c25
#define	CHERI_REG_C26	$c26	/* Invoked data capability. */
#define	CHERI_REG_IDC	CHERI_REG_C26
#define	CHERI_REG_C27	$c27
#define	CHERI_REG_KSCRATCH CHERI_REG_C27 /* Kernel scratch capability. */
#define	CHERI_REG_C28	$c28
#define	CHERI_REG_C29	$c29	/* Former Kernel code capability. */
#define	CHERI_REG_C30	$c30	/* Former Kernel data capability. */
#define	CHERI_REG_C31	$c31	/* Former Exception program counter cap. */

/*
 * In kernel inline assembly, employee these two caller-save registers.  This
 * means that we don't need to worry about preserving prior values -- as long
 * as there is no direct use of a capability register in a function.
 */
#define	CHERI_REG_CTEMP0	CHERI_REG_C13	/* C capability manipulation. */
#define	CHERI_REG_CTEMP1	CHERI_REG_C14	/* C capability manipulation. */

/*
 * (Possibly) temporary ABI in which $c1 is the code argument to CCall, and
 * $c2 is the data argument.
 */
#define	CHERI_REG_CCALLCODE	$c1
#define	CHERI_REG_CCALLDATA	$c2

/*
 * Macro to abstract use of cmove in kernel assembly, used as a temporary
 * workaround for cmove generating CIncBase instructions on 128-bit CHERI.
 * This will be removed once all live bitfiles and toolchain have been
 * updated.
 */
#if (defined(CPU_CHERI) && !defined(CPU_CHERI128))
#define	CHERI_ASM_CMOVE(cd, cb)		cmove cd, cb
#else
#define	CHERI_ASM_CMOVE(cd, cb)		cincoffset cd, cb, zero
#endif

/*
 * Assembly code to be used in CHERI exception handling and context switching.
 *
 * When entering an exception handler from userspace, conditionally save the
 * default user data capability.  Then install the kernel's default data
 * capability.  The caller provides a temporary register to use for the
 * purposes of querying CP0 SR to determine whether the target is userspace or
 * the kernel.
 */
#define	CHERI_EXCEPTION_ENTER(reg)					\
	mfc0	reg, MIPS_COP_0_STATUS;					\
	andi	reg, reg, MIPS_SR_KSU_USER;				\
	beq	reg, $0, 64f;						\
	nop;								\
	/* Save user $c27. */						\
	csetkr1c	CHERI_REG_KSCRATCH;				\
	/* Save user $ddc in $kr2c. */					\
	cgetdefault	CHERI_REG_KSCRATCH;				\
	csetkr2c	CHERI_REG_KSCRATCH;				\
	/* Install kernel $ddc. */					\
	cgetkdc		CHERI_REG_KSCRATCH;				\
	csetdefault	CHERI_REG_KSCRATCH;				\
	/* Restore user $c27. */					\
	cgetkr1c	CHERI_REG_KSCRATCH;				\
64:

/*
 * When returning from an exception, conditionally restore the default user
 * data capability.  The caller provides a temporary register to use for the
 * purposes of querying CP0 SR to determine whether the target is userspace
 * or the kernel.
 *
 * XXXCHERI: We assume that the caller will install an appropriate $pcc for a
 * return to userspace, but that in the kernel case, we need to install a
 * kernel $epcc, potentially overwriting a previously present user $epcc from
 * exception entry.  Once the kernel does multiple security domains, the
 * caller should manage $epcc in that case as well, and we can remove $epcc
 * assignment here.
 */
#define	CHERI_EXCEPTION_RETURN(reg)					\
	/* Save $c27 in $kr1c. */					\
	csetkr1c	CHERI_REG_KSCRATCH;				\
	mfc0	reg, MIPS_COP_0_STATUS;					\
	andi	reg, reg, MIPS_SR_KSU_USER;				\
	beq	reg, $0, 65f;						\
	nop;								\
	/* If returning to userspace, restore saved user $ddc. */	\
	cgetkr2c	CHERI_REG_KSCRATCH;				\
	csetdefault	CHERI_REG_KSCRATCH; 				\
	b	66f;							\
	nop; /* delay slot */						\
65:									\
	/* If returning to kernelspace, reinstall kernel code $pcc. */	\
	/*								\
	 * XXXRW: If requested PC has been adjusted by stack, similarly	\
	 * adjust $epcc.offset, which will overwrite an earlier $epc	\
	 * assignment.							\
	 * FIXME: this does not work with non-zero $pcc base		\
	 */								\
	MFC0	reg, MIPS_COP_0_EXC_PC;					\
	CGetKCC		CHERI_REG_KSCRATCH;				\
	CSetOffset	CHERI_REG_KSCRATCH, CHERI_REG_KSCRATCH, reg;	\
	CSetEPCC	CHERI_REG_KSCRATCH;				\
66:									\
	/* Restore $c27. */						\
	cgetkr1c	CHERI_REG_KSCRATCH;

/*
 * Save and restore user CHERI state on an exception.  Assumes that $ddc has
 * already been moved to $krc2, and that if we write $krc2, it will get moved
 * to $ddc later.  Unlike kernel context switches, we both save and restore
 * the capability cause register.
 *
 * XXXRW: We should in fact also do this for the kernel version?
 */
#define	SAVE_CREGS_TO_PCB(pcb, treg)					\
	SAVE_U_PCB_CREG(CHERI_REG_C1, C1, pcb);				\
	SAVE_U_PCB_CREG(CHERI_REG_C2, C2, pcb);				\
	SAVE_U_PCB_CREG(CHERI_REG_C3, C3, pcb);				\
	SAVE_U_PCB_CREG(CHERI_REG_C4, C4, pcb);				\
	SAVE_U_PCB_CREG(CHERI_REG_C5, C5, pcb);				\
	SAVE_U_PCB_CREG(CHERI_REG_C6, C6, pcb);				\
	SAVE_U_PCB_CREG(CHERI_REG_C7, C7, pcb);				\
	SAVE_U_PCB_CREG(CHERI_REG_C8, C8, pcb);				\
	SAVE_U_PCB_CREG(CHERI_REG_C9, C9, pcb);				\
	SAVE_U_PCB_CREG(CHERI_REG_C10, C10, pcb);			\
	SAVE_U_PCB_CREG(CHERI_REG_STC, STC, pcb);			\
	SAVE_U_PCB_CREG(CHERI_REG_C12, C12, pcb);			\
	SAVE_U_PCB_CREG(CHERI_REG_C13, C13, pcb);			\
	SAVE_U_PCB_CREG(CHERI_REG_C14, C14, pcb);			\
	SAVE_U_PCB_CREG(CHERI_REG_C15, C15, pcb);			\
	SAVE_U_PCB_CREG(CHERI_REG_C16, C16, pcb);			\
	SAVE_U_PCB_CREG(CHERI_REG_C17, C17, pcb);			\
	SAVE_U_PCB_CREG(CHERI_REG_C18, C18, pcb);			\
	SAVE_U_PCB_CREG(CHERI_REG_C19, C19, pcb);			\
	SAVE_U_PCB_CREG(CHERI_REG_C20, C20, pcb);			\
	SAVE_U_PCB_CREG(CHERI_REG_C21, C21, pcb);			\
	SAVE_U_PCB_CREG(CHERI_REG_C22, C22, pcb);			\
	SAVE_U_PCB_CREG(CHERI_REG_C23, C23, pcb);			\
	SAVE_U_PCB_CREG(CHERI_REG_C24, C24, pcb);			\
	SAVE_U_PCB_CREG(CHERI_REG_C25, C25, pcb);			\
	SAVE_U_PCB_CREG(CHERI_REG_C26, IDC, pcb);			\
	SAVE_U_PCB_CREG(CHERI_REG_C27, C27, pcb);			\
	SAVE_U_PCB_CREG(CHERI_REG_C28, C28, pcb);			\
	SAVE_U_PCB_CREG(CHERI_REG_C29, C29, pcb);			\
	SAVE_U_PCB_CREG(CHERI_REG_C30, C30, pcb);			\
	SAVE_U_PCB_CREG(CHERI_REG_C31, C31, pcb);			\
	/* Save special registers after KSCRATCH (C27) */		\
	CGetEPCC	CHERI_REG_KSCRATCH;				\
	SAVE_U_PCB_CREG(CHERI_REG_KSCRATCH, PCC, pcb);			\
	/* User DDC is saved in $kr2c. */				\
	CGetKR2C	CHERI_REG_KSCRATCH;				\
	SAVE_U_PCB_CREG(CHERI_REG_KSCRATCH, DDC, pcb);			\
	cgetcause	treg;						\
	SAVE_U_PCB_REG(treg, CAPCAUSE, pcb)


#define RESTORE_EPCC(capreg, pc_offset, tmpreg)					\
	/* Do not attempt to modify EPCC if it is already correct. */		\
	/* This is needed in case it is a sentry (e.g. for signal handlers) */	\
	CGetOffset tmpreg, capreg;						\
	/* update the offset of EPCC to the return pc if different */		\
	beq tmpreg, pc_offset, 12345f; nop;					\
	CSetOffset capreg, capreg, pc_offset;					\
	12345:									\
	CSetEPCC capreg;

#define	RESTORE_CREGS_FROM_PCB(pcb, treg)				\
	/* Restore special registers before KSCRATCH (C27) */		\
	/* User DDC is saved in $kr2c. */				\
	RESTORE_U_PCB_CREG(CHERI_REG_KSCRATCH, DDC, pcb);		\
	CSetKR2C	CHERI_REG_KSCRATCH;				\
	RESTORE_U_PCB_CREG(CHERI_REG_C1, C1, pcb);			\
	RESTORE_U_PCB_CREG(CHERI_REG_C2, C2, pcb);			\
	RESTORE_U_PCB_CREG(CHERI_REG_C3, C3, pcb);			\
	RESTORE_U_PCB_CREG(CHERI_REG_C4, C4, pcb);			\
	RESTORE_U_PCB_CREG(CHERI_REG_C5, C5, pcb);			\
	RESTORE_U_PCB_CREG(CHERI_REG_C6, C6, pcb);			\
	RESTORE_U_PCB_CREG(CHERI_REG_C7, C7, pcb);			\
	RESTORE_U_PCB_CREG(CHERI_REG_C8, C8, pcb);			\
	RESTORE_U_PCB_CREG(CHERI_REG_C9, C9, pcb);			\
	RESTORE_U_PCB_CREG(CHERI_REG_C10, C10, pcb);			\
	RESTORE_U_PCB_CREG(CHERI_REG_STC, STC, pcb);			\
	RESTORE_U_PCB_CREG(CHERI_REG_C12, C12, pcb);			\
	RESTORE_U_PCB_CREG(CHERI_REG_C13, C13, pcb);			\
	RESTORE_U_PCB_CREG(CHERI_REG_C14, C14, pcb);			\
	RESTORE_U_PCB_CREG(CHERI_REG_C15, C15, pcb);			\
	RESTORE_U_PCB_CREG(CHERI_REG_C16, C16, pcb);			\
	RESTORE_U_PCB_CREG(CHERI_REG_C17, C17, pcb);			\
	RESTORE_U_PCB_CREG(CHERI_REG_C18, C18, pcb);			\
	RESTORE_U_PCB_CREG(CHERI_REG_C19, C19, pcb);			\
	RESTORE_U_PCB_CREG(CHERI_REG_C20, C20, pcb);			\
	RESTORE_U_PCB_CREG(CHERI_REG_C21, C21, pcb);			\
	RESTORE_U_PCB_CREG(CHERI_REG_C22, C22, pcb);			\
	RESTORE_U_PCB_CREG(CHERI_REG_C23, C23, pcb);			\
	RESTORE_U_PCB_CREG(CHERI_REG_C24, C24, pcb);			\
	RESTORE_U_PCB_CREG(CHERI_REG_C25, C25, pcb);			\
	RESTORE_U_PCB_CREG(CHERI_REG_C26, IDC, pcb);			\
	/* Wait to restore KSCRATCH (C27) until after EPCC */	\
	RESTORE_U_PCB_CREG(CHERI_REG_C28, C28, pcb);			\
	RESTORE_U_PCB_CREG(CHERI_REG_C29, C29, pcb);			\
	RESTORE_U_PCB_CREG(CHERI_REG_C30, C30, pcb);			\
	RESTORE_U_PCB_CREG(CHERI_REG_C31, C31, pcb);			\
	RESTORE_U_PCB_REG(treg, CAPCAUSE, pcb);				\
	csetcause	treg

/*
 * Macros saving capability state to, and restoring it from, voluntary kernel
 * context-switch storage in pcb.pcb_cherikframe.
 */
#define	SAVE_U_PCB_CHERIKFRAME_CREG(creg, offs, base)			\
	csc		creg, base, (U_PCB_CHERIKFRAME +		\
			    CHERICAP_SIZE * offs)($ddc)

#define	RESTORE_U_PCB_CHERIKFRAME_CREG(creg, offs, base)		\
	clc		creg, base, (U_PCB_CHERIKFRAME +		\
			    CHERICAP_SIZE * offs)($ddc)

/*
 * Macros to save (and restore) callee-save capability registers when
 * performing a voluntary kernel context switch (the compiler will have saved,
 * or will restore, caller-save registers).
 */
#define	SAVE_U_PCB_CHERIKFRAME(base)					\
	SAVE_U_PCB_CHERIKFRAME_CREG(CHERI_REG_C17, CHERIKFRAME_OFF_C17,	\
	    base);							\
	SAVE_U_PCB_CHERIKFRAME_CREG(CHERI_REG_C18, CHERIKFRAME_OFF_C18,	\
	    base);							\
	SAVE_U_PCB_CHERIKFRAME_CREG(CHERI_REG_C19, CHERIKFRAME_OFF_C19,	\
	    base);							\
	SAVE_U_PCB_CHERIKFRAME_CREG(CHERI_REG_C20, CHERIKFRAME_OFF_C20,	\
	    base);							\
	SAVE_U_PCB_CHERIKFRAME_CREG(CHERI_REG_C21, CHERIKFRAME_OFF_C21,	\
	    base);							\
	SAVE_U_PCB_CHERIKFRAME_CREG(CHERI_REG_C22, CHERIKFRAME_OFF_C22,	\
	    base);							\
	SAVE_U_PCB_CHERIKFRAME_CREG(CHERI_REG_C23, CHERIKFRAME_OFF_C23,	\
	    base);							\
	SAVE_U_PCB_CHERIKFRAME_CREG(CHERI_REG_C24, CHERIKFRAME_OFF_C24,	\
	    base)

#define	RESTORE_U_PCB_CHERIKFRAME(base)					\
	RESTORE_U_PCB_CHERIKFRAME_CREG(CHERI_REG_C17,			\
	    CHERIKFRAME_OFF_C17, base);					\
	RESTORE_U_PCB_CHERIKFRAME_CREG(CHERI_REG_C18,			\
	    CHERIKFRAME_OFF_C18, base);					\
	RESTORE_U_PCB_CHERIKFRAME_CREG(CHERI_REG_C19,			\
	    CHERIKFRAME_OFF_C19, base);					\
	RESTORE_U_PCB_CHERIKFRAME_CREG(CHERI_REG_C20,			\
	    CHERIKFRAME_OFF_C20, base);					\
	RESTORE_U_PCB_CHERIKFRAME_CREG(CHERI_REG_C21,			\
	    CHERIKFRAME_OFF_C21, base);					\
	RESTORE_U_PCB_CHERIKFRAME_CREG(CHERI_REG_C22,			\
	    CHERIKFRAME_OFF_C22, base);					\
	RESTORE_U_PCB_CHERIKFRAME_CREG(CHERI_REG_C23,			\
	    CHERIKFRAME_OFF_C23, base);					\
	RESTORE_U_PCB_CHERIKFRAME_CREG(CHERI_REG_C24,			\
	    CHERIKFRAME_OFF_C24, base)

#define CHERI_CLEAR_GPLO_ZR    (1 << 0)
#define CHERI_CLEAR_GPLO_AT    (1 << 1)
#define CHERI_CLEAR_GPLO_V0    (1 << 2)
#define CHERI_CLEAR_GPLO_V1    (1 << 3)
#define CHERI_CLEAR_GPLO_A0    (1 << 4)
#define CHERI_CLEAR_GPLO_A1    (1 << 5)
#define CHERI_CLEAR_GPLO_A2    (1 << 6)
#define CHERI_CLEAR_GPLO_A3    (1 << 7)
#define CHERI_CLEAR_GPLO_A4    (1 << 8)
#define CHERI_CLEAR_GPLO_A5    (1 << 9)
#define CHERI_CLEAR_GPLO_A6    (1 << 10)
#define CHERI_CLEAR_GPLO_A7    (1 << 11)
#define CHERI_CLEAR_GPLO_T0    (1 << 12)
#define CHERI_CLEAR_GPLO_T1    (1 << 13)
#define CHERI_CLEAR_GPLO_T2    (1 << 14)
#define CHERI_CLEAR_GPLO_T3    (1 << 15)
#define CHERI_CLEAR_GPHI_S0    (1 << (16 - 16))
#define CHERI_CLEAR_GPHI_S1    (1 << (17 - 16))
#define CHERI_CLEAR_GPHI_S2    (1 << (18 - 16))
#define CHERI_CLEAR_GPHI_S3    (1 << (19 - 16))
#define CHERI_CLEAR_GPHI_S4    (1 << (20 - 16))
#define CHERI_CLEAR_GPHI_S5    (1 << (21 - 16))
#define CHERI_CLEAR_GPHI_S6    (1 << (22 - 16))
#define CHERI_CLEAR_GPHI_S7    (1 << (23 - 16))
#define CHERI_CLEAR_GPHI_T8    (1 << (24 - 16))
#define CHERI_CLEAR_GPHI_T9    (1 << (25 - 16))
#define CHERI_CLEAR_GPHI_K0    (1 << (26 - 16))
#define CHERI_CLEAR_GPHI_K1    (1 << (27 - 16))
#define CHERI_CLEAR_GPHI_GP    (1 << (28 - 16))
#define CHERI_CLEAR_GPHI_SP    (1 << (29 - 16))
#define CHERI_CLEAR_GPHI_S8    (1 << (30 - 16))
#define CHERI_CLEAR_GPHI_RA    (1 << (31 - 16))

#define CHERI_CLEAR_CAPLO_C0   (1 << 0 )
#define CHERI_CLEAR_CAPLO_C1   (1 << 1 )
#define CHERI_CLEAR_CAPLO_C2   (1 << 2 )
#define CHERI_CLEAR_CAPLO_C3   (1 << 3 )
#define CHERI_CLEAR_CAPLO_C4   (1 << 4 )
#define CHERI_CLEAR_CAPLO_C5   (1 << 5 )
#define CHERI_CLEAR_CAPLO_C6   (1 << 6 )
#define CHERI_CLEAR_CAPLO_C7   (1 << 7 )
#define CHERI_CLEAR_CAPLO_C8   (1 << 8 )
#define CHERI_CLEAR_CAPLO_C9   (1 << 9 )
#define CHERI_CLEAR_CAPLO_C10  (1 << 10)
#define CHERI_CLEAR_CAPLO_C11  (1 << 11)
#define CHERI_CLEAR_CAPLO_C12  (1 << 12)
#define CHERI_CLEAR_CAPLO_C13  (1 << 13)
#define CHERI_CLEAR_CAPLO_C14  (1 << 14)
#define CHERI_CLEAR_CAPLO_C15  (1 << 15)
#define CHERI_CLEAR_CAPHI_C16  (1 << (16 - 16))
#define CHERI_CLEAR_CAPHI_C17  (1 << (17 - 16))
#define CHERI_CLEAR_CAPHI_C18  (1 << (18 - 16))
#define CHERI_CLEAR_CAPHI_C19  (1 << (19 - 16))
#define CHERI_CLEAR_CAPHI_C20  (1 << (20 - 16))
#define CHERI_CLEAR_CAPHI_C21  (1 << (21 - 16))
#define CHERI_CLEAR_CAPHI_C22  (1 << (22 - 16))
#define CHERI_CLEAR_CAPHI_C23  (1 << (23 - 16))
#define CHERI_CLEAR_CAPHI_C24  (1 << (24 - 16))
#define CHERI_CLEAR_CAPHI_C25  (1 << (25 - 16))
#define CHERI_CLEAR_CAPHI_IDC  (1 << (26 - 16))
#define CHERI_CLEAR_CAPHI_C27  (1 << (27 - 16))
#define CHERI_CLEAR_CAPHI_C28  (1 << (28 - 16))
#define CHERI_CLEAR_CAPHI_C29  (1 << (29 - 16))
#define CHERI_CLEAR_CAPHI_C30  (1 << (30 - 16))
#define CHERI_CLEAR_CAPHI_C31  (1 << (31 - 16))

/*
 * The CCall (selector 1) branch delay slot has been removed but in order to
 * run on older hardware we use this macro ensure it is followed by a nop
 *
 * TODO: remove this once we drop support for older bitfiles
 */
#define CCALL(cb, cd)						\
	.set push;						\
	.set noreorder;						\
	ccall cb, cd, 1;					\
	nop; /* Fill branch delay slot for old harware*/	\
	.set pop;

/* Derive the initial DDC/KDC and PCC/KCC from an omnipotent boot
 * capability, presumed to be in DDC.  Clobbers C27 and C28, which surely
 * want to be cleared before handing off control.  (We don't do so here
 * because in locore.S we have more privileged caps to derive, and we'll
 * clean up later.)
 *
 * TODO: The capabilities derived for DDC/KDC and for PCC/KCC cover the
 * entirety of the kernel.  Acutally changing base/length requires changes
 * in linkage.
 */
#define CHERI_LOCORE_ROOT_CAPS \
	/* Grab the initial omnipotent capability */                 \
	cgetdefault	CHERI_REG_C28;                               \
	                                                             \
	/* Create a reduced DDC.  */                                 \
	cmove		CHERI_REG_C27, CHERI_REG_C28;                \
	REG_LI		t0, CHERI_CAP_KERN_BASE;                     \
	csetoffset	CHERI_REG_C27, CHERI_REG_C27, t0;            \
	REG_LI		t0, CHERI_CAP_KERN_LENGTH;                   \
	csetbounds	CHERI_REG_C27, CHERI_REG_C27, t0;            \
	REG_LI		t0, CHERI_PERMS_KERNEL_DATA;                 \
	candperm	CHERI_REG_C27, CHERI_REG_C27, t0;            \
	                                                             \
	/* Preserve a copy in KDC for exception handlers. */         \
	csetkdc		CHERI_REG_C27;                               \
	                                                             \
	/* Install the new DDC. */                                   \
	csetdefault	CHERI_REG_C27;                               \
	                                                             \
	/* Create a reduced PCC.  */                                 \
	cgetpcc		CHERI_REG_C27;                               \
	REG_LI		t0, CHERI_CAP_KERN_BASE;                     \
	csetoffset	CHERI_REG_C27, CHERI_REG_C27, t0;            \
	REG_LI		t0, CHERI_CAP_KERN_LENGTH;                   \
	csetbounds	CHERI_REG_C27, CHERI_REG_C27, t0;            \
	REG_LI		t0, CHERI_PERMS_KERNEL_CODE;                 \
	candperm	CHERI_REG_C27, CHERI_REG_C27, t0;            \
	                                                             \
	/* Preserve a copy in KCC for exception handlers.  */        \
	                                                             \
	csetkcc		CHERI_REG_C27;                               \
	                                                             \
	/* Install the new PCC. */                                   \
	REG_LI		t0, CHERI_CAP_KERN_BASE;                     \
	cgetpcc		CHERI_REG_C28;                               \
	cgetoffset	t1, CHERI_REG_C28;                   /* 1 */ \
	PTR_SUBU	t1, t1, t0;                          /* 2 */ \
	PTR_ADDIU	t1, t1, (4 * 7);                     /* 3 */ \
	csetoffset	CHERI_REG_C27, CHERI_REG_C27, t1;    /* 4 */ \
	cjr		CHERI_REG_C27;                       /* 5 */ \
	nop;                                                 /* 6 */ \
	/* 7 (land here) */

#endif /* _MIPS_INCLUDE_CHERIASM_H_ */
