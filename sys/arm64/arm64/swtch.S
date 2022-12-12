/*-
 * Copyright (c) 2014 Andrew Turner
 * Copyright (c) 2014 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed by Andrew Turner under sponsorship from
 * the FreeBSD Foundation.
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
 */

#include "assym.inc"
#include "opt_kstack_pages.h"
#include "opt_sched.h"

#include <machine/asm.h>
#include <machine/armreg.h>

__FBSDID("$FreeBSD$");

.macro clear_step_flag pcbflags, tmp
	tbz	\pcbflags, #PCB_SINGLE_STEP_SHIFT, 999f
	mrs	\tmp, mdscr_el1
	bic	\tmp, \tmp, #MDSCR_SS
	msr	mdscr_el1, \tmp
	isb
999:
.endm

.macro set_step_flag pcbflags, tmp
	tbz	\pcbflags, #PCB_SINGLE_STEP_SHIFT, 999f
	mrs	\tmp, mdscr_el1
	orr	\tmp, \tmp, #MDSCR_SS
	msr	mdscr_el1, \tmp
	isb
999:
.endm

/*
 * void cpu_throw(struct thread *old, struct thread *new)
 */
ENTRY(cpu_throw)
	/* Of old == NULL skip disabling stepping */
	cbz	x0, 1f

	/* If we were single stepping, disable it */
	ldr	PTR(4), [PTR(0), #TD_PCB]
	ldr	w5, [PTR(4), #PCB_FLAGS]
	clear_step_flag w5, x6
1:

#ifdef VFP
	/* Backup the new thread pointer around a call to C code */
	mov	PTR(19), PTR(1)
	bl	vfp_discard
	mov	PTR(0), PTR(19)
#else
	mov	PTR(0), PTR(1)
#endif

#ifdef PAC
	/* This returns the thread pointer so no need to save it */
	bl	ptrauth_switch
#endif
	/* This returns the thread pcb */
	bl	pmap_switch
	mov	PTR(4), PTR(0)

	/* If we are single stepping, enable it */
	ldr	w5, [PTR(4), #PCB_FLAGS]
	set_step_flag w5, x6

	/* Restore the registers */
#if __has_feature(capabilities)
	ldr	PTR(5), [PTR(4), #PCB_SP]
	mov	PTRN(sp), PTR(5)
	ldp	c5, c6, [PTR(4), #PCB_TPIDR]
	msr	ctpidr_el0, c5
	msr	ctpidrro_el0, c6
	ldp	c5, c6, [PTR(4), #PCB_CID]
	msr	cid_el0, c5
	msr	rcsp_el0, c6
	ldp	c5, c6, [PTR(4), #PCB_RDDC]
	msr	rddc_el0, c5
	msr	rctpidr_el0, c6
#else
	ldp	x5, x6, [x4, #PCB_SP]
	mov	sp, x5
	msr	tpidr_el0, x6
	ldr	x6, [x4, #PCB_TPIDRRO]
	msr	tpidrro_el0, x6
#endif
	ldp	PTR(19), PTR(20), [PTR(4), #PCB_REGS + 19 * PTR_WIDTH]
	ldp	PTR(21), PTR(22), [PTR(4), #PCB_REGS + 21 * PTR_WIDTH]
	ldp	PTR(23), PTR(24), [PTR(4), #PCB_REGS + 23 * PTR_WIDTH]
	ldp	PTR(25), PTR(26), [PTR(4), #PCB_REGS + 25 * PTR_WIDTH]
	ldp	PTR(27), PTR(28), [PTR(4), #PCB_REGS + 27 * PTR_WIDTH]
	ldp	PTR(29), PTRN(lr), [PTR(4), #PCB_REGS + 29 * PTR_WIDTH]

	ret
END(cpu_throw)

/*
 * void cpu_switch(struct thread *old, struct thread *new, struct mtx *mtx)
 *
 * x/c0 = old
 * x/c1 = new
 * x/c2 = mtx
 * x3 to x7, x16 and x17 are caller saved
 */
ENTRY(cpu_switch)
	/*
	 * Save the old context.
	 */
	ldr	PTR(4), [PTR(0), #TD_PCB]

	/* Store the callee-saved registers */
	stp	PTR(19), PTR(20), [PTR(4), #PCB_REGS + 19 * PTR_WIDTH]
	stp	PTR(21), PTR(22), [PTR(4), #PCB_REGS + 21 * PTR_WIDTH]
	stp	PTR(23), PTR(24), [PTR(4), #PCB_REGS + 23 * PTR_WIDTH]
	stp	PTR(25), PTR(26), [PTR(4), #PCB_REGS + 25 * PTR_WIDTH]
	stp	PTR(27), PTR(28), [PTR(4), #PCB_REGS + 27 * PTR_WIDTH]
	stp	PTR(29), PTRN(lr), [PTR(4), #PCB_REGS + 29 * PTR_WIDTH]
	/* And the old stack pointer */
	mov	PTR(5), PTRN(sp)
#if __has_feature(capabilities)
	str	PTR(5), [PTR(4), #PCB_SP]
	mrs	c5, ctpidr_el0
	mrs	c6, ctpidrro_el0
	stp	c5, c6, [PTR(4), #PCB_TPIDR]
	mrs	c5, cid_el0
	mrs	c6, rcsp_el0
	stp	c5, c6, [PTR(4), #PCB_CID]
	mrs	c5, rddc_el0
	mrs	c6, rctpidr_el0
	stp	c5, c6, [PTR(4), #PCB_RDDC]
#else
	mrs	x6, tpidrro_el0
	str	x6, [x4, #PCB_TPIDRRO]
	mrs	x6, tpidr_el0
	stp	x5, x6, [x4, #PCB_SP]
#endif

	/* If we were single stepping, disable it */
	ldr	w5, [PTR(4), #PCB_FLAGS]
	clear_step_flag w5, x6

	mov	PTR(19), PTR(0)
	mov	PTR(20), PTR(1)
	mov	PTR(21), PTR(2)

#ifdef VFP
	/* Load the pcb address */
	mov	PTR(1), PTR(4)
	bl	vfp_save_state
	mov	PTR(0), PTR(20)
#else
	mov	PTR(0), PTR(1)
#endif

#ifdef PAC
	/* This returns the thread pointer so no need to save it */
	bl	ptrauth_switch
#endif
	/* This returns the thread pcb */
	bl	pmap_switch
	/* Move the new pcb out of the way */
	mov	PTR(4), PTR(0)

	mov	PTR(2), PTR(21)
	mov	PTR(1), PTR(20)
	mov	PTR(0), PTR(19)

	/*
	 * Release the old thread.
	 */
	stlr	PTR(2), [PTR(0), #TD_LOCK]
#if defined(SCHED_ULE) && defined(SMP)
	/* Spin if TD_LOCK points to a blocked_lock */
	ldr	x2, =_C_LABEL(blocked_lock)
1:
	ldar	x3, [PTR(1), #TD_LOCK]
	cmp	x3, x2
	b.eq	1b
#endif

	/* If we are single stepping, enable it */
	ldr	w5, [PTR(4), #PCB_FLAGS]
	set_step_flag w5, x6

	/* Restore the registers */
#if __has_feature(capabilities)
	ldr	PTR(5), [PTR(4), #PCB_SP]
	mov	PTRN(sp), PTR(5)
	ldp	c5, c6, [PTR(4), #PCB_TPIDR]
	msr	ctpidr_el0, c5
	msr	ctpidrro_el0, c6
	ldp	c5, c6, [PTR(4), #PCB_CID]
	msr	cid_el0, c5
	msr	rcsp_el0, c6
	ldp	c5, c6, [PTR(4), #PCB_RDDC]
	msr	rddc_el0, c5
	msr	rctpidr_el0, c6
#else
	ldp	x5, x6, [x4, #PCB_SP]
	mov	sp, x5
	msr	tpidr_el0, x6
	ldr	x6, [x4, #PCB_TPIDRRO]
	msr	tpidrro_el0, x6
#endif
	ldp	PTR(19), PTR(20), [PTR(4), #PCB_REGS + 19 * PTR_WIDTH]
	ldp	PTR(21), PTR(22), [PTR(4), #PCB_REGS + 21 * PTR_WIDTH]
	ldp	PTR(23), PTR(24), [PTR(4), #PCB_REGS + 23 * PTR_WIDTH]
	ldp	PTR(25), PTR(26), [PTR(4), #PCB_REGS + 25 * PTR_WIDTH]
	ldp	PTR(27), PTR(28), [PTR(4), #PCB_REGS + 27 * PTR_WIDTH]
	ldp	PTR(29), PTRN(lr), [PTR(4), #PCB_REGS + 29 * PTR_WIDTH]

	str	PTR(zr), [PTR(4), #PCB_REGS + 18 * PTR_WIDTH]
	ret
END(cpu_switch)

ENTRY(fork_trampoline)
	mov	PTR(0), PTR(19)
	mov	PTR(1), PTR(20)
	mov	PTR(2), PTRN(sp)
	mov	fp, #0	/* Stack traceback stops here. */
	bl	_C_LABEL(fork_exit)

	/*
	 * Disable interrupts as we are setting userspace specific
	 * state that we won't handle correctly in an interrupt while
	 * in the kernel.
	 */
	msr	daifset, #(DAIF_D | DAIF_INTR)

#ifdef PAC
	ldr	x0, [x18, #PC_CURTHREAD]
	bl	ptrauth_enter_el0
#endif

	/* Restore sp, lr, elr, and spsr */
	ldp	CAP(18), CAPN(lr), [PTRN(sp), #TF_SP]
#if __has_feature(capabilities)
	ldr	CAP(10), [PTRN(sp), #TF_ELR]
	ldr	x11, [PTRN(sp), #TF_SPSR]
#else
	ldp	CAP(10), CAP(11), [sp, #TF_ELR]
#endif
	msr	CAPN(sp_el0), CAP(18)
	msr	spsr_el1, x11
	msr	CAPN(elr_el1), CAP(10)

	/* Restore ddc */
#if __has_feature(capabilities)
	ldr	c0, [PTRN(sp), #TF_DDC]
	msr	ddc_el0, c0
#endif

	/* Restore the CPU registers */
	ldp	CAP(0), CAP(1), [PTRN(sp), #TF_X + 0 * CAP_WIDTH]
	ldp	CAP(2), CAP(3), [PTRN(sp), #TF_X + 2 * CAP_WIDTH]
	ldp	CAP(4), CAP(5), [PTRN(sp), #TF_X + 4 * CAP_WIDTH]
	ldp	CAP(6), CAP(7), [PTRN(sp), #TF_X + 6 * CAP_WIDTH]
	ldp	CAP(8), CAP(9), [PTRN(sp), #TF_X + 8 * CAP_WIDTH]
	ldp	CAP(10), CAP(11), [PTRN(sp), #TF_X + 10 * CAP_WIDTH]
	ldp	CAP(12), CAP(13), [PTRN(sp), #TF_X + 12 * CAP_WIDTH]
	ldp	CAP(14), CAP(15), [PTRN(sp), #TF_X + 14 * CAP_WIDTH]
	ldp	CAP(16), CAP(17), [PTRN(sp), #TF_X + 16 * CAP_WIDTH]
	ldp	CAP(18), CAP(19), [PTRN(sp), #TF_X + 18 * CAP_WIDTH]
	ldp	CAP(20), CAP(21), [PTRN(sp), #TF_X + 20 * CAP_WIDTH]
	ldp	CAP(22), CAP(23), [PTRN(sp), #TF_X + 22 * CAP_WIDTH]
	ldp	CAP(24), CAP(25), [PTRN(sp), #TF_X + 24 * CAP_WIDTH]
	ldp	CAP(26), CAP(27), [PTRN(sp), #TF_X + 26 * CAP_WIDTH]
	ldp	CAP(28), CAP(29), [PTRN(sp), #TF_X + 28 * CAP_WIDTH]

	/*
	 * No need for interrupts reenabling since PSR
	 * will be set to the desired value anyway.
	 */
	ERET
	
END(fork_trampoline)

ENTRY(savectx)
	/* Store the callee-saved registers */
	stp	PTR(19), PTR(20), [PTR(0), #PCB_REGS + 19 * PTR_WIDTH]
	stp	PTR(21), PTR(22), [PTR(0), #PCB_REGS + 21 * PTR_WIDTH]
	stp	PTR(23), PTR(24), [PTR(0), #PCB_REGS + 23 * PTR_WIDTH]
	stp	PTR(25), PTR(26), [PTR(0), #PCB_REGS + 25 * PTR_WIDTH]
	stp	PTR(27), PTR(28), [PTR(0), #PCB_REGS + 27 * PTR_WIDTH]
	stp	PTR(29), PTRN(lr), [PTR(0), #PCB_REGS + 29 * PTR_WIDTH]
	/* And the old stack pointer */
	mov	PTR(5), PTRN(sp)
#if __has_feature(capabilities)
	str	PTR(5), [PTR(0), #PCB_SP]
	mrs	c5, ctpidr_el0
	mrs	c6, ctpidrro_el0
	stp	c5, c6, [PTR(0), #PCB_TPIDR]
	mrs	c5, cid_el0
	mrs	c6, rcsp_el0
	stp	c5, c6, [PTR(0), #PCB_CID]
	mrs	c5, rddc_el0
	mrs	c6, rctpidr_el0
	stp	c5, c6, [PTR(0), #PCB_RDDC]
#else
	mrs	x6, tpidrro_el0
	str	x6, [x0, #PCB_TPIDRRO]
	mrs	x6, tpidr_el0
	stp	x5, x6, [x0, #PCB_SP]
#endif

	/* Store the VFP registers */
#ifdef VFP
	mov	PTR(28), PTRN(lr)
	mov	PTR(1), PTR(0)		/* move pcb to the correct register */
	mov	x0, xzr			/* td = NULL */
	bl	vfp_save_state
	mov	PTRN(lr), PTR(28)
#endif

	ret
END(savectx)
// CHERI CHANGES START
// {
//   "updated": 20221129,
//   "target_type": "kernel",
//   "changes_purecap": [
//     "support"
//   ]
// }
// CHERI CHANGES END
