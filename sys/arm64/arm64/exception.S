/*-
 * Copyright (c) 2014 Andrew Turner
 * All rights reserved.
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

#include <machine/asm.h>
#include <machine/armreg.h>
__FBSDID("$FreeBSD$");

#include "assym.inc"

	.text

/*
 * This is limited to 28 instructions as it's placed in the exception vector
 * slot that is 32 instructions long. We need one for the branch, and three
 * for the prologue.
 */
.macro	save_registers_head el
.if \el == 1
	mov	PTR(18), PTRN(sp)
	sub	PTRN(sp), PTRN(sp), #128
.endif
	sub	PTRN(sp), PTRN(sp), #(TF_SIZE)
	stp	CAP(28), CAP(29), [PTRN(sp), #(TF_X + 28 * CAP_WIDTH)]
	stp	CAP(26), CAP(27), [PTRN(sp), #(TF_X + 26 * CAP_WIDTH)]
	stp	CAP(24), CAP(25), [PTRN(sp), #(TF_X + 24 * CAP_WIDTH)]
	stp	CAP(22), CAP(23), [PTRN(sp), #(TF_X + 22 * CAP_WIDTH)]
	stp	CAP(20), CAP(21), [PTRN(sp), #(TF_X + 20 * CAP_WIDTH)]
	stp	CAP(18), CAP(19), [PTRN(sp), #(TF_X + 18 * CAP_WIDTH)]
	stp	CAP(16), CAP(17), [PTRN(sp), #(TF_X + 16 * CAP_WIDTH)]
	stp	CAP(14), CAP(15), [PTRN(sp), #(TF_X + 14 * CAP_WIDTH)]
	stp	CAP(12), CAP(13), [PTRN(sp), #(TF_X + 12 * CAP_WIDTH)]
	stp	CAP(10), CAP(11), [PTRN(sp), #(TF_X + 10 * CAP_WIDTH)]
	stp	CAP(8),  CAP(9),  [PTRN(sp), #(TF_X + 8  * CAP_WIDTH)]
	stp	CAP(6),  CAP(7),  [PTRN(sp), #(TF_X + 6  * CAP_WIDTH)]
	stp	CAP(4),  CAP(5),  [PTRN(sp), #(TF_X + 4  * CAP_WIDTH)]
	stp	CAP(2),  CAP(3),  [PTRN(sp), #(TF_X + 2  * CAP_WIDTH)]
	stp	CAP(0),  CAP(1),  [PTRN(sp), #(TF_X + 0  * CAP_WIDTH)]
#if __has_feature(capabilities)
	mrs	c9, ddc_el0
#endif
	mrs	CAP(10), CAPN(elr_el1)
	mrs	x11, spsr_el1
	mrs	x12, esr_el1
.if \el == 0
	mrs	CAP(18), CAPN(sp_el0)
.endif
#if __has_feature(capabilities)
	stp	c10, c9, [PTRN(sp), #(TF_ELR)]
#else
	str	x10, [sp, #(TF_ELR)]
#endif
	stp	w11, w12, [PTRN(sp), #(TF_SPSR)]
	stp	CAP(18), CAPN(lr), [PTRN(sp), #(TF_SP)]
	mrs	PTR(18), PTRN(tpidr_el1)
.endm

.macro	save_registers el
	add	PTR(29), PTRN(sp), #(TF_SIZE)
.if \el == 0
#if defined(PERTHREAD_SSP)
	/* Load the SSP canary to sp_el0 */
	ldr	x1, [x18, #(PC_CURTHREAD)]
	add	x1, x1, #(TD_MD_CANARY)
	msr	sp_el0, x1
#endif

	/* Apply the SSBD (CVE-2018-3639) workaround if needed */
	ldr	PTR(1), [PTR(18), #PC_SSBD]
	cbz	x1, 1f
	mov	w0, #1
	blr	PTR(1)
1:

#ifdef PAC
	ldr	PTR(0), [PTR(18), #PC_CURTHREAD]
	bl	ptrauth_exit_el0
#endif

	ldr	PTR(0), [PTR(18), #(PC_CURTHREAD)]
	bl	dbg_monitor_enter

	/* Unmask debug and SError exceptions */
	msr	daifclr, #(DAIF_D | DAIF_A)
.else
	/*
	 * Unmask debug and SError exceptions.
	 * For EL1, debug exceptions are conditionally unmasked in
	 * do_el1h_sync().
	 */
	msr	daifclr, #(DAIF_A)
.endif
.endm

.macro	restore_registers el
	/*
	 * Mask all exceptions, x18 may change in the interrupt exception
	 * handler.
	 */
	msr	daifset, #(DAIF_ALL)
.if \el == 0
	ldr	PTR(0), [PTR(18), #PC_CURTHREAD]
	mov	PTR(1), PTRN(sp)
	bl	dbg_monitor_exit

#ifdef PAC
	ldr	x0, [x18, #PC_CURTHREAD]
	bl	ptrauth_enter_el0
#endif

	/* Remove the SSBD (CVE-2018-3639) workaround if needed */
	ldr	PTR(1), [PTR(18), #PC_SSBD]
	cbz	x1, 1f
	mov	w0, #0
	blr	PTR(1)
1:
.endif
	ldp	CAP(18), CAPN(lr), [PTRN(sp), #(TF_SP)]
#if __has_feature(capabilities)
	ldr	w11, [PTRN(sp), #(TF_SPSR)]
	ldp	c10, c9, [PTRN(sp), #(TF_ELR)]
#else
	ldp	x10, x11, [sp, #(TF_ELR)]
#endif
.if \el == 0
	msr	CAPN(sp_el0), CAP(18)
.endif
	msr	spsr_el1, x11
	msr	CAPN(elr_el1), CAP(10)
#if __has_feature(capabilities)
	msr	ddc_el0, c9
#endif
	ldp	CAP(0),  CAP(1),  [PTRN(sp), #(TF_X + 0  * CAP_WIDTH)]
	ldp	CAP(2),  CAP(3),  [PTRN(sp), #(TF_X + 2  * CAP_WIDTH)]
	ldp	CAP(4),  CAP(5),  [PTRN(sp), #(TF_X + 4  * CAP_WIDTH)]
	ldp	CAP(6),  CAP(7),  [PTRN(sp), #(TF_X + 6  * CAP_WIDTH)]
	ldp	CAP(8),  CAP(9),  [PTRN(sp), #(TF_X + 8  * CAP_WIDTH)]
	ldp	CAP(10), CAP(11), [PTRN(sp), #(TF_X + 10 * CAP_WIDTH)]
	ldp	CAP(12), CAP(13), [PTRN(sp), #(TF_X + 12 * CAP_WIDTH)]
	ldp	CAP(14), CAP(15), [PTRN(sp), #(TF_X + 14 * CAP_WIDTH)]
	ldp	CAP(16), CAP(17), [PTRN(sp), #(TF_X + 16 * CAP_WIDTH)]
#if !__has_feature(capabilities) || defined(__CHERI_PURE_CAPABILITY__)
.if \el == 0
	/*
	 * We only restore the callee saved registers when returning to
	 * userland as they may have been updated by a system call or signal.
	 * Hybrid kernels, however, won't preserve the full capability
	 * registers so must always do this.
	 */
#endif
	ldp	CAP(18), CAP(19), [PTRN(sp), #(TF_X + 18 * CAP_WIDTH)]
	ldp	CAP(20), CAP(21), [PTRN(sp), #(TF_X + 20 * CAP_WIDTH)]
	ldp	CAP(22), CAP(23), [PTRN(sp), #(TF_X + 22 * CAP_WIDTH)]
	ldp	CAP(24), CAP(25), [PTRN(sp), #(TF_X + 24 * CAP_WIDTH)]
	ldp	CAP(26), CAP(27), [PTRN(sp), #(TF_X + 26 * CAP_WIDTH)]
	ldp	CAP(28), CAP(29), [PTRN(sp), #(TF_X + 28 * CAP_WIDTH)]
#if !__has_feature(capabilities) || defined(__CHERI_PURE_CAPABILITY__)
.else
	ldr	         CAP(29), [PTRN(sp), #(TF_X + 29 * CAP_WIDTH)]
.endif
#endif
.if \el == 0
	add	PTRN(sp), PTRN(sp), #(TF_SIZE)
.else
	mov	PTRN(sp), PTR(18)
	mrs	PTR(18), PTRN(tpidr_el1)
.endif
.endm

.macro	do_ast
	mrs	x19, daif
	/* Make sure the IRQs are enabled before calling ast() */
	bic	x19, x19, #PSR_I
1:
	/*
	 * Mask interrupts while checking the ast pending flag
	 */
	msr	daifset, #(DAIF_INTR)

	/* Read the current thread flags */
	ldr	PTR(1), [PTR(18), #PC_CURTHREAD]	/* Load curthread */
	ldr	w2, [PTR(1), #TD_FLAGS]

	/* Check if we have either bits set */
	mov	x3, #((TDF_ASTPENDING|TDF_NEEDRESCHED) >> 8)
	lsl	x3, x3, #8
	and	x2, x2, x3
	cbz	x2, 2f

	/* Restore interrupts */
	msr	daif, x19

	/* handle the ast */
	mov	PTR(0), PTRN(sp)
	bl	_C_LABEL(ast)

	/* Re-check for new ast scheduled */
	b	1b
2:
.endm

ENTRY(handle_el1h_sync)
	save_registers 1
	ldr	PTR(0), [PTR(18), #PC_CURTHREAD]
	mov	PTR(1), PTRN(sp)
	bl	do_el1h_sync
	restore_registers 1
	ERET
END(handle_el1h_sync)

ENTRY(handle_el1h_irq)
	save_registers 1
	mov	PTR(0), PTRN(sp)
	bl	intr_irq_handler
	restore_registers 1
	ERET
END(handle_el1h_irq)

ENTRY(handle_el0_sync)
	save_registers 0
	ldr	PTR(0), [PTR(18), #PC_CURTHREAD]
	mov	PTR(1), PTRN(sp)
	str	PTR(1), [PTR(0), #TD_FRAME]
	bl	do_el0_sync
	do_ast
	restore_registers 0
	ERET
END(handle_el0_sync)

ENTRY(handle_el0_irq)
	save_registers 0
	mov	PTR(0), PTRN(sp)
	bl	intr_irq_handler
	do_ast
	restore_registers 0
	ERET
END(handle_el0_irq)

ENTRY(handle_serror)
	save_registers 0
	mov	PTR(0), PTRN(sp)
1:	bl	do_serror
	b	1b
END(handle_serror)

ENTRY(handle_empty_exception)
	save_registers 0
	mov	PTR(0), PTRN(sp)
1:	bl	unhandled_exception
	b	1b
END(handle_empty_exception)

.macro	vector	name, el
	.align 7
	save_registers_head \el
	b	handle_\name
	dsb	sy
	isb
	/* Break instruction to ensure we aren't executing code here. */
	brk	0x42
.endm

.macro	vempty el
	vector	empty_exception \el
.endm

	.align 11
	.globl exception_vectors
exception_vectors:
	vempty 1		/* Synchronous EL1t */
	vempty 1		/* IRQ EL1t */
	vempty 1		/* FIQ EL1t */
	vempty 1		/* Error EL1t */

	vector el1h_sync 1	/* Synchronous EL1h */
	vector el1h_irq 1	/* IRQ EL1h */
	vempty 1		/* FIQ EL1h */
	vector serror 1		/* Error EL1h */

	vector el0_sync 0	/* Synchronous 64-bit EL0 */
	vector el0_irq 0	/* IRQ 64-bit EL0 */
	vempty 0		/* FIQ 64-bit EL0 */
	vector serror 0		/* Error 64-bit EL0 */

	vector el0_sync 0	/* Synchronous 32-bit EL0 */
	vector el0_irq 0	/* IRQ 32-bit EL0 */
	vempty 0		/* FIQ 32-bit EL0 */
	vector serror 0		/* Error 32-bit EL0 */

