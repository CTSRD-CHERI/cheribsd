/*-
 * Copyright (c) 2014, 2020 Andrew Turner
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

.macro	save_registers el
.if \el == 1
	mov	x18, sp
	sub	sp, sp, #128
.endif
	stp	c29, c30, [sp], #-32
	sub	sp, sp, #(TF_SIZE)
	stp	c28, c29, [sp, #(TF_X + 28 * 16)]
	stp	c26, c27, [sp, #(TF_X + 26 * 16)]
	stp	c24, c25, [sp, #(TF_X + 24 * 16)]
	stp	c22, c23, [sp, #(TF_X + 22 * 16)]
	stp	c20, c21, [sp, #(TF_X + 20 * 16)]
	stp	c18, c19, [sp, #(TF_X + 18 * 16)]
	stp	c16, c17, [sp, #(TF_X + 16 * 16)]
	stp	c14, c15, [sp, #(TF_X + 14 * 16)]
	stp	c12, c13, [sp, #(TF_X + 12 * 16)]
	stp	c10, c11, [sp, #(TF_X + 10 * 16)]
	stp	c8,  c9,  [sp, #(TF_X + 8  * 16)]
	stp	c6,  c7,  [sp, #(TF_X + 6  * 16)]
	stp	c4,  c5,  [sp, #(TF_X + 4  * 16)]
	stp	c2,  c3,  [sp, #(TF_X + 2  * 16)]
	stp	c0,  c1,  [sp, #(TF_X + 0  * 16)]
	mrs	c9, ddc_el0
	mrs	c10, celr_el1
	mrs	x11, spsr_el1
	mrs	x12, esr_el1
.if \el == 0
	mrs	c18, csp_el0
.endif
	str	c10, [sp, #(TF_ELR)]
	str	c9, [sp, #(TF_DDC)]
	stp	w11, w12, [sp, #(TF_SPSR)]
	stp	c18, clr, [sp, #(TF_SP)]
	mrs	x18, tpidr_el1
	add	x29, sp, #(TF_SIZE)
.if \el == 0
	/* Apply the SSBD (CVE-2018-3639) workaround if needed */
	ldr	x1, [x18, #PC_SSBD]
	cbz	x1, 1f
	mov	w0, #1
	blr	x1
1:

	ldr	x0, [x18, #(PC_CURTHREAD)]
	bl	dbg_monitor_enter
.endif
	msr	daifclr, #8	/* Enable the debug exception */
.endm

.macro	restore_registers el
.if \el == 1
	/*
	 * Disable interrupts and debug exceptions, x18 may change in the
	 * interrupt exception handler.  For EL0 exceptions, do_ast already
	 * did this.
	 */
	msr	daifset, #10
.endif
.if \el == 0
	ldr	x0, [x18, #PC_CURTHREAD]
	mov	x1, sp
	bl	dbg_monitor_exit

	/* Remove the SSBD (CVE-2018-3639) workaround if needed */
	ldr	x1, [x18, #PC_SSBD]
	cbz	x1, 1f
	mov	w0, #0
	blr	x1
1:
.endif
	ldp	c18, clr, [sp, #(TF_SP)]
	ldr	c10, [sp, #(TF_ELR)]
	ldr	c9, [sp, #(TF_DDC)]
	ldr	w11, [sp, #(TF_SPSR)]
.if \el == 0
	msr	csp_el0, c18
.endif
	msr	spsr_el1, x11
	msr	celr_el1, c10
	msr	ddc_el0, c9
	ldp	c0,  c1,  [sp, #(TF_X + 0  * 16)]
	ldp	c2,  c3,  [sp, #(TF_X + 2  * 16)]
	ldp	c4,  c5,  [sp, #(TF_X + 4  * 16)]
	ldp	c6,  c7,  [sp, #(TF_X + 6  * 16)]
	ldp	c8,  c9,  [sp, #(TF_X + 8  * 16)]
	ldp	c10, c11, [sp, #(TF_X + 10 * 16)]
	ldp	c12, c13, [sp, #(TF_X + 12 * 16)]
	ldp	c14, c15, [sp, #(TF_X + 14 * 16)]
	ldp	c16, c17, [sp, #(TF_X + 16 * 16)]
.if \el == 0
	/*
	 * We only restore the callee saved registers when returning to
	 * userland as they may have been updated by a system call or signal.
	 */
	ldp	c18, c19, [sp, #(TF_X + 18 * 16)]
	ldp	c20, c21, [sp, #(TF_X + 20 * 16)]
	ldp	c22, c23, [sp, #(TF_X + 22 * 16)]
	ldp	c24, c25, [sp, #(TF_X + 24 * 16)]
	ldp	c26, c27, [sp, #(TF_X + 26 * 16)]
	ldp	c28, c29, [sp, #(TF_X + 28 * 16)]
.else
	ldr	     x29, [sp, #(TF_X + 29 * 16)]
.endif
.if \el == 0
	add	sp, sp, #(TF_SIZE + 32)
.else
	mov	sp, x18
	mrs	x18, tpidr_el1
.endif
.endm

.macro	do_ast
	mrs	x19, daif
	/* Make sure the IRQs are enabled before calling ast() */
	bic	x19, x19, #PSR_I
1:
	/* Disable interrupts */
	msr	daifset, #10

	/* Read the current thread flags */
	ldr	x1, [x18, #PC_CURTHREAD]	/* Load curthread */
	ldr	x2, [x1, #TD_FLAGS]

	/* Check if we have either bits set */
	mov	x3, #((TDF_ASTPENDING|TDF_NEEDRESCHED) >> 8)
	lsl	x3, x3, #8
	and	x2, x2, x3
	cbz	x2, 2f

	/* Restore interrupts */
	msr	daif, x19

	/* handle the ast */
	mov	x0, sp
	bl	_C_LABEL(ast)

	/* Re-check for new ast scheduled */
	b	1b
2:
.endm

ENTRY(handle_el1h_sync)
	save_registers 1
	ldr	x0, [x18, #PC_CURTHREAD]
	mov	x1, sp
	bl	do_el1h_sync
	restore_registers 1
	ERET
END(handle_el1h_sync)

ENTRY(handle_el1h_irq)
	save_registers 1
	mov	x0, sp
	bl	intr_irq_handler
	restore_registers 1
	ERET
END(handle_el1h_irq)

ENTRY(handle_el0_sync)
	save_registers 0
	ldr	x0, [x18, #PC_CURTHREAD]
	mov	x1, sp
	str	x1, [x0, #TD_FRAME]
	bl	do_el0_sync
	do_ast
	restore_registers 0
	ERET
END(handle_el0_sync)

ENTRY(handle_el0_irq)
	save_registers 0
	mov	x0, sp
	bl	intr_irq_handler
	do_ast
	restore_registers 0
	ERET
END(handle_el0_irq)

ENTRY(handle_serror)
	save_registers 0
	mov	x0, sp
1:	bl	do_serror
	b	1b
END(handle_serror)

ENTRY(handle_empty_exception)
	save_registers 0
	mov	x0, sp
1:	bl	unhandled_exception
	b	1b
END(handle_unhandled_exception)

.macro	vempty
	.align 7
	b	handle_empty_exception
.endm

.macro	vector	name
	.align 7
	b	handle_\name
.endm

	.align 11
	.globl exception_vectors
exception_vectors:
	vempty			/* Synchronous EL1t */
	vempty			/* IRQ EL1t */
	vempty			/* FIQ EL1t */
	vempty			/* Error EL1t */

	vector el1h_sync	/* Synchronous EL1h */
	vector el1h_irq		/* IRQ EL1h */
	vempty			/* FIQ EL1h */
	vector serror		/* Error EL1h */

	vector el0_sync		/* Synchronous 64-bit EL0 */
	vector el0_irq		/* IRQ 64-bit EL0 */
	vempty			/* FIQ 64-bit EL0 */
	vector serror		/* Error 64-bit EL0 */

	vector el0_sync		/* Synchronous 32-bit EL0 */
	vector el0_irq		/* IRQ 32-bit EL0 */
	vempty			/* FIQ 32-bit EL0 */
	vector serror		/* Error 32-bit EL0 */


