/*
 * Copyright (C) 2017 Alexandru Elisei <alexandru.elisei@gmail.com>
 * All rights reserved.
 * Copyright (c) 2021 Andrew Turner
 *
 * This software was developed by Alexandru Elisei under sponsorship
 * from the FreeBSD Foundation.
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
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


#include <machine/asm.h>
#include <machine/hypervisor.h>

#include "assym.inc"
#include "hyp.h"

.macro	save_host_registers
	/* TODO: Only store callee saved registers */
	sub	PTRN(sp), PTRN(sp), #(32 * CAP_WIDTH)
	str	CAP(30),          [PTRN(sp), #(30 * CAP_WIDTH)]
	stp	CAP(28), CAP(29), [PTRN(sp), #(28 * CAP_WIDTH)]
	stp	CAP(26), CAP(27), [PTRN(sp), #(26 * CAP_WIDTH)]
	stp	CAP(24), CAP(25), [PTRN(sp), #(24 * CAP_WIDTH)]
	stp	CAP(22), CAP(23), [PTRN(sp), #(22 * CAP_WIDTH)]
	stp	CAP(20), CAP(21), [PTRN(sp), #(20 * CAP_WIDTH)]
	stp	CAP(18), CAP(19), [PTRN(sp), #(18 * CAP_WIDTH)]
	stp	CAP(16), CAP(17), [PTRN(sp), #(16 * CAP_WIDTH)]
	stp	CAP(14), CAP(15), [PTRN(sp), #(14 * CAP_WIDTH)]
	stp	CAP(12), CAP(13), [PTRN(sp), #(12 * CAP_WIDTH)]
	stp	CAP(10), CAP(11), [PTRN(sp), #(10 * CAP_WIDTH)]
	stp	CAP(8),  CAP(9),  [PTRN(sp), #(8  * CAP_WIDTH)]
	stp	CAP(6),  CAP(7),  [PTRN(sp), #(6  * CAP_WIDTH)]
	stp	CAP(4),  CAP(5),  [PTRN(sp), #(4  * CAP_WIDTH)]
	stp	CAP(2),  CAP(3),  [PTRN(sp), #(2  * CAP_WIDTH)]
	stp	CAP(0),  CAP(1),  [PTRN(sp), #(0  * CAP_WIDTH)]
.endm

.macro	restore_host_registers
	/* TODO: Only restore callee saved registers */
	ldp	CAP(0),  CAP(1),  [PTRN(sp), #(0  * CAP_WIDTH)]
	ldp	CAP(2),  CAP(3),  [PTRN(sp), #(2  * CAP_WIDTH)]
	ldp	CAP(4),  CAP(5),  [PTRN(sp), #(4  * CAP_WIDTH)]
	ldp	CAP(6),  CAP(7),  [PTRN(sp), #(6  * CAP_WIDTH)]
	ldp	CAP(8),  CAP(9),  [PTRN(sp), #(8  * CAP_WIDTH)]
	ldp	CAP(10), CAP(11), [PTRN(sp), #(10 * CAP_WIDTH)]
	ldp	CAP(12), CAP(13), [PTRN(sp), #(12 * CAP_WIDTH)]
	ldp	CAP(14), CAP(15), [PTRN(sp), #(14 * CAP_WIDTH)]
	ldp	CAP(16), CAP(17), [PTRN(sp), #(16 * CAP_WIDTH)]
	ldp	CAP(18), CAP(19), [PTRN(sp), #(18 * CAP_WIDTH)]
	ldp	CAP(20), CAP(21), [PTRN(sp), #(20 * CAP_WIDTH)]
	ldp	CAP(22), CAP(23), [PTRN(sp), #(22 * CAP_WIDTH)]
	ldp	CAP(24), CAP(25), [PTRN(sp), #(24 * CAP_WIDTH)]
	ldp	CAP(26), CAP(27), [PTRN(sp), #(26 * CAP_WIDTH)]
	ldp	CAP(28), CAP(29), [PTRN(sp), #(28 * CAP_WIDTH)]
	ldr	CAP(30),          [PTRN(sp), #(30 * CAP_WIDTH)]
	add	PTRN(sp), PTRN(sp), #(32 * CAP_WIDTH)
.endm

.macro	save_guest_registers
	/* Back up x0 so we can use it as a temporary register */
	stp	CAP(0),  CAP(1),  [PTRN(sp), #(-2 * CAP_WIDTH)]!

	/* Restore the hypctx pointer */
	mrs	PTR(0), PTRN(tpidr_el2)

	stp	CAP(2),  CAP(3),  [PTR(0), #(TF_X + 2  * CAP_WIDTH)]
	stp	CAP(4),  CAP(5),  [PTR(0), #(TF_X + 4  * CAP_WIDTH)]
	stp	CAP(6),  CAP(7),  [PTR(0), #(TF_X + 6  * CAP_WIDTH)]
	stp	CAP(8),  CAP(9),  [PTR(0), #(TF_X + 8  * CAP_WIDTH)]
	stp	CAP(10), CAP(11), [PTR(0), #(TF_X + 10 * CAP_WIDTH)]
	stp	CAP(12), CAP(13), [PTR(0), #(TF_X + 12 * CAP_WIDTH)]
	stp	CAP(14), CAP(15), [PTR(0), #(TF_X + 14 * CAP_WIDTH)]
	stp	CAP(16), CAP(17), [PTR(0), #(TF_X + 16 * CAP_WIDTH)]
	stp	CAP(18), CAP(19), [PTR(0), #(TF_X + 18 * CAP_WIDTH)]
	stp	CAP(20), CAP(21), [PTR(0), #(TF_X + 20 * CAP_WIDTH)]
	stp	CAP(22), CAP(23), [PTR(0), #(TF_X + 22 * CAP_WIDTH)]
	stp	CAP(24), CAP(25), [PTR(0), #(TF_X + 24 * CAP_WIDTH)]
	stp	CAP(26), CAP(27), [PTR(0), #(TF_X + 26 * CAP_WIDTH)]
	stp	CAP(28), CAP(29), [PTR(0), #(TF_X + 28 * CAP_WIDTH)]

	str	CAPN(lr), [PTR(0), #(TF_LR)]

	/* Restore the saved x0 & x1 and save them */
	ldp	CAP(2),  CAP(3),  [PTRN(sp)], #(2 * CAP_WIDTH)
	stp	CAP(2),  CAP(3),  [PTR(0), #(TF_X + 0  * CAP_WIDTH)]
.endm

.macro	restore_guest_registers
	/*
	 * Copy the guest x0 and x1 to the stack so we can restore them
	 * after loading the other registers.
	 */
	ldp	CAP(2),  CAP(3),  [PTR(0), #(TF_X + 0  * CAP_WIDTH)]
	stp	CAP(2),  CAP(3),  [PTRN(sp), #-(2 * CAP_WIDTH)]!

	ldr	CAPN(lr), [PTR(0), #(TF_LR)]

	ldp	CAP(28), CAP(29), [PTR(0), #(TF_X + 28 * CAP_WIDTH)]
	ldp	CAP(26), CAP(27), [PTR(0), #(TF_X + 26 * CAP_WIDTH)]
	ldp	CAP(24), CAP(25), [PTR(0), #(TF_X + 24 * CAP_WIDTH)]
	ldp	CAP(22), CAP(23), [PTR(0), #(TF_X + 22 * CAP_WIDTH)]
	ldp	CAP(20), CAP(21), [PTR(0), #(TF_X + 20 * CAP_WIDTH)]
	ldp	CAP(18), CAP(19), [PTR(0), #(TF_X + 18 * CAP_WIDTH)]
	ldp	CAP(16), CAP(17), [PTR(0), #(TF_X + 16 * CAP_WIDTH)]
	ldp	CAP(14), CAP(15), [PTR(0), #(TF_X + 14 * CAP_WIDTH)]
	ldp	CAP(12), CAP(13), [PTR(0), #(TF_X + 12 * CAP_WIDTH)]
	ldp	CAP(10), CAP(11), [PTR(0), #(TF_X + 10 * CAP_WIDTH)]
	ldp	CAP(8),  CAP(9),  [PTR(0), #(TF_X + 8  * CAP_WIDTH)]
	ldp	CAP(6),  CAP(7),  [PTR(0), #(TF_X + 6  * CAP_WIDTH)]
	ldp	CAP(4),  CAP(5),  [PTR(0), #(TF_X + 4  * CAP_WIDTH)]
	ldp	CAP(2),  CAP(3),  [PTR(0), #(TF_X + 2  * CAP_WIDTH)]

	ldp	CAP(0),  CAP(1),  [PTRN(sp)], #(2 * CAP_WIDTH)
.endm

.macro vempty
	.align 7
	1: b	1b
.endm

.macro vector name
	.align 7
	b	handle_\name
.endm

	.section ".vmm_vectors","ax"
	.align 11
hyp_init_vectors:
	vempty		/* Synchronous EL2t */
	vempty		/* IRQ EL2t */
	vempty		/* FIQ EL2t */
	vempty		/* Error EL2t */

	vempty		/* Synchronous EL2h */
	vempty		/* IRQ EL2h */
	vempty		/* FIQ EL2h */
	vempty		/* Error EL2h */

	vector hyp_init	/* Synchronous 64-bit EL1 */
	vempty		/* IRQ 64-bit EL1 */
	vempty		/* FIQ 64-bit EL1 */
	vempty		/* Error 64-bit EL1 */

	vempty		/* Synchronous 32-bit EL1 */
	vempty		/* IRQ 32-bit EL1 */
	vempty		/* FIQ 32-bit EL1 */
	vempty		/* Error 32-bit EL1 */

	.text
	.align 11
hyp_vectors:
	vempty			/* Synchronous EL2t */
	vempty			/* IRQ EL2t */
	vempty			/* FIQ EL2t */
	vempty			/* Error EL2t */

	vector el2_el2h_sync	/* Synchronous EL2h */
	vector el2_el2h_irq	/* IRQ EL2h */
	vector el2_el2h_fiq	/* FIQ EL2h */
	vector el2_el2h_error	/* Error EL2h */

	vector el2_el1_sync64	/* Synchronous 64-bit EL1 */
	vector el2_el1_irq64	/* IRQ 64-bit EL1 */
	vector el2_el1_fiq64	/* FIQ 64-bit EL1 */
	vector el2_el1_error64	/* Error 64-bit EL1 */

	vempty			/* Synchronous 32-bit EL1 */
	vempty			/* IRQ 32-bit EL1 */
	vempty			/* FIQ 32-bit EL1 */
	vempty			/* Error 32-bit EL1 */

/*
 * Initialize the hypervisor mode with a new exception vector table, translation
 * table and stack.
 *
 * Expecting:
 * x0 - translation tables physical address
 * x1 - stack top virtual address
 * x2 - TCR_EL2 value
 * x3 - SCTLR_EL2 value
 * x4 - VTCR_EL2 value
 */
LENTRY(handle_hyp_init)
	/* Install the new exception vectors */
	adrp	x6, hyp_vectors
	add	x6, x6, :lo12:hyp_vectors
#if __has_feature(capabilities)
	cvtp	c6, x6
	msr	cvbar_el2, c6
#else
	msr	vbar_el2, x6
#endif
	/* Set the stack top address */
	mov	PTRN(sp), PTR(1)
	/* Use the host VTTBR_EL2 to tell the host and the guests apart */
	mov	x9, #VTTBR_HOST
	msr	vttbr_el2, x9
	/* Load the base address for the translation tables */
	msr	ttbr0_el2, x0
	/* Invalidate the TLB */
	tlbi	alle2
	/* Use the same memory attributes as EL1 */
	mrs	x9, mair_el1
	msr	mair_el2, x9
	/* Configure address translation */
	msr	tcr_el2, x2
	isb
	/* Set the system control register for EL2 */
	msr	sctlr_el2, x3
	/* Set the Stage 2 translation control register */
	msr	vtcr_el2, x4
	/* Return success */
	mov	x0, #0
	/* MMU is up and running */
	ERET
LEND(handle_hyp_init)

.macro do_world_switch_to_host
	save_guest_registers
	restore_host_registers

	/* Restore host VTTBR */
	mov	x9, #VTTBR_HOST
	msr	vttbr_el2, x9
.endm


.macro handle_el2_excp type
	/* Save registers before modifying so we can restore them */
	str	CAP(9), [PTRN(sp), #-16]!

	/* Test if the exception happened when the host was running */
	mrs	x9, vttbr_el2
	cmp	x9, #VTTBR_HOST
	beq	1f

	/* We got the exception while the guest was running */
	ldr	CAP(9), [PTRN(sp)], #16
	do_world_switch_to_host
	mov	x0, \type
	ret

1:
	/* We got the exception while the host was running */
	ldr	CAP(9), [PTRN(sp)], #16
	mov	x0, \type
	eret
.endm


LENTRY(handle_el2_el2h_sync)
	handle_el2_excp #EXCP_TYPE_EL2_SYNC
LEND(handle_el2_el2h_sync)

LENTRY(handle_el2_el2h_irq)
	handle_el2_excp #EXCP_TYPE_EL2_IRQ
LEND(handle_el2_el2h_irq)

LENTRY(handle_el2_el2h_fiq)
	handle_el2_excp #EXCP_TYPE_EL2_FIQ
LEND(handle_el2_el2h_fiq)

LENTRY(handle_el2_el2h_error)
	handle_el2_excp #EXCP_TYPE_EL2_ERROR
LEND(handle_el2_el2h_error)


LENTRY(handle_el2_el1_sync64)
	/* Save registers before modifying so we can restore them */
	str	CAP(9), [PTRN(sp), #-16]!

	/* Check for host hypervisor call */
	mrs	x9, vttbr_el2
	cmp	x9, #VTTBR_HOST
	ldr	CAP(9), [PTRN(sp)], #16 /* Restore the temp register */
	bne	1f

	/*
	 * Called from the host
	 */

	/* Check if this is a cleanup call and handle in a controlled state */
	cmp	x0, #(HYP_CLEANUP)
	b.eq	vmm_cleanup

	str	CAPN(lr), [PTRN(sp), #-16]!
	bl	vmm_hyp_enter
	ldr	CAPN(lr), [PTRN(sp)], #16
	ERET

1:	/* Guest exception taken to EL2 */
	do_world_switch_to_host
	mov	x0, #EXCP_TYPE_EL1_SYNC
	ret
LEND(handle_el2_el1_sync64)

/*
 * We only trap IRQ, FIQ and SError exceptions when a guest is running. Do a
 * world switch to host to handle these exceptions.
 */

LENTRY(handle_el2_el1_irq64)
	do_world_switch_to_host
	str	CAP(9), [PTRN(sp), #-16]!
	mrs	x9, ich_misr_el2
	cmp	x9, xzr
	beq	1f
	mov	x0, #EXCP_TYPE_MAINT_IRQ
	b	2f
1:
	mov	x0, #EXCP_TYPE_EL1_IRQ
2:
	ldr	CAP(9), [PTRN(sp)], #16
	ret
LEND(handle_el2_el1_irq)

LENTRY(handle_el2_el1_fiq64)
	do_world_switch_to_host
	mov	x0, #EXCP_TYPE_EL1_FIQ
	ret
LEND(handle_el2_el1_fiq64)

LENTRY(handle_el2_el1_error64)
	do_world_switch_to_host
	mov	x0, #EXCP_TYPE_EL1_ERROR
	ret
LEND(handle_el2_el1_error64)


/*
 * Usage:
 * uint64_t vmm_enter_guest(struct hypctx *hypctx)
 *
 * Expecting:
 * x0 - hypctx address
 */
ENTRY(vmm_enter_guest)
	/* Save hypctx address */
	msr	PTRN(tpidr_el2), PTR(0)

	save_host_registers
	restore_guest_registers

	/* Enter guest */
	eret
END(vmm_enter_guest)

/*
 * Usage:
 * void vmm_cleanup(uint64_t handle, void *hyp_stub_vectors)
 *
 * Expecting:
 * x1 - physical address of hyp_stub_vectors
 */
LENTRY(vmm_cleanup)
	/* Restore the stub vectors */
	msr	PTRN(vbar_el2), PTR(1)

	/* Disable the MMU */
	dsb	sy
	mrs	x2, sctlr_el2
	bic	x2, x2, #SCTLR_EL2_M
	msr	sctlr_el2, x2
	isb

	ERET
LEND(vmm_cleanup)
