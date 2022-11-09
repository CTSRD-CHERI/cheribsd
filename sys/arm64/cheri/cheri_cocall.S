/*-
 * Copyright (c) 2020, 2021 Edward Tomasz Napierala <trasz@FreeBSD.org>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory as part of the CHERI for Hypervisors and Operating Systems
 * (CHaOS) project, funded by EPSRC grant EP/V000292/1.
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

#include <sys/errno.h>
#include <machine/asm.h>
#include <machine/cherireg.h>
#include <machine/switcher.h>

/*
 * Register usage: we save and restore csp and cra.  The rest gets zeroed;
 * the libc wrappers are responsible for saving and restoring the context.
 *
 * The switchercb is pointed to by c29 (caller) and, later on, c8 (callee).
 */

#define	SIGCODE(sym)						\
	.section .rodata; .globl sym; .type sym,@object; .align 4; sym: .cfi_startproc

#define CSYM(x)							\
	.globl x; .type x,@object; x:

SIGCODE(switcher_cocall)
	/*
	 * Save the caller's CPU context in the caller's control block.
	 *
	 * XXX: Make sure the IDC is cleared if we get a signal while here.
	 */
	mov	c8, csp
	str	c8, SCB_CSP(c29)
	str	c30, SCB_CRA(c29)

	str	q8, SCB_Q8(c29)
	str	q9, SCB_Q9(c29)
	str	q10, SCB_Q10(c29)
	str	q11, SCB_Q11(c29)
	str	q12, SCB_Q12(c29)
	str	q13, SCB_Q13(c29)
	str	q14, SCB_Q14(c29)
	str	q15, SCB_Q15(c29)
	mrs	x8, FPCR
	str	x8, SCB_FPCR(c29)
	mrs	x8, FPSR
	str	x8, SCB_FPSR(c29)

	str	c19, SCB_C19(c29)
	str	c20, SCB_C20(c29)
	str	c21, SCB_C21(c29)
	str	c22, SCB_C22(c29)
	str	c23, SCB_C23(c29)
	str	c24, SCB_C24(c29)
	str	c25, SCB_C25(c29)
	str	c26, SCB_C26(c29)
	str	c27, SCB_C27(c29)
	str	c28, SCB_C28(c29)

	/*
	 * Save CTPIDR_EL0, the TLS pointer.
	 */
	mrs	c8, CTPIDR_EL0
	str	c8, SCB_TLS(c29)

	/*
	 * Save the data transfer args.
	 */
	str	c3, SCB_OUTBUF(c29)
	str	x4, SCB_OUTLEN(c29)
	str	c5, SCB_INBUF(c29)
	str	x6, SCB_INLEN(c29)

	/*
	 * Unseal the callee's control block.
	 */
	ldr	c8, SCB_UNSEALCAP(c29)	/* Load the unsealing capability */
	unseal	c8, c2, c8		/* Unseal the callee control block */

	/*
	 * Save the capability to the callee's control block in the caller
	 * context.
	 */
	str	c8, SCB_CALLEE_SCB(c29)
1:
#ifdef notyet
	/*
	 * Save the capability to the caller's control block in the callee
	 * context.  This also serves as the callee's spinlock.
	 */
	clr.c	c9, (c8)
	cgettag	x10, c9
	bnez	x10, 10f
	csc.c	x11, c29, (c8)
	beqz	x11, 1b
#else
	/*
	 * Implement a trivial almost-spinlock.
	 */
	ldr	c9, SCB_CALLER_SCB(c8)
	gctag	x10, c9
	cbnz	x10, 10f
	str	c29, SCB_CALLER_SCB(c8)
#endif

	/*
	 * If scb_borrower_td in the callee's scb is NULL, then
	 * the current thread is the caller thread and is going
	 * to borrow the callee thread.  Set scb_borrower_td in
	 * the caller's scb to the callee thread.  However, if
	 * scb_borrower_td is not NULL, then the callee's thread
	 * is returning to the callee and scb_borrower_thread
	 * needs to be set to NULL in the callee's scb.
	 */
	ldr	x9, SCB_BORROWER_TD(c8)
	cbnz	x9, 5f
	ldr	x12, SCB_TD(c8)
	str	x12, SCB_BORROWER_TD(c29)
	b	6f
5:
	str	czr, SCB_BORROWER_TD(c8)
6:

	/*
	 * Put the caller cookie (caller's data capability with the tag
	 * stripped off) where the callee wants it.
	 */
	ldr	c13, SCB_COOKIEP(c8)
	cbz	x13, 2f
	clrtag	c1, c1
	str	c1, [c13]
2:

	/*
	 * Restore the callee's context.
	 */
	ldr	c10, SCB_CSP(c8)
	mov	csp, c10
	ldr	c30, SCB_CRA(c8)

#ifdef can_build_now
	ldr	q8, SCB_Q9(c8)
	ldr	q9, SCB_Q9(c8)
	ldr	q10, SCB_Q10(c8)
	ldr	q11, SCB_Q11(c8)
	ldr	q12, SCB_Q12(c8)
	ldr	q13, SCB_Q13(c8)
	ldr	q14, SCB_Q14(c8)
	ldr	q15, SCB_Q15(c8)
#else
	add	c9, c8, #3*CHERICAP_SIZE
	# XXX: Won't compile if the immediate is #0, that's why we need the line above
	ldr	q8, [c9, #1*CHERICAP_SIZE]
	ldr	q9, [c9, #2*CHERICAP_SIZE]
	ldr	q10, [c9, #3*CHERICAP_SIZE]
	ldr	q11, [c9, #4*CHERICAP_SIZE]
	ldr	q12, [c9, #5*CHERICAP_SIZE]
	ldr	q13, [c9, #6*CHERICAP_SIZE]
	ldr	q14, [c9, #7*CHERICAP_SIZE]
	ldr	q15, [c9, #8*CHERICAP_SIZE]
#endif
	ldr	x10, SCB_FPCR(c8);
	msr	FPCR, x10
	ldr	x10, SCB_FPSR(c8);
	msr	FPSR, x10

	ldr	c19, SCB_C19(c8)
	ldr	c20, SCB_C20(c8)
	ldr	c21, SCB_C21(c8)
	ldr	c22, SCB_C22(c8)
	ldr	c23, SCB_C23(c8)
	ldr	c24, SCB_C24(c8)
	ldr	c25, SCB_C25(c8)
	ldr	c26, SCB_C26(c8)
	ldr	c27, SCB_C27(c8)
	ldr	c28, SCB_C28(c8)

	/*
	 * Restore CTPIDR_EL0, the TLS pointer.
	 */
	ldr	c10, SCB_TLS(c8)
	msr	CTPIDR_EL0, c10

	/*
	 * Do the data transfer.
	 */
	ldr	c12, SCB_INBUF(c8)
	ldr	x13, SCB_INLEN(c8)

	/*
	 * Compare buffer sizes, put the smaller one into x13.
	 */
	sub	x11, x4, x13
	cmp	x11, #0
	bge	3f
	mov	x13, x4

CSYM(switcher_cocall_copy_start)
3:
	add	x13, x13, #-8
	ldr	x11, [c3, x13]
	str	x11, [c12, x13]
	cbnz	x13, 3b
CSYM(switcher_cocall_copy_end)

	/*
	 * We're returning success; clear the carry flag.
	 */
	mov	x0, 0
	adds	x0, x0, x0
4:
	/* Preserve x0, which is our return value. */
	mov	x1, 0
	mov	x2, 0
	mov	x3, 0
	mov	x4, 0
	mov	x5, 0
	mov	x6, 0
	mov	x7, 0
	mov	x8, 0
	mov	x9, 0
	mov	x11, 0
	mov	x12, 0
	mov	x13, 0
	mov	x14, 0
	mov	x15, 0
	mov	x16, 0
	mov	x17, 0
	mov	x18, 0
	/* Preserve x18-x28, restored from calee's SCB. */
	mov	x29, 0
	/* Preserve x30 (lr) and csp, restored from calee's SCB. */

	/*
	 * "Return" to the callee - or the caller, if returning error.
	 */
	rets	c30
10:
	/*
	 * The spinlock is already taken.  Or is it?
	 */
	gclen	x10, c9

	/*
	 * It is, go around.
	 */
	cbnz	x10, 1b

	/*
	 * Nope - length zero means we need to return error encoded as offset.
	 * Set the carry bit to let the libc stub know it's an error.
	 */
	gcoff	x0, c9
	subs	x0, x0, #0
	b	4b

CSYM(switcher_cocall_copy_onfault)
	/* Assumes x0 holds errno and that 'c29' points to caller's scb. */

	/* Clear state in the callee's scb. */
	ldr	c9, SCB_CALLEE_SCB(c29)
	ldr	c10, SCB_COOKIEP(c9)
	cbz	x10, 5f
	str	czr, [c10]
5:
	str	czr, SCB_CALLER_SCB(c9)

	/* Clear state in the caller's scb. */
	str	czr, SCB_BORROWER_TD(c29)
	str	czr, SCB_CALLEE_SCB(c29)

	ldr	c8, SCB_CSP(c29)
	mov	csp, c8
	ldr	clr, SCB_CRA(c29)

	// XXX: I have no idea how to get here.
	brk	42

	b	4b

END(switcher_cocall)

eswitcher_cocall:

	.data
	.align	3
	.globl szswitcher_cocall
	.type szswitcher_cocall,@object
szswitcher_cocall:
	.long eswitcher_cocall - switcher_cocall
	.size szswitcher_cocall, . - szswitcher_cocall
