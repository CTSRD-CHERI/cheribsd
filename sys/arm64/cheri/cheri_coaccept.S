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

#include <sys/syscall.h>
#include <machine/asm.h>
#include <machine/cherireg.h>
#include <machine/switcher.h>

/*
 * Everywhere below the "caller" and "callee" terms are swapped.
 * In other words, the "caller" here is the same thread as the "caller"
 * on the cocall(2) side.  We - the thread calling into coaccept(2) - are
 * called the callee here.
 *
 * Note that this code executes while ignoring all the signals - a trapping
 * instruction will just get skipped over.
 *
 * The switchercb is pointed to by c29/c29 (callee side) and, later on,
 * c8 (caller side).
 *
 */

.text
.globl _C_LABEL(switcher_coaccept)
_C_LABEL(switcher_coaccept):
	/*
	 * Save the callee's CPU context in the callee's control block.
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
	 * Save the pointer to the cookie.
	 */
	str	c2, SCB_COOKIEP(c29)

	/*
	 * Save the data transfer args.
	 */
	str	c3, SCB_OUTBUF(c29)
	str	x4, SCB_OUTLEN(c29)
	str	c5, SCB_INBUF(c29)
	str	x6, SCB_INLEN(c29)

	/*
	 * Load the capability to the caller's control block.
	 */
	ldr	c8, SCB_CALLER_SCB(c29)

	/*
	 * Is this the first invocation of coaccept, or rather a response
	 * for a ccall()?  If the former - call copark(2).
	 */
	gclen	x9, c8
	cbnz	x9, 1f
	str	czr, SCB_CALLER_SCB(c29)
	mov	x8, SYS_copark
	svc	#0

	/*
	 * Returned from copark(2).
	 *
	 * XXX: Wait for the spinlock to be released.
	 */
	b	3f

1:
	/*
	 * If scb_borrower_td in the caller's scb is NULL, then
	 * the current thread is the callee thread and is going
	 * to borrow the caller thread.  Set scb_borrower_td in
	 * the callee's scb to the caller thread.  However, if
	 * scb_borrower_td is not NULL, then the caller's thread
	 * is returning to the caller and scb_borrower_thread
	 * needs to be set to NULL in the caller's scb.
	 */
	ldr	x9, SCB_BORROWER_TD(c8)
	cbnz	x9, 4f
	ldr	x11, SCB_TD(c8)
	str	x11, SCB_BORROWER_TD(c29)
	b	5f
4:
	str	czr, SCB_BORROWER_TD(c8)
5:

	/*
	 * Restore the caller's context.
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
	 * Do the data transfer back to the caller.  The reason
	 * for this is to mimic what the "syscall_timing pipeping"
	 * is doing - it transfers the data there and back, both
	 * sides.
	 */
	ldr	c12, SCB_INBUF(c8)
	ldr	x13, SCB_INLEN(c8)

	/*
	 * Compare buffer sizes, put the smaller one into x13.
	 * XXX: use csel
	 */
	sub	x11, x4, x13
	cmp	x11, #0
	bge	2f
	mov	x13, x4

2:
	add	x13, x13, #-8
	ldr	x11, [c3, x13]
	str	x11, [c12, x13]
	cbnz	x13, 2b

	/*
	 * Zero out the scb_peer_scb variables, releasing the spinlock.
	 */
	str	czr, SCB_CALLEE_SCB(c8)
	str	czr, SCB_CALLER_SCB(c29)

	/*
	 * Return success; clear the carry flag.
	 */
	adds	x0, x0, x0
	mov	x0, 0
3:
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
	/* Preserve x18-x28, restored from caller's SCB. */
	mov	x29, 0
	/* Preserve x30 (lr) and csp, restored from calee's SCB. */

	/*
	 * Bye!
	 */
	rets	c30
.globl _C_LABEL(eswitcher_coaccept)
_C_LABEL(eswitcher_coaccept):

.data
.globl szswitcher_coaccept
szswitcher_coaccept:
.long eswitcher_coaccept-switcher_coaccept
