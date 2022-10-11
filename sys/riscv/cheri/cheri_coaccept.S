/*-
 * Copyright (c) 2020 Edward Tomasz Napierala <trasz@FreeBSD.org>
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

#include <sys/syscall.h>
#include <machine/asm.h>
#include <machine/cherireg.h>
#include <machine/switcher.h>

#define	idc ct6

.option capmode

/*
 * Everywhere below the "caller" and "callee" terms are swapped.
 * In other words, the "caller" here is the same thread as the "caller"
 * on the cocall(2) side.  We - the thread calling into coaccept(2) - are
 * called the callee here.
 *
 * Register usage: we save and restore csp and cra.  The rest gets zeroed;
 * the libc wrappers are responsible for saving and restoring the context.
 *
 * Note that this code executes while ignoring all the signals - a trapping
 * instruction will just get skipped over.
 *
 * Layout of struct switchercb, pointed to by idc (callee side)
 * and, later on, ct0 (caller side):
 *
 * scb_caller_scb:	0(idc)
 * scb_callee_scb:	1*CHERICAP_SIZE(idc)
 * scb_td:		2*CHERICAP_SIZE(idc)
 * scb_borrower_td:	2*CHERICAP_SIZE+8(idc)
 * scb_unsealcap:	3*CHERICAP_SIZE(idc)
 * scb_csp:		4*CHERICAP_SIZE(idc)
 * scb_cra:		5*CHERICAP_SIZE(idc)
 * scb_outbuf (ca3):	6*CHERICAP_SIZE(idc)
 * scb_outlen (a4):	7*CHERICAP_SIZE(idc)
 * scb_inbuf (ca3):	8*CHERICAP_SIZE(idc)
 * scb_inlen (a4):	9*CHERICAP_SIZE(idc)
 * scb_cookiep (ca2):	10*CHERICAP_SIZE(idc)
 */

.text
.globl _C_LABEL(switcher_coaccept)
_C_LABEL(switcher_coaccept):
	/*
	 * Save the callee's stack pointer and return address (PCC)
	 * in the callee's control block.
	 *
	 * XXX: Make sure the IDC is cleared if we get a signal while here.
	 */
	csc	csp, SCB_CSP(idc)
	csc	cra, SCB_CRA(idc)

	/*
	 * Save the pointer to the cookie.
	 */
	csc	ca2, SCB_COOKIEP(idc)

	/*
	 * Save the data transfer args.
	 */
	csc	ca3, SCB_OUTBUF(idc)
	csd	a4, SCB_OUTLEN(idc)
	csc	ca5, SCB_INBUF(idc)
	csd	a6, SCB_INLEN(idc)

	/*
	 * Load the capability to the caller's control block.
	 */
6:
	clr.c.aqrl	ct0, SCB_CALLER_SCB(idc)

	/*
	 * Is this the first invocation of coaccept, or rather a response
	 * for a ccall()?  If the former - call copark(2).
	 */
	cgetlen	t1, ct0
	bnez	t1, 1f
	csc.c.aqrl	t1, cnull, SCB_CALLER_SCB(idc)
	bnez	t1, 6b
	li	t0, SYS_copark
	ecall

	/*
	 * Returned from copark(2).
	 *
	 * XXX: Wait for the spinlock to be released.
	 */
7:
	clr.c.aqrl	ct0, SCB_CALLER_SCB(idc)
	cgetlen	t1, ct0
	bnez	t1, 7b
	csc.c.aqrl	t1, cnull, SCB_CALLER_SCB(idc)
	bnez	t1, 7b
	j	3f

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
	cld	t1, SCB_BORROWER_TD(ct0)
	bnez	t1, 4f
	cld	t3, SCB_TD(ct0)
	csd	t3, SCB_BORROWER_TD(idc)
	/*
	 * Immediately swap back.
	 */
	cmove cs0, ct0
	li	t0, SYS_getpid
	ecall
	cmove ct0, cs0
	j	5f
4:
	csd	zero, SCB_BORROWER_TD(ct0)
5:

	/*
	 * Restore the caller's context.
	 */
	clc	csp, SCB_CSP(ct0)
	clc	cra, SCB_CRA(ct0)

	/*
	 * Do the data transfer back to the caller.  The reason
	 * for this is to mimic what the "syscall_timing pipeping"
	 * is doing - it transfers the data there and back, both
	 * sides.
	 */
	clc	ct4, SCB_INBUF(ct0)
	cld	t5, SCB_INLEN(ct0)

	/*
	 * Compare buffer sizes, put the smaller one into t5.
	 */
	sub	t3, a4, t5
	bgez	t3, 2f
	mv	t5, a4

2:
	clc	ct2, 0(ca3)
	csc	ct2, 0(ct4)
	cincoffset ca3, ca3, CHERICAP_SIZE
	cincoffset ct4, ct4, CHERICAP_SIZE
	addi	t5, t5, -CHERICAP_SIZE
	bgtz	t5, 2b

	/*
	 * Zero out the scb_peer_scb variables, releasing the spinlock.
	 */
	cmove	ct2, cnull
	csc		cnull, SCB_CALLEE_SCB(ct0)
	camoswap.c.aqrl	ct4, ct2, SCB_CALLER_SCB(idc)

	li	t0, 0
	li	a0, 0

3:
	/*
	 * XXX: We should use cclear here, but until it's supported in qemu, let's just...
	 */
	/* Preserve x1 (ra), and x2 (sp). */
	li x3, 0
	li x4, 0
	/* Preserve x5 (t0), used for errno (XXX). */
	li x6, 0
	li x7, 0
	li x8, 0
	li x9, 0
	/* Preserve x10 (a0), which is our return value. */
	li x11, 0
	li x12, 0
	li x13, 0
	li x14, 0
	li x15, 0
	li x16, 0
	li x17, 0
	li x18, 0
	li x19, 0
	li x20, 0
	li x21, 0
	li x22, 0
	li x23, 0
	li x24, 0
	li x25, 0
	li x26, 0
	li x27, 0
	li x28, 0
	li x29, 0
	li x30, 0
	li x31, 0

	/*
	 * Bye!
	 */
	cret
.globl _C_LABEL(eswitcher_coaccept)
_C_LABEL(eswitcher_coaccept):

.data
.globl szswitcher_coaccept
szswitcher_coaccept:
.long eswitcher_coaccept-switcher_coaccept
