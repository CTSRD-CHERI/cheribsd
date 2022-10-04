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

#include <sys/errno.h>
#include <machine/asm.h>
#include <machine/cherireg.h>
#include <machine/switcher.h>

#define	idc ct6

.option capmode

/*
 * Register usage: we save and restore csp and cra.  The rest gets zeroed;
 * the libc wrappers are responsible for saving and restoring the context.
 *
 * Layout of struct switchercb, pointed to by idc (caller)
 * and, later on, ct0 (callee):
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

#define	SIGCODE(sym)						\
	.text; .globl sym; .type sym,@object; .align 4; sym: .cfi_startproc

#define CSYM(x)							\
	.globl x; .type x,@object; x:

SIGCODE(switcher_cocall)
	/*
	 * Save the caller's stack pointer and return address (PCC)
	 * in the caller's control block.
	 *
	 * XXX: Make sure the IDC is cleared if we get a signal while here.
	 */
	csc	csp, SCB_CSP(idc)
	csc	cra, SCB_CRA(idc)

	/*
	 * Save the data transfer args.
	 */
	csc	ca3, SCB_OUTBUF(idc)
	csd	a4, SCB_OUTLEN(idc)
	csc	ca5, SCB_INBUF(idc)
	csd	a6, SCB_INLEN(idc)

	/*
	 * Unseal the callee's control block.
	 */
	clc	ct0, SCB_UNSEALCAP(idc)	/* Load the unsealing capability */
	cunseal	ct0, ca2, ct0		/* Unseal the callee control block */

	/*
	 * Save the capability to the callee's control block in the caller
	 * context.
	 */
	csc	ct0, SCB_CALLEE_SCB(idc)
1:
	/*
	 * Save the capability to the caller's control block in the callee
	 * context.  This also serves as the callee's spinlock.
	 */
	clr.c.aqrl	ct1, SCB_CALLER_SCB(ct0)
	cgettag		t2, ct1
	bnez		t2, 10f
	csc.c.aqrl	t3, idc, SCB_CALLER_SCB(ct0)
	bnez		t3, 1b

	/*
	 * If scb_borrower_td in the callee's scb is NULL, then
	 * the current thread is the caller thread and is going
	 * to borrow the callee thread.  Set scb_borrower_td in
	 * the caller's scb to the callee thread.  However, if
	 * scb_borrower_td is not NULL, then the callee's thread
	 * is returning to the callee and scb_borrower_thread
	 * needs to be set to NULL in the callee's scb.
	 */
	cld	t1, SCB_BORROWER_TD(ct0)
	bnez	t1, 5f
	cld	t4, SCB_TD(ct0)
	csd	t4, SCB_BORROWER_TD(idc)
	j	6f
5:
	csd	zero, SCB_BORROWER_TD(ct0)
6:

	/*
	 * Put the caller cookie (caller's data capability with the tag
	 * stripped off) where the callee wants it.
	 */
	clc	ct5, SCB_COOKIEP(ct0)
	beqz	t5, 2f
	ccleartag	ca1, ca1
	csc	ca1, 0(ct5)
2:

	/*
	 * Restore the callee's context.
	 */
	clc	csp, SCB_CSP(ct0)
	clc	cra, SCB_CRA(ct0)

	/*
	 * Do the data transfer.
	 */
	clc	ct4, SCB_INBUF(ct0)
	cld	t5, SCB_INLEN(ct0)

	/*
	 * Compare buffer sizes, put the smaller one into t5.
	 */
	sub	t3, a4, t5
	bgez	t3, 3f
	mv	t5, a4

CSYM(switcher_cocall_copy_start)
3:
	clc	ct2, 0(ca3)
	csc	ct2, 0(ct4)
	cincoffset ca3, ca3, CHERICAP_SIZE
	cincoffset ct4, ct4, CHERICAP_SIZE
	addi	t5, t5, -CHERICAP_SIZE
	bgtz	t5, 3b
CSYM(switcher_cocall_copy_end)

	li	t0, 0
	li	a0, 0

4:
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
	 * "Return" to the callee - or the caller, if returning error.
	 */
	cret
10:
	/*
	 * The spinlock is already taken.  Or is it?
	 */
	cgetlen	t2, ct1

	/*
	 * It is, return EAGAIN
	 */
	bnez	t2, 11f
	nop

	/*
	 * Nope - length zero means we need to return error encoded as offset.
	 */
	cgetoffset	a0, ct1
	beqz	a0, 11f
	li	t0, 1
	j	4b
11:
	li	a0, EBUSY
	li	t0, 1
	j	4b

CSYM(switcher_cocall_copy_onfault)
	/* Assumes a0 holds errno and that 'idc' points to caller's scb. */

	/* Clear state in the callee's scb. */
	clc	ct1, SCB_CALLEE_SCB(idc)
	clc	ct2, SCB_COOKIEP(ct1)
	beqz	t2, 5f
	csc	cnull, (ct2)
5:
	csc	cnull, SCB_CALLER_SCB(ct1)

	/* Clear state in the caller's scb. */
	csd	zero, SCB_BORROWER_TD(idc)
	csc	cnull, SCB_CALLEE_SCB(idc)

	clc	csp, SCB_CSP(idc)
	clc	cra, SCB_CRA(idc)

	li	t0, 1
	j	4b

END(switcher_cocall)
eswitcher_cocall:

	.data
	.align	3
	.globl szswitcher_cocall
	.type szswitcher_cocall,@object
szswitcher_cocall:
	.long eswitcher_cocall - switcher_cocall
	.size szswitcher_cocall, . - szswitcher_cocall
