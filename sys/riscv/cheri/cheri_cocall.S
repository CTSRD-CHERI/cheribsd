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
 * Note that this code executes while ignoring all the signals - a trapping
 * instruction will just get skipped over.
 *
 * Layout of struct switchercb, pointed to by idc (caller)
 * and, later on, ct0 (callee):
 *
 * scb_peer_scb:	0(idc)
 * scb_td:		1*CHERICAP_SIZE(idc)
 * scb_borrower_td:	1*CHERICAP_SIZE+8(idc)
 * scb_unsealcap:	2*CHERICAP_SIZE(idc)
 * scb_csp:		4*CHERICAP_SIZE(idc)
 * scb_cra:		5*CHERICAP_SIZE(idc)
 * scb_buf (ca3):	6*CHERICAP_SIZE(idc)
 * scb_buflen (a4):	7*CHERICAP_SIZE(idc)
 * scb_cookiep (ca2):	8*CHERICAP_SIZE(idc)
 */

.text
.globl _C_LABEL(switcher_cocall)
_C_LABEL(switcher_cocall):
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
	csc	ca3, SCB_BUF(idc)
	csd	a4, SCB_BUFLEN(idc)

	/*
	 * Unseal the callee's control block.
	 */
	clc	ct0, SCB_UNSEALCAP(idc)	/* Load the unsealing capability */
	cunseal	ct0, ca2, ct0		/* Unseal the calee control block */

	/*
	 * Save the capability to the callee's control block in the caller
	 * context.
	 */
	csc	ct0, SCB_PEER_SCB(idc)
1:
#ifdef notyet
	/*
	 * Save the capability to the caller's control block in the callee
	 * context.  This also serves as the callee's spinlock.
	 */
	clr.c	ct1, (ct0)
	cgettag	t2, ct1
	bne	t2, zero, 10f
	csc.c	t3, idc, (ct0)
	beq	t3, zero, 1b
#else
	/*
	 * Implement a trivial almost-spinlock.
	 */
	clc	ct1, SCB_PEER_SCB(ct0)
	cgettag	t2, ct1
	bne	t2, zero, 10f
	csc	idc, SCB_PEER_SCB(ct0)
#endif

	/*
	 * Save the capability to the callee's thread in the caller context.
	 * This is used by kernel to look up the real thread.  Also clear
	 * the same field on the callee side.
	 */
	cld	t4, SCB_TD(ct0)
	csd	t4, SCB_BORROWER_TD(idc)
	csd	zero, SCB_BORROWER_TD(ct0)

	/*
	 * Put the caller cookie (caller's data capability with the tag
	 * stripped off) where the callee wants it.
	 */
	clc	ct5, SCB_COOKIEP(ct0)
	beq	t5, zero, 2f		// XXX: Right opcode?
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
	clc	ct4, SCB_BUF(ct0)
	cld	t5, SCB_BUFLEN(ct0)

	/*
	 * Compare buffer sizes, put the smaller one into t5.
	 */
	sub	t3, a4, t5
	bgez	t3, 3f
	addi	t5, a4, 0

3:
	cld	t3, 0(ca3)
	csd	t3, 0(ct4)
	cincoffset ca3, ca3, 8
	cincoffset ct4, ct4, 8
	addi	t5, t5, -8
	bgtz	t5, 3b

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
	 * It is, go around.
	 */
	bne	t2, zero, 1b
	nop

	/*
	 * Nope - length zero means we need to return error encoded as offset.
	 */
	clc	ct2, SCB_CRA(idc)
	cgetoffset	a0, ct1
	li	t0, 1
	j	4b

.globl _C_LABEL(eswitcher_cocall)
_C_LABEL(eswitcher_cocall):

.data
.globl szswitcher_cocall
szswitcher_cocall:
.long eswitcher_cocall-switcher_cocall
