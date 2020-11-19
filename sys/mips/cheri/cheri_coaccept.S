/*-
 * Copyright (c) 2018 Edward Tomasz Napierala <trasz@FreeBSD.org>
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

#include "opt_compat.h"
#include <sys/syscall.h>
#include <machine/asm.h>

#include <machine/cheriasm.h>
#include <machine/cherireg.h>
#include <machine/switcher.h>

.set noreorder
.set noat

#define	CLEARLO_BITS	(1 << 1  /* $at */ | \
			 /* preserve $v0 */ \
			 1 << 3  /* $v1 */ | \
			 1 << 4  /* $a0 */ | \
			 1 << 5  /* $a1 */ | \
			 1 << 6  /* $a2 */ | \
			 1 << 7  /* $a3 */ | \
			 1 << 8  /* $a4 */ | \
			 1 << 9  /* $a5 */ | \
			 1 << 10 /* $a6 */ | \
			 1 << 11 /* $a7 */ | \
			 1 << 12 /* $t4 */ | \
			 1 << 13 /* $t5 */ | \
			 1 << 14 /* $t6 */ | \
			 1 << 15 /* $t7 */)

#define	CLEARHI_BITS	(1 << 0  /* $s0 */ | \
			 1 << 1  /* $s1 */ | \
			 1 << 2  /* $s2 */ | \
			 1 << 3  /* $s3 */ | \
			 1 << 4  /* $s4 */ | \
			 1 << 5  /* $s5 */ | \
			 1 << 6  /* $s6 */ | \
			 1 << 7  /* $s7 */ | \
			 1 << 8  /* $t8 */ | \
			 1 << 9  /* $t9 */ | \
			 /* $k0 and $k1 are reserved for the kernel */ \
			 1 << 12 /* $gp */ | \
			 1 << 13 /* $sp */ | \
			 1 << 14 /* $s8 */ | \
			 1 << 15 /* $ra */)

#define	CCLEARLO_BITS	(1 << 0  /* DDC */ | \
			 1 << 1  /* PCC */ | \
			 1 << 2  /* IDC */ | \
			 1 << 3  /* $c3 */ | \
			 1 << 4  /* $c4 */ | \
			 1 << 5  /* $c5 */ | \
			 1 << 6  /* $c6 */ | \
			 1 << 7  /* $c7 */ | \
			 1 << 8  /* $c8 */ | \
			 1 << 9  /* $c9 */ | \
			 1 << 10 /* $c10 */ | \
			 /* $c11 is loaded from the caller's context */ \
			 1 << 12 /* $c12 */ | \
			 /* $c13 is loaded from the caller's context */ \
			 1 << 14 /* $c14 */ | \
			 1 << 15 /* $c15 */)

#define	CCLEARHI_BITS	(1 << 0  /* $c16 */ | \
			 1 << 1  /* $c17 */ | \
			 1 << 2  /* $c18 */ | \
			 1 << 3  /* $c19 */ | \
			 1 << 4  /* $c20 */ | \
			 1 << 5  /* $c21 */ | \
			 1 << 6  /* $c22 */ | \
			 1 << 7  /* $c23 */ | \
			 1 << 8  /* $c24 */ | \
			 1 << 9  /* $c25 */ | \
			 1 << 10 /* $c26 */)
			 /* $c27-$c33 are reserved for the kernel */

/*
 * Everywhere below the "caller" and "callee" terms are swapped.
 * In other words, the "caller" here is the same thread as the "caller"
 * on the cocall(2) side.  We - the thread calling into coaccept(2) - are
 * called the callee here.
 *
 * Register usage: we save and restore c11 (stack) and c13 (ra).
 * The rest gets zeroed; the libc wrappers are responsible for saving
 * and restoring the neccessary context.
 *
 * Note that this code executes while ignoring all the signals - a trapping
 * instruction will just get skipped over.
 *
 * Layout of struct switchercb, pointed to by $idc (callee side)
 * and, later on, $c25 (caller side):
 *
 * scb_peer_scb:	0($idc)
 * scb_td:		1*CHERICAP_SIZE($idc)
 * scb_borrower_td:	1*CHERICAP_SIZE+8($idc)
 * scb_unsealcap:	2*CHERICAP_SIZE($idc)
 * scb_tls:		3*CHERICAP_SIZE($idc)
 * scb_csp (c11):	4*CHERICAP_SIZE($idc)
 * scb_cra (c13):	5*CHERICAP_SIZE($idc)
 * scb_buf (c6):	6*CHERICAP_SIZE($idc)
 * scb_len (a0):	7*CHERICAP_SIZE($idc)
 * scb_cookiep (c5):	8*CHERICAP_SIZE($idc)
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
	csc	$c11, zero, SCB_CSP($idc)
	csc	$c13, zero, SCB_CRA($idc)

	/*
	 * Save the data transfer args.
	 */
	csc	$c6, zero, SCB_BUF($idc)
	csd	a0, zero, SCB_BUFLEN($idc)

	/*
	 * Save the pointer to the cookie.
	 */
	csc	$c5, zero, SCB_COOKIEP($idc)

	/*
	 * Load the capability to the caller's control block.
	 */
	clc	$c25, zero, SCB_CALLER_SCB($idc)

	/*
	 * Is this the first invocation of coaccept, or rather a response
	 * for a ccall()?  If the former - call copark(2).
	 */
	cgetlen	t0, $c25
	bnez	t0, 1f
	nop
	ccleartag $c24, $cnull
	csc	$c24, zero, SCB_CALLER_SCB($idc)
	li	v0, SYS_copark
	syscall
	nop

	/*
	 * Returned from copark(2).
	 *
	 * XXX: Wait for the spinlock to be released.
	 */
	b	3f
	nop

1:
	/*
	 * Save the pointer to the caller's kernel thread in the callee control
	 * block.  This is used by kernel to look up the real thread.
	 */
	cld	t8, zero, SCB_TD($c25)
	csd	t8, zero, SCB_BORROWER_TD($idc)

	/*
	 * Restore caller's TLS pointer.
	 */
	clc	$c11, zero, SCB_TLS($c25)
	cwritehwr	$c11, $chwr_userlocal

	/*
	 * Restore the caller's context.
	 */
	clc	$c11, zero, SCB_CSP($c25)
	clc	$c13, zero, SCB_CRA($c25)

	/*
	 * Do the data transfer back to the caller.  The reason
	 * for this is to mimic what the "syscall_timing pipeping"
	 * is doing - it transfers the data there and back, both
	 * sides.
	 */
	clc	$c7, zero, SCB_BUF($c25)
	cld	t0, zero, SCB_BUFLEN($c25)

	/*
	 * Compare buffer sizes, put the smaller one into t0.
	 */
	dsub	t8, a0, t0
	bgez	t8, 2f
	nop
	daddiu	t0, a0, 0

2:
	daddi 	t0, -CHERICAP_SIZE
	clc	$c16, t0, 0($c6)
	csc	$c16, t0, 0($c7)
	bgtz	t0, 2b
	nop

	li	v0, 0

	/*
	 * Zero out the scb_peer_scb variables, releasing the spinlock.
	 */
	csd	zero, zero, SCB_CALLER_SCB($c25)
	csd	zero, zero, SCB_CALLER_SCB($idc)

3:
	clearlo		CLEARLO_BITS
	clearhi		CLEARHI_BITS
	cclearlo	CCLEARLO_BITS
	cclearhi	CCLEARHI_BITS
#ifdef notyet
	fpclearlo	0xff
	fpclearhi	0xff
#endif

	/*
	 * Clear lo and hi.
	 */
	multu	zero, zero

	/*
	 * Bye!
	 */
	cjr	$c13
	nop

.globl _C_LABEL(eswitcher_coaccept)
_C_LABEL(eswitcher_coaccept):

.data
.globl szswitcher_coaccept
szswitcher_coaccept:
.long eswitcher_coaccept-switcher_coaccept
