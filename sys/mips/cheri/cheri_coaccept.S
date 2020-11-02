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

#ifdef CPU_CHERI
#include <machine/cheriasm.h>
#include <machine/cherireg.h>
#endif

.set noreorder
.set noat

#define	CLEARLO_BITS	(1 << 1  /* $at */ | \
			 1 << 2  /* $v0 */ | \
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

// XXX: $c0 (DDC)?
#define	CCLEARLO_BITS	(1 << 1  /* PCC */ | \
			 1 << 2  /* IDC */ | \
			 1 << 3  /* $c3 */ | \
			 1 << 4  /* $c4 */ | \
			 1 << 5  /* $c5 */ | \
			 1 << 6  /* $c6 */ | \
			 1 << 7  /* $c7 */ | \
			 1 << 8  /* $c8 */ | \
			 1 << 9  /* $c9 */ | \
			 1 << 10 /* $c10 */ | \
			 /* $c11 is loaded from the caller's context, despite being marked as caller-save */ \
			 1 << 12 /* $c12 */ | \
			 /* $c13 is loaded from the caller's context */ \
			 1 << 14 /* $c14 */ | \
			 1 << 15 /* $c15 */)

#define	CCLEARHI_BITS	(1 << 0  /* $c16 */ | \
			 /* $c17-$c24 are loaded from the caller's context */ \
			 1 << 9  /* $c25 */ | \
			 1 << 10 /* $c26 */)
			 /* $c27-$c33 are reserved for the kernel */

/*
 * Everywhere below the "caller" and "callee" terms are swapped.
 * In other words, the "caller" here is the same thread as the "caller"
 * on the cocall(2) side.  We - the thread calling into coaccept(2) - are
 * called the callee here.
 *
 * Register usage:
 *
 * Do not touch: a0-a7, c3-c10
 *
 * Save before calling the calee, and restore afterwards: s0-s7, gp, sp, s8
 *
 * Zero before calling the callee: at, v0, v1, t4-t7, s0-s7, t8, t9, gp, sp, s8, ra, hi, lo
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
 * ... and the rest:	4*CHERICAP_SIZE+XXX($idc)
 *
 */
.text
.globl _C_LABEL(switcher_coaccept)
_C_LABEL(switcher_coaccept):

	/*
	 * Save the callee's context in the callee's control block.  We are
	 * only saving the registeres which are defined as callee-saved;
	 * the caller-saved ones will be zeroed on return.
	 *
	 * The "4*CHERICAP_SIZE" is to skip over 'struct switchercb'.
	 *
	 * XXX: Make sure the IDC is cleared if we get a signal while here.
	 */
	csc	$c11, zero, 1*CHERICAP_SIZE+4*CHERICAP_SIZE+256($idc)
	csc	$c17, zero, 2*CHERICAP_SIZE+4*CHERICAP_SIZE+256($idc)
	csc	$c18, zero, 3*CHERICAP_SIZE+4*CHERICAP_SIZE+256($idc)
	csc	$c19, zero, 4*CHERICAP_SIZE+4*CHERICAP_SIZE+256($idc)
	csc	$c20, zero, 5*CHERICAP_SIZE+4*CHERICAP_SIZE+256($idc)
	csc	$c21, zero, 6*CHERICAP_SIZE+4*CHERICAP_SIZE+256($idc)
	csc	$c22, zero, 7*CHERICAP_SIZE+4*CHERICAP_SIZE+256($idc)
	csc	$c23, zero, 8*CHERICAP_SIZE+4*CHERICAP_SIZE+256($idc)
	csc	$c24, zero, 9*CHERICAP_SIZE+4*CHERICAP_SIZE+256($idc)

	/*
	 * Save the data transfer args.
	 */
	csc	$c6, zero, 10*CHERICAP_SIZE+4*CHERICAP_SIZE+256($idc)
	csd	a0, zero, 4*CHERICAP_SIZE+104($idc)

	/*
	 * Save the PCC, put there by coaccept().
	 */
	csc	$c13, zero, 11*CHERICAP_SIZE+4*CHERICAP_SIZE+256($idc)

	/*
	 * Save the pointer to the cookie.
	 */
	csc	$c5, zero, 12*CHERICAP_SIZE+4*CHERICAP_SIZE+256($idc)

	/*
	 * Load the capability to the caller's control block.
	 */
	clc	$c25, zero, 0($idc)

	/*
	 * Is this the first invocation of coaccept, or rather a response
	 * for a ccall()?  If the former - call copark(2).
	 */
	cbts	$c25, 1f
	nop
	li	v0, SYS_copark
	syscall
	nop

1:
	/*
	 * Save the capability to the caller's thread in the callee control block.
	 * This is used by kernel to look up the real thread.  Also clear
	 * the same field on the caller side.
	 */
	cld	t8, zero, 1*CHERICAP_SIZE($c25);
	csd	t8, zero, 1*CHERICAP_SIZE+8($idc)
	csd	zero, zero, 1*CHERICAP_SIZE+8($c25)

	/*
	 * Restore caller's TLS pointer.
	 */
	clc	$c11, zero, 3*CHERICAP_SIZE($c25)
	cwritehwr	$c11, $chwr_userlocal

	/*
	 * Restore the caller's context.
	 */
	clc	$c11, zero, 1*CHERICAP_SIZE+4*CHERICAP_SIZE+256($c25)
	clc	$c17, zero, 2*CHERICAP_SIZE+4*CHERICAP_SIZE+256($c25)
	clc	$c18, zero, 3*CHERICAP_SIZE+4*CHERICAP_SIZE+256($c25)
	clc	$c19, zero, 4*CHERICAP_SIZE+4*CHERICAP_SIZE+256($c25)
	clc	$c20, zero, 5*CHERICAP_SIZE+4*CHERICAP_SIZE+256($c25)
	clc	$c21, zero, 6*CHERICAP_SIZE+4*CHERICAP_SIZE+256($c25)
	clc	$c22, zero, 7*CHERICAP_SIZE+4*CHERICAP_SIZE+256($c25)
	clc	$c23, zero, 8*CHERICAP_SIZE+4*CHERICAP_SIZE+256($c25)
	clc	$c24, zero, 9*CHERICAP_SIZE+4*CHERICAP_SIZE+256($c25)

	clc	$c13, zero, 11*CHERICAP_SIZE+4*CHERICAP_SIZE+256($c25)

	/*
	 * Do the data transfer back to the caller.  The reason
	 * for this is to mimic what the "syscall_timing pipeping"
	 * is doing - it transfers the data there and back, both
	 * sides.
	 */
	clc	$c7, zero, 10*CHERICAP_SIZE+4*CHERICAP_SIZE+256($c25)
	cld	t0, zero, 4*CHERICAP_SIZE+104($c25)

	/*
	 * Compare buffer sizes, put the smaller one into t0.
	 */
	dsub	t8, a0, t0
	bgez	t8, 2f
	nop
	daddiu	t0, a0, 0

2:
	daddi	t0, -8
	cld	t1, t0, 0($c6)
	csd	t1, t0, 0($c7)
	bgtz	t0, 2b
	nop

	/*
	 * Zero out the scb_peer_scb variables, releasing the spinlock.
	 */
	csd	zero, zero, 0($c25);
	csd	zero, zero, 0($idc);

	clearlo		CLEARLO_BITS
	clearhi		CLEARHI_BITS
	cclearlo	CCLEARLO_BITS
	cclearhi	CCLEARHI_BITS

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
