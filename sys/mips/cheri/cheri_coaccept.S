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
			 /* $v0 and $v1 are preserved and passed to the caller */ \
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

#define	CLEARHI_BITS	(/* s0-s7 are loaded from the caller's context */ \
			 1 << 8  /* $t8 */ | \
			 1 << 9  /* $t9 */)
			 /* $k0 and $k1 are reserved for the kernel */
			 /* $gp and $sp are loaded from the caller's context */
			 /* $s8 is loaded from the caller's context */
			 /* $ra is loaded from the caller's context */ 

// XXX: $c0?
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
			 /* $c11 is loaded from the caller's context */ \
			 1 << 12 /* $c12 */ | \
			 1 << 13 /* $c13 */ | \
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
 * XXX: Floating point
 */
.text
.globl _C_LABEL(switcher_coaccept)
_C_LABEL(switcher_coaccept):

	/*
	 * Save the callee's context in the callee's control block.  We are
	 * only saving the registeres which are defined as callee-saved;
	 * the caller-saved ones will be zeroed on return.
	 *
	 * The "3*CHERICAP_SIZE" is to skip over 'struct switcher_context'.
	 *
	 * XXX: Make sure the IDC is cleared if we get a signal while here.
	 */
	csd	s0, zero, 3*CHERICAP_SIZE+0($idc)
	csd	s1, zero, 3*CHERICAP_SIZE+8($idc)
	csd	s2, zero, 3*CHERICAP_SIZE+16($idc)
	csd	s3, zero, 3*CHERICAP_SIZE+24($idc)
	csd	s4, zero, 3*CHERICAP_SIZE+32($idc)
	csd	s5, zero, 3*CHERICAP_SIZE+40($idc)
	csd	s6, zero, 3*CHERICAP_SIZE+48($idc)
	csd	s7, zero, 3*CHERICAP_SIZE+56($idc)
	csd	gp, zero, 3*CHERICAP_SIZE+64($idc)
	csd	sp, zero, 3*CHERICAP_SIZE+72($idc)
	csd	s8, zero, 3*CHERICAP_SIZE+80($idc)
	csd	ra, zero, 3*CHERICAP_SIZE+88($idc)

	csc	$c17, zero, 1*CHERICAP_SIZE+3*CHERICAP_SIZE+256($idc)
	csc	$c18, zero, 2*CHERICAP_SIZE+3*CHERICAP_SIZE+256($idc)
	csc	$c19, zero, 3*CHERICAP_SIZE+3*CHERICAP_SIZE+256($idc)
	csc	$c20, zero, 4*CHERICAP_SIZE+3*CHERICAP_SIZE+256($idc)
	csc	$c21, zero, 5*CHERICAP_SIZE+3*CHERICAP_SIZE+256($idc)
	csc	$c22, zero, 6*CHERICAP_SIZE+3*CHERICAP_SIZE+256($idc)
	csc	$c23, zero, 7*CHERICAP_SIZE+3*CHERICAP_SIZE+256($idc)
	csc	$c24, zero, 8*CHERICAP_SIZE+3*CHERICAP_SIZE+256($idc)

	/*
	 * Save the data transfer args.
	 */
	csd	a0, zero, 3*CHERICAP_SIZE+96($idc)
	csd	a1, zero, 3*CHERICAP_SIZE+104($idc)

	/*
	 * Save the PCC, put there by coaccept().
	 */
	csc	$c11, zero, 9*CHERICAP_SIZE+3*CHERICAP_SIZE+256($idc)

	/*
	 * Load the capability to the caller's control block.
	 */
	clc	$c5, zero, 0($idc)

	/*
	 * Is this the first invocation of coaccept, or rather a response
	 * for a ccall()?  If the former - call copark(2).
	 */
	cbts	$c5, 1f
	nop
	li	v0, SYS_copark
	syscall
	nop

1:
	/*
	 * Zero out the sc_peer_context variables, releasing the spinlock.
	 */
	csd	zero, zero, 0($c5);
	csd	zero, zero, 0($idc);

	/*
	 * Save the capability to the caller's thread in the callee context.
	 * This is used by kernel to look up the real thread.  Also clear
	 * the same field on the caller side.
	 */
	cld	t8, zero, 1*CHERICAP_SIZE($c5);
	csd	t8, zero, 1*CHERICAP_SIZE+8($idc)
	csd	zero, zero, 1*CHERICAP_SIZE+8($c5)

	/*
	 * Restore the caller's context.
	 */
	cld	s0, zero, 3*CHERICAP_SIZE+0($c5)
	cld	s1, zero, 3*CHERICAP_SIZE+8($c5)
	cld	s2, zero, 3*CHERICAP_SIZE+16($c5)
	cld	s3, zero, 3*CHERICAP_SIZE+24($c5)
	cld	s4, zero, 3*CHERICAP_SIZE+32($c5)
	cld	s5, zero, 3*CHERICAP_SIZE+40($c5)
	cld	s6, zero, 3*CHERICAP_SIZE+48($c5)
	cld	s7, zero, 3*CHERICAP_SIZE+56($c5)
	cld	gp, zero, 3*CHERICAP_SIZE+64($c5)
	cld	sp, zero, 3*CHERICAP_SIZE+72($c5)
	cld	s8, zero, 3*CHERICAP_SIZE+80($c5)
	cld	ra, zero, 3*CHERICAP_SIZE+88($c5)

	clc	$c17, zero, 1*CHERICAP_SIZE+3*CHERICAP_SIZE+256($c5)
	clc	$c18, zero, 2*CHERICAP_SIZE+3*CHERICAP_SIZE+256($c5)
	clc	$c19, zero, 3*CHERICAP_SIZE+3*CHERICAP_SIZE+256($c5)
	clc	$c20, zero, 4*CHERICAP_SIZE+3*CHERICAP_SIZE+256($c5)
	clc	$c21, zero, 5*CHERICAP_SIZE+3*CHERICAP_SIZE+256($c5)
	clc	$c22, zero, 6*CHERICAP_SIZE+3*CHERICAP_SIZE+256($c5)
	clc	$c23, zero, 7*CHERICAP_SIZE+3*CHERICAP_SIZE+256($c5)
	clc	$c24, zero, 8*CHERICAP_SIZE+3*CHERICAP_SIZE+256($c5)

	clc	$c11, zero, 9*CHERICAP_SIZE+3*CHERICAP_SIZE+256($c5)

	/*
	 * Do the data transfer back to the caller.  The reason
	 * for this is to mimic what the "syscall_timing pipeping"
	 * is doing - it transfers the data there and back, both
	 * sides.
	 */
	cld	t0, zero, 3*CHERICAP_SIZE+96($c5)
	cld	t1, zero, 3*CHERICAP_SIZE+104($c5)

	/*
	 * Compare buffer sizes, put the smaller one into t1.
	 */
	dsub	t3, a1, t1
	bgez	t3, 2f
	nop
	daddiu	t1, a1, 0

2:
	ld	t2, 0(a0)
	sd	t2, 0(t0)
	daddiu	a0, 8
	daddiu	t0, 8
	daddi	t1, -8
	bgtz	t1, 2b
	nop

	//clearlo		CLEARLO_BITS
	//clearhi		CLEARHI_BITS
	cclearlo	CCLEARLO_BITS
	cclearhi	CCLEARHI_BITS

	/*
	 * Clear lo and hi.
	 */
	multu	zero, zero

	/*
	 * Bye!
	 */
	cjr	$c11
	nop

.globl _C_LABEL(eswitcher_coaccept)
_C_LABEL(eswitcher_coaccept):

.data
.globl szswitcher_coaccept
szswitcher_coaccept:
.long eswitcher_coaccept-switcher_coaccept
