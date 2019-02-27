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
#include <machine/asm.h>
#include <sys/errno.h>

#ifdef CPU_CHERI
#include <machine/cheriasm.h>
#include <machine/cherireg.h>
#endif

.set noreorder
.set noat

#define	CLEARLO_BITS	(1 << 1  /* $at */ | \
			 1 << 2  /* $v0 */ | \
			 1 << 3  /* $v1 */ | \
			 /* $a0-$a7 are preserved and passed to the callee */ \
			 1 << 12 /* $t4 */ | \
			 1 << 13 /* $t5 */ | \
			 1 << 14 /* $t6 */)
			 /* $t7 is used by libc stub to save $gp */

#define	CLEARHI_BITS	(/* s0-s7 are loaded from the callee context */ \
			 1 << 8  /* $t8 */ | \
			 1 << 9  /* $t9 */)
			 /* $k0 and $k1 are reserved for the kernel */
			 /* $gp and $sp are loaded from the callee context */
			 /* $s8 is loaded from the callee context */
			 /* $ra is loaded from the callee context */ 

// XXX: $c0 (DDC)?
#define	CCLEARLO_BITS	(1 << 1  /* PCC */ | \
			 1 << 2  /* IDC */ | \
			 1 << 3  /* $c3, containing the sealed code capability */ | \
			 1 << 4  /* $c4, containing the sealed data capability */ | \
			 /* $c5-$c10 are preserved and passed to the callee */ \
			 /* $c11 is loaded from the callee context, despite being marked as caller-save */ \
			 1 << 12 /* $c12 */ | \
			 /* $c13 is loaded from the callee context */ \
			 1 << 14 /* $c14 */ | \
			 1 << 15 /* $c15 */)

#define	CCLEARHI_BITS	(1 << 0  /* $c16 */ | \
			 /* $c17-$c24 are loaded from the callee context */ \
			 1 << 9  /* $c25 */ | \
			 1 << 10 /* $c26 */)
			 /* $c27-$c33 are reserved for the kernel */

/*
 * Register usage:
 *
 * Do not touch: a0-a7, c3-c10
 *
 * Save before calling the calee, and restore afterwards: s0-s7, gp, sp, s8
 *
 * Zero before calling the callee: at, v0, v1, t4-t6, s0-s7, t8, t9, gp, sp, s8, ra, hi, lo
 *
 * XXX: Floating point
 */
.text
.globl _C_LABEL(switcher_cocall)
_C_LABEL(switcher_cocall):

	/*
	 * Save the caller's context in the caller's control block.  We are
	 * only saving the registeres which are defined as callee-saved;
	 * the caller-saved ones will be zeroed on return.
	 *
	 * The "3*CHERICAP_SIZE" is to skip over 'struct switchercb'.
	 *
	 * XXX: Would be nice if we could redefine the ABI for cocall(2)
	 *      so that most of those don't need restoring.
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
	csd	$15, zero, 3*CHERICAP_SIZE+96($idc) // t7

	csc	$c11, zero, 1*CHERICAP_SIZE+3*CHERICAP_SIZE+256($idc)
	csc	$c17, zero, 2*CHERICAP_SIZE+3*CHERICAP_SIZE+256($idc)
	csc	$c18, zero, 3*CHERICAP_SIZE+3*CHERICAP_SIZE+256($idc)
	csc	$c19, zero, 4*CHERICAP_SIZE+3*CHERICAP_SIZE+256($idc)
	csc	$c20, zero, 5*CHERICAP_SIZE+3*CHERICAP_SIZE+256($idc)
	csc	$c21, zero, 6*CHERICAP_SIZE+3*CHERICAP_SIZE+256($idc)
	csc	$c22, zero, 7*CHERICAP_SIZE+3*CHERICAP_SIZE+256($idc)
	csc	$c23, zero, 8*CHERICAP_SIZE+3*CHERICAP_SIZE+256($idc)
	csc	$c24, zero, 9*CHERICAP_SIZE+3*CHERICAP_SIZE+256($idc)

	/*
	 * Save the data transfer args.
	 */
	csc	$c6, zero, 10*CHERICAP_SIZE+3*CHERICAP_SIZE+256($idc)
	csd	a0, zero, 3*CHERICAP_SIZE+104($idc)

	/*
	 * Save the PCC, put there by cocall().
	 */
	csc	$c13, zero, 11*CHERICAP_SIZE+3*CHERICAP_SIZE+256($idc)

	/*
	 * Unseal the callee's control block.
	 */
	clc	$c13, zero, 2*CHERICAP_SIZE($idc)	/* Load the unsealing capability */
	cunseal	$c25, $c5, $c13				/* Unseal the calee control block */

1:
	/*
	 * Save the capability to the caller's control block in the callee
	 * context.  This also serves as the callee's spinlock.
	 */
	cllc	$c12, $c25
	cbts	$c12, 10f
	nop
	cscc	t8, $idc, $c25
	beq	t8, zero, 1b
	/* no branch delay slot needed */

	/*
	 * Save the capability to the callee's thread in the caller context.
	 * This is used by kernel to look up the real thread.  Also clear
	 * the same field on the callee side.
	 */
	cld	t8, zero, 1*CHERICAP_SIZE($c25);
	csd	t8, zero, 1*CHERICAP_SIZE+8($idc)
	csd	zero, zero, 1*CHERICAP_SIZE+8($c25)

	/*
	 * Save the capability to the callee's control block in the caller
	 * context.
	 */
	csc	$c25, zero, 0($idc);

	/*
	 * Put the caller cookie (caller's data capability with the tag
	 * stripped off) where the callee wants it.
	 */
	clc	$c24, zero, 12*CHERICAP_SIZE+3*CHERICAP_SIZE+256($c25)
	ccleartag	$c4, $c4
	csc	$c4, zero, 0($c24)

	/*
	 * Restore the callee's context.
	 */
	cld	s0, zero, 3*CHERICAP_SIZE+0($c25)
	cld	s1, zero, 3*CHERICAP_SIZE+8($c25)
	cld	s2, zero, 3*CHERICAP_SIZE+16($c25)
	cld	s3, zero, 3*CHERICAP_SIZE+24($c25)
	cld	s4, zero, 3*CHERICAP_SIZE+32($c25)
	cld	s5, zero, 3*CHERICAP_SIZE+40($c25)
	cld	s6, zero, 3*CHERICAP_SIZE+48($c25)
	cld	s7, zero, 3*CHERICAP_SIZE+56($c25)
	cld	gp, zero, 3*CHERICAP_SIZE+64($c25)
	cld	sp, zero, 3*CHERICAP_SIZE+72($c25)
	cld	s8, zero, 3*CHERICAP_SIZE+80($c25)
	cld	ra, zero, 3*CHERICAP_SIZE+88($c25)
	cld	$15, zero, 3*CHERICAP_SIZE+96($c25) // t7

	clc	$c11, zero, 1*CHERICAP_SIZE+3*CHERICAP_SIZE+256($c25)
	clc	$c17, zero, 2*CHERICAP_SIZE+3*CHERICAP_SIZE+256($c25)
	clc	$c18, zero, 3*CHERICAP_SIZE+3*CHERICAP_SIZE+256($c25)
	clc	$c19, zero, 4*CHERICAP_SIZE+3*CHERICAP_SIZE+256($c25)
	clc	$c20, zero, 5*CHERICAP_SIZE+3*CHERICAP_SIZE+256($c25)
	clc	$c21, zero, 6*CHERICAP_SIZE+3*CHERICAP_SIZE+256($c25)
	clc	$c22, zero, 7*CHERICAP_SIZE+3*CHERICAP_SIZE+256($c25)
	clc	$c23, zero, 8*CHERICAP_SIZE+3*CHERICAP_SIZE+256($c25)
	clc	$c24, zero, 9*CHERICAP_SIZE+3*CHERICAP_SIZE+256($c25)

	clc	$c13, zero, 11*CHERICAP_SIZE+3*CHERICAP_SIZE+256($c25)

	/*
	 * Do the data transfer.
	 */
	clc	$c7, zero, 10*CHERICAP_SIZE+3*CHERICAP_SIZE+256($c25)
	cld	t0, zero, 3*CHERICAP_SIZE+104($c25)

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

	clearlo		CLEARLO_BITS
	clearhi		CLEARHI_BITS
	cclearlo	CCLEARLO_BITS
	cclearhi	CCLEARHI_BITS

	/*
	 * Clear lo and hi.
	 */
	multu	zero, zero

	/*
	 * "Return" to the callee.
	 */
	cjr	$c13
	nop
10:
	/*
	 * The spinlock is already taken.  Or is it?
	 */
	cgetlen	t8, $c12

	/*
	 * It is, go around.
	 */
	bne	t8, zero, 1b
	nop

	/*
	 * Nope - length zero means the callee is dead.
	 */
	cjr	$c13
	li	v0, EPIPE

.globl _C_LABEL(eswitcher_cocall)
_C_LABEL(eswitcher_cocall):

.data
.globl szswitcher_cocall
szswitcher_cocall:
.long eswitcher_cocall-switcher_cocall
