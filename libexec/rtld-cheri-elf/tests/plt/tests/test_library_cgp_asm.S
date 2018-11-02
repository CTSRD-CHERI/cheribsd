/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2018 Alex Richadson <arichardson@FreeBSD.org>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
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

#include <machine/cherireg.h>

.macro fail_if_eq reg, imm
	.set push
	.set noat
	dli $at, \imm
	teq \reg, $at
	.set pop
.endm

.macro fail_if_not_eq reg, imm
	.set push
	.set noat
	dli $at, \imm
	tne \reg, $at
	.set pop
.endm

.global __start
.type	__start,@function
.set	nomicromips
.set	nomips16
.ent	__start
__start:                                # @__start
	.frame	$c24,48,$c17
	.mask 	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	.set	noat
.set FRAME_SIZE, (3*CHERICAP_SIZE)
	# save important registers on the stack
	cincoffset	$c11, $c11, -FRAME_SIZE
	csc	$cgp, $zero, (2 * CHERICAP_SIZE)($c11)	# $cgp
	csc	$cfp, $zero, (1 * CHERICAP_SIZE)($c11)	# frame ptr
	csc	$cra, $zero, 0($c11)    # return addr

	# now call the library function:
	clc $c12, $zero, %capcall(get_library_cgp_plus_global_int)($cgp)
	cgettag $t0, $c12
	fail_if_not_eq $t0, 1	# Check that we got a tag on $c12


	cgetnull	$cgp	# clear $cgp (to ensure that the plt stub loads it)
	cgetnull	$c3	# clear return register
	cjalr	$c12, $c17	 # call get_library_cgp_plus_global_int
	nop

	# Now check that the target $cgp is sensible
	fail_if_not_eq $t0, 1	# Check that we got a tag on $c12

	clc $cgp, $zero, (2 * CHERICAP_SIZE)($c11)	# reload original $cgp
	clc $c12, $zero, %capcall(exit)($cgp)
	li	$a0, 0
	cjr	$c12	# call exit(0)
	nop
	teq $zero, $zero
.end __start

#if 0
// TODO:
	// And should have a offset of 42 and nonzero base+length
	require(cheri_getoffset(library_cgp) == 42);
	require(cheri_getbase(library_cgp) != 0);
	require(cheri_getlen(library_cgp) != 0);
	// Check that we have permit_load and permit_load_capability on the library $cgp
	require((cheri_getperm(library_cgp) & CHERI_PERM_EXECUTE) == 0);
	require((cheri_getperm(library_cgp) & CHERI_PERM_STORE) == 0);
	require((cheri_getperm(library_cgp) & CHERI_PERM_STORE_CAP) == 0);
	require((cheri_getperm(library_cgp) & CHERI_PERM_EXECUTE) == 0);
	require((cheri_getperm(library_cgp) & CHERI_PERM_LOAD) == CHERI_PERM_LOAD);
	require((cheri_getperm(library_cgp) & CHERI_PERM_LOAD_CAP) == CHERI_PERM_LOAD);

	// Check that the library $cgp is different from the current $cgp
	require(cheri_getbase(library_cgp) != cheri_getbase(original_cgp));
	exit(0);
}

#endif
