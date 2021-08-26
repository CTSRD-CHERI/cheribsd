/*-
 * Copyright (c) 2014-2015 Robert N. M. Watson
 * Copyright (c) 2017 SRI International
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

/* XXXRW: Can I drop some of these? */
#include <machine/asm.h>
#include <machine/cpu.h>
#include <machine/regnum.h>
#include <machine/cpuregs.h>
#include <machine/pte.h>

#ifdef CPU_CHERI
#include <machine/cheriasm.h>
#include <cheri/cherireg.h>
#endif

#include "assym.inc"

.set noat
.set noreorder

/*
 * Copy a string from one capabilty to another up to a maximum length.
 * Return the length by reference.
 *
 * copystr_c() accepts:
 * c3 - source pointer
 * c4 - destination pointer
 * c5 - pointer length copied (size_t)
 * a0 - maximum length
 */
LEAF(copystr_c)
	li		v0, 0	/* Hopefully we succeed */
	beqz		a0, cstr_return_toolong /* Return if zero-length. */
	li		t1, 1	/* Length we will have copied in loop */
cstr_loop:
	clbu		t0, t1, -1($c3)
	beq		t0, zero, cstr_return_nul
	csb		t0, t1, -1($c4)
	bne		t1, a0, cstr_loop
	daddiu		t1, t1, 1

cstr_return_toolong:
	li		v0, ENAMETOOLONG
	daddiu		t1, t1, -1	/* Count is 1 too high */
cstr_return_nul:	/* Store length read if c5 is non-NULL */
#ifdef __CHERI_PURE_CAPABILITY__
	cbez		$c5, cstr_return
#else
	cgetdefault	$c3
	ctoptr		t0, $c5, $c3
	beq		t0, zero, cstr_return
#endif
	nop
	csd		t1, zero, 0($c5)	/* Store bytes copied */
cstr_return:
#ifdef __CHERI_PURE_CAPABILITY__
	cjr	$c17
	nop
#else
	jr	ra
	nop
#endif
END(copystr_c)
// CHERI CHANGES START
// {
//   "updated": 20200706,
//   "target_type": "kernel",
//   "changes_purecap": [
//     "support"
//   ]
// }
// CHERI CHANGES END
