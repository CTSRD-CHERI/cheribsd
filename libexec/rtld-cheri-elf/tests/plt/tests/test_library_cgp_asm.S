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

#include <cheri/cherireg.h>
#include "SYS.h"

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

.macro PRINT msg
	.set push
	.set noat
	# write(1, msg, __builtin_strlen(msg))
	dla	a0, 1
	PIC_LOAD_CODE_PTR($c3, $at, .Lmsg_\@)
	.option pic0
	nop
	dla	a1, .Lmsg_\@_end - .Lmsg_\@
	nop
	SYSTRAP(write)
	nop
	.rodata
	.Lmsg_\@:
	.asciiz "\msg"
	.Lmsg_\@_end:
	.size .Lmsg_\@, .Lmsg_\@_end - .Lmsg_\@
	.text
	.set pop
.endm

LEAF(_get_library_cgp_with_null_caller_cgp)
	.set	noreorder
	.set	nomacro
	.set	noat
	PIC_PROLOGUE(_get_library_cgp_with_null_caller_cgp)
	# save important registers in callee-save registers:
	# FIXME: this breaks everything, we need to actually save to the stack
	cmove	$c18, $cra
	cmove	$c19, $cgp
	cmove	$c20, $cfp
	cmove	$c21, $csp

	PRINT "Hello from ASM\n"

	# now call the library function:
	# clc $c12, zero, %capcall(get_library_cgp)($cgp)
	clcbi $c12, %capcall20(get_library_cgp)($cgp)
	cgettag t0, $c12
	fail_if_not_eq t0, 1	# Check that we got a tag on $c12

	cgetnull	$cgp	# clear $cgp (to ensure that the plt stub loads it)
	cgetnull	$c3	# clear return register
	cjalr	$c12, $c17	 # call get_library_cgp
	nop

	# restore registers
	cmove	$cra, $c18
	cmove	$cgp, $c19
	cmove	$cfp, $c20
	cmove	$csp, $c21
	cgetnull	$c12

	cmove	$c4, $c3	# print clobbers $c3 -> use different caller-save reg
	PRINT "Sucessfully called library function from ASM\n"
	cmove	$c3, $c4	# restore again
	# return
	cjr $cra
	nop
	teq zero, zero
END(_get_library_cgp_with_null_caller_cgp)
