/*-
 * Copyright (c) 2019 Alfredo Mazzinghi
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

#include <machine/asm.h>
#include <machine/cpu.h>
#include <machine/cpuregs.h>
#include <machine/regnum.h>
#include <machine/cheriasm.h>
#include <machine/cherireg.h>

#include "assym.inc"

	.set noreorder
	.text
/*
 * void _yamon_cheri_syscon_read(vaddr_t fn_addr, t_yamon_syscon_id id,
 * 	void *param, uint32_t size);
 */
NESTED(_yamon_cheri_syscon_read, 32, $c17)
	cincoffset	$c11, $c11, -(2 * CHERICAP_SIZE)
	csc	$c24, zero, 0($c11)
	csc	$c17, zero, CHERICAP_SIZE($c11)
	cincoffset	$c24, $c11, 0

	/* Switch to an unbounded kernel PCC */
	CAPTABLE_LOAD($c12, _C_LABEL(kernel_root_cap))
	clc	$c12, zero, 0($c12)
	REG_LI	t0, CHERI_PERMS_KERNEL_CODE
	candperm	$c12, $c12, t0
	cgetpcc		$c4
	cgetaddr	t0, $c4			// 1
	PTR_ADDIU	t0, t0, (4 * 6)		// 2
	csetaddr	$c12, $c12, t0		// 3
	cjr		$c12			// 4
	nop					// 5
yamon_pc:
	// 6 (land here)
	/* Destroy capability in c12, just in case */
	cmove	$c12, $cnull
	/* The jalr is relative to current pcc base */
	cgetpcc		$c4
	csetaddr	$c4, $c4, a0
	cgetoffset	t0, $c4
	move a0, a1	/* id */
	cgetaddr a1, $c3 /* param */
	/* size already in a2 */
	/* syscon_read(id, param, size) */
	jalr t0
	nop
	/* return already in v0 */

	clc	$c17, zero, CHERICAP_SIZE($c11)
	clc	$c24, zero, 0($c11)
	cjr	$c17
	cincoffset $c11, $c11, (2 * CHERICAP_SIZE)
END(_yamon_cheri_syscon_read)
