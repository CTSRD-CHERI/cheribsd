/*-
 * Copyright (c) 2015-2016 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * Portions of this software were developed by SRI International and the
 * University of Cambridge Computer Laboratory under DARPA/AFRL contract
 * FA8750-10-C-0237 ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Portions of this software were developed by the University of Cambridge
 * Computer Laboratory as part of the CTSRD Project, with support from the
 * UK Higher Education Innovation Fund (HEIF).
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
#include <machine/setjmp.h>

ENTRY(_setjmp)
	/* Store the magic value and stack pointer */
	LLA_PTR	t0, .Lmagic
	ld	t0, (t0)
	S_PTR	t0, (0 * PTR_WIDTH)(a0)
	S_PTR	sp, (1 * PTR_WIDTH)(a0)
	ADDI_PTR	a0, a0, (2 * PTR_WIDTH)

	/* Store the general purpose registers and ra */
	S_PTR	s0, (0 * PTR_WIDTH)(a0)
	S_PTR	s1, (1 * PTR_WIDTH)(a0)
	S_PTR	s2, (2 * PTR_WIDTH)(a0)
	S_PTR	s3, (3 * PTR_WIDTH)(a0)
	S_PTR	s4, (4 * PTR_WIDTH)(a0)
	S_PTR	s5, (5 * PTR_WIDTH)(a0)
	S_PTR	s6, (6 * PTR_WIDTH)(a0)
	S_PTR	s7, (7 * PTR_WIDTH)(a0)
	S_PTR	s8, (8 * PTR_WIDTH)(a0)
	S_PTR	s9, (9 * PTR_WIDTH)(a0)
	S_PTR	s10, (10 * PTR_WIDTH)(a0)
	S_PTR	s11, (11 * PTR_WIDTH)(a0)
	S_PTR	ra, (12 * PTR_WIDTH)(a0)
#ifdef __CHERI__
	GET_DDC(t0)
	S_PTR	t0, (13 * 16)(a0)
	ADDI_PTR	a0, a0, (14 * PTR_WIDTH)
#else
	ADDI_PTR	a0, a0, (13 * PTR_WIDTH)
#endif

#if !defined(_STANDALONE) && defined(__riscv_float_abi_double)
	/* Store the fpe registers */
	fsd	fs0, (0 * 8)(a0)
	fsd	fs1, (1 * 8)(a0)
	fsd	fs2, (2 * 8)(a0)
	fsd	fs3, (3 * 8)(a0)
	fsd	fs4, (4 * 8)(a0)
	fsd	fs5, (5 * 8)(a0)
	fsd	fs6, (6 * 8)(a0)
	fsd	fs7, (7 * 8)(a0)
	fsd	fs8, (8 * 8)(a0)
	fsd	fs9, (9 * 8)(a0)
	fsd	fs10, (10 * 8)(a0)
	fsd	fs11, (11 * 8)(a0)
	ADDI_PTR	a0, a0, (12 * 8)
#endif

	/* Return value */
	li	a0, 0
	ret

	.align	3
.Lmagic:
	.quad	_JB_MAGIC__SETJMP
END(_setjmp)

ENTRY(_longjmp)
	/* Check the magic value */
	ld	t0, 0(a0)
	LLA_PTR	t1, .Lmagic
	ld	t1, (t1)
	bne	t0, t1, botch

	/* Restore the stack pointer */
	L_PTR	sp, PTR_WIDTH(a0)
	ADDI_PTR	a0, a0, (2 * PTR_WIDTH)

	/* Restore the general purpose registers and ra */
	L_PTR	s0, (0 * PTR_WIDTH)(a0)
	L_PTR	s1, (1 * PTR_WIDTH)(a0)
	L_PTR	s2, (2 * PTR_WIDTH)(a0)
	L_PTR	s3, (3 * PTR_WIDTH)(a0)
	L_PTR	s4, (4 * PTR_WIDTH)(a0)
	L_PTR	s5, (5 * PTR_WIDTH)(a0)
	L_PTR	s6, (6 * PTR_WIDTH)(a0)
	L_PTR	s7, (7 * PTR_WIDTH)(a0)
	L_PTR	s8, (8 * PTR_WIDTH)(a0)
	L_PTR	s9, (9 * PTR_WIDTH)(a0)
	L_PTR	s10, (10 * PTR_WIDTH)(a0)
	L_PTR	s11, (11 * PTR_WIDTH)(a0)
	L_PTR	ra, (12 * PTR_WIDTH)(a0)
#ifdef __CHERI__
	L_PTR	t0, (13 * PTR_WIDTH)(a0)
	SET_DDC(t0)
	ADDI_PTR	a0, a0, (14 * PTR_WIDTH)
#else
	ADDI_PTR	a0, a0, (13 * PTR_WIDTH)
#endif

#if !defined(_STANDALONE) && defined(__riscv_float_abi_double)
	/* Restore the fpe registers */
	fld	fs0, (0 * 8)(a0)
	fld	fs1, (1 * 8)(a0)
	fld	fs2, (2 * 8)(a0)
	fld	fs3, (3 * 8)(a0)
	fld	fs4, (4 * 8)(a0)
	fld	fs5, (5 * 8)(a0)
	fld	fs6, (6 * 8)(a0)
	fld	fs7, (7 * 8)(a0)
	fld	fs8, (8 * 8)(a0)
	fld	fs9, (9 * 8)(a0)
	fld	fs10, (10 * 8)(a0)
	fld	fs11, (11 * 8)(a0)
	ADDI_PTR	a0, a0, (12 * 8)
#endif

	/* Load the return value */
	mv	a0, a1
	bnez	a1, 1f
	li	a0, 1
1:
	ret

botch:
#ifdef _STANDALONE
	j	botch
#else
	call	_C_LABEL(longjmperror)
	call	_C_LABEL(abort)
#endif
END(_longjmp)
