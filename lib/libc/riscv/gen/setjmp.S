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

ENTRY(setjmp)
#ifdef __CHERI_PURE_CAPABILITY__
	_CADDI	PTR(sp), PTR(sp), -(2 * 16)
	_SC	PTR(a0), 0(PTR(sp))
	_SC	PTR(ra), 16(PTR(sp))

	/* Store the signal mask */
	_CADDI PTR(a2), PTR(a0), (_JB_SIGMASK * 16)	/* oset */
	li	a1, 0				/* set */
	li	a0, 1				/* SIG_BLOCK */
	_LGC	PTR(t0), _C_LABEL(sigprocmask)
	_JALR	PTR(t0)

	_LC	PTR(a0), 0(PTR(sp))
	_LC	PTR(ra), 16(PTR(sp))
	_CADDI	PTR(sp), PTR(sp), (2 * 16)

	/* Store the magic value and stack pointer */
	_LLC	PTR(t0), .Lmagic
	_LD	t0, (PTR(t0))
	_SC	PTR(t0), (0 * 16)(PTR(a0))
	_SC	PTR(sp), (1 * 16)(PTR(a0))
	_CADDI	PTR(a0), PTR(a0), (2 * 16)
#ifdef CHERI_LIB_C18N
	/* Store the trusted stack pointer */
	caddi	csp, csp, -(2 * 16)
	sc	ca0, (0 * 16)(csp)
	sc	cra, (1 * 16)(csp)
	cmv	ca0, cra
	lgc	ct0, _C_LABEL(dl_c18n_get_trusted_stack)
	jalr	ct0
	lc	ca1, (0 * 16)(csp)
	lc	cra, (1 * 16)(csp)
	caddi	csp, csp, (2 * 16)
	sc	ca0, 0(ca1)
	caddi	ca0, ca1, 16
#endif

	/* Store the general purpose registers and ra */
	_SC	PTR(s0), (0 * 16)(PTR(a0))
	_SC	PTR(s1), (1 * 16)(PTR(a0))
	_SC	PTR(s2), (2 * 16)(PTR(a0))
	_SC	PTR(s3), (3 * 16)(PTR(a0))
	_SC	PTR(s4), (4 * 16)(PTR(a0))
	_SC	PTR(s5), (5 * 16)(PTR(a0))
	_SC	PTR(s6), (6 * 16)(PTR(a0))
	_SC	PTR(s7), (7 * 16)(PTR(a0))
	_SC	PTR(s8), (8 * 16)(PTR(a0))
	_SC	PTR(s9), (9 * 16)(PTR(a0))
	_SC	PTR(s10), (10 * 16)(PTR(a0))
	_SC	PTR(s11), (11 * 16)(PTR(a0))
	_SC	PTR(ra), (12 * 16)(PTR(a0))
	_CSRR	PTR(t0), ddc
	_SC	PTR(t0), (13 * 16)(PTR(a0))
	_CADDI	PTR(a0), PTR(a0), (14 * 16)

#ifdef __riscv_float_abi_double
	/* Store the fpe registers */
	_FSD	fs0, (0 * 8)(PTR(a0))
	_FSD	fs1, (1 * 8)(PTR(a0))
	_FSD	fs2, (2 * 8)(PTR(a0))
	_FSD	fs3, (3 * 8)(PTR(a0))
	_FSD	fs4, (4 * 8)(PTR(a0))
	_FSD	fs5, (5 * 8)(PTR(a0))
	_FSD	fs6, (6 * 8)(PTR(a0))
	_FSD	fs7, (7 * 8)(PTR(a0))
	_FSD	fs8, (8 * 8)(PTR(a0))
	_FSD	fs9, (9 * 8)(PTR(a0))
	_FSD	fs10, (10 * 8)(PTR(a0))
	_FSD	fs11, (11 * 8)(PTR(a0))
	_CADDI	PTR(a0), PTR(a0), (12 * 8)
#endif

	/* Return value */
	li	a0, 0
	RETURN
#else
	addi	sp, sp, -(2 * 8)
	sd	a0, 0(sp)
	sd	ra, 8(sp)

	/* Store the signal mask */
	addi	a2, a0, (_JB_SIGMASK * 8)	/* oset */
	li	a1, 0				/* set */
	li	a0, 1				/* SIG_BLOCK */
	call	_C_LABEL(sigprocmask)

	ld	a0, 0(sp)
	ld	ra, 8(sp)
	addi	sp, sp, (2 * 8)

	/* Store the magic value and stack pointer */
	ld	t0, .Lmagic
	sd	t0, (0 * 8)(a0)
	sd	sp, (1 * 8)(a0)
	addi	a0, a0, (2 * 8)

	/* Store the general purpose registers and ra */
	sd	s0, (0 * 8)(a0)
	sd	s1, (1 * 8)(a0)
	sd	s2, (2 * 8)(a0)
	sd	s3, (3 * 8)(a0)
	sd	s4, (4 * 8)(a0)
	sd	s5, (5 * 8)(a0)
	sd	s6, (6 * 8)(a0)
	sd	s7, (7 * 8)(a0)
	sd	s8, (8 * 8)(a0)
	sd	s9, (9 * 8)(a0)
	sd	s10, (10 * 8)(a0)
	sd	s11, (11 * 8)(a0)
	sd	ra, (12 * 8)(a0)
	addi	a0, a0, (13 * 8)

#ifdef __riscv_float_abi_double
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
	addi	a0, a0, (12 * 8)
#endif

	/* Return value */
	li	a0, 0
	ret
#endif
	.align	3
.Lmagic:
	.quad	_JB_MAGIC_SETJMP
END(setjmp)

ENTRY(longjmp)
#ifdef __CHERI_PURE_CAPABILITY__
	/* Check the magic value */
	_LD	t0, 0(PTR(a0))
	_LLC	PTR(t1), .Lmagic
	_LD	t1, (PTR(t1))
	bne	t0, t1, botch

#ifdef CHERI_LIB_C18N
	/*
	 * Preserve the arguments in callee-saved registers instead of pushing
	 * them onto the stack because stack unwinding will switch the stack.
	 */
	cmv	cs0, ca0
	cmv	cs1, ca1
	/* Pass the target untrusted stack pointer and trusted stack pointer */
	lc	ca0, (1 * 16)(cs0)
	lc	ca1, (2 * 16)(cs0)
	lgc	ct0, _C_LABEL(dl_c18n_unwind_trusted_stack)
	jalr	ct0
	cmv	ca0, cs0
	cmv	ca1, cs1
#endif

	_CADDI	PTR(sp), PTR(sp), -(3 * 16)
	_SC	PTR(a0), (0 * 16)(PTR(sp))
	_SC	PTR(ra), (1 * 16)(PTR(sp))
	_SC	PTR(a1), (2 * 16)(PTR(sp))

	/* Restore the signal mask */
	li	a2, 0				/* oset */
	_CADDI	PTR(a1), PTR(a0), (_JB_SIGMASK * 16)	/* set */
	li	a0, 3				/* SIG_BLOCK */
	_LGC	PTR(t0), _C_LABEL(sigprocmask)
	_JALR	PTR(t0)

	_LC	PTR(a1), (2 * 16)(PTR(sp))
	_LC	PTR(ra), (1 * 16)(PTR(sp))
	_LC	PTR(a0), (0 * 16)(PTR(sp))
	_CADDI	PTR(sp), PTR(sp), (3 * 16)

	/* Restore the stack pointer */
	_LC	PTR(sp), 16(PTR(a0))
	_CADDI	PTR(a0), PTR(a0), (2 * 16)
#ifdef CHERI_LIB_C18N
	/* Skip the trusted stack pointer */
	caddi	ca0, ca0, 16
#endif

	/* Restore the general purpose registers and ra */
	_LC	PTR(s0), (0 * 16)(PTR(a0))
	_LC	PTR(s1), (1 * 16)(PTR(a0))
	_LC	PTR(s2), (2 * 16)(PTR(a0))
	_LC	PTR(s3), (3 * 16)(PTR(a0))
	_LC	PTR(s4), (4 * 16)(PTR(a0))
	_LC	PTR(s5), (5 * 16)(PTR(a0))
	_LC	PTR(s6), (6 * 16)(PTR(a0))
	_LC	PTR(s7), (7 * 16)(PTR(a0))
	_LC	PTR(s8), (8 * 16)(PTR(a0))
	_LC	PTR(s9), (9 * 16)(PTR(a0))
	_LC	PTR(s10), (10 * 16)(PTR(a0))
	_LC	PTR(s11), (11 * 16)(PTR(a0))
	_LC	PTR(ra), (12 * 16)(PTR(a0))
	_LC	PTR(t0), (13 * 16)(PTR(a0))
	_CSRW	ddc, PTR(t0)
	_CADDI	PTR(a0), PTR(a0), (14 * 16)

#ifdef __riscv_float_abi_double
	/* Restore the fpe registers */
	_FLD	fs0, (0 * 8)(PTR(a0))
	_FLD	fs1, (1 * 8)(PTR(a0))
	_FLD	fs2, (2 * 8)(PTR(a0))
	_FLD	fs3, (3 * 8)(PTR(a0))
	_FLD	fs4, (4 * 8)(PTR(a0))
	_FLD	fs5, (5 * 8)(PTR(a0))
	_FLD	fs6, (6 * 8)(PTR(a0))
	_FLD	fs7, (7 * 8)(PTR(a0))
	_FLD	fs8, (8 * 8)(PTR(a0))
	_FLD	fs9, (9 * 8)(PTR(a0))
	_FLD	fs10, (10 * 8)(PTR(a0))
	_FLD	fs11, (11 * 8)(PTR(a0))
	_CADDI	PTR(a0), PTR(a0), (12 * 8)
#endif

	/* Load the return value */
	mv	a0, a1
	RETURN

botch:
	_LGC	PTR(t0), _C_LABEL(longjmperror)
	_JALR	PTR(t0)
	_LGC	PTR(t0), _C_LABEL(abort)
	_JALR	PTR(t0)
#else
	/* Check the magic value */
	ld	t0, 0(a0)
	ld	t1, .Lmagic
	bne	t0, t1, botch

	addi	sp, sp, -(4 * 8)
	sd	a0, (0 * 8)(sp)
	sd	ra, (1 * 8)(sp)
	sd	a1, (2 * 8)(sp)

	/* Restore the signal mask */
	li	a2, 0				/* oset */
	addi	a1, a0, (_JB_SIGMASK * 8)	/* set */
	li	a0, 3				/* SIG_BLOCK */
	call	_C_LABEL(sigprocmask)

	ld	a1, (2 * 8)(sp)
	ld	ra, (1 * 8)(sp)
	ld	a0, (0 * 8)(sp)
	addi	sp, sp, (4 * 8)

	/* Restore the stack pointer */
	ld	t0, 8(a0)
	mv	sp, t0
	addi	a0, a0, (2 * 8)

	/* Restore the general purpose registers and ra */
	ld	s0, (0 * 8)(a0)
	ld	s1, (1 * 8)(a0)
	ld	s2, (2 * 8)(a0)
	ld	s3, (3 * 8)(a0)
	ld	s4, (4 * 8)(a0)
	ld	s5, (5 * 8)(a0)
	ld	s6, (6 * 8)(a0)
	ld	s7, (7 * 8)(a0)
	ld	s8, (8 * 8)(a0)
	ld	s9, (9 * 8)(a0)
	ld	s10, (10 * 8)(a0)
	ld	s11, (11 * 8)(a0)
	ld	ra, (12 * 8)(a0)
	addi	a0, a0, (13 * 8)

#ifdef __riscv_float_abi_double
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
	addi	a0, a0, (12 * 8)
#endif

	/* Load the return value */
	mv	a0, a1
	bnez	a1, 1f
	li	a0, 1
1:
	ret

botch:
	call	_C_LABEL(longjmperror)
	call	_C_LABEL(abort)
#endif
END(longjmp)
