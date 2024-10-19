/*-
 * Copyright (c) 2014 Andrew Turner
 * Copyright (c) 2014 The FreeBSD Foundation
 *
 * Portions of this software were developed by Andrew Turner
 * under sponsorship from the FreeBSD Foundation
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
 *
 */

#include <machine/asm.h>
#include <machine/setjmp.h>
#include <sys/elf_common.h>

ENTRY(_setjmp)
	/* Store the magic value and stack pointer */
	ldr	x8, .Lmagic
	mov	REG(9), REGN(sp)
	stp	REG(8), REG(9), [REG(0)], #(REG_WIDTH * 2)
#ifdef CHERI_LIB_C18N
	/* Store the trusted stack pointer */
	stp	c0, c30, [csp, #-0x20]!
	bl	dl_c18n_get_trusted_stk
	ldp	c1, c30, [csp], #0x20
	str	c0, [c1], #REG_WIDTH
	mov	c0, c1
#endif

	/* Store the general purpose registers and lr */
	stp	REG(19), REG(20), [REG(0)], #(REG_WIDTH * 2)
	stp	REG(21), REG(22), [REG(0)], #(REG_WIDTH * 2)
	stp	REG(23), REG(24), [REG(0)], #(REG_WIDTH * 2)
	stp	REG(25), REG(26), [REG(0)], #(REG_WIDTH * 2)
	stp	REG(27), REG(28), [REG(0)], #(REG_WIDTH * 2)
	stp	REG(29), REGN(lr), [REG(0)], #(REG_WIDTH * 2)

#ifndef _STANDALONE
	/* Store the vfp registers */
	stp	d8, d9, [REG(0)], #16
	stp	d10, d11, [REG(0)], #16
	stp	d12, d13, [REG(0)], #16
	stp	d14, d15, [REG(0)], #16
#endif

	/* Return value */
	mov	x0, #0
	RETURN
	.align	3
.Lmagic:
	.quad	_JB_MAGIC__SETJMP
END(_setjmp)

ENTRY(_longjmp)
	/* Check the magic value */
	ldr	REG(8), [REG(0)], #(REG_WIDTH)
	ldr	x9, .Lmagic
	cmp	x8, x9
	b.ne	botch

#ifdef CHERI_LIB_C18N
	/*
	 * Preserve the arguments in callee-saved registers instead of pushing
	 * them onto the stack because stack unwinding will switch the stack.
	 */
	mov	c19, c0
	mov	c20, c1
	/* Pass the target untrusted stack pointer and trusted stack pointer */
	ldp	c0, c1, [c0]
	bl	dl_c18n_unwind_trusted_stk
	mov	c0, c19
	mov	c1, c20
#endif

	/* Restore the stack pointer */
	ldr	REG(8), [REG(0)], #(REG_WIDTH)
	mov	REGN(sp), REG(8)
#ifdef CHERI_LIB_C18N
	/* Skip the trusted stack pointer */
	add	c0, c0, #REG_WIDTH
#endif

	/* Restore the general purpose registers and lr */
	ldp	REG(19), REG(20), [REG(0)], #(REG_WIDTH * 2)
	ldp	REG(21), REG(22), [REG(0)], #(REG_WIDTH * 2)
	ldp	REG(23), REG(24), [REG(0)], #(REG_WIDTH * 2)
	ldp	REG(25), REG(26), [REG(0)], #(REG_WIDTH * 2)
	ldp	REG(27), REG(28), [REG(0)], #(REG_WIDTH * 2)
	ldp	REG(29), REGN(lr), [REG(0)], #(REG_WIDTH * 2)

#ifndef _STANDALONE
	/* Restore the vfp registers */
	ldp	d8, d9, [REG(0)], #16
	ldp	d10, d11, [REG(0)], #16
	ldp	d12, d13, [REG(0)], #16
	ldp	d14, d15, [REG(0)], #16
#endif

	/* Load the return value */
	cmp	x1, #0
	csinc	x0, x1, xzr, ne
	RETURN

botch:
#ifdef _STANDALONE
	b	botch
#else
	bl	_C_LABEL(longjmperror)
	bl	_C_LABEL(abort)
#endif
END(_longjmp)

GNU_PROPERTY_AARCH64_FEATURE_1_NOTE(GNU_PROPERTY_AARCH64_FEATURE_1_VAL)
