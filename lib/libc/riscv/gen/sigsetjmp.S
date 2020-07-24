/*-
 * Copyright (c) 2015 Ruslan Bukin <br@bsdpad.com>
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
__FBSDID("$FreeBSD$");

#include <machine/setjmp.h>

ENTRY(sigsetjmp)
#ifdef __CHERI_PURE_CAPABILITY__
	beqz	a1, 1f
	clgc	ct0, _C_LABEL(setjmp)
	cjr	ct0
1:
	clgc	ct0, _C_LABEL(_setjmp)
	cjr	ct0
#else
	beqz	a1, 1f
	tail	_C_LABEL(setjmp)
1:
	tail	_C_LABEL(_setjmp)
#endif
END(sigsetjmp)

ENTRY(siglongjmp)
#ifdef __CHERI_PURE_CAPABILITY__
	/* Load the _setjmp magic */
	cllc	ca2, .Lmagic
	cld	a2, (ca2)
	cld	a3, 0(ca0)

	/* Check the magic */
	beq	a2, a3, 1f
	clgc	ct0, _C_LABEL(longjmp)
	cjr	ct0
1:
	clgc	ct0, _C_LABEL(_longjmp)
	cjr	ct0
#else
	/* Load the _setjmp magic */
	ld	a2, .Lmagic
	ld	a3, 0(a0)

	/* Check the magic */
	beq	a2, a3, 1f
	tail	_C_LABEL(longjmp)
1:
	tail	_C_LABEL(_longjmp)
#endif

	.align	3
.Lmagic:
	.quad	_JB_MAGIC__SETJMP
END(siglongjmp)
