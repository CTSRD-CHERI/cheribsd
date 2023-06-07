/*-
 * Copyright (c) 2014 The FreeBSD Foundation
 *
 * This software was developed by Andrew Turner under sponsorship from
 * the FreeBSD Foundation.
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

#include "assym.inc"
#include <sys/syscall.h>
#include <machine/asm.h>

/*
 * sigcode has to be labeled as an #object type so that the symbols
 * resolve to the correct address as a source for copies.  This also
 * ensures that captable pointers to it will be able to read it.  This
 * is fine as the code is never executed directly in the kernel, just
 * copied to places for userland to execute.
 */
#define	SIGCODE(sym)						\
	.section .rodata; .globl sym; .align 2; .type sym,#object; sym:	\
	.cfi_startproc

SIGCODE(sigcode)
#if __has_feature(capabilities)
#ifndef __CHERI_PURE_CAPABILITY__
	.arch_extension c64
#endif
	blrr	c8
	add	c0, csp, #SF_UC
#else
	blr	x8
	mov	x0, sp
	add	x0, x0, #SF_UC
#endif

1:
	mov	x8, #SYS_sigreturn
	svc	0

	/* sigreturn failed, exit */
	mov	x8, #SYS_exit
	svc	0

	b	1b
#if __has_feature(capabilities)
#ifndef __CHERI_PURE_CAPABILITY__
	.arch_extension noc64
	.arch_extension a64c
#endif
#endif
	/* This may be copied to the stack, keep it 16-byte aligned */
	.align	3
END(sigcode)
esigcode:

	.data
	.align	3
	.global	szsigcode
	.type	szsigcode,#object
	.size	szsigcode, 8
szsigcode:
	.quad	esigcode - sigcode
