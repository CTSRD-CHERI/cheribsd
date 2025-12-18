/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
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

#include "assym.inc"

#include <sys/syscall.h>

#include <machine/asm.h>

/*
 * sigcode has to be labeled as an @object type so that captable pointers
 * to it will be able to read it.  This is fine as the code is never
 * executed directly in the kernel, just copied to places for userland
 * to execute.
 */
#define	SIGCODE(sym)						\
	.text; .globl sym; .type sym,@object; .align 4; sym: .cfi_startproc

/*
 * This code is copied to the user's stack for returning from signal handlers
 * (see sendsig() and sigreturn()). We have to compute the address of the
 * sigcontext struct for the sigreturn call.
 */
.option push
#if __has_feature(capabilities)
.option capmode
#endif
SIGCODE(sigcode)
#if __has_feature(capabilities)
	cincoffset ca0, csp, SF_UC
#else
	mv	a0, sp
	addi	a0, a0, SF_UC
#endif

1:
	li	t0, SYS_sigreturn
	ecall

	/* sigreturn failed, exit */
	li	t0, SYS_exit
	ecall

	j	1b
	/* This may be copied to the stack, keep it 16-byte aligned */
	.align	3
END(sigcode)
esigcode:
.option pop

#ifdef COMPAT_FREEBSD64
.option push
#if __has_feature(capabilities)
.option nocapmode
#endif
SIGCODE(freebsd64_sigcode)
	mv	a0, sp
	addi	a0, a0, SF64_UC

1:
	li	t0, SYS_sigreturn
	ecall

	/* sigreturn failed, exit */
	li	t0, SYS_exit
	ecall

	j	1b
	/* This may be copied to the stack, keep it 16-byte aligned */
	.align	3
END(freebsd64_sigcode)
freebsd64_esigcode:
.option pop
#endif

	.data
	.align	3
	.global	szsigcode
	.type	szsigcode, @object
szsigcode:
	.quad	esigcode - sigcode
	.size	szsigcode, . - szsigcode
#ifdef COMPAT_FREEBSD64
	.global	freebsd64_szsigcode
	.type	freebsd64_szsigcode, @object
freebsd64_szsigcode:
	.quad	freebsd64_esigcode - freebsd64_sigcode
	.size	freebsd64_szsigcode, . - freebsd64_szsigcode
#endif
