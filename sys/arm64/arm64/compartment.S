/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2022 Konrad Witaszczyk
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) under Office of
 * Naval Research (ONR) Contract No. N00014-22-1-2463 ("SoftWare Integrated
 * with Secure Hardware (SWISH)").
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

#ifdef __CHERI_PURE_CAPABILITY__
#define	TRAMPOLINECODE(sym)					\
	.section .rodata; .globl sym; .p2align 4; .type sym,#object; sym:

TRAMPOLINECODE(compartment_entry_trampoline)
compartment_entry_id:
	.word		0
	.p2align	4
compartment_entry_func:
	.chericap	0
compartment_entry_stackptr_func:
	.chericap	0

	str	c30, [csp, #-CAP_WIDTH]!
	str	c19, [csp, #-CAP_WIDTH]!
	str	c20, [csp, #-CAP_WIDTH]!
	str	c10, [csp, #-CAP_WIDTH]!

	/* Save func arguments. */
	stp	c0, c1, [csp, #-(CAP_WIDTH * 2)]!
	stp	c2, c3, [csp, #-(CAP_WIDTH * 2)]!
	stp	c4, c5, [csp, #-(CAP_WIDTH * 2)]!
	stp	c6, c7, [csp, #-(CAP_WIDTH * 2)]!

	/* Get or allocate a callee stack. */
	ldr	x0, compartment_entry_id
	ldr	c10, compartment_entry_stackptr_func
	blr	c10

	/* Store the callee stack. */
	mov	c20, c0

	/* Restore func arguments. */
	ldp	c6, c7, [csp], #(CAP_WIDTH * 2)
	ldp	c4, c5, [csp], #(CAP_WIDTH * 2)
	ldp	c2, c3, [csp], #(CAP_WIDTH * 2)
	ldp	c0, c1, [csp], #(CAP_WIDTH * 2)

	/* Switch to the callee stack. */
	mov	c19, csp
	msr	rcsp_el0, c20

	/* Call func. */
	ldr	c10, compartment_entry_func
	blrr	c10

	/* Switch to the caller stack. */
	mov	csp, c19

	ldr	c10, [csp], #CAP_WIDTH
	ldr	c20, [csp], #CAP_WIDTH
	ldr	c19, [csp], #CAP_WIDTH
	ldr	c30, [csp], #CAP_WIDTH
	ret	c30
EEND(compartment_entry_trampoline)
ecompartment_entry_trampoline:

	.data
	.align	3
	.global	szcompartment_entry_trampoline
	.type	szcompartment_entry_trampoline,#object
	.size	szcompartment_entry_trampoline, 8
szcompartment_entry_trampoline:
	.quad	ecompartment_entry_trampoline - compartment_entry_trampoline

TRAMPOLINECODE(compartment_jump_trampoline)
	.word		0
	.p2align	4
compartment_jump_func:
	.chericap	0
	.chericap	0

	str	c30, [csp, #-CAP_WIDTH]!
	str	c10, [csp, #-CAP_WIDTH]!

	/* Call func. */
	ldr	c10, compartment_jump_func
	blr	c10

	ldr	c10, [csp], #CAP_WIDTH
	ldr	c30, [csp], #CAP_WIDTH
	retr	c30
EEND(compartment_jump_trampoline)
ecompartment_jump_trampoline:

	.data
	.align	3
	.global	szcompartment_jump_trampoline
	.type	szcompartment_jump_trampoline,#object
	.size	szcompartment_jump_trampoline, 8
szcompartment_jump_trampoline:
	.quad	ecompartment_jump_trampoline - compartment_jump_trampoline
#endif	/* __CHERI_PURE_CAPABILITY__ */
