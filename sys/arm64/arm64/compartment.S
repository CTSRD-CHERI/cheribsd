/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2022-2024 Konrad Witaszczyk
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

#include <sys/cdefs.h>

#include <machine/asm.h>
#include <machine/param.h>
__FBSDID("$FreeBSD$");

#ifdef __CHERI_PURE_CAPABILITY__
#ifdef CHERI_COMPARTMENTALIZE_KERNEL
	/*
	 * Root compartment entries.
	 */
	.bss
	.type	compartment_entries,#object
	.global	compartment_entries
	.p2align	4
compartment_entries:
	.space	(PAGE_SIZE * COMPARTMENT_ENTRY_PAGES)
	.size	compartment_entries, . - compartment_entries
	.global	compartment_entries_length
	.type	compartment_entries_length,#object
	.size	compartment_entries_length, 8
compartment_entries_length:
	.quad	0
#endif

#define	TRAMPOLINECODE(sym)					\
	.section .rodata; .globl sym; .p2align 4; .type sym,#object; sym:

.macro template_entry_trampoline type
\type\()_entry_id:
	.word		0
\type\()_entry_type:
	.word		0
	.p2align 4
\type\()_entry_func:
	.chericap	0
\type\()_entry_stackptr_func:
	.chericap	0

	/*
	 * The trampoline uses r16-17 as scratch registers, as in PLT code.
	 */

	/*
	 * Store the caller's current Restricted stack pointer at the bottom of
	 * its own Restricted stack.
	 */
	mrs	c16, rcsp_el0
	gclim	x17, c16
	scvalue	c17, c16, x17
	str	c16, [c17, #-CAP_WIDTH]
	mov	x17, xzr

	/*
	 * Push the caller's Restricted stack pointer and the link register onto
	 * the trusted stack.
	 */
	stp	c16, c30, [csp, #-(CAP_WIDTH * 2)]!

.ifc \type,supervisor
	/*
	 * Don't modify the Restricted stack pointer if we're branching into
	 * Executive.
	 */
.else
	/*
	 * Push function arguments.
	 */
	stp	c0, c1, [csp, #-(CAP_WIDTH * 2)]!
	stp	c2, c3, [csp, #-(CAP_WIDTH * 2)]!
	stp	c4, c5, [csp, #-(CAP_WIDTH * 2)]!
	stp	c6, c7, [csp, #-(CAP_WIDTH * 2)]!
	stp	c8, c9, [csp, #-(CAP_WIDTH * 2)]!

	/*
	 * TODO: Clear all registers unused by the stack pointer function.
	 */

	/* Get or allocate a callee stack. */
	ldr	x0, \type\()_entry_id
	ldr	x1, \type\()_entry_type
	ldr	c16, \type\()_entry_stackptr_func
	blr	c16

	/*
	 * TODO: Clear all registers that could have been set by the stack
	 * allocating function.
	 */

	/*
	 * Load the calee's stack pointer from the bottom of its stack.
	 */
	gclim	x16, c0
	scvalue	c16, c0, x16
	ldr	c16, [c16, #-CAP_WIDTH]

	/*
	 * Pop function arguments.
	 */
	ldp	c8, c9, [csp], #(CAP_WIDTH * 2)
	ldp	c6, c7, [csp], #(CAP_WIDTH * 2)
	ldp	c4, c5, [csp], #(CAP_WIDTH * 2)
	ldp	c2, c3, [csp], #(CAP_WIDTH * 2)
	ldp	c0, c1, [csp], #(CAP_WIDTH * 2)

	/* Switch to the callee's stack. */
	msr	rcsp_el0, c16
.endif

	/*
	 * TODO: Clear registers not used by the function signature.
	 */

	/*
	 * Call the target function.
	 */
	ldr	c16, \type\()_entry_func
.ifc \type,supervisor
	blr	c16
.else
	blrr	c16
.endif

	/*
	 * Pop the caller's Restricted stack pointer and link register from the
	 * trusted stack.
	 */
	ldp	c16, c30, [csp], #(CAP_WIDTH * 2)

	/*
	 * Restore the caller's current Restricted stack pointer.
	 */
	msr	rcsp_el0, c16

	/*
	 * Clear temporary registers.
	 */
	mov	x16, xzr

	/*
	 * Return to the caller, possibly in Restricted.
	 */
	retr	c30
	.p2align 4
.endmacro

TRAMPOLINECODE(compartment_entry_trampoline)
	template_entry_trampoline compartment
EEND(compartment_entry_trampoline)
ecompartment_entry_trampoline:

	.data
	.align	3
	.global	szcompartment_entry_trampoline
	.type	szcompartment_entry_trampoline,#object
	.size	szcompartment_entry_trampoline, 8
szcompartment_entry_trampoline:
	.quad	ecompartment_entry_trampoline - compartment_entry_trampoline

TRAMPOLINECODE(supervisor_entry_trampoline)
	template_entry_trampoline supervisor
EEND(supervisor_entry_trampoline)
esupervisor_entry_trampoline:

	.data
	.align	3
	.global	szsupervisor_entry_trampoline
	.type	szsupervisor_entry_trampoline,#object
	.size	szsupervisor_entry_trampoline, 8
szsupervisor_entry_trampoline:
	.quad	esupervisor_entry_trampoline - supervisor_entry_trampoline
#endif	/* __CHERI_PURE_CAPABILITY__ */
