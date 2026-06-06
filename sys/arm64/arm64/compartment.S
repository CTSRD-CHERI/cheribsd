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
#include <sys/elf_common.h>

#include <machine/asm.h>
#include <machine/param.h>

#ifdef __CHERI_PURE_CAPABILITY__
#ifdef CHERI_COMPARTMENTALIZE_KERNEL
	/*
	 * In-kernel compartment entries.
	 */
	.bss
	.type	compartment_entries,#object
	.global	compartment_entries
	.p2align 4
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
	.quad		0
\type\()_entry_type:
	.word		0
	.p2align 4
\type\()_entry_func:
	.chericap	0
\type\()_entry_stackptr_func:
	.chericap	0
	/* sizeof(RB_ENTRY(compartment_trampoline)) */
\type\()_node:
	.space		48

	/*
	 * The trampoline uses r16-17 as scratch registers, as in PLT code.
	 *
	 * For the purecap benchmark ABI, we also use r19-20 to save the
	 * caller's stack pointer and link register, so we don't have to deal
	 * with the complexity of pushing/popping them from an appropriate
	 * stack when we only have the one stack.
	 */

	/* Save callee-saved registers we'll be using */
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	stp	c19, c20, [csp, #-(CAP_WIDTH * 2)]!
#endif

	/*
	 * Store the caller's current Restricted stack pointer at the bottom of
	 * its own Restricted stack.
	 *
	 * For the purecap benchmark ABI we're always in Executive so use that
	 * stack pointer, which means we will update the bottom of even the
	 * Executive's stack.
	 */
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	mov	c16, csp
#else
	mrs	c16, rcsp_el0
#endif
	gclim	x17, c16
	scvalue	c17, c16, x17
	str	c16, [c17, #-CAP_WIDTH]
	mov	x17, xzr

#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	/*
	 * Save the caller's stack pointer and the link register in saved
	 * registers rather than the same stack we just stored.
	 */
	mov	c19, c16
	mov	c20, c30
#else
	/*
	 * Push the caller's Restricted stack pointer and the link register onto
	 * the trusted stack.
	 */
	stp	c16, c30, [csp, #-(CAP_WIDTH * 2)]!
#endif

.ifc \type,executive
	/*
	 * Don't modify the Restricted stack pointer if we're branching into
	 * Executive, except in the purecap benchmark ABI, since we can't
	 * exploit csp being banked. In the purecap benchmark ABI we repurpose
	 * rcsp_el0 to point to the reserved stack slot on the Executive stack
	 * so we can always find it, without needing curthread->td_kstack.
	 */
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	mrs	c16, rcsp_el0
	ldr	c16, [c16]
	mov	csp, c16
#endif
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
	ldr	w1, \type\()_entry_type
	ldr	c16, \type\()_entry_stackptr_func
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	blr	x16
#else
	blr	c16
#endif

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
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	mov	csp, c16
#else
	msr	rcsp_el0, c16
#endif
.endif

	/*
	 * TODO: Clear registers not used by the function signature.
	 */

	/*
	 * Call the target function.
	 */
	ldr	c16, \type\()_entry_func
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	blr	x16
#else
.ifc \type,executive
	blr	c16
.else
	blrr	c16
.endif
#endif

	/*
	 * Store the callee's current Restricted stack pointer at the bottom of
	 * its own Restricted stack in case it changed in a nested call.
	 *
	 * As above, for the purecap benchmark ABI, always use the Executive
	 * stack pointer, which includes the Executive's stack.
	 */
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	mov	c16, csp
#else
	mrs	c16, rcsp_el0
#endif
	gclim	x17, c16
	scvalue	c17, c16, x17
	str	c16, [c17, #-CAP_WIDTH]

#ifndef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	/*
	 * Pop the caller's Restricted stack pointer and link register from the
	 * trusted stack.
	 */
	ldp	c16, c30, [csp], #(CAP_WIDTH * 2)
#endif

	/*
	 * Restore the caller's current Restricted stack pointer, or normal
	 * stack pointer for the purecap benchmark ABI. Also restore the link
	 * register for the purecap benchmark ABI from the saved register, and
	 * restore the callee-saved registers themselves.
	 */
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	mov	csp, c19
	mov	c30, c20
	ldp	c19, c20, [csp], #(CAP_WIDTH * 2)
#else
	msr	rcsp_el0, c16
#endif

	/*
	 * Clear temporary registers.
	 */
	mov	x16, xzr
	mov	x17, xzr

	/*
	 * Return to the caller, possibly in Restricted.
	 */
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	RETURN
#else
	retr	c30
#endif
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

TRAMPOLINECODE(executive_entry_trampoline)
	template_entry_trampoline executive
EEND(executive_entry_trampoline)
eexecutive_entry_trampoline:

	.data
	.align	3
	.global	szexecutive_entry_trampoline
	.type	szexecutive_entry_trampoline,#object
	.size	szexecutive_entry_trampoline, 8
szexecutive_entry_trampoline:
	.quad	eexecutive_entry_trampoline - executive_entry_trampoline
#endif	/* __CHERI_PURE_CAPABILITY__ */

GNU_PROPERTY_AARCH64_FEATURE_1_NOTE(GNU_PROPERTY_AARCH64_FEATURE_1_VAL)
