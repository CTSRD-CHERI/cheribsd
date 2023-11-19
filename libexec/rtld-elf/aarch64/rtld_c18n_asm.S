/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2021-2023 Dapeng Gao
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

#if defined(__CHERI_PURE_CAPABILITY__) && defined(RTLD_SANDBOX)
ENTRY(_rtld_setjmp)
	/*
	 * This function MUST update c0 to point at the buffer that saves the
	 * general purpose registers.
	 */
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	mrs	c2, rcsp_el0
#else
	mov	c2, csp
#endif
	b	_rtld_setjmp_impl
END(_rtld_setjmp)

ENTRY(_rtld_longjmp)
	/*
	 * This function MUST preserve the value of x1 and update c0 to point at
	 * the general purpose registers to be restored.
	 */
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	mrs	c2, rcsp_el0
#else
	mov	c2, csp
#endif

	str	c30, [csp, #-CAP_WIDTH]!
	bl	_rtld_longjmp_impl
	ldr	c30, [csp], #CAP_WIDTH

#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	mrs	c10, rcsp_el0
#define	TRUSTED_STACK	c10
#else
#define	TRUSTED_STACK	csp
#endif
	ldr	x2, [TRUSTED_STACK]
	scvalue	TRUSTED_STACK, TRUSTED_STACK, x2
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	msr	rcsp_el0, TRUSTED_STACK
#endif
#undef	TRUSTED_STACK

	RETURN
END(_rtld_longjmp)

ENTRY(_rtld_thread_start)
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	sub	c10, csp, #CAP_WIDTH
	str	c10, [csp, #-CAP_WIDTH]!
#else
	/*
	 * Move the Executive mode thread pointer to Restricted mode.
	 */
	mrs	c10, ctpidr_el0
	msr	rctpidr_el0, c10
#endif
	b	_rtld_thread_start_impl
END(_rtld_thread_start)

ENTRY(_rtld_sighandler)
#ifndef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	mov	c3, csp
#endif
	b	_rtld_sighandler_impl
END(_rtld_sighandler)

ENTRY(_rtld_get_rstk)
	/*
	 * NON-STANDARD CALLING CONVENTION
	 *
	 * This function is only called from trampolines when lazily allocating
	 * a restricted stack for the callee compartment.
	 *
	 * Upon entry, w14 holds the callee's compartment ID, c19 holds the
	 * callee, and, in the benchmark ABI, c20 holds the bottom of the RTLD
	 * stack.
	 *
	 * The function should resolve the callee's stack, install it, and tail-
	 * call the callee.
	 *
	 * All temporary registers must be cleared.
	 */

#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	ldr	c20, [c20, #-CAP_WIDTH]
	mov	csp, c20
#endif

	/* Save argument registers */
	mov	c20, c0
	mov	c21, c1
	mov	c22, c2
	mov	c23, c3
	mov	c24, c4
	mov	c25, c5
	mov	c26, c6
	mov	c27, c7
	mov	c28, c8
	mov	c29, c9

	/* Save floating point arguments */
	stp	q0, q1, [csp, #-(16 * 8)]!
	stp	q2, q3, [csp, #(16 * 2)]
	stp	q4, q5, [csp, #(16 * 4)]
	stp	q6, q7, [csp, #(16 * 6)]

	mov	w0, w14

	str	c30, [csp, #-CAP_WIDTH]!
	bl	get_rstk
	ldr	c30, [csp], #CAP_WIDTH

	/* Restore floating point arguments */
	ldp	q6, q7, [csp, #(16 * 6)]
	ldp	q4, q5, [csp, #(16 * 4)]
	ldp	q2, q3, [csp, #(16 * 2)]
	ldp	q0, q1, [csp], #(16 * 8)

	ldr	c0, [c0, #-CAP_WIDTH]
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	mov	csp, c0
#else
	msr	rcsp_el0, c0
#endif

	/* Restore argument registers */
	mov	c0, c20
	mov	c1, c21
	mov	c2, c22
	mov	c3, c23
	mov	c4, c24
	mov	c5, c25
	mov	c6, c26
	mov	c7, c27
	mov	c8, c28
	mov	c9, c29

	mov	x10, xzr
	mov	x11, xzr
	mov	x12, xzr
	mov	x13, xzr
	mov	x14, xzr
	mov	x15, xzr
	mov	x16, xzr
	mov	x17, xzr
	mov	x18, xzr

#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	br	x19
#else
	brr	c19
#endif
END(_rtld_get_rstk)

ENTRY(_rtld_tramp_hook)
	/*
	 * NON-STANDARD CALLING CONVENTION
	 *
	 * This function is only called from trampolines when tracing
	 * compartment transitions.
	 *
	 * Upon entry, c10-c15 hold the first arguments of tramp_hook.
	 *
	 * All argument registers must be preserved.
	 */

	/* Save argument registers */
	stp	c0, c1, [csp, #-(CAP_WIDTH * 10)]!
	stp	c2, c3, [csp, #(CAP_WIDTH * 2)]
	stp	c4, c5, [csp, #(CAP_WIDTH * 4)]
	stp	c6, c7, [csp, #(CAP_WIDTH * 6)]
	stp	c8, c9, [csp, #(CAP_WIDTH * 8)]

	/* Save floating point arguments */
	stp	q0, q1, [csp, #-(16 * 8)]!
	stp	q2, q3, [csp, #(16 * 2)]
	stp	q4, q5, [csp, #(16 * 4)]
	stp	q6, q7, [csp, #(16 * 6)]

	mov	c0, c10
	mov	c1, c11
	mov	c2, c12
	mov	c3, c13
	mov	c4, c14
	mov	c5, c15

	str	c30, [csp, #-CAP_WIDTH]!
	bl	tramp_hook
	ldr	c30, [csp], #CAP_WIDTH

	/* Restore floating point arguments */
	ldp	q6, q7, [csp, #(16 * 6)]
	ldp	q4, q5, [csp, #(16 * 4)]
	ldp	q2, q3, [csp, #(16 * 2)]
	ldp	q0, q1, [csp], #(16 * 8)

	/* Restore argument registers */
	ldp	c8, c9, [csp, #(CAP_WIDTH * 8)]
	ldp	c6, c7, [csp, #(CAP_WIDTH * 6)]
	ldp	c4, c5, [csp, #(CAP_WIDTH * 4)]
	ldp	c2, c3, [csp, #(CAP_WIDTH * 2)]
	ldp	c0, c1, [csp], #(CAP_WIDTH * 10)

#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	RETURN
#else
	retr	c30
#endif
END(_rtld_tramp_hook)

/*
 * Trampoline templates are code but reside in rodata. Hence a new macro is
 * defined to describe them.
 */
#define TRAMP(sym)							\
	.section .rodata; .globl sym; .align 4; .type sym,#object; sym:

#define TRAMPEND(sym)							\
	end_##sym:							\
	EEND(sym);							\
	.section .rodata; .globl size_##sym; .align 3;			\
	.type size_##sym,#object; .size size_##sym, 8; size_##sym:	\
	.quad	end_##sym - sym

#define	PATCH_POINT(tramp, name, label)					\
	.section .rodata; .globl patch_##tramp##_##name; .align 3;	\
	.type patch_##tramp##_##name,#object;				\
	.size patch_##tramp##_##name, 4; patch_##tramp##_##name:	\
	.word	label - end_##tramp

TRAMP(tramp_save_caller)
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	mov	c10, csp
#else
	mrs	c10, rcsp_el0
#endif

	/*
	 * Maintain consistency of rcsp by saving it at the bottom of itself.
	 * This step must be done before the table lookup so that
	 * same-compartment switches get the correct stack.
	 */
	gclim	x11, c10
	scvalue	c18, c10, x11
	ldr	c17, [c18, #-CAP_WIDTH]
	str	c10, [c18, #-CAP_WIDTH]

#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	mrs	c18, rcsp_el0
#define	TRUSTED_STACK	c18
	mov	x12, x18
#else
	mov	x12, sp
#define	TRUSTED_STACK	csp
#endif

	/*
	 * Save the number of unused return value registers in the flags of csp.
	 */
1:	movz	x13, #0		/* To be patched at runtime */

	/* Push frame */
	stp	x12, x13, [TRUSTED_STACK, #-(CAP_WIDTH * 14)]!
	str	c17, [TRUSTED_STACK, #(CAP_WIDTH * 1)]
	stp	c30, c19, [TRUSTED_STACK, #(CAP_WIDTH * 2)]
	stp	c20, c21, [TRUSTED_STACK, #(CAP_WIDTH * 4)]
	stp	c22, c23, [TRUSTED_STACK, #(CAP_WIDTH * 6)]
	stp	c24, c25, [TRUSTED_STACK, #(CAP_WIDTH * 8)]
	stp	c26, c27, [TRUSTED_STACK, #(CAP_WIDTH * 10)]
	stp	c28, c29, [TRUSTED_STACK, #(CAP_WIDTH * 12)]
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	msr	rcsp_el0, TRUSTED_STACK
#endif
#undef	TRUSTED_STACK

2:	ldr	c19, #0		/* To be patched at runtime */
TRAMPEND(tramp_save_caller)

PATCH_POINT(tramp_save_caller, ret_args, 1b)
PATCH_POINT(tramp_save_caller, target, 2b)

TRAMP(tramp_call_hook)
1:	ldr	c18, #0		/* To be patched at runtime */

	mov	c20, c10
2:	mov	w11, #0		/* To be patched at runtime */
	mov	c12, c19
3:	ldr	c13, #0		/* To be patched at runtime */
4:	ldr	c14, #0		/* To be patched at runtime */
	mov	c15, c30

#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	blr	x18
#else
	blr	c18
#endif

	mov	c10, c20
TRAMPEND(tramp_call_hook)

PATCH_POINT(tramp_call_hook, function, 1b)
PATCH_POINT(tramp_call_hook, event, 2b)
PATCH_POINT(tramp_call_hook, obj, 3b)
PATCH_POINT(tramp_call_hook, def, 4b)

TRAMP(tramp_switch_stack)
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	mrs	c30, rctpidr_el0	/* c30 = table */
#else
	mrs	c30, ctpidr_el0		/* c30 = table */
#endif
1:	movz	w14, #0		/* w14 = cid, to be patched at runtime */
	gclen	x15, c30	/* x15 = len(table) */

	/*
	 * Callee is Restricted, so switch to its saved rcsp at the bottom of
	 * itself.
	 *
	 * Use subs instead of cmp to clear a register tag.
	 */
	subs	x16, x15, x14, lsl #4
	/*
	 * If the stack table index is out-of-bounds, set it to zero.
	 */
	csel	w17, w14, wzr, hi
	/*
	 * Load the callee's stack if the stack table index is within bounds.
	 * Otherwise the resolver will be loaded.
	 */
	ldr	c20, [c30, w17, uxtw #4]
	/*
	 * If the resolver has been loaded, set the branch target to it.
	 */
	mov	x18, #(1 << 15)
	gcperm	x29, c20
	ands	x28, x18, x29
	csel	c21, c20, c19, ne
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	/*
	 * Increment the stack table pointer such that the next load will load
	 * the RTLD stack if needed.
	 */
	add	c30, c30, #(CAP_WIDTH * 3)
#else
	/*
	 * Increment the stack table pointer such that the next load will load
	 * the resolver if needed.
	 */
	add	c30, c30, #CAP_WIDTH
#endif
	csel	c20, c30, c20, ne
	/*
	 * If the resolver has been loaded, the result of this load is either
	 * discarded (purecap ABI) or the bottom of the RTLD stack (benchmark
	 * ABI). Otherwise, the top of the callee's stack is loaded.
	 */
	ldr	c20, [c20, #-CAP_WIDTH]
	/*
	 * If the resolver has been loaded, keep the original caller's stack.
	 * Otherwise, install the callee's stack.
	 */
	csel	c10, c10, c20, ne
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	mov	csp, c10
#else
	msr	rcsp_el0, c10
#endif
TRAMPEND(tramp_switch_stack)

PATCH_POINT(tramp_switch_stack, cid, 1b)

TRAMP(tramp_invoke_exe)
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	blr	x19
#else
	blr	c19
#endif
TRAMPEND(tramp_invoke_exe)

TRAMP(tramp_clear_mem_args)
	mov	x9, xzr
TRAMPEND(tramp_clear_mem_args)

TRAMP(tramp_clear_ret_args_indirect)
	mov	x8, xzr
TRAMPEND(tramp_clear_ret_args_indirect)

TRAMP(tramp_clear_ret_args)
	mov	x7, xzr
	mov	x6, xzr
	mov	x5, xzr
	mov	x4, xzr
	mov	x3, xzr
	mov	x2, xzr
	mov	x1, xzr
	mov	x0, xzr
TRAMPEND(tramp_clear_ret_args)

TRAMP(tramp_invoke_res)
	/*
	 * Clear callee-saved registers, except
	 * - c19: Callee's code
	 * - c20: Callee's stack
	 * - c21: Callee's code
	 */
	mov	x22, xzr
	mov	x23, xzr
	mov	x24, xzr
	mov	x25, xzr
	mov	x26, xzr
	mov	x27, xzr
	/*
	 * - c28: Test result (scalar)
	 * - c29: Permission bits (scalar)
	 */

	/*
	 * Clear temporary registers, except
	 * - c10: Callee's stack
	 * - c11: Top of caller's stack (scalar)
	 * - c12: Link to previous frame (scalar)
	 * - c13: Number of unused return argument registers (scalar)
	 * - c14: Callee's compartment ID (scalar)
	 * - c15: Length of stack table (scalar)
	 * - c16: Comparison result (scalar)
	 * - c17: Stack table index (scalar)
	 * - c18: CHERI_PERM_EXECUTE (scalar)
	 */

#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	blr	x21
#else
	blrr	c21
#endif
TRAMPEND(tramp_invoke_res)

TRAMP(tramp_pop_frame)
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	mrs	c18, rcsp_el0
#define	TRUSTED_STACK	c18
#else
#define	TRUSTED_STACK	csp
#endif
	/* Restore callee-saved registers */
	ldp	c28, c29, [TRUSTED_STACK, #(CAP_WIDTH * 12)]
	ldp	c26, c27, [TRUSTED_STACK, #(CAP_WIDTH * 10)]
	ldp	c24, c25, [TRUSTED_STACK, #(CAP_WIDTH * 8)]
	ldp	c22, c23, [TRUSTED_STACK, #(CAP_WIDTH * 6)]
	ldp	c20, c21, [TRUSTED_STACK, #(CAP_WIDTH * 4)]
	ldp	c30, c19, [TRUSTED_STACK, #(CAP_WIDTH * 2)]
	ldr	c12, [TRUSTED_STACK, #(CAP_WIDTH * 1)]
	ldp	x10, x11, [TRUSTED_STACK], #(CAP_WIDTH * 14)

	/*
	 * Restore caller's saved rcsp.
	 */
	gclim	x13, c12
	scvalue	c14, c12, x13
	ldr	c15, [c14, #-CAP_WIDTH]
	str	c12, [c14, #-CAP_WIDTH]

	/*
	 * Clear unused return value registers. The registers to clear is
	 * encoded as follows and stored in the flags of csp:
	 * - None:	0b00
	 * - c1 only:	0b01
	 * - c0 and c1:	0b1x
	 * Use comparison and csel to avoid branching.
	 *
	 * Use subs instead of cmp to clear a register tag.
	 */
	subs	x16, x11, #0b01
	csel	c0, czr, c0, hi
	csel	c1, czr, c1, hs

	mov	x2, xzr
	mov	x3, xzr
	mov	x4, xzr
	mov	x5, xzr
	mov	x6, xzr
	mov	x7, xzr
	mov	x8, xzr
	mov	x9, xzr

#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	msr	rcsp_el0, TRUSTED_STACK
#endif

	/*
	 * Clear temporary registers, except
	 * - c10: Link to previous frame (scalar)
	 * - c11: Number of unused return argument registers (scalar)
	 * - c12: Old top of caller's stack
	 * - c13: Bottom of caller's stack (scalar)
	 * - c14: Bottom of caller's stack
	 * - c15: Current top of caller's stack
	 * - c16: Comparison result (scalar)
	 */
	mov	x17, xzr
	mov	x18, xzr

	/*
	 * Restore caller's saved rcsp (has no effect if the caller is
	 * Executive).
	 */
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	mov	csp, c15
#else
	msr	rcsp_el0, c15
#endif
#undef	TRUSTED_STACK
TRAMPEND(tramp_pop_frame)

TRAMP(tramp_return)
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	RETURN
#else
	retr	c30
#endif
TRAMPEND(tramp_return)

TRAMP(tramp_return_hook)
	/* Save return value registers */
1:	ldr	c18, #0			/* To be patched at runtime */

	mov	c10, c15
2:	mov	w11, #0			/* To be patched at runtime */
	mov	x12, xzr
3:	ldr	c13, #0			/* To be patched at runtime */
4:	ldr	c14, #0			/* To be patched at runtime */
	mov	c15, c30

#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	br	x18
#else
	br	c18
#endif
TRAMPEND(tramp_return_hook)

PATCH_POINT(tramp_return_hook, function, 1b)
PATCH_POINT(tramp_return_hook, event, 2b)
PATCH_POINT(tramp_return_hook, obj, 3b)
PATCH_POINT(tramp_return_hook, def, 4b)
#endif
