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
#define	IN_ASM
#include "rtld_c18n_machdep.h"
#undef IN_ASM

ENTRY(_rtld_thread_start)
	mov	c1, csp
	sub	csp, csp, #(CAP_WIDTH * 2)
	/*
	 * This function MUST preserve the value of c0.
	 */
	bl	c18n_init_rtld_stack
#ifndef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	/*
	 * Move the Executive mode thread pointer to Restricted mode.
	 */
	mrs	c10, ctpidr_el0
	msr	rctpidr_el0, c10
#endif
	b	_rtld_thread_start_impl
END(_rtld_thread_start)

/*
 * void _rtld_sighandler(int, siginfo_t *, void *);
 *
 * This function clobbers some callee-saved registers. This is fine because it
 * is only ever invoked via a trampoline by the kernel when a signal is
 * delivered.
 */
ENTRY(_rtld_sighandler_unsafe)
#ifndef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	/*
	 * The sigframe is pushed onto the trusted stack, disrupting the linked-
	 * list. Repair the link by pointing it to the pre-signal top of the
	 * trusted stack.
	 */
	mov	c19, c30
	mov	c20, c0
	mov	c21, c1
	mov	c22, c2

	mov	c0, csp
	mov	c1, c2
	bl	sighandler_fix_link
	mov	x23, x0

	mov	c0, c20
	mov	c1, c21
	mov	c2, c22
#endif

	ldr	c3, signal_dispatcher
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	br	x3
#else
	blr	c3

	/*
	 * Restore the link to its original value.
	 */
	mov	c0, csp
	mov	x1, x23
	mov	c30, c19
	b	sighandler_unfix_link
#endif
END(_rtld_sighandler_unsafe)

/*
 * void _rtld_dispatch_signal(int, siginfo_t *, void *);
 *
 * This function clobbers some callee-saved registers. This is fine because it
 * is only ever invoked by either RTLD code that is aware of this behaviour or
 * external code via a trampoline.
 */
ENTRY(_rtld_dispatch_signal_unsafe)
	mov	c24, c30
	mov	w25, w0
	mov	c26, c1
	mov	c27, c2
	bl	dispatch_signal_get
	mov	c28, c0

	mov	c1, c26
	mov	c2, c27
	bl	dispatch_signal_begin
	mov	c26, c1

	mov	c2, c1
	mov	c1, c0
	mov	w0, w25
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	blr	x28
#else
	blr	c28
#endif

	mov	c0, c26
	mov	c1, c27
	mov	c30, c24
	b	dispatch_signal_end
END(_rtld_dispatch_signal_unsafe)

ENTRY(_rtld_unw_setcontext_epilogue)
	mov	c16, c3
	ldp	c3, c4, [c4, #-0x030]
	mov	csp, c16
	ret
END(_rtld_unw_setcontext_epilogue)

ENTRY(allocate_rstk)
	/*
	 * NON-STANDARD CALLING CONVENTION
	 *
	 * This function is only called from trampolines when lazily allocating
	 * a restricted stack for the callee compartment.
	 *
	 * Upon entry, w14 holds the callee's compartment ID, c19 holds the
	 * callee to be tail-called, and, in the benchmark ABI, c20 holds the
	 * bottom of the RTLD stack.
	 *
	 * The function should resolve the callee's stack, install it, and tail-
	 * call the callee.
	 *
	 * All temporary registers must be cleared.
	 */

#ifndef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	gclim	x20, csp
	scvalue	c20, csp, x20
#endif
	ldr	c20, [c20, #-CAP_WIDTH]
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	mov	csp, c20
#else
	msr	rcsp_el0, c20
#endif

	/* Save floating point arguments */
	stp	q0, q1, [csp, #-(16 * 8)]!
	stp	q2, q3, [csp, #(16 * 2)]
	stp	q4, q5, [csp, #(16 * 4)]
	stp	q6, q7, [csp, #(16 * 6)]

	/* Save the callee and the return address */
	stp	c19, c30, [csp, #-(CAP_WIDTH * 2)]!

	/* Save argument registers */
	mov	c19, c0
	mov	c20, c1
	mov	c21, c2
	mov	c22, c3
	mov	c23, c4
	mov	c24, c5
	mov	c25, c6
	mov	c26, c7
	mov	c27, c8
	mov	c28, c9

	mov	w0, w14
	bl	allocate_rstk_impl

	/* Load the callee's stack */
	ldr	c10, [c0, #-CAP_WIDTH]

	/* Restore the callee and the return address */
	ldp	c11, c30, [csp], #(CAP_WIDTH * 2)

	/* Restore floating point arguments */
	ldp	q6, q7, [csp, #(16 * 6)]
	ldp	q4, q5, [csp, #(16 * 4)]
	ldp	q2, q3, [csp, #(16 * 2)]
	ldp	q0, q1, [csp], #(16 * 8)

	/* Restore argument registers */
	mov	c0, c19
	mov	c1, c20
	mov	c2, c21
	mov	c3, c22
	mov	c4, c23
	mov	c5, c24
	mov	c6, c25
	mov	c7, c26
	mov	c8, c27
	mov	c9, c28

	/*
	 * Clear temporary registers, except
	 * - c10: Callee's stack
	 * - c11: Callee's code
	 */
	mov	x12, xzr
	mov	x13, xzr
	mov	x14, xzr
	mov	x15, xzr
	mov	x16, xzr
	mov	x17, xzr
	mov	x18, xzr

#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	mov	csp, c10
	br	x11
#else
	msr	rcsp_el0, c10
	brr	c11
#endif
END(allocate_rstk)

ENTRY(tramp_hook)
	/*
	 * NON-STANDARD CALLING CONVENTION
	 *
	 * This function is only called from trampolines when tracing
	 * compartment transitions.
	 *
	 * Upon entry, c10-c12 hold the first arguments of tramp_hook.
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

	str	c30, [csp, #-CAP_WIDTH]!
	bl	tramp_hook_impl
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
END(tramp_hook)

/*
 * Trampoline templates are code but reside in rodata. Hence a new macro is
 * defined to describe them.
 */
#define TRAMP(sym)							\
	.section .rodata; .globl sym; .type sym,#object; sym:

#define TRAMPEND(sym)							\
	end_##sym:							\
	EEND(sym);							\
	.section .rodata; .globl size_##sym; .align 3;			\
	.type size_##sym,#object; .size size_##sym, 8; size_##sym:	\
	.quad	end_##sym - sym

#define	PATCH_POINT(tramp, name, label)					\
	.section .rodata; .globl patch_##tramp##_##name; .align 2;	\
	.type patch_##tramp##_##name,#object;				\
	.size patch_##tramp##_##name, 4; patch_##tramp##_##name:	\
	.word	label - end_##tramp

#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
#define	TRUSTED_STACK	c18
#define	TRUSTED_STACK_X	x18
#else
#define	TRUSTED_STACK	csp
#define	TRUSTED_STACK_X	sp
#endif

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
	ldr	x17, [c18, #-CAP_WIDTH]
	str	c10, [c18, #-CAP_WIDTH]

#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	mrs	TRUSTED_STACK, rcsp_el0
#endif
	mov	x12, TRUSTED_STACK_X

	/*
	 * Save the address that the callee should return to.
	 */
1:	adr	c13, #0		/* To be patched at runtime */
	/*
	 * Save the number of unused return value registers in the 2 least
	 * significant bits of the register.
	 */
2:	add	x13, x13, #0	/* To be patched at runtime */

	/* Push frame */
	stp	c29, c30, [TRUSTED_STACK, #-(CAP_WIDTH * C18N_TRUSTED_FRAME_SIZE)]!
	stp	x12, x13, [TRUSTED_STACK, #(CAP_WIDTH * 2)]
	str	c10, [TRUSTED_STACK, #(CAP_WIDTH * 3)]
	stp	x17, x12, [TRUSTED_STACK, #(CAP_WIDTH * 4)]
	stp	c19, c20, [TRUSTED_STACK, #(CAP_WIDTH * 5)]
	stp	c21, c22, [TRUSTED_STACK, #(CAP_WIDTH * 7)]
	stp	c23, c24, [TRUSTED_STACK, #(CAP_WIDTH * 9)]
	stp	c25, c26, [TRUSTED_STACK, #(CAP_WIDTH * 11)]
	stp	c27, c28, [TRUSTED_STACK, #(CAP_WIDTH * 13)]
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	msr	rcsp_el0, TRUSTED_STACK
#endif

3:	ldr	c19, #0		/* To be patched at runtime */
TRAMPEND(tramp_save_caller)

PATCH_POINT(tramp_save_caller, cookie, 1b)
PATCH_POINT(tramp_save_caller, ret_args, 2b)
PATCH_POINT(tramp_save_caller, target, 3b)

/*
 * Save the address of the current frame to c29 so that unwinders can locate it.
 * When transitioning to Restricted mode code, its tag must be cleared.
 */
TRAMP(tramp_update_fp)
	mov	c29, TRUSTED_STACK
TRAMPEND(tramp_update_fp)

TRAMP(tramp_update_fp_untagged)
	mov	x29, TRUSTED_STACK_X
TRAMPEND(tramp_update_fp_untagged)

TRAMP(tramp_call_hook)
1:	ldr	c13, #0		/* To be patched at runtime */

2:	mov	w10, #0		/* To be patched at runtime */
3:	adr	c11, #0		/* To be patched at runtime */
	mov	c12, TRUSTED_STACK
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	blr	x13
#else
	blr	c13
#endif
TRAMPEND(tramp_call_hook)

PATCH_POINT(tramp_call_hook, function, 1b)
PATCH_POINT(tramp_call_hook, event, 2b)
PATCH_POINT(tramp_call_hook, header, 3b)

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
	csel	w26, w14, wzr, hi
	/*
	 * Load the callee's stack if the stack table index is within bounds.
	 * Otherwise the resolver will be loaded.
	 */
	ldr	c20, [c30, w26, uxtw #4]
	/*
	 * If the resolver has been loaded, set the branch target to it.
	 */
	mov	x18, #(1 << 15)
	gcperm	x28, c20
	ands	x27, x18, x28
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
	 * If the resolver has been loaded, set the stack to zero. Otherwise,
	 * install the callee's stack.
	 */
	csel	c10, czr, c20, ne
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
	/*
	 * Set the Restricted stack to a dummy stack located at the bottom of
	 * the trusted stack.
	 */
	gclim	x30, csp
	scvalue	c30, csp, x30
	ldr	c30, [c30, #-CAP_WIDTH]
	msr	rcsp_el0, c30

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
	/*
	 * - c26: Stack table index (scalar)
	 * - c27: Test result (scalar)
	 * - c28: Permission bits (scalar)
	 * - c29: Frame pointer (scalar)
	 */

	/*
	 * Clear temporary registers, except
	 * - c10: Callee's stack
	 * - c11: Limit of caller's stack (scalar)
	 * - c12: Old trusted stack (scalar)
	 * - c13: Cookie and number of unused return argument registers (scalar)
	 * - c14: Callee's compartment ID (scalar)
	 * - c15: Length of stack table (scalar)
	 * - c16: Comparison result (scalar)
	 * - c17: Old bottom of caller's stack (scalar)
	 * - c18: CHERI_PERM_EXECUTE (scalar)
	 */

#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	blr	x21
#else
	blrr	c21
#endif
TRAMPEND(tramp_invoke_res)

TRAMP(tramp_return_hook)
1:	ldr	c13, #0			/* To be patched at runtime */

2:	mov	w10, #0			/* To be patched at runtime */
3:	adr	c11, #0			/* To be patched at runtime */
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	mrs	c12, rcsp_el0
	blr	x13
#else
	mov	c12, csp
	blr	c13
#endif
TRAMPEND(tramp_return_hook)

PATCH_POINT(tramp_return_hook, function, 1b)
PATCH_POINT(tramp_return_hook, event, 2b)
PATCH_POINT(tramp_return_hook, header, 3b)

TRAMP(tramp_return)
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	mrs	TRUSTED_STACK, rcsp_el0
#endif
	/* Restore callee-saved registers */
	ldp	c29, c30, [TRUSTED_STACK]
	ldp	x10, x11, [TRUSTED_STACK, #(CAP_WIDTH * 2)]
	ldp	c15, c12, [TRUSTED_STACK, #(CAP_WIDTH * 3)]
	ldp	c19, c20, [TRUSTED_STACK, #(CAP_WIDTH * 5)]
	ldp	c21, c22, [TRUSTED_STACK, #(CAP_WIDTH * 7)]
	ldp	c23, c24, [TRUSTED_STACK, #(CAP_WIDTH * 9)]
	ldp	c25, c26, [TRUSTED_STACK, #(CAP_WIDTH * 11)]
	ldp	c27, c28, [TRUSTED_STACK, #(CAP_WIDTH * 13)]

	/*
	 * Restore caller's saved rcsp.
	 */
	gclim	x13, c15
	scvalue	c14, c15, x13
	scvalue	c2, c15, x12
	str	c2, [c14, #-CAP_WIDTH]

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
	and	x16, x11, #0b11
	subs	x17, x16, #0b01
	csel	c0, czr, c0, hi
	csel	c1, czr, c1, hs

	scvalue	TRUSTED_STACK, TRUSTED_STACK, x10
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	msr	rcsp_el0, TRUSTED_STACK
#endif

	/*
	 * Clear temporary registers, except
	 * - c2: Old bottom of caller's stack
	 */
	mov	x3, xzr
	mov	x4, xzr
	mov	x5, xzr
	mov	x6, xzr
	mov	x7, xzr
	mov	x8, xzr
	mov	x9, xzr

	/*
	 * Clear temporary registers, except
	 * - c10: Link to previous frame (scalar)
	 * - c11: Cookie and number of unused return argument registers (scalar)
	 * - c12: Old bottom of caller's stack (scalar)
	 * - c13: Limit of caller's stack (scalar)
	 * - c14: Limit of caller's stack
	 * - c15: Current top of caller's stack
	 * - c16: Logical operation result (scalar)
	 * - c17: Comparison result (scalar)
	 */
	mov	x18, xzr

	/*
	 * Restore caller's saved rcsp (has no effect if the caller is
	 * Executive).
	 */
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	mov	csp, c15
	RETURN
#else
	msr	rcsp_el0, c15
	retr	c30
#endif
TRAMPEND(tramp_return)
