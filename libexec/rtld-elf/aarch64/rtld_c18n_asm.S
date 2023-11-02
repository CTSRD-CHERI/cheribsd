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
#define	TRUSTED_STACK	csp
	mov	c2, TRUSTED_STACK
	b	_rtld_setjmp_impl
#undef	TRUSTED_STACK
END(_rtld_setjmp)

ENTRY(_rtld_longjmp)
	/*
	 * This function MUST preserve the value of x1 and update c0 to point at
	 * the general purpose registers to be restored.
	 */
#define	TRUSTED_STACK	csp

	mov	c2, TRUSTED_STACK

	str	c30, [TRUSTED_STACK, #-CAP_WIDTH]!

	bl	_rtld_longjmp_impl

	ldr	c30, [TRUSTED_STACK], #CAP_WIDTH

	ldr	x3, [TRUSTED_STACK]
	scvalue	TRUSTED_STACK, TRUSTED_STACK, x3

	RETURN
#undef	TRUSTED_STACK
END(_rtld_longjmp)

ENTRY(_rtld_thread_start)
	/*
	 * Move the Executive mode thread pointer to Restricted mode.
	 */
	mrs	c10, ctpidr_el0
	msr	rctpidr_el0, c10
	b	_rtld_thread_start_impl
END(_rtld_thread_start)

ENTRY(_rtld_thr_exit)
	b	_rtld_thr_exit_impl
END(_rtld_thr_exit)

ENTRY(_rtld_sighandler)
	mov	c3, csp
	b	_rtld_sighandler_impl
END(_rtld_sighandler)

ENTRY(_rtld_get_rstk)
	/*
	 * NON-STANDARD CALLING CONVENTION
	 *
	 * This function is only called from trampolines when lazily allocating
	 * a restricted stack for the callee compartment.
	 *
	 * Upon entry, w14 holds the compartment ID of the callee compartment.
	 *
	 * Upon return, c17 holds the allocated stack.
	 *
	 * All caller-saved registers must be preserved except c17.
	 */

	stp	c18, c30, [csp, #-(CAP_WIDTH * 2)]!
	str	c16, [csp, #-(CAP_WIDTH * 2)]!
	stp	c14, c15, [csp, #-(CAP_WIDTH * 2)]!
	stp	c12, c13, [csp, #-(CAP_WIDTH * 2)]!
	stp	c10, c11, [csp, #-(CAP_WIDTH * 2)]!
	stp	c8, c9, [csp, #-(CAP_WIDTH * 2)]!
	stp	c6, c7, [csp, #-(CAP_WIDTH * 2)]!
	stp	c4, c5, [csp, #-(CAP_WIDTH * 2)]!
	stp	c2, c3, [csp, #-(CAP_WIDTH * 2)]!
	stp	c0, c1, [csp, #-(CAP_WIDTH * 2)]!
	stp	q6, q7, [csp, #-(16 * 2)]!
	stp	q4, q5, [csp, #-(16 * 2)]!
	stp	q2, q3, [csp, #-(16 * 2)]!
	stp	q0, q1, [csp, #-(16 * 2)]!

	mov	w0, w14					/* w0 = cid */
	bl	get_rstk
	mov	c17, c0

	ldp	q6, q7, [csp, #(16 * 6)]
	ldp	q4, q5, [csp, #(16 * 4)]
	ldp	q2, q3, [csp, #(16 * 2)]
	ldp	q0, q1, [csp], #(16 * 8)
	ldp	c18, c30, [csp, #(CAP_WIDTH * 18)]
	ldr	c16, [csp, #(CAP_WIDTH * 16)]
	ldp	c14, c15, [csp, #(CAP_WIDTH * 14)]
	ldp	c12, c13, [csp, #(CAP_WIDTH * 12)]
	ldp	c10, c11, [csp, #(CAP_WIDTH * 10)]
	ldp	c8, c9, [csp, #(CAP_WIDTH * 8)]
	ldp	c6, c7, [csp, #(CAP_WIDTH * 6)]
	ldp	c4, c5, [csp, #(CAP_WIDTH * 4)]
	ldp	c2, c3, [csp, #(CAP_WIDTH * 2)]
	ldp	c0, c1, [csp], #(CAP_WIDTH * 20)

	RETURN
END(_rtld_get_rstk)

ENTRY(_rtld_tramp_hook)
	/*
	 * NON-STANDARD CALLING CONVENTION
	 *
	 * This function is only called from trampolines when tracing
	 * compartment transitions.
	 *
	 * Upon entry, c10-c14 hold the first arguments of tramp_hook.
	 *
	 * All argument registers must be preserved.
	 */

	/* Save argument registers */
	stp	c0, c1, [csp, #-(CAP_WIDTH * 10)]!
	stp	c2, c3, [csp, #(CAP_WIDTH * 2)]
	stp	c4, c5, [csp, #(CAP_WIDTH * 4)]
	stp	c6, c7, [csp, #(CAP_WIDTH * 6)]
	stp	c8, c9, [csp, #(CAP_WIDTH * 8)]

	/* Save floating point registers */
	stp	q0, q1, [csp, #-(16 * 8)]!
	stp	q2, q3, [csp, #(16 * 2)]
	stp	q4, q5, [csp, #(16 * 4)]
	stp	q6, q7, [csp, #(16 * 6)]

	mov	c0, c10
	mov	c1, c11
	mov	c2, c12
	mov	c3, c13
	mov	c4, c14
	mrs	c5, rcsp_el0

	stp	c18, c30, [csp, #-(CAP_WIDTH * 2)]!
	bl	tramp_hook
	ldp	c18, c30, [csp], #(CAP_WIDTH * 2)

	/* Restore floating point registers */
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

	retr	c30
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
1:	ldr	c18, #0		/* To be patched at runtime */
	mrs	c17, rcsp_el0
	mov	x10, sp
#define	TRUSTED_STACK	csp

	/*
	 * Maintain consistency of rcsp by saving it at the bottom of itself.
	 * This step must be done before the table lookup so that
	 * same-compartment switches get the correct stack.
	 */
	gclim	x11, c17
	scvalue	c16, c17, x11
	ldr	x12, [c16, #-CAP_WIDTH]
	str	c17, [c16, #-CAP_WIDTH]

	/* Push frame */
	stp	x10, x12, [TRUSTED_STACK, #-(CAP_WIDTH * 14)]!
	str	c16, [TRUSTED_STACK, #(CAP_WIDTH * 1)]
	stp	c30, c19, [TRUSTED_STACK, #(CAP_WIDTH * 2)]
	stp	c20, c21, [TRUSTED_STACK, #(CAP_WIDTH * 4)]
	stp	c22, c23, [TRUSTED_STACK, #(CAP_WIDTH * 6)]
	stp	c24, c25, [TRUSTED_STACK, #(CAP_WIDTH * 8)]
	stp	c26, c27, [TRUSTED_STACK, #(CAP_WIDTH * 10)]
	stp	c28, c29, [TRUSTED_STACK, #(CAP_WIDTH * 12)]

	/*
	 * Save the number of unused return value registers in the flags of csp.
	 */
2:	movz	x13, #0		/* To be patched at runtime */
	scflgs	TRUSTED_STACK, TRUSTED_STACK, x13
#undef	TRUSTED_STACK
TRAMPEND(tramp_save_caller)

PATCH_POINT(tramp_save_caller, target, 1b)
PATCH_POINT(tramp_save_caller, ret_args, 2b)

TRAMP(tramp_call_hook)
1:	ldr	c17, #0		/* To be patched at runtime */

2:	mov	w10, #0		/* To be patched at runtime */
3:	ldr	c11, #0		/* To be patched at runtime */
4:	ldr	c12, #0		/* To be patched at runtime */
5:	ldr	c13, #0		/* To be patched at runtime */
	mov	c14, c30

	blr	c17
TRAMPEND(tramp_call_hook)

PATCH_POINT(tramp_call_hook, function, 1b)
PATCH_POINT(tramp_call_hook, event, 2b)
PATCH_POINT(tramp_call_hook, target, 3b)
PATCH_POINT(tramp_call_hook, obj, 4b)
PATCH_POINT(tramp_call_hook, def, 5b)

TRAMP(tramp_switch_stack)
	mrs	c30, ctpidr_el0		/* c30 = table */
1:	movz	w14, #0		/* w14 = cid, to be patched at runtime */
	gclen	x15, c30	/* x15 = len(table) */

	/*
	 * Callee is Restricted, so switch to its saved rcsp at the bottom of
	 * itself.
	 *
	 * Use subs instead of cmp to clear a register tag.
	 */
	subs	x16, x15, x14, lsl #4		/* if (len(table) <= cid) */
	b.ls	2f				/* goto 2f */
	ldr	c17, [c30, w14, uxtw #4]	/* c17 = table[cid] */
	cbnz	x17, 3f

	/*
	 * Call get_rstk(), which may invoke Restricted code (e.g. locking
	 * procedures in libthr), causing another trampoline to run. The
	 * implications of re-entrancy must be carefully addressed.
	 */
2:
	blr	[c30, #0]			/* get_rstk() */
3:	ldr	c17, [c17, #-CAP_WIDTH]

	/* Move the c9 buffer to the target stack */
	cbz	x9, 6f
	gclen	x11, c9
	add	c30, c9, x11
	lsr	x11, x11, #4
	tst	x30, #0xf
	b.eq	5f

	orr	x12, x30, #0xfffffffffffffff0
	add	c17, c17, x12
7:	ldrb	w12, [c30, #-1]!
	strb	w12, [c17, #-1]!
	tst	x30, #0xf
	b.ne	7b

4:	cbz	x11, 6f
5:	ldr	c12, [c30, #-CAP_WIDTH]!
	str	c12, [c17, #-CAP_WIDTH]!
	sub	x11, x11, #1
	b	4b
6:
TRAMPEND(tramp_switch_stack)

PATCH_POINT(tramp_switch_stack, cid, 1b)

TRAMP(tramp_invoke_exe)
	blr	c18
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
	/* Clear callee-saved registers */
	mov	x29, xzr
	mov	x28, xzr
	mov	x27, xzr
	mov	x26, xzr
	mov	x25, xzr
	mov	x24, xzr
	mov	x23, xzr
	mov	x22, xzr
	mov	x21, xzr
	mov	x20, xzr
	mov	x19, xzr

	/*
	 * Clear temporary registers, except
	 * - c10: Link to previous frame (scalar)
	 * - c11: Top of caller's stack (scalar)
	 * - c12: Old top of caller's stack (scalar)
	 * - c13: Flags of csp (scalar)
	 * - c14: Callee's compartment ID (scalar)
	 * - c15: Length of stack table (scalar)
	 * - c16: Comparison result (scalar)
	 * - c17: Callee's stack
	 * - c18: Callee's code
	 */

	msr	rcsp_el0, c17
	blrr	c18
TRAMPEND(tramp_invoke_res)

TRAMP(tramp_pop_frame)
#define	TRUSTED_STACK	csp
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
	ldr	c13, [c12, #-CAP_WIDTH]
	scvalue	c14, c12, x11
	str	c14, [c12, #-CAP_WIDTH]

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
	gcflgs	x15, TRUSTED_STACK
	subs	x16, x15, #0b01
	csel	c1, czr, c1, hs
	csel	c0, czr, c0, hi

	mov	x9, xzr
	mov	x8, xzr
	mov	x7, xzr
	mov	x6, xzr
	mov	x5, xzr
	mov	x4, xzr
	mov	x3, xzr
	mov	x2, xzr

	/*
	 * Clear temporary registers, except
	 * - c10: Link to previous frame (scalar)
	 * - c11: Old top of caller's stack (scalar)
	 * - c12: Bottom of caller's stack
	 * - c13: Current top of caller's stack
	 * - c14: Old top of caller's stack
	 * - c15: Flags of csp (scalar)
	 * - c16: Comparison result (scalar)
	 */
	mov	x17, xzr
	mov	x18, xzr

	/*
	 * Restore caller's saved rcsp (has no effect if the caller is
	 * Executive).
	 */
	msr	rcsp_el0, c13
#undef	TRUSTED_STACK
TRAMPEND(tramp_pop_frame)

TRAMP(tramp_return)
	retr	c30
TRAMPEND(tramp_return)

TRAMP(tramp_return_hook)
	/* Save return value registers */
1:	ldr	c18, #0			/* To be patched at runtime */

2:	mov	w10, #0			/* To be patched at runtime */
	mov	x11, xzr
3:	ldr	c12, #0			/* To be patched at runtime */
4:	ldr	c13, #0			/* To be patched at runtime */
	mov	c14, c30

	br	c18
TRAMPEND(tramp_return_hook)

PATCH_POINT(tramp_return_hook, function, 1b)
PATCH_POINT(tramp_return_hook, event, 2b)
PATCH_POINT(tramp_return_hook, obj, 3b)
PATCH_POINT(tramp_return_hook, def, 4b)
#endif
