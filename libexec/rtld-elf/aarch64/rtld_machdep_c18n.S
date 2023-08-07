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
__FBSDID("$FreeBSD$");

#if defined(__CHERI_PURE_CAPABILITY__) && defined(RTLD_SANDBOX)
ENTRY(_rtld_setjmp)
	/*
	 * This function MUST save the callee-saved registers in the c0 buffer.
	 *
	 * Before setjmp is called, the top of the Executive stack contains:
	 * 	-3.	Caller's data
	 * 	-2.	Caller's stack
	 * 	-1.	Return address
	 * 	0.	Link to previous frame
	 * When setjmp is called, the following is pushed to the Executive
	 * stack:
	 * 	1.	Caller's data
	 * 	2.	Caller's stack
	 * 	3.	Return address
	 * 	4.	Link to 0
	 * setjmp then calls _rtld_setjmp, which pushes the following:
	 * 	5.	Caller's data
	 * 	6.	Caller's stack
	 * 	7.	Return address
	 * 	8.	Link to 4
	 * In _rtld_setjmp, we manipulate the stack content to the following:
	 * 	-6.	Copy of 2
	 * 	-5.	Copy of 3
	 * 	-4.	Link to 0
	 * 	-3.	Caller's data
	 * 	-2.	Caller's stack
	 * 	-1.	Return address
	 * 	0.	Link to previous frame
	 * 	------------------------------
	 * 	1.	Caller's data
	 * 	2.	Caller's stack
	 * 	3.	Return address
	 * 	4.	Link to 0
	 * 	------------------------------
	 * 	5.	Caller's data
	 * 	6.	Caller's stack
	 * 	7.	Return address
	 * 	8.	Link to 4
	 * To do this, we shift everything from -3 to 8 by 3 positions.
	 */

#define	SETJMP_SHIFT	3
	/*
	 * Move 8 and adjust it's cursor.
	 * Also adjust csp.
	 */
	ldr	c2, [csp], #-(SETJMP_SHIFT * CAP_WIDTH)
	sub	c2, c2, #(SETJMP_SHIFT * CAP_WIDTH)
	str	c2, [csp]

	add	c1, csp, #CAP_WIDTH

	/* Shift 5, 6, and 7 */
1:	ldr	c3, [c1, #(SETJMP_SHIFT * CAP_WIDTH)]
	str	c3, [c1], #CAP_WIDTH
	cmp	x1, x2
	b.ne	1b

	/* Save link to 4 for buffer */
	mov	c4, c1

	ldp	c19, c20, [c1, #((SETJMP_SHIFT + 3) * CAP_WIDTH)]
	ldp	c21, c22, [c1, #((SETJMP_SHIFT + 5) * CAP_WIDTH)]
	ldp	c23, c24, [c1, #((SETJMP_SHIFT + 7) * CAP_WIDTH)]
	ldp	c25, c26, [c1, #((SETJMP_SHIFT + 9) * CAP_WIDTH)]
	ldp	c27, c28, [c1, #((SETJMP_SHIFT + 11) * CAP_WIDTH)]
	ldr	c29, [c1, #((SETJMP_SHIFT + 13) * CAP_WIDTH)]

	stp	c19, c20, [c0, #(CAP_WIDTH * 1)]
	stp	c21, c22, [c0, #(CAP_WIDTH * 3)]
	stp	c23, c24, [c0, #(CAP_WIDTH * 5)]
	stp	c25, c26, [c0, #(CAP_WIDTH * 7)]
	stp	c27, c28, [c0, #(CAP_WIDTH * 9)]
	str	c29, [c0, #(CAP_WIDTH * 11)]

	/* Shift 4 and adjust it's cursor */
	ldr	c2, [c1, #(SETJMP_SHIFT * CAP_WIDTH)]
	sub	c2, c2, #(SETJMP_SHIFT * CAP_WIDTH)
	str	c2, [c1], #CAP_WIDTH

	/* Shift 1, 2, and 3 */
2:	ldr	c3, [c1, #(SETJMP_SHIFT * CAP_WIDTH)]
	str	c3, [c1], #CAP_WIDTH
	cmp	x1, x2
	b.ne	2b

	/* Shift 0 */
	ldr	c2, [c1, #(SETJMP_SHIFT * CAP_WIDTH)]
	str	c2, [c1], #CAP_WIDTH
	sub	c2, c2, #(SETJMP_SHIFT * CAP_WIDTH)

	/* Load RTLD sealer to detect other jump buffers */
	ldr	c5, sealer_jmpbuf

	/* Shift -3, -2, and -1 */
3:	ldr	c3, [c1, #(SETJMP_SHIFT * CAP_WIDTH)]
	unseal	c6, c3, c5
	gctag	x6, c6
	cbnz	x6, 4f
	str	c3, [c1], #CAP_WIDTH
	cmp	x1, x2
	b.ne	3b
	b	5f

4:	seal	c3, c1, c5
	str	c3, [c1, #(SETJMP_SHIFT * CAP_WIDTH)]

	/* Store -4, -5, and -6 */
5:	ldr	c2, [c4]
	ldp	c3, c4, [c4, #CAP_WIDTH]
	seal	c2, c2, c5
	str	c2, [c1]
	stp	c3, c4, [c1, #CAP_WIDTH]

	scbnds	c1, c1, #(SETJMP_SHIFT * CAP_WIDTH)
	seal	c1, c1, c5
	str	c1, [c0], #(CAP_WIDTH * 12)

	mov	x6, xzr
	mov	x5, xzr
	mov	x4, xzr
	mov	x3, xzr
	mov	x2, xzr
	mov	x1, xzr
	ret
END(_rtld_setjmp)

ENTRY(_rtld_longjmp)
	/*
	 * This function MUST preserve the value of x1 and update c0 to point at
	 * the value of lr to be restored.
	 *
	 * Before longjmp is called, the top of the Executive stack contains:
	 * 	0.	Link to previous frame
	 * When longjmp is called, the following is pushed to the Executive
	 * stack:
	 * 	1.	Caller's data
	 * 	2.	Caller's stack
	 * 	3.	Return address
	 * 	4.	Link to 0
	 * longjmp then calls _rtld_longjmp, which pushes the following:
	 * 	5.	Caller's data
	 * 	6.	Caller's stack
	 * 	7.	Return address
	 * 	8.	Link to 4
	 * In _rtld_longjmp, we manipulate the stack content to the following:
	 * 	-n.	Link to previous frame
	 * 	------------------------------
	 * 	...
	 * 	0.	Link to previous frame
	 * 	------------------------------
	 * 	1.	Supplied caller's data
	 * 	2.	Supplied caller's stack
	 * 	3.	Supplied return address
	 * 	4.	Link to supplied Executive stack pointer (-n)
	 * 	------------------------------
	 * 	5.	Caller's data
	 * 	6.	Caller's stack
	 * 	7.	Return address
	 * 	8.	Link to 4
	 * When longjmp makes its final branch, it will go to the returning
	 * phase of setjmp's trampoline, which unwinds to the frame and PC
	 * supplied by 3.
	 */

	/*
	 * Load link to the supplied buffer
	 * c2: Link to the supplied buffer
	 */
	ldr	c2, [c0], #CAP_WIDTH

	/* Check that the supplied buffer is on the current Executive stack */
	chkssu	c2, c2, csp
	b.pl	1f

	/* Check that the supplied buffer is below the top of the stack */
	cmp	sp, x2
	b.hs	1f

	/*
	 * All sanity checks have passed
	 * Locate the frame of the supplied buffer
	 * c2: Frame of the supplied buffer
	 */
	ldr	c4, [c2]
	ldr	c5, sealer_jmpbuf
2:	unseal	c3, c4, c5
	ldr	c4, [c3]
	gcseal	x6, c4
	cbnz	x6, 2b

	/*
	 * Get the previous frame.
	 * c4: Previous frame
	 */
	ldr	c4, [csp]

	/* Unwind the frames */
	mov	c5, c4
4:	ldr	c5, [c5]
	cmp	c5, c3
	b.eq	3f

	/* Enforce security policy here for each frame being unwound */
	b	4b

3:	ldp	c2, c5, [c2, #CAP_WIDTH]

	/* Restore general purpose registers */
	ldp	c19, c20, [c0], #(CAP_WIDTH * 2)
	ldp	c21, c22, [c0], #(CAP_WIDTH * 2)
	ldp	c23, c24, [c0], #(CAP_WIDTH * 2)
	ldp	c25, c26, [c0], #(CAP_WIDTH * 2)
	ldp	c27, c28, [c0], #(CAP_WIDTH * 2)
	ldr	c29, [c0], #CAP_WIDTH

	/* Update frame and save callee-saved registers */
	stp	c3, c2, [c4]
	stp	c5, c19, [c4, #(CAP_WIDTH * 2)]
	stp	c20, c21, [c4, #(CAP_WIDTH * 4)]
	stp	c22, c23, [c4, #(CAP_WIDTH * 6)]
	stp	c24, c25, [c4, #(CAP_WIDTH * 8)]
	stp	c26, c27, [c4, #(CAP_WIDTH * 10)]
	stp	c28, c29, [c4, #(CAP_WIDTH * 12)]

	mov	x6, xzr
	mov	x5, xzr
	mov	x4, xzr
	mov	x3, xzr
	mov	x2, xzr
	ret

	/* TODO: Abort */
1:	ret
END(_rtld_longjmp)

ENTRY(_rtld_get_rstk)
	/*
	 * This function MUST preserve all caller-saved registers except:
	 * - c11: Target restricted stack
	 * - c18: Code capability to this function
	 */
	stp	c17, c30, [csp, #-(CAP_WIDTH * 2)]
	stp	c15, c16, [csp, #-(CAP_WIDTH * 4)]
	stp	c13, c14, [csp, #-(CAP_WIDTH * 6)]
	stp	c10, c12, [csp, #-(CAP_WIDTH * 8)]
	stp	c8, c9, [csp, #-(CAP_WIDTH * 10)]
	stp	c6, c7, [csp, #-(CAP_WIDTH * 12)]
	stp	c4, c5, [csp, #-(CAP_WIDTH * 14)]
	stp	c2, c3, [csp, #-(CAP_WIDTH * 16)]
	stp	c0, c1, [csp, #-(CAP_WIDTH * 18)]!
	stp	q6, q7, [csp, #-(16 * 2)]
	stp	q4, q5, [csp, #-(16 * 4)]
	stp	q2, q3, [csp, #-(16 * 6)]
	stp	q0, q1, [csp, #-(16 * 8)]!

	mov	c0, c10					/* c0 = data */
	mov	w1, w12					/* w1 = index */
	mrs	c2, ctpidr_el0				/* c2 = table */

	bl	get_rstk
	mov	c11, c0

	ldp	q6, q7, [csp, #(16 * 6)]
	ldp	q4, q5, [csp, #(16 * 4)]
	ldp	q2, q3, [csp, #(16 * 2)]
	ldp	q0, q1, [csp], #(16 * 8)
	ldp	c17, c30, [csp, #(CAP_WIDTH * 16)]
	ldp	c15, c16, [csp, #(CAP_WIDTH * 14)]
	ldp	c13, c14, [csp, #(CAP_WIDTH * 12)]
	ldp	c10, c12, [csp, #(CAP_WIDTH * 10)]
	ldp	c8, c9, [csp, #(CAP_WIDTH * 8)]
	ldp	c6, c7, [csp, #(CAP_WIDTH * 6)]
	ldp	c4, c5, [csp, #(CAP_WIDTH * 4)]
	ldp	c2, c3, [csp, #(CAP_WIDTH * 2)]
	ldp	c0, c1, [csp], #(CAP_WIDTH * 18)

	ret
END(_rtld_get_rstk)

/*
 * Trampoline templates are code but reside in rodata. Hence a new macro is
 * defined to describe them.
 */
#define TRAMP(sym) \
	.section .rodata; .globl sym; .type sym,#object; sym:

#define TRAMPEND(sym) \
	end_##sym: \
	EEND(sym); \
	.section .rodata; .globl size_##sym; .align 3; .type size_##sym,#object; \
	.size size_##sym, 8; size_##sym: \
	.quad	end_##sym - sym

TRAMP(tramp_header)
tramp_header_target:
	.chericap	0
	ldr	c10, tramp_header_target
	mrs	c17, rcsp_el0
	mov	c18, csp

	/* Push frame */
	stp	c28, c29, [csp, #-(CAP_WIDTH * 2)]
	stp	c26, c27, [csp, #-(CAP_WIDTH * 4)]
	stp	c24, c25, [csp, #-(CAP_WIDTH * 6)]
	stp	c22, c23, [csp, #-(CAP_WIDTH * 8)]
	stp	c20, c21, [csp, #-(CAP_WIDTH * 10)]
	stp	c17, c19, [csp, #-(CAP_WIDTH * 12)]
	stp	c18, c30, [csp, #-(CAP_WIDTH * 14)]!
TRAMPEND(tramp_header)

TRAMP(tramp_header_hook)
tramp_header_hook_obj:
	.chericap	0
tramp_header_hook_def:
	.chericap	0
tramp_header_hook_function:
	.chericap	0
tramp_header_hook_target:
	.chericap	0
	ldr	c10, tramp_header_hook_obj
	ldr	c11, tramp_header_hook_def
	ldr	c12, tramp_header_hook_function
	mrs	c17, rcsp_el0
	mov	c18, csp

	str	c12, [csp, #-CAP_WIDTH]
	stp	c10, c11, [csp, #-(CAP_WIDTH * 3)]!

	/* Push frame */
	stp	c28, c29, [csp, #-(CAP_WIDTH * 2)]
	stp	c26, c27, [csp, #-(CAP_WIDTH * 4)]
	stp	c24, c25, [csp, #-(CAP_WIDTH * 6)]
	stp	c22, c23, [csp, #-(CAP_WIDTH * 8)]
	stp	c20, c21, [csp, #-(CAP_WIDTH * 10)]
	stp	c17, c19, [csp, #-(CAP_WIDTH * 12)]
	stp	c18, c30, [csp, #-(CAP_WIDTH * 14)]!

	/* Save argument registers */
	stp	c8, c9, [csp, #-(CAP_WIDTH * 2)]
	stp	c6, c7, [csp, #-(CAP_WIDTH * 4)]
	stp	c4, c5, [csp, #-(CAP_WIDTH * 6)]
	stp	c2, c3, [csp, #-(CAP_WIDTH * 8)]
	stp	c0, c1, [csp, #-(CAP_WIDTH * 10)]!
	stp	q6, q7, [csp, #-(16 * 2)]
	stp	q4, q5, [csp, #-(16 * 4)]
	stp	q2, q3, [csp, #-(16 * 6)]
	stp	q0, q1, [csp, #-(16 * 8)]!

	mov	w0, #0
	ldr	c1, tramp_header_hook_target
	mov	c2, c10
	mov	c3, c11
	blr	c12

	/* Restore argument registers */
	ldp	q6, q7, [csp, #(16 * 6)]
	ldp	q4, q5, [csp, #(16 * 4)]
	ldp	q2, q3, [csp, #(16 * 2)]
	ldp	q0, q1, [csp], #(16 * 8)
	ldp	c8, c9, [csp, #(CAP_WIDTH * 8)]
	ldp	c6, c7, [csp, #(CAP_WIDTH * 6)]
	ldp	c4, c5, [csp, #(CAP_WIDTH * 4)]
	ldp	c2, c3, [csp, #(CAP_WIDTH * 2)]
	ldp	c0, c1, [csp], #(CAP_WIDTH * 10)
	ldp	c30, c17, [csp, #CAP_WIDTH]
	ldr	c10, tramp_header_hook_target
TRAMPEND(tramp_header_hook)

TRAMP(tramp_header_res)
	mrs	c18, ctpidr_el0	/* c18 = table */
	movz	w12, #0		/* w12 = index, to be patched at runtime */
	gclen	x13, c18	/* x13 = len(table) */
TRAMPEND(tramp_header_res)

TRAMP(tramp_save_caller)
	/*
	 * If caller is Restricted, save its rcsp at the bottom of its own stack.
	 * Otherwise, the caller is RTLD or Restricted code performing a
	 * tail-call. In either case, there is no need to save the rcsp of the
	 * caller. This step must be done before the table lookup so that
	 * same-compartment switches get the correct stack.
	 */
	gcperm	x14, c30
	tbnz	x14, #1, 1f
	gclim	x15, c17
	scvalue	c16, c17, x15
	str	c17, [c16, #-CAP_WIDTH]

	/*
	 * Save the number of unused return value registers in the flags of csp.
	 */
1:	movz	x16, #0
	scflgs	csp, csp, x16
TRAMPEND(tramp_save_caller)

TRAMP(tramp_switch_stack)
	/*
	 * Callee is Restricted, so switch to its saved rcsp at the bottom of
	 * itself.
	 *
	 * Use subs instead of cmp to clear a register tag.
	 */
	subs	x17, x13, x12, lsl #4		/* if (len(table) <= index) */
	b.ls	2f				/* goto 2f */
	ldr	c11, [c18, w12, uxtw #4]	/* c11 = table[index] */
	cbnz	x11, 3f
	/*
	 * Call get_rstk(), which may invoke Restricted code (e.g. locking
	 * procedures in libthr), causing another trampoline to run. The
	 * implications of re-entrancy must be carefully addressed.
	 */
2:	blr	[c18, #0]			/* get_rstk() */
3:	ldr	c11, [c11, #-CAP_WIDTH]

	/* Move the c9 buffer to the target stack */
	cbz	x9, 6f
	gclen	x16, c9
	add	c17, c9, x16
	lsr	x16, x16, #4
	tst	x17, #0xf
	b.eq	5f

	orr	x18, x17, #0xfffffffffffffff0
	add	c11, c11, x18
7:	ldrb	w18, [c17, #-1]!
	strb	w18, [c11, #-1]!
	tst	x17, #0xf
	b.ne	7b

4:	cbz	x16, 6f
5:	ldr	c18, [c17, #-CAP_WIDTH]!
	str	c18, [c11, #-CAP_WIDTH]!
	sub	x16, x16, #1
	b	4b
6:
TRAMPEND(tramp_switch_stack)

TRAMP(tramp_invoke_exe)
	blr	c10

	/* Restore callee-saved registers */
	ldp	c18, c30, [csp], #(CAP_WIDTH * 14)
	ldp	c10, c19, [csp, #-(CAP_WIDTH * 12)]
	ldp	c20, c21, [csp, #-(CAP_WIDTH * 10)]
	ldp	c22, c23, [csp, #-(CAP_WIDTH * 8)]
	ldp	c24, c25, [csp, #-(CAP_WIDTH * 6)]
	ldp	c26, c27, [csp, #-(CAP_WIDTH * 4)]
	ldp	c28, c29, [csp, #-(CAP_WIDTH * 2)]

	/* Clear c11 */
	mov	x11, xzr
TRAMPEND(tramp_invoke_exe)

TRAMP(tramp_clear_regs)
	mov	x9, xzr
	mov	x8, xzr
	mov	x7, xzr
	mov	x6, xzr
	mov	x5, xzr
	mov	x4, xzr
	mov	x3, xzr
	mov	x2, xzr
	mov	x1, xzr
	mov	x0, xzr
TRAMPEND(tramp_clear_regs)

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
	 * - c10: Callee's code
	 * - c11: Callee's stack
	 * - c12: Callee's compartment ID (scalar)
	 * - c13: Length of stack table (scalar)
	 * - c14: Permissions of c30 (scalar)
	 * - c15: Limit of caller's stack (scalar)
	 * - c16: Flags of csp (scalar)
	 * - c17: Comparison result (scalar)
	 */
	mov	x18, xzr

	msr	rcsp_el0, c11
	blrr	c10

	/* Restore callee-saved registers */
	ldp	c18, c30, [csp], #(CAP_WIDTH * 14)
	ldp	c10, c19, [csp, #-(CAP_WIDTH * 12)]
	ldp	c20, c21, [csp, #-(CAP_WIDTH * 10)]
	ldp	c22, c23, [csp, #-(CAP_WIDTH * 8)]
	ldp	c24, c25, [csp, #-(CAP_WIDTH * 6)]
	ldp	c26, c27, [csp, #-(CAP_WIDTH * 4)]
	ldp	c28, c29, [csp, #-(CAP_WIDTH * 2)]

	/*
	 * Callee's saved rcsp may have changed during the call (e.g. because it
	 * called into another compartment). Restore it to the correct value
	 * here.
	 */
	mrs	c12, rcsp_el0
	gclim	x11, c12
	scvalue	c13, c12, x11
	str	c12, [c13, #-CAP_WIDTH]
TRAMPEND(tramp_invoke_res)

TRAMP(tramp_return_hook)
	/* Save return value registers */
	swp	c0, c2, [csp]
	add	csp, csp, #CAP_WIDTH
	swp	c1, c3, [csp]

	/* Save temporary registers and return address */
	add	csp, csp, #CAP_WIDTH
	swp	c10, c4, [csp]
	stp	c18, c30, [csp, #-(CAP_WIDTH * 4)]!

	/* Save floating point registers */
	stp	q6, q7, [csp, #-(16 * 2)]
	stp	q4, q5, [csp, #-(16 * 4)]
	stp	q2, q3, [csp, #-(16 * 6)]
	stp	q0, q1, [csp, #-(16 * 8)]!

	mov	w0, #1
	mov	x1, xzr
	blr	c4

	/* Restore floating point registers */
	ldp	q6, q7, [csp, #(16 * 6)]
	ldp	q4, q5, [csp, #(16 * 4)]
	ldp	q2, q3, [csp, #(16 * 2)]
	ldp	q0, q1, [csp], #(16 * 8)

	/* Restore temporary registers and return address */
	ldp	c18, c30, [csp], #(CAP_WIDTH * 2)
	ldp	c0, c1, [csp], #(CAP_WIDTH * 2)
	ldr	c10, [csp], #CAP_WIDTH
	mov	x11, xzr
TRAMPEND(tramp_return_hook)

TRAMP(tramp_return)
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
	gcflgs	x12, csp
	subs	x13, x12, #0b01
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
	 * - c10: Caller's stack
	 * - c11: Limit of callee's stack (scalar) or zero
	 * - c12: Flags of csp (scalar)
	 * - c13: Comparison result (scalar)
	 */
	mov	x17, xzr
	mov	x16, xzr
	mov	x15, xzr
	mov	x14, xzr

	mov	csp, c18
	mov	x18, xzr

	/*
	 * Restore caller's saved rcsp (has no effect if the caller is
	 * Executive).
	 */
	msr	rcsp_el0, c10
	retr	c30
TRAMPEND(tramp_return)
#endif
