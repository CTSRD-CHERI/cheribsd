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

/*
 * See rtld_c18n.h for an overview of the design.
 */

/*
 * XXX Dapeng: These assembly stubs are kept here for compatibility with old
 * libc and libunwind.
 */
/*
 * The _rtld_unw_{get,set}context_epilogue functions are stack unwinding
 * helpers. See the 'Stack unwinding' section in rtld_c18n.c.
 */
ENTRY(_rtld_unw_getcontext_epilogue)
	/*
	 * FIXME: llvm-libunwind specific ABI. This should be better specified.
	 */
	mov	c2, csp
	str	c2, [c1]
	RETURN
END(_rtld_unw_getcontext_epilogue)

/*
 * XXX: If compartmentalisation is not enabled, _rtld_unw_setcontext_ptr is NULL
 * and we simply restore a few registers and return via retr (back to Restricted
 * mode). Otherwise, call _rtld_unw_setcontext_impl via a trampoline.
 */
ENTRY(_rtld_unw_setcontext)
	ldr	c16, _rtld_unw_setcontext_ptr
	cbnz	w16, 1f
	/*
	 * FIXME: llvm-libunwind specific ABI. This should be better specified.
	 */
	mov	c16, c2
	ldp	c2, c3, [c3, #(-0x210 + 0x20)]
	mov	csp, c16
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	RETURN
#else
	retr	c30
#endif
1:
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	br	x16
#else
	br	c16
#endif
END(_rtld_unw_setcontext)

/*
 * The _rtld_sighandler function is the actual signal handler passed to the
 * kernel when the user calls sigaction. It dispatches the signal to the
 * appropriate handler registered by the user.
 */
ENTRY(_rtld_sighandler)
	/*
	 * Get the interrupted compartment's current stack top.
	 */
	get_untrusted_stk	c3
	/*
	 * The function is executing on an unknown untrusted stack. Switch to
	 * RTLD's stack.
	 */
	get_rtld_stk		c4
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	/*
	 * Allocate a sigframe on RTLD's stack.
	 */
	sub	c4, c4, #SIG_FRAME_SIZE
#endif
	set_untrusted_stk	c4
	b	_rtld_sighandler_impl
END(_rtld_sighandler)

.macro save_arguments
	/* Save the callee and the return address */
	str	c30, [csp, #-CAP_WIDTH]!

	/* Save floating point arguments */
	stp	q6, q7, [csp, #-(16 * 2)]
	stp	q4, q5, [csp, #-(16 * 4)]
	stp	q2, q3, [csp, #-(16 * 6)]
	stp	q0, q1, [csp, #-(16 * 8)]!

	/* Save argument registers */
	stp	c8, c9, [csp, #-(CAP_WIDTH * 2)]
	stp	c6, c7, [csp, #-(CAP_WIDTH * 4)]
	stp	c4, c5, [csp, #-(CAP_WIDTH * 6)]
	stp	c2, c3, [csp, #-(CAP_WIDTH * 8)]
	stp	c0, c1, [csp, #-(CAP_WIDTH * 10)]!
.endmacro

.macro restore_arguments
	/* Restore argument registers */
	ldp	c0, c1, [csp], #(CAP_WIDTH * 10)
	ldp	c2, c3, [csp, #-(CAP_WIDTH * 8)]
	ldp	c4, c5, [csp, #-(CAP_WIDTH * 6)]
	ldp	c6, c7, [csp, #-(CAP_WIDTH * 4)]
	ldp	c8, c9, [csp, #-(CAP_WIDTH * 2)]

	/* Restore floating point arguments */
	ldp	q0, q1, [csp], #(16 * 8)
	ldp	q2, q3, [csp, #-(16 * 6)]
	ldp	q4, q5, [csp, #-(16 * 4)]
	ldp	q6, q7, [csp, #-(16 * 2)]

	/* Restore the callee and the return address */
	ldr	c30, [csp], #CAP_WIDTH
.endmacro

/*
 * The create_untrusted_stack function has non-standard ABI and is only called
 * by trampolines when the destination compartment's stack has not been
 * allocated yet.
 */
ENTRY(create_untrusted_stk)
	/*
	 * NON-STANDARD CALLING CONVENTION
	 *
	 * c19: Callee to be tail-called
	 * w20: Callee's compartment ID
	 *
	 * The function resolves the callee's stack, installs it, and tail-calls
	 * the callee.
	 *
	 * All argument registers must be preserved. All temporary registers and
	 * callee-saved registers must be cleared.
	 */

	/*
	 * The execution stack is still the caller's stack. Switch to RTLD's
	 * stack.
	 */
	get_rtld_stk		c10
	set_untrusted_stk	c10

	save_arguments

	mov	w0, w20
	bl	resolve_untrusted_stk_impl
	mov	c10, c0

	restore_arguments

	set_untrusted_stk	c10

	/*
	 * Clear temporary registers, except:
	 * c10: Callee's stack
	 */
	mov	x11, xzr
	mov	x12, xzr
	mov	x13, xzr
	mov	x14, xzr
	mov	x15, xzr
	mov	x16, xzr
	mov	x17, xzr
	mov	x18, xzr

	/*
	 * All callee-saved registers are safe except c23
	 */
	mov	x23, xzr

#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	br	x19
#else
	brr	c19
#endif
END(create_untrusted_stk)

/*
 * The tramp_hook function has non-standard ABI and is only called by
 * trampolines to trace compartment transitions.
 */
ENTRY(tramp_hook)
	/*
	 * NON-STANDARD CALLING CONVENTION
	 *
	 * c10-c11 hold the first two arguments of tramp_hook.
	 *
	 * All argument registers and callee-saved registers must be preserved.
	 */

	save_arguments

	mov	c0, c10
	mov	c1, c11
	mrs	c2, TRUSTED_STACK
	bl	tramp_hook_impl

	restore_arguments

#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	RETURN
#else
	retr	c30
#endif
END(tramp_hook)

/*
 * The trampoline templates are assembly code sequences used to construct
 * trampolines by tramp_compile. They are code but reside in rodata. Hence a new
 * macro is defined to describe them.
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

#define	TRUSTED_STACK_C		c18

TRAMP(tramp_push_frame)
	mrs	TRUSTED_STACK_C, TRUSTED_STACK

	/*
	 * Load the caller's compartment ID and the landing address from the
	 * previous trusted frame.
	 */
	ldp	x10, x11, [TRUSTED_STACK_C, #TRUSTED_FRAME_CALLER]
	/*
	 * Get the stack lookup table.
	 */
	mrs	STACK_TABLE_C, STACK_TABLE
	/*
	 * Extract the caller's compartment ID.
	 */
	ubfx	x12, x10, #32, #16
	/*
	 * Load the caller's old stack top from the stack lookup table.
	 */
	ldr	c16, [STACK_TABLE_C, w12, uxtw #0]
	/*
	 * Get the caller's current stack top.
	 */
	get_untrusted_stk	c15
	/*
	 * Store the caller's current stack top in the stack lookup table.
	 */
	str	c15, [STACK_TABLE_C, w12, uxtw #0]

	stp	c19, c20, [TRUSTED_STACK_C, #(-CAP_WIDTH * TRUSTED_FRAME_SIZE + CAP_WIDTH * 2)]
	/*
	 * Load the target capability.
	 */
1:	ldr	c19, #0		/* To be patched at runtime */
	/*
	 * Get the callee's compartment ID.
	 */
2:	movz	w20, #0			/* To be patched at runtime */
	/*
	 * Get the length of the stack lookup table.
	 */
	gclen	x13, STACK_TABLE_C
	/*
	 * Use subs instead of cmp to clear a register tag.
	 */
	subs	x14, x13, x20

	/*
	 * Save the callee's current stack top and old stack top.
	 */
	stp	c15, c16, [TRUSTED_STACK_C, #(-CAP_WIDTH * TRUSTED_FRAME_SIZE + TRUSTED_FRAME_SP_OSP)]
	/*
	 * If the stack lookup table index is out-of-bounds, set it to zero.
	 */
	csel	w16, w20, wzr, hi
	/*
	 * Load the callee's stack if the stack lookup table index is within
	 * bounds. Otherwise the resolver will be loaded.
	 */
	ldr	c17, [STACK_TABLE_C, w16, uxtw #0]

	stp	c21, c22, [TRUSTED_STACK_C, #(-CAP_WIDTH * TRUSTED_FRAME_SIZE + CAP_WIDTH * 4)]
	/*
	 * The resolver is loaded iff the condition flag is ne.
	 */
	gcperm	x21, c17
	ands	x22, x21, #(1 << 15)
	/*
	 * If the resolver is loaded, keep the stack unchanged. Otherwise,
	 * install the callee's stack.
	 */
	csel	c15, c15, c17, ne

	stp	c23, c24, [TRUSTED_STACK_C, #(-CAP_WIDTH * TRUSTED_FRAME_SIZE + CAP_WIDTH * 6)]
	/*
	 * If the resolver is loaded, set the branch target to it. Otherwise,
	 * install the callee.
	 */
	csel	c23, c17, c19, ne
	/*
	 * Compare the return address to the landing address.
	 */
	subs	x24, x30, x11

	stp	c25, c26, [TRUSTED_STACK_C, #(-CAP_WIDTH * TRUSTED_FRAME_SIZE + CAP_WIDTH * 8)]
	/*
	 * Get the tag of the return capability.
	 */
	gctag	x25, c30
	/*
	 * Get the offset to the next trusted frame.
	 */
	mov	x26, #-(CAP_WIDTH * TRUSTED_FRAME_SIZE)
	/*
	 * The call is a tail-call iff the condition flag is eq.
	 */
	ccmp	x25, #1, #0, eq

	stp	c27, c28, [TRUSTED_STACK_C, #(-CAP_WIDTH * TRUSTED_FRAME_SIZE + CAP_WIDTH * 10)]
	/*
	 * If the call is a tail call, do not bump the trusted stack pointer.
	 */
	csel	x27, xzr, x26, eq
	/*
	 * Get the landing address.
	 */
3:	adr	c28, #0			/* To be patched at runtime */

	/*
	 * Save the address of the previous trusted frame and the compartment ID
	 * of the caller.
	 */
	stp	TRUSTED_STACK_C, c12, [TRUSTED_STACK_C, #(-CAP_WIDTH * TRUSTED_FRAME_SIZE + TRUSTED_FRAME_PREV)]

	stp	c29, c30, [TRUSTED_STACK_C, #(-CAP_WIDTH * TRUSTED_FRAME_SIZE)]
	/*
	 * Bump the trusted stack pointer if the call is not a tail-call. The
	 * callee-related portion of the trsuted stack must be written after
	 * this so that the topmost trusted frame contains the correct
	 * information about the callee regardless of whether the call is a
	 * tail-call.
	 */
	add	TRUSTED_STACK_C, TRUSTED_STACK_C, x27

	/*
	 * Save the landing address.
	 */
	str	x28, [TRUSTED_STACK_C, #TRUSTED_FRAME_LANDING]
	/*
	 * Get the number of return value registers.
	 */
4:	add	w28, w20, #0, lsl #12	/* To be patched at runtime */
	/*
	 * Save the callee's compartment ID and the number of return value
	 * registers.
	 */
	str	w28, [TRUSTED_STACK_C, #TRUSTED_FRAME_CALLEE]

	msr	TRUSTED_STACK, TRUSTED_STACK_C

	/*
	 * Install the callee's stack.
	 *
	 * Note: If an interrupt occurs between this instruction and the
	 * previous store instruction, the callee as identified by the topmost
	 * trusted frame would be inconsistent with the untrusted stack.
	 */
	set_untrusted_stk	c15
TRAMPEND(tramp_push_frame)

PATCH_POINT(tramp_push_frame, target, 1b)
PATCH_POINT(tramp_push_frame, cid, 2b)
PATCH_POINT(tramp_push_frame, landing, 3b)
PATCH_POINT(tramp_push_frame, ret_args, 4b)

/*
 * Save the address of the current frame to c29 so that unwinders can locate it.
 * When transitioning to Restricted mode code, its tag must be cleared.
 */
TRAMP(tramp_update_fp)
	mov	c29, TRUSTED_STACK_C
TRAMPEND(tramp_update_fp)

TRAMP(tramp_update_fp_untagged)
	clrtag	c29, TRUSTED_STACK_C
TRAMPEND(tramp_update_fp_untagged)

TRAMP(tramp_count_entry)
1:	ldr	c24, #0		/* To be patched at runtime */
	stadd	w25, [c24]
TRAMPEND(tramp_count_entry)

PATCH_POINT(tramp_count_entry, counter, 1b)

TRAMP(tramp_call_hook)
1:	ldr	c12, #0		/* To be patched at runtime */

2:	mov	w10, #0		/* To be patched at runtime */
3:	adr	c11, #0		/* To be patched at runtime */
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	blr	x12
#else
	blr	c12
#endif
TRAMPEND(tramp_call_hook)

PATCH_POINT(tramp_call_hook, function, 1b)
PATCH_POINT(tramp_call_hook, event, 2b)
PATCH_POINT(tramp_call_hook, header, 3b)

TRAMP(tramp_invoke_exe)
#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	blr	x23
#else
	blr	c23
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
	clrtag	TRUSTED_STACK_C, TRUSTED_STACK_C

#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	blr	x23
#else
	blrr	c23
#endif
TRAMPEND(tramp_invoke_res)

TRAMP(tramp_count_return)
	stadd	w25, [c24]
TRAMPEND(tramp_count_return)

TRAMP(tramp_pop_frame)
	mrs	TRUSTED_STACK_C, TRUSTED_STACK

	/*
	 * Load the address of the previous trusted frame, the compartment ID of
	 * the caller, and the number of return value registers.
	 */
	ldp	c17, c10, [TRUSTED_STACK_C, #TRUSTED_FRAME_PREV]

	/*
	 * Load the caller's current stack top and old stack top.
	 */
	ldp	c11, c12, [TRUSTED_STACK_C, #TRUSTED_FRAME_SP_OSP]

	/*
	 * Restore callee-saved registers.
	 */
	ldp	c27, c28, [TRUSTED_STACK_C, #(CAP_WIDTH * 10)]
	ldp	c25, c26, [TRUSTED_STACK_C, #(CAP_WIDTH * 8)]
	ldp	c23, c24, [TRUSTED_STACK_C, #(CAP_WIDTH * 6)]
	ldp	c21, c22, [TRUSTED_STACK_C, #(CAP_WIDTH * 4)]
	ldp	c19, c20, [TRUSTED_STACK_C, #(CAP_WIDTH * 2)]
	ldp	c29, c30, [TRUSTED_STACK_C]

	/*
	 * Install the caller's stack.
	 *
	 * Note: If an interrupt occurs between this instruction and the next,
	 * the callee as identified by the topmost trusted frame would be
	 * inconsistent with the untrusted stack.
	 */
	set_untrusted_stk	c11
	/*
	 * Bump the trusted stack pointer.
	 */
	msr	TRUSTED_STACK, c17

	/*
	 * Get the stack lookup table.
	 */
	mrs	STACK_TABLE_C, STACK_TABLE
	/*
	 * Store the caller's old stack top in the stack lookup table.
	 */
	str	c12, [STACK_TABLE_C, w10, uxtw #0]

	/*
	 * Extract the number of return value registers.
	 */
	ubfx	x13, x10, #48, #2
	/*
	 * Clear unused return value registers. The registers to clear are
	 * encoded as follows:
	 * - None:	0b00
	 * - c1 only:	0b01
	 * - c0 and c1:	0b1x
	 * Use comparison and csel to avoid branching.
	 *
	 * Use subs instead of cmp to clear a register tag.
	 */
	subs	w14, w13, #0b01
	csel	c0, czr, c0, hi
	csel	c1, czr, c1, hs

	/*
	 * Clear temporary registers.
	 */
	mov	x2, xzr
	mov	x3, xzr
	mov	x4, xzr
	mov	x5, xzr
	mov	x6, xzr
	mov	x7, xzr
	mov	x8, xzr
	mov	x9, xzr
	mov	x15, xzr
	mov	x16, xzr
	mov	x17, xzr
	mov	x18, xzr

#ifdef __ARM_MORELLO_PURECAP_BENCHMARK_ABI
	RETURN
#else
	retr	c30
#endif
TRAMPEND(tramp_pop_frame)
