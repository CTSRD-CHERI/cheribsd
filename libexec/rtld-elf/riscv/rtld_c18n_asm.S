/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Dapeng Gao
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
 * The _rtld_sighandler function is the actual signal handler passed to the
 * kernel when the user calls sigaction. It dispatches the signal to the
 * appropriate handler registered by the user.
 */
ENTRY(_rtld_sighandler)
	/*
	 * Get the interrupted compartment's current stack top.
	 */
	get_untrusted_stk	ca3
	/*
	 * The function is executing on an unknown untrusted stack. Switch to
	 * RTLD's stack.
	 */
	get_rtld_stk		ca4
	/*
	 * Allocate a sigframe on RTLD's stack.
	 */
	cincoffsetimm		ca4, ca4, -SIG_FRAME_SIZE
	set_untrusted_stk	ca4
	j			_rtld_sighandler_impl
END(_rtld_sighandler)

.macro save_arguments
	cincoffsetimm	csp, csp, -(9 * CLEN_BYTES + 8 * 8)

	/* Save floating point arguments */
	cfsd	fa0, (0 * 8)(csp)
	cfsd	fa1, (1 * 8)(csp)
	cfsd	fa2, (2 * 8)(csp)
	cfsd	fa3, (3 * 8)(csp)
	cfsd	fa4, (4 * 8)(csp)
	cfsd	fa5, (5 * 8)(csp)
	cfsd	fa6, (6 * 8)(csp)
	cfsd	fa7, (7 * 8)(csp)

	/* Save argument registers */
	csc	ca0, (0 * CLEN_BYTES + 8 * 8)(csp)
	csc	ca1, (1 * CLEN_BYTES + 8 * 8)(csp)
	csc	ca2, (2 * CLEN_BYTES + 8 * 8)(csp)
	csc	ca3, (3 * CLEN_BYTES + 8 * 8)(csp)
	csc	ca4, (4 * CLEN_BYTES + 8 * 8)(csp)
	csc	ca5, (5 * CLEN_BYTES + 8 * 8)(csp)
	csc	ca6, (6 * CLEN_BYTES + 8 * 8)(csp)
	csc	ca7, (7 * CLEN_BYTES + 8 * 8)(csp)

	/* Save return address */
	csc	cra, (8 * CLEN_BYTES + 8 * 8)(csp)
.endmacro

.macro restore_arguments
	/* Restore floating point arguments */
	cfsd	fa0, (0 * 8)(csp)
	cfsd	fa1, (1 * 8)(csp)
	cfsd	fa2, (2 * 8)(csp)
	cfsd	fa3, (3 * 8)(csp)
	cfsd	fa4, (4 * 8)(csp)
	cfsd	fa5, (5 * 8)(csp)
	cfsd	fa6, (6 * 8)(csp)
	cfsd	fa7, (7 * 8)(csp)

	/* Restore argument registers */
	clc	ca0, (0 * CLEN_BYTES + 8 * 8)(csp)
	clc	ca1, (1 * CLEN_BYTES + 8 * 8)(csp)
	clc	ca2, (2 * CLEN_BYTES + 8 * 8)(csp)
	clc	ca3, (3 * CLEN_BYTES + 8 * 8)(csp)
	clc	ca4, (4 * CLEN_BYTES + 8 * 8)(csp)
	clc	ca5, (5 * CLEN_BYTES + 8 * 8)(csp)
	clc	ca6, (6 * CLEN_BYTES + 8 * 8)(csp)
	clc	ca7, (7 * CLEN_BYTES + 8 * 8)(csp)

	/* Restore return address */
	clc	cra, (8 * CLEN_BYTES + 8 * 8)(csp)

	cincoffsetimm	csp, csp, (9 * CLEN_BYTES + 8 * 8)
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
	 * s8: Callee to be tail-called
	 * s9: Callee's compartment ID
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
	get_rtld_stk		ct0
	set_untrusted_stk	ct0

	save_arguments

	move		a0, s9
	cjal		resolve_untrusted_stk_impl
	cmove		ct0, ca0

	restore_arguments

	set_untrusted_stk	ct0

	/*
	 * Clear temporary registers, except:
	 * t0: Callee's stack
	 */
	move		t1, x0
	move		t2, x0
	move		t3, x0
	move		t4, x0
	move		t5, x0
	move		t6, x0

	/*
	 * All callee-saved registers are safe except s4
	 */
	move		s4, x0

	cjr		cs8
END(create_untrusted_stk)

/*
 * The tramp_hook function has non-standard ABI and is only called by
 * trampolines to trace compartment transitions.
 */
ENTRY(tramp_hook)
	/*
	 * NON-STANDARD CALLING CONVENTION
	 *
	 * ct0-ct1 hold the first two arguments of tramp_hook.
	 *
	 * All argument registers and callee-saved registers must be preserved.
	 */

	save_arguments

	cmove		ca0, ct0
	cmove		ca1, ct1
	cjal		tramp_hook_impl

	restore_arguments

	cret
END(tramp_hook)

/*
 * The trampoline templates are assembly code sequences used to construct
 * trampolines by tramp_compile. They are code but reside in rodata. Hence a new
 * macro is defined to describe them.
 */
#define TRAMP(sym)							\
	.section .rodata; .globl sym; .type sym,%object; sym:

#define TRAMPEND(sym)							\
	end_##sym:							\
	EEND(sym);							\
	.section .rodata; .globl size_##sym; .align 3;			\
	.type size_##sym,%object; .size size_##sym, 8; size_##sym:	\
	.quad	end_##sym - sym

#define	PATCH_POINT(tramp, name, label)					\
	.section .rodata; .globl patch_##tramp##_##name; .align 2;	\
	.type patch_##tramp##_##name,%object;				\
	.size patch_##tramp##_##name, 4; patch_##tramp##_##name:	\
	.word	label - end_##tramp

#define	TRUSTED_STACK_C		ct3

TRAMP(tramp_push_frame)
1:	auipcc		ct0, 0
	/*
	 * Get the unsealer for the thread identifier buffer.
	 */
.option push
.option norvc
2:	clc		ct1, 0(ct0)		/* To be patched at runtime */
.option pop
	/*
	 * Get and unseal the thread identifier buffer.
	 */
	cspecialr	ct2, TIDC
	cunseal		ct1, ct2, ct1
	/*
	 * Get the trusted stack.
	 */
	clc		TRUSTED_STACK_C, TRUSTED_STACK(ct1)
	/*
	 * Load the caller's compartment ID from the previous trusted frame.
	 */
	clhu		t4, TRUSTED_FRAME_CALLEE(TRUSTED_STACK_C)
	/*
	 * Get the stack lookup table.
	 */
	clc		STACK_TABLE_C, STACK_TABLE(ct1)
	/*
	 * Load the caller's old stack top from the stack lookup table.
	 */
	csetoffset	STACK_TABLE_C, STACK_TABLE_C, t4
	clc		ct5, 0(STACK_TABLE_C)
	/*
	 * Store the caller's current stack top in the stack lookup table.
	 */
	csc		csp, 0(STACK_TABLE_C)

	csc		cs11, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + CLEN_BYTES * 12)(TRUSTED_STACK_C)
	/*
	 * Get the length of the stack lookup table.
	 */
	cgetlen		s11, STACK_TABLE_C

	csc		cs10, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + CLEN_BYTES * 11)(TRUSTED_STACK_C)
	/*
	 * Get the callee's compartment ID.
	 */
.option push
.option norvc
3:	addi		s10, x0, 0		/* To be patched at runtime */
.option pop
	csc		cs9, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + CLEN_BYTES * 10)(TRUSTED_STACK_C)
	addi		s9, s10, 0
	/*
	 * Compare the compartment ID to the length of the stack lookup table.
	 * If the stack lookup table index is out-of-bounds, set it to zero.
	 */
	bltu		s10, s11, 4f
	addi		s10, x0, 0
4:
	/*
	 * Load the callee's stack if the stack lookup table index is within
	 * bounds. Otherwise the resolver will be loaded.
	 */
	csetoffset	STACK_TABLE_C, STACK_TABLE_C, s10
	clc		ct6, 0(STACK_TABLE_C)

	/*
	 * Load the target capability.
	 */
	csc		cs8, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + CLEN_BYTES * 9)(TRUSTED_STACK_C)
.option push
.option norvc
5:	clc		cs8, 0(ct0)		/* To be patched at runtime */
.option pop
	/*
	 * Get the permissions of the loaded value.
	 */
	csc		cs7, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + CLEN_BYTES * 8)(TRUSTED_STACK_C)
	cgetperm	s7, ct6
	/*
	 * The resolver is loaded iff the value is non-zero.
	 */
	csc		cs6, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + CLEN_BYTES * 7)(TRUSTED_STACK_C)
	andi		s6, s7, (1 << 1)
	/*
	 * If the resolver is loaded, keep the stack unchanged. Otherwise,
	 * install the callee's stack.
	 */
	csc		cs5, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + CLEN_BYTES * 6)(TRUSTED_STACK_C)
	cmove		cs5, ct6
	/*
	 * If the resolver is loaded, set the branch target to it. Otherwise,
	 * install the callee.
	 */
	csc		cs4, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + CLEN_BYTES * 5)(TRUSTED_STACK_C)
	cmove		cs4, cs8
	beqz		s6, 6f
	cmove		cs5, csp
	cmove		cs4, ct6
6:

	csc		cs3, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + CLEN_BYTES * 4)(TRUSTED_STACK_C)
	/*
	 * Load the landing address from the previous trusted frame.
	 */
	cld		s3, TRUSTED_FRAME_LANDING(TRUSTED_STACK_C)
	csc		cs2, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + CLEN_BYTES * 3)(TRUSTED_STACK_C)
	/*
	 * Load the existing number of return value registers.
	 */
	clbu		s2, (TRUSTED_FRAME_CALLEE + 2)(TRUSTED_STACK_C)
	/*
	 * Get the tag of the return capability.
	 */
	csc		cs1, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + CLEN_BYTES * 2)(TRUSTED_STACK_C)
	cgettag		s1, cra

	csc		cra, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + CLEN_BYTES * 1)(TRUSTED_STACK_C)
	csc		cs0, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + CLEN_BYTES * 0)(TRUSTED_STACK_C)

	/*
	 * Save the caller's current stack top and old stack top.
	 */
	csc		csp, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + TRUSTED_FRAME_SP_OSP)(TRUSTED_STACK_C)
	csc		ct5, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + TRUSTED_FRAME_SP_OSP + CLEN_BYTES)(TRUSTED_STACK_C)
	/*
	 * Save the address of the previous trusted frame.
	 */
	csc		TRUSTED_STACK_C, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + TRUSTED_FRAME_PREV)(TRUSTED_STACK_C)
	/*
	 * Save the the compartment ID of the caller.
	 */
	csw		t4, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + TRUSTED_FRAME_CALLER)(TRUSTED_STACK_C)
TRAMPEND(tramp_push_frame)

PATCH_POINT(tramp_push_frame, pcc, 1b)
PATCH_POINT(tramp_push_frame, unsealer, 2b)
PATCH_POINT(tramp_push_frame, cid, 3b)
PATCH_POINT(tramp_push_frame, target, 5b)

TRAMP(tramp_count_entry)
.option push
.option norvc
1:	clc		cs6, 0(ct0)		/* To be patched at runtime */
.option pop
	li		s7, 1
	camoadd.d	x0, s7, (cs6)
TRAMPEND(tramp_count_entry)

PATCH_POINT(tramp_count_entry, counter, 1b)

TRAMP(tramp_push_frame_2)
	/*
	 * Get the landing address.
	 */
.option push
.option norvc
7:	addi		t0, t0, 0		/* To be patched at runtime */
.option pop

	/*
	 * Compare the return address to the landing address.
	 *
	 * Bump the trusted stack pointer if the call is not a tail-call. The
	 * callee-related portion of the trsuted stack must be written after
	 * this so that the topmost trusted frame contains the correct
	 * information about the callee regardless of whether the call is a
	 * tail-call.
	 */
	bne		ra, s3, 8f
	bnez		s1, 9f
8:
	cincoffsetimm	TRUSTED_STACK_C, TRUSTED_STACK_C, (-CLEN_BYTES * TRUSTED_FRAME_SIZE)
	csc		TRUSTED_STACK_C, TRUSTED_STACK(ct1)
	addi		s2, x0, 0
9:

	/*
	 * Save the callee's compartment ID.
	 */
	csh		s9, TRUSTED_FRAME_CALLEE(TRUSTED_STACK_C)
	/*
	 * Compute and save the number of return value registers.
	 */
.option push
.option norvc
10:	ori		t1, s2, 0		/* To be patched at runtime */
.option pop
	csb		t1, (TRUSTED_FRAME_CALLEE + 2)(TRUSTED_STACK_C)
	/*
	 * Save the landing address.
	 */
	csd		t0, TRUSTED_FRAME_LANDING(TRUSTED_STACK_C)

	/*
	 * Install the callee's stack.
	 *
	 * Note: If an interrupt occurs between this instruction and the
	 * previous store instruction, the callee as identified by the topmost
	 * trusted frame would be inconsistent with the untrusted stack.
	 */
	set_untrusted_stk	cs5
TRAMPEND(tramp_push_frame_2)

PATCH_POINT(tramp_push_frame_2, landing, 7b)
PATCH_POINT(tramp_push_frame_2, n_rets, 10b)

TRAMP(tramp_call_hook)
1:	auipcc		ct1, 0
.option push
.option norvc
2:	clc		cra, 0(ct1)		/* To be patched at runtime */

3:	addi		t0, x0, 0		/* To be patched at runtime */
4:	cincoffsetimm	ct1, ct1, 0		/* To be patched at runtime */
.option pop
	cjalr		cra, cra
TRAMPEND(tramp_call_hook)

PATCH_POINT(tramp_call_hook, pcc, 1b)
PATCH_POINT(tramp_call_hook, function, 2b)
PATCH_POINT(tramp_call_hook, event, 3b)
PATCH_POINT(tramp_call_hook, header, 4b)

/*
 * Save the address of the current frame to fp so that unwinders can locate it.
 * When transitioning to Restricted mode code, its tag must be cleared.
 */
TRAMP(tramp_update_fp)
	cmove		cs0, TRUSTED_STACK_C
TRAMPEND(tramp_update_fp)

TRAMP(tramp_update_fp_untagged)
	ccleartag	cs0, TRUSTED_STACK_C
TRAMPEND(tramp_update_fp_untagged)

TRAMP(tramp_clear_args_a67)
/*                                 xx */
1:	cclear		2, 0b00000000		/* To be patched at runtime */
TRAMPEND(tramp_clear_args_a67)

PATCH_POINT(tramp_clear_args_a67, a67, 1b)

TRAMP(tramp_clear_args_a05)
/*                           xxxxxx   */
1:	cclear		1, 0b00000000		/* To be patched at runtime */
TRAMPEND(tramp_clear_args_a05)

PATCH_POINT(tramp_clear_args_a05, a05, 1b)

TRAMP(tramp_clear_args)
	/*
	 * Each instruction here is 2 bytes long.
	 */
	addi		a7, x0, 0
	addi		a6, x0, 0
	addi		a5, x0, 0
	addi		a4, x0, 0
	addi		a3, x0, 0
	addi		a2, x0, 0
	addi		a1, x0, 0
	addi		a0, x0, 0
TRAMPEND(tramp_clear_args)

TRAMP(tramp_invoke)
	ccleartag	TRUSTED_STACK_C, TRUSTED_STACK_C
	cjalr		cra, cs4
TRAMPEND(tramp_invoke)

TRAMP(tramp_count_return)
	camoadd.d	x0, s7, (cs6)
TRAMPEND(tramp_count_return)

TRAMP(tramp_pop_frame)
1:	auipcc		ct4, 0
	/*
	 * Get the unsealer for the thread identifier buffer.
	 */
.option push
.option norvc
2:	clc		ct4, 0(ct4)		/* To be patched at runtime */
.option pop
	/*
	 * Get and unseal the thread identifier buffer.
	 */
	cspecialr	ct0, TIDC
	cunseal		ct4, ct0, ct4

	/*
	 * Get the trusted stack.
	 */
	clc		TRUSTED_STACK_C, TRUSTED_STACK(ct4)
	/*
	 * Load the address of the previous trusted frame, the compartment ID of
	 * the caller, and the compartment ID of the caller.
	 */
	clc		ct5, TRUSTED_FRAME_PREV(TRUSTED_STACK_C)
	clhu		t1, TRUSTED_FRAME_CALLER(TRUSTED_STACK_C)
	clbu		t2, (TRUSTED_FRAME_CALLEE + 2)(TRUSTED_STACK_C)
	/*
	 * Load the caller's current stack top and old stack top.
	 */
	clc		ca7, (TRUSTED_FRAME_SP_OSP)(TRUSTED_STACK_C)
	clc		ca6, (TRUSTED_FRAME_SP_OSP + CLEN_BYTES)(TRUSTED_STACK_C)

	/*
	 * Get the stack lookup table.
	 */
	clc		STACK_TABLE_C, STACK_TABLE(ct4)

	/*
	 * Restore callee-saved registers.
	 */
	clc		cs0, (CLEN_BYTES * 0)(TRUSTED_STACK_C)
	clc		cra, (CLEN_BYTES * 1)(TRUSTED_STACK_C)
	clc		cs1, (CLEN_BYTES * 2)(TRUSTED_STACK_C)
	clc		cs2, (CLEN_BYTES * 3)(TRUSTED_STACK_C)
	clc		cs3, (CLEN_BYTES * 4)(TRUSTED_STACK_C)
	clc		cs4, (CLEN_BYTES * 5)(TRUSTED_STACK_C)
	clc		cs5, (CLEN_BYTES * 6)(TRUSTED_STACK_C)
	clc		cs6, (CLEN_BYTES * 7)(TRUSTED_STACK_C)
	clc		cs7, (CLEN_BYTES * 8)(TRUSTED_STACK_C)
	clc		cs8, (CLEN_BYTES * 9)(TRUSTED_STACK_C)
	clc		cs9, (CLEN_BYTES * 10)(TRUSTED_STACK_C)
	clc		cs10, (CLEN_BYTES * 11)(TRUSTED_STACK_C)
	clc		cs11, (CLEN_BYTES * 12)(TRUSTED_STACK_C)

	/*
	 * Install the caller's stack.
	 *
	 * Note: If an interrupt occurs between this instruction and the next,
	 * the callee as identified by the topmost trusted frame would be
	 * inconsistent with the untrusted stack.
	 */
	set_untrusted_stk	ca7
	/*
	 * Bump the trusted stack pointer.
	 */
	csc		ct5, TRUSTED_STACK(ct4)

	/*
	 * Store the caller's old stack top in the stack lookup table.
	 */
	csetoffset	STACK_TABLE_C, STACK_TABLE_C, t1
	csc		ca6, 0(STACK_TABLE_C)

	/*
	 * Extract the number of return value registers. The number of return
	 * value registers is encoded as follows:
	 * - TWO:	0b00
	 * - ONE:	0b01
	 * - NONE:	0b10
	 * - INDIRECT:	0b11
	 */
	beqz		t2, 3f
	addi		a1, x0, 1
	beq		t2, a1, 3f
	addi		a0, x0, 0
3:

	/*
	 * Clear temporary registers.
	 * cclear		1, 0b11110000		a2 to a5
	 * cclear		3, 0b11110000		t3 to t6
	 */
	addi		a2, x0, 0
	addi		a3, x0, 0
	addi		a4, x0, 0
	addi		a5, x0, 0
	addi		t3, x0, 0
	addi		t4, x0, 0
	addi		t5, x0, 0
	addi		t6, x0, 0

	cret
TRAMPEND(tramp_pop_frame)

PATCH_POINT(tramp_pop_frame, pcc, 1b)
PATCH_POINT(tramp_pop_frame, unsealer, 2b)
