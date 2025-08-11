/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024-2025 Dapeng Gao
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
	 * The function is executing on a sigaltstack. Switch to RTLD's stack.
	 */
	get_rtld_stk		ca3, a3, t0
	/*
	 * Allocate a sigframe on RTLD's stack.
	 */
	caddi			ca3, ca3, -SIG_FRAME_SIZE
	set_untrusted_stk	ca3
	j			_rtld_sighandler_impl
END(_rtld_sighandler)

.macro save_arguments
	caddi	csp, csp, -(10 * CLEN_BYTES + 8 * 8)

	/* Save floating point arguments */
	fsd	fa0, (0 * 8)(csp)
	fsd	fa1, (1 * 8)(csp)
	fsd	fa2, (2 * 8)(csp)
	fsd	fa3, (3 * 8)(csp)
	fsd	fa4, (4 * 8)(csp)
	fsd	fa5, (5 * 8)(csp)
	fsd	fa6, (6 * 8)(csp)
	fsd	fa7, (7 * 8)(csp)

	/* Save argument registers */
	sc	ca0, (0 * CLEN_BYTES + 8 * 8)(csp)
	sc	ca1, (1 * CLEN_BYTES + 8 * 8)(csp)
	sc	ca2, (2 * CLEN_BYTES + 8 * 8)(csp)
	sc	ca3, (3 * CLEN_BYTES + 8 * 8)(csp)
	sc	ca4, (4 * CLEN_BYTES + 8 * 8)(csp)
	sc	ca5, (5 * CLEN_BYTES + 8 * 8)(csp)
	sc	ca6, (6 * CLEN_BYTES + 8 * 8)(csp)
	sc	ca7, (7 * CLEN_BYTES + 8 * 8)(csp)
	sc	ct6, (8 * CLEN_BYTES + 8 * 8)(csp)

	/* Save return address */
	sc	cra, (9 * CLEN_BYTES + 8 * 8)(csp)
.endmacro

.macro restore_arguments
	/* Restore floating point arguments */
	fsd	fa0, (0 * 8)(csp)
	fsd	fa1, (1 * 8)(csp)
	fsd	fa2, (2 * 8)(csp)
	fsd	fa3, (3 * 8)(csp)
	fsd	fa4, (4 * 8)(csp)
	fsd	fa5, (5 * 8)(csp)
	fsd	fa6, (6 * 8)(csp)
	fsd	fa7, (7 * 8)(csp)

	/* Restore argument registers */
	lc	ca0, (0 * CLEN_BYTES + 8 * 8)(csp)
	lc	ca1, (1 * CLEN_BYTES + 8 * 8)(csp)
	lc	ca2, (2 * CLEN_BYTES + 8 * 8)(csp)
	lc	ca3, (3 * CLEN_BYTES + 8 * 8)(csp)
	lc	ca4, (4 * CLEN_BYTES + 8 * 8)(csp)
	lc	ca5, (5 * CLEN_BYTES + 8 * 8)(csp)
	lc	ca6, (6 * CLEN_BYTES + 8 * 8)(csp)
	lc	ca7, (7 * CLEN_BYTES + 8 * 8)(csp)
	lc	ct6, (8 * CLEN_BYTES + 8 * 8)(csp)

	/* Restore return address */
	lc	cra, (9 * CLEN_BYTES + 8 * 8)(csp)

	caddi	csp, csp, (10 * CLEN_BYTES + 8 * 8)
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
	 * cs7: Callee to be tail-called
	 * s10: Callee's compartment ID
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
	get_rtld_stk		ct0, t0, t1
	set_untrusted_stk	ct0

	save_arguments

	move		a0, s10
	jal		resolve_untrusted_stk_impl
	cmv		ct0, ca0

	restore_arguments

	set_untrusted_stk	ct0

	/*
	 * Clear temporary registers, except:
	 * ct0: Callee's stack
	 * ct6: Memory arguments
	 */
	li		t1, 0
	li		t2, 0
	li		t3, 0
	li		t4, 0
	li		t5, 0

	/*
	 * All callee-saved registers are safe except cs4 and cs5
	 */
	li		s4, 0
	li		s5, 0

	jr		cs7
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

	cmv		ca0, ct0
	cmv		ca1, ct1
	jal		tramp_hook_impl

	restore_arguments

	ret
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

#define	TRUSTED_STACK_S		t4
#define	TRUSTED_STACK_C		ct4
#undef	CHERI_C18N_ZICOND

TRAMP(tramp_push_frame)
1:	auipc		ct0, 0
.option push
.option norvc
	/*
	 * Get the unsealer for the thread identifier buffer.
	 */
2:	lc		ct1, 0(ct0)		/* To be patched at runtime */
.option pop
	/*
	 * Get and unseal the thread identifier buffer.
	 */
	csrr		ct2, utidc
	unseal_tidc	ct1, ct1, ct2, t2, t3
	/*
	 * Get the trusted stack.
	 */
	lc		TRUSTED_STACK_C, TRUSTED_STACK(ct1)
	/*
	 * Load the caller's compartment ID from the previous trusted frame.
	 */
	sc		cs11, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + CLEN_BYTES * 10)(TRUSTED_STACK_C)
	lhu		s11, TRUSTED_FRAME_CALLEE(TRUSTED_STACK_C)
	/*
	 * Get the stack lookup table.
	 */
	lc		STACK_TABLE_C, STACK_TABLE(ct1)
	/*
	 * Load the caller's old stack top from the stack lookup table and save
	 * it in the trusted frame.
	 */
	sc		cs10, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + CLEN_BYTES * 9)(TRUSTED_STACK_C)
	cadd		STACK_TABLE_C, STACK_TABLE_C, s11
	lc		cs10, 0(STACK_TABLE_C)
	/*
	 * Store the caller's current stack top in the stack lookup table. The
	 * current stack top is rederived from the old stack top to inductively
	 * guarantee that the stack has not been swapped.
	 */
	scaddr		csp, cs10, sp
	sc		csp, 0(STACK_TABLE_C)

	/*
	 * Get the callee's compartment ID.
	 */
	sc		cs10, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + TRUSTED_FRAME_SP_OSP + CLEN_BYTES)(TRUSTED_STACK_C)
3:	c.li		s10, 0			/* To be patched at runtime */
.option push
.option norvc
4:	addi		s10, s10, 0		/* To be patched at runtime */
.option pop
	/*
	 * Get the length of the stack lookup table.
	 */
	sc		cs9, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + CLEN_BYTES * 8)(TRUSTED_STACK_C)
	gclen		s9, STACK_TABLE_C
	/*
	 * Compare the compartment ID to the length of the stack lookup table.
	 * If the stack lookup table index is out-of-bounds, set it to zero.
	 */
	sc		cs8, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + CLEN_BYTES * 7)(TRUSTED_STACK_C)
	sltu		s8, s10, s9
#ifdef CHERI_C18N_ZICOND
	//czero.eqz	s8, s10, s8
	.word		0x0f8d5c33
#else
	neg		s8, s8
	and		s8, s10, s8
#endif
	sub		s8, s8, s11
	/*
	 * Load the callee's stack if the stack lookup table index is within
	 * bounds. Otherwise the resolver will be loaded.
	 */
	cadd		STACK_TABLE_C, STACK_TABLE_C, s8
	lc		ct5, 0(STACK_TABLE_C)

	/*
	 * Load the target capability.
	 */
	sc		cs7, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + CLEN_BYTES * 6)(TRUSTED_STACK_C)
.option push
.option norvc
5:	lc		cs7, 0(ct0)		/* To be patched at runtime */
.option pop
	/*
	 * Get the type of the loaded value. The resolver is loaded iff the
	 * type is 1.
	 */
	sc		cs6, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + CLEN_BYTES * 5)(TRUSTED_STACK_C)
	gctype		s6, ct5
	/*
	 * If the resolver is loaded, keep the stack unchanged. Otherwise,
	 * install the callee's stack.
	 */
	sc		cs5, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + CLEN_BYTES * 4)(TRUSTED_STACK_C)
	cmv		cs5, ct5
	/*
	 * If the resolver is loaded, set the branch target to it. Otherwise,
	 * install the callee.
	 */
	sc		cs4, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + CLEN_BYTES * 3)(TRUSTED_STACK_C)
	cmv		cs4, cs7
	beqz		s6, 6f
	cmv		cs5, csp
	cmv		cs4, ct5
6:

	/*
	 * Load the landing address from the previous trusted frame.
	 */
	sc		cs3, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + CLEN_BYTES * 2)(TRUSTED_STACK_C)
	ld		s3, TRUSTED_FRAME_LANDING(TRUSTED_STACK_C)
	/*
	 * Load the existing number of return value registers.
	 */
	sc		cs2, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + CLEN_BYTES * 1)(TRUSTED_STACK_C)
	lbu		s2, (TRUSTED_FRAME_CALLEE + 2)(TRUSTED_STACK_C)
	/*
	 * Get the tag of the return capability.
	 */
	sc		cs1, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + CLEN_BYTES * 0)(TRUSTED_STACK_C)
	gctag		s1, cra
	/*
	 * Save the return address, the frame pointer, and the caller's current stack top.
	 */
	sc		cs0, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + CLEN_BYTES * 11)(TRUSTED_STACK_C)
	sc		cra, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + CLEN_BYTES * 12)(TRUSTED_STACK_C)
	sc		csp, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + TRUSTED_FRAME_SP_OSP)(TRUSTED_STACK_C)
	/*
	 * Save the address of the previous trusted frame.
	 */
	sc		TRUSTED_STACK_C, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + TRUSTED_FRAME_PREV)(TRUSTED_STACK_C)
	/*
	 * Save the compartment ID of the caller.
	 */
	sw		s11, (-CLEN_BYTES * TRUSTED_FRAME_SIZE + TRUSTED_FRAME_CALLER)(TRUSTED_STACK_C)
TRAMPEND(tramp_push_frame)

PATCH_POINT(tramp_push_frame, pcc, 1b)
PATCH_POINT(tramp_push_frame, unsealer, 2b)
PATCH_POINT(tramp_push_frame, cidu, 3b)
PATCH_POINT(tramp_push_frame, cid, 4b)
PATCH_POINT(tramp_push_frame, target, 5b)

TRAMP(tramp_count_entry)
.option push
.option norvc
1:	lc		cs9, 0(ct0)		/* To be patched at runtime */
.option pop
	li		s8, 1
	camoadd.d	x0, s8, (cs9)
TRAMPEND(tramp_count_entry)

PATCH_POINT(tramp_count_entry, counter, 1b)

TRAMP(tramp_push_frame_2)
	/*
	 * Compare the return address to the landing address.
	 *
	 * Bump the trusted stack pointer if the call is not a tail-call. The
	 * callee-related portion of the trusted stack must be written after
	 * this so that the topmost trusted frame contains the correct
	 * information about the callee regardless of whether the call is a
	 * tail-call.
	 */
	xor		s3, s3, ra
	seqz		s3, s3
	and		s1, s1, s3
	addi		s3, s1, -1
	andi		s6, s3, (-CLEN_BYTES * TRUSTED_FRAME_SIZE)
#ifdef CHERI_C18N_ZICOND
	//czero.eqz	s2, s2, s1
	.word		0x0e995933
#else
	neg		s1, s1
	and		s2, s2, s1
#endif
	cadd		TRUSTED_STACK_C, TRUSTED_STACK_C, s6
	sc		TRUSTED_STACK_C, TRUSTED_STACK(ct1)

	/*
	 * Save the callee's compartment ID.
	 */
	sh		s10, TRUSTED_FRAME_CALLEE(TRUSTED_STACK_C)
	/*
	 * Compute and save the number of return value registers.
	 */
.option push
.option norvc
6:	ori		t1, s2, 0		/* To be patched at runtime */
.option pop
	sb		t1, (TRUSTED_FRAME_CALLEE + 2)(TRUSTED_STACK_C)
	/*
	 * Compute and save the landing address.
	 */
.option push
.option norvc
7:	addi		t0, t0, 0		/* To be patched at runtime */
.option pop
	sd		t0, TRUSTED_FRAME_LANDING(TRUSTED_STACK_C)

	/*
	 * Install the callee's stack.
	 *
	 * Note: If an interrupt occurs between this instruction and the
	 * previous store instruction, the callee as identified by the topmost
	 * trusted frame would be inconsistent with the untrusted stack.
	 */
	set_untrusted_stk	cs5
TRAMPEND(tramp_push_frame_2)

PATCH_POINT(tramp_push_frame_2, n_rets, 6b)
PATCH_POINT(tramp_push_frame_2, landing, 7b)

TRAMP(tramp_call_hook)
1:	auipc		ct1, 0
.option push
.option norvc
2:	lc		ct2, 0(ct1)		/* To be patched at runtime */

3:	li		t0, 0			/* To be patched at runtime */
4:	caddi		ct1, ct1, 0		/* To be patched at runtime */
.option pop
	jalr		cra, ct2
TRAMPEND(tramp_call_hook)

PATCH_POINT(tramp_call_hook, pcc, 1b)
PATCH_POINT(tramp_call_hook, function, 2b)
PATCH_POINT(tramp_call_hook, event, 3b)
PATCH_POINT(tramp_call_hook, header, 4b)

/*
 * Save the address of the current frame to cs0 so that unwinders can locate
 * it.
 */
TRAMP(tramp_update_fp)
	caddi		cs0, TRUSTED_STACK_C, TRUSTED_FRAME_SP_OSP
TRAMPEND(tramp_update_fp)

TRAMP(tramp_update_fp_untagged)
	addi		s0, TRUSTED_STACK_S, TRUSTED_FRAME_SP_OSP
TRAMPEND(tramp_update_fp_untagged)

TRAMP(tramp_clear_mem_args)
	li		t6, 0
TRAMPEND(tramp_clear_mem_args)

TRAMP(tramp_clear_args)
	/*
	 * Each instruction here is 2 bytes long.
	 */
	li		a7, 0
	li		a6, 0
	li		a5, 0
	li		a4, 0
	li		a3, 0
	li		a2, 0
	li		a1, 0
	li		a0, 0
TRAMPEND(tramp_clear_args)

TRAMP(tramp_invoke)
	li		TRUSTED_STACK_S, 0
	jalr		cra, cs4
TRAMPEND(tramp_invoke)

TRAMP(tramp_count_return)
	camoadd.d	x0, s8, (cs9)
TRAMPEND(tramp_count_return)

TRAMP(tramp_pop_frame)
1:	auipc		ct3, 0
.option push
.option norvc
	/*
	 * Get the unsealer for the thread identifier buffer.
	 */
2:	lc		ct3, 0(ct3)		/* To be patched at runtime */
.option pop
	/*
	 * Get and unseal the thread identifier buffer.
	 */
	csrr		ct0, utidc
	unseal_tidc	ct3, ct3, ct0, t0, t1

	/*
	 * Get the trusted stack.
	 */
	lc		TRUSTED_STACK_C, TRUSTED_STACK(ct3)
	/*
	 * Load the address of the previous trusted frame, the compartment ID
	 * of the caller, and the number of return values registers.
	 */
	lc		ct6, TRUSTED_FRAME_PREV(TRUSTED_STACK_C)
	lhu		t2, TRUSTED_FRAME_CALLER(TRUSTED_STACK_C)
	lbu		a7, (TRUSTED_FRAME_CALLEE + 2)(TRUSTED_STACK_C)
	/*
	 * Load the caller's current stack top and old stack top.
	 */
	lc		ca6, (TRUSTED_FRAME_SP_OSP)(TRUSTED_STACK_C)
	lc		ca5, (TRUSTED_FRAME_SP_OSP + CLEN_BYTES)(TRUSTED_STACK_C)

	/*
	 * Get the stack lookup table.
	 */
	lc		STACK_TABLE_C, STACK_TABLE(ct3)

	/*
	 * Restore callee-saved registers.
	 */
	lc		cs1, (CLEN_BYTES * 0)(TRUSTED_STACK_C)
	lc		cs2, (CLEN_BYTES * 1)(TRUSTED_STACK_C)
	lc		cs3, (CLEN_BYTES * 2)(TRUSTED_STACK_C)
	lc		cs4, (CLEN_BYTES * 3)(TRUSTED_STACK_C)
	lc		cs5, (CLEN_BYTES * 4)(TRUSTED_STACK_C)
	lc		cs6, (CLEN_BYTES * 5)(TRUSTED_STACK_C)
	lc		cs7, (CLEN_BYTES * 6)(TRUSTED_STACK_C)
	lc		cs8, (CLEN_BYTES * 7)(TRUSTED_STACK_C)
	lc		cs9, (CLEN_BYTES * 8)(TRUSTED_STACK_C)
	lc		cs10, (CLEN_BYTES * 9)(TRUSTED_STACK_C)
	lc		cs11, (CLEN_BYTES * 10)(TRUSTED_STACK_C)
	lc		cs0, (CLEN_BYTES * 11)(TRUSTED_STACK_C)
	lc		cra, (CLEN_BYTES * 12)(TRUSTED_STACK_C)

	/*
	 * Install the caller's stack.
	 *
	 * Note: If an interrupt occurs between this instruction and the next,
	 * the callee as identified by the topmost trusted frame would be
	 * inconsistent with the untrusted stack.
	 */
	set_untrusted_stk	ca6
	/*
	 * Bump the trusted stack pointer.
	 */
	sc		ct6, TRUSTED_STACK(ct3)

	/*
	 * Store the caller's old stack top in the stack lookup table.
	 */
	cadd		STACK_TABLE_C, STACK_TABLE_C, t2
	sc		ca5, 0(STACK_TABLE_C)

	/*
	 * Extract the number of return value registers. The number of return
	 * value registers is encoded as follows:
	 * - TWO:	0b00
	 * - ONE:	0b01
	 * - NONE:	0b10
	 * - INDIRECT:	0b11
	 */
#ifdef CHERI_C18N_ZICOND
	andi		t6, a7, -2
	/* These instructions have capability semantics in capability mode. */
//	czero.nez	a1, a1, a7
	.word		0x0f15f5b3
//	czero.nez	a0, a0, t6
	.word		0x0ff57533
#else
	beqz		a7, 3f
	li		a1, 1
	beq		a7, a1, 3f
	li		a0, 0
3:
#endif

	/*
	 * Clear temporary registers.
	 */
	li		a2, 0
	li		a3, 0
	li		a4, 0
	li		t3, 0
	li		t4, 0
	li		t5, 0
#ifndef CHERI_C18N_ZICOND
	li		t6, 0
#endif

	ret
TRAMPEND(tramp_pop_frame)

PATCH_POINT(tramp_pop_frame, pcc, 1b)
PATCH_POINT(tramp_pop_frame, unsealer, 2b)
