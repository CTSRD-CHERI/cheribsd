/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2005 Antoine Brodin
 * All rights reserved.
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
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/stack.h>

#include <machine/mips_opcode.h>

#include <machine/pcb.h>
#include <machine/regnum.h>

#include <machine/abi.h>

static uintptr_t
stack_register_fetch(uintptr_t sp, u_register_t stack_pos)
{
	uintptr_t * stack =
	    ((uintptr_t *)sp + (size_t)stack_pos / sizeof(uintptr_t));

	return (*stack);
}

static bool
op_is_cheri_cincoffsetimm(InstFmt insn)
{
	InstFmt mask = { .CIType = { .op = 0x3f, .fmt = 0x1f} };
	InstFmt match = { .CIType = { .op = 0x12, .fmt = 0x13} };

	return ((insn.word & mask.word) == match.word);
}

static bool
op_is_cheri_csc(InstFmt insn)
{
	InstFmt mask = { .CCMType = { .op = 0x3f } };
	InstFmt match = { .CCMType = { .op = 0x3e } };

	return ((insn.word & mask.word) == match.word);
}

static bool
op_is_cheri_cjr(InstFmt insn)
{
	InstFmt mask = {
		.CBIType = {
			.op = 0x3f,
			.fmt = 0x1f,
			.cb = 0x1f,
			.res1 = 0x1f,
			.res2 = 0x3f
		}
	};
	InstFmt match = {
		.CBIType = {
			.op = 0x12,
			.fmt = 0x00,
			.cb = 0x03,
			.res1 = 0x1f,
			.res2 = 0x3f
		}
	};

	return ((insn.word & mask.word) == match.word);
}

static void
stack_capture(struct stack *st, uintptr_t pc, uintptr_t sp)
{
	uintptr_t ra;
	uintptr_t i;
	uintptr_t next_sp;
	short ra_stack_pos;
	InstFmt insn;
	uintptr_t exc_saved_ra = 0;
	boolean_t is_exc_handler;

	stack_zero(st);

	for (;;) {
		if (exc_saved_ra)
			next_sp = sp;
		else
			next_sp = 0;
		ra_stack_pos = -1;

		if ((__cheri_addr vaddr_t)pc <= (__cheri_addr vaddr_t)btext)
			break;
		for (i = pc; i >= (intptr_t)btext &&
		    (int64_t)cheri_getoffset((void *)i) >= 0;
		    i -= sizeof(insn)) {
			bcopy((void *)i, &insn, sizeof(insn));
			if (op_is_cheri_cincoffsetimm(insn) &&
			    insn.CIType.r1 == insn.CIType.r2 &&
			    insn.CIType.r1 == OP_CHERI_STC_REGNO &&
			    (short)insn.CIType.imm < 0) {
				next_sp = sp + -(short)insn.CIType.imm;
				break;
			}
			else if (op_is_cheri_csc(insn) &&
			    insn.CCMType.cs == OP_CHERI_RAC_REGNO &&
			    insn.CCMType.cb == OP_CHERI_STC_REGNO) {
				exc_saved_ra = 0;
				ra_stack_pos = (short)insn.CCMType.offset * 16;
			}
			else if (op_is_cheri_csc(insn) &&
			    insn.CCMType.cs == OP_CHERI_FPC_REGNO &&
			    insn.CCMType.cb == OP_CHERI_STC_REGNO) {
				next_sp = stack_register_fetch(sp,
				    (short)insn.CCMType.offset * 16);
				break;
			}
		}

		if (stack_put(st, (__cheri_addr vm_offset_t)pc) == -1)
			break;

		/*
		 * Stop if we do not have any information on the next frame and
		 * we are not be in a leaf function.
		 */
		if (!next_sp)
		    break;

		/*
		 * Check if we are in an exception handler, if so we record
		 * the saved return capability, in case we took an exception
		 * in a leaf function.
		 */
		is_exc_handler = false;
		for (i = pc; cheri_getoffset((void *)i) + sizeof(insn) <=
		    cheri_getlen((void *)i); i += sizeof(insn)) {
			bcopy((void *)i, &insn, sizeof(insn));
			if (insn.word == 0x42000018) {
				/* eret */
				is_exc_handler = true;
				break;
			}
			else if (op_is_cheri_cjr(insn) &&
			    insn.CBIType.cd == OP_CHERI_RAC_REGNO) {
				/* common return sequence, not a handler */
				break;
			}
		}

		if (is_exc_handler) {
			exc_saved_ra = stack_register_fetch(sp,
			    (CALLFRAME_SIZ + SZREG * C17));
			pc = stack_register_fetch(sp, ra_stack_pos);
		}
		else {
			if (ra_stack_pos < 0) {
				if (exc_saved_ra)
					/* In leaf function where exception happened */
					pc = exc_saved_ra;
				else
					break;
			}
			else {
				ra = stack_register_fetch(sp, ra_stack_pos);
				if (!ra)
					break;
				pc = ra - sizeof(insn);
			}
		}
		sp = next_sp;
	}

	return;
}

void
stack_save_td(struct stack *st, struct thread *td)
{
	uintptr_t pc, sp;

	if (TD_IS_SWAPPED(td))
		panic("stack_save_td: swapped");
	if (TD_IS_RUNNING(td))
		panic("stack_save_td: running");

	/* XXX-AM: get thread pc and sp instead. */
	pc = (uintptr_t)cheri_getpcc();
	sp = (uintptr_t)cheri_getstack();
	stack_capture(st, pc, sp);
}

int
stack_save_td_running(struct stack *st, struct thread *td)
{

	return (EOPNOTSUPP);
}

void
stack_save(struct stack *st)
{
	uintptr_t pc, sp;

	if (curthread == NULL)
		panic("stack_save: curthread == NULL");

	pc = (uintptr_t)cheri_getpcc();
	sp = (uintptr_t)cheri_getstack();
	stack_capture(st, pc, sp);
}
// CHERI CHANGES START
// {
//   "updated": 20190830,
//   "target_type": "kernel",
//   "changes_purecap": [
//     "support",
//     "kdb",
//     "uintptr_interp_offset"
//   ]
// }
// CHERI CHANGES END

