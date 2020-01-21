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

#ifdef CHERI_PURECAP_KERNEL
static uintptr_t
stack_register_fetch(uintptr_t sp, u_register_t stack_pos)
{
	uintptr_t * stack =
	    ((uintptr_t *)sp + (size_t)stack_pos);

	return (*stack);
}

static __attribute__((noinline)) bool
op_is_cheri_cincoffsetimm(InstFmt insn)
{
	InstFmt mask = { .CIType = { .op = 0x3f, .fmt = 0x1f} };
	InstFmt match = { .CIType = { .op = 0x12, .fmt = 0x13} };

	return ((insn.word & mask.word) == match.word);
}

static __attribute__((noinline)) bool
op_is_cheri_csc(InstFmt insn)
{
	InstFmt mask = { .CCMType = { .op = 0x3f } };
	InstFmt match = { .CCMType = { .op = 0x3e } };

	return ((insn.word & mask.word) == match.word);
}

static __attribute__((noinline)) bool
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

#else /* !CHERI_PURECAP_KERNEL */
static u_register_t
stack_register_fetch(u_register_t sp, u_register_t stack_pos)
{
	u_register_t * stack = 
	    ((u_register_t *)(intptr_t)sp + (size_t)stack_pos/sizeof(u_register_t));

	return (*stack);
}
#endif /* !CHERI_PURECAP_KERNEL */

static void
stack_capture(struct stack *st, uintptr_t pc, uintptr_t sp)
{
	uintptr_t  ra = 0;
	uintptr_t i;
	u_register_t stacksize;
	short ra_stack_pos = 0;
	short fp_stack_pos = 0;
	InstFmt insn;

	stack_zero(st);

	/* XXXRW: appears to be inadequately robust? */
	for (;;) {
		stacksize = 0;
		fp_stack_pos = -1;
		ra_stack_pos = -1;
		if ((__cheri_addr vaddr_t)pc <= (__cheri_addr vaddr_t)btext)
			break;
		for (i = pc; i >= (intptr_t)btext; i -= sizeof(insn)) {
			bcopy((void *)i, &insn, sizeof(insn));
#ifdef CHERI_PURECAP_KERNEL
			if (op_is_cheri_cincoffsetimm(insn) &&
			    insn.CIType.r1 == insn.CIType.r2 &&
			    insn.CIType.r1 == OP_CHERI_STC_REGNO &&
			    (short)insn.CIType.imm < 0) {
				stacksize = -(short)insn.CIType.imm;
			}
			else if (op_is_cheri_csc(insn) &&
			    insn.CCMType.cs == OP_CHERI_RAC_REGNO &&
			    insn.CCMType.cb == OP_CHERI_STC_REGNO) {
				/* XXX-AM: What about leaf functions that do not save c17? */
				ra_stack_pos = (short)insn.CCMType.offset;
			}
			else if (op_is_cheri_csc(insn) &&
			    insn.CCMType.cs == OP_CHERI_FPC_REGNO &&
			    insn.CCMType.cb == OP_CHERI_STC_REGNO) {
				fp_stack_pos = (short)insn.CCMType.offset;
			}
#else
			switch (insn.IType.op) {
			case OP_ADDI:
			case OP_ADDIU:
			case OP_DADDI:
			case OP_DADDIU:
				if (insn.IType.rs != SP || insn.IType.rt != SP)
					break;
				stacksize = -(short)insn.IType.imm;
				break;

			case OP_SW:
			case OP_SD:
				if (insn.IType.rs != SP || insn.IType.rt != RA)
					break;
				ra_stack_pos = (short)insn.IType.imm;
				break;
			default:
				break;
			}
#endif

			if (stacksize || fp_stack_pos != -1)
				break;
		}

		if (stack_put(st, (__cheri_addr vm_offset_t)pc) == -1)
			break;

		for (i = pc; !ra; i += sizeof (insn)) {
			bcopy((void *)i, &insn, sizeof insn);
#ifdef CHERI_PURECAP_KERNEL
			if (op_is_cheri_cjr(insn) &&
			    insn.CBIType.cd == OP_CHERI_RAC_REGNO) {
				ra = stack_register_fetch(sp, ra_stack_pos);
				if (!ra)
					goto done;
				ra -= 8;
			}
#else
			switch (insn.IType.op) {
			case OP_SPECIAL:
				if (insn.RType.func == OP_JR) {
					if (ra >= (u_register_t)(intptr_t)btext)
						break;
					if (insn.RType.rs != RA)
						break;
					ra = stack_register_fetch(sp, 
					    ra_stack_pos);
					if (!ra)
						goto done;
					ra -= 8;
				}
				break;
			default:
				break;
			}
#endif
			/* eret */
			if (insn.word == 0x42000018)
				goto done;
		}

		if (pc == ra && stacksize == 0)
			break;

#ifdef CHERI_PURECAP_KERNEL
		if (stacksize)
			sp += stacksize;
		else if (fp_stack_pos) {
			sp = stack_register_fetch(sp, fp_stack_pos);
			if (!sp)
				goto done;
		}
#else
		sp += stacksize;
#endif
		pc = ra;
		ra = 0;
	}
done:
	return;
}

void
stack_save_td(struct stack *st, struct thread *td)
{
#ifdef CHERI_PURECAP_KERNEL
	uintptr_t pc, sp;
#else
	vaddr_t pc, sp;
#endif

	if (TD_IS_SWAPPED(td))
		panic("stack_save_td: swapped");
	if (TD_IS_RUNNING(td))
		panic("stack_save_td: running");

#ifdef CHERI_PURECAP_KERNEL
	/* XXX-AM: what about compat64 processes? */
	pc = (uintptr_t)td->td_pcb->pcb_regs.pc;
	sp = (uintptr_t)td->td_pcb->pcb_regs.csp;
#else
	/* XXXRW: Should be pcb_context? */
	pc = TRAPF_PC(&td->td_pcb->pcb_regs);
	sp = td->td_pcb->pcb_regs.sp; // FIXME: use $c11 for CHERI purecap
#endif
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
#ifdef CHERI_PURECAP_KERNEL
	uintptr_t pc, sp;
#else
	vaddr_t pc, sp;
#endif

	if (curthread == NULL)
		panic("stack_save: curthread == NULL");

#ifdef CHERI_PURECAP_KERNEL
	/* XXX-AM: what about compat64 processes? */
	pc = (uintptr_t)cheri_getpcc();
	sp = (uintptr_t)cheri_getstack();
#else
	/* XXXRW: Should be pcb_context? */
	pc = TRAPF_PC(&curthread->td_pcb->pcb_regs);
	sp = curthread->td_pcb->pcb_regs.sp; // FIXME: use $c11 for CHERI purecap
#endif
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
