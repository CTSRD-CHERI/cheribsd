/*-
 * Copyright (c) 2015 David Chisnall
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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
#include <sys/types.h>
#include <machine/cheri.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <ucontext.h>
#include "cheri_c_test.h"

static const size_t cap_size = sizeof(void*);

static void handler(void * __capability capreg __unused, int cause __unused)
{
	faults++;
}


cheri_handler test_fault_handler = handler;
volatile int faults;


/**
 * Opcodes for MIPS branch instructions.
 */
enum branch_ops
{
	// The real opcode is stored in the second register field
	MIPS_BRANCH_REGIMM= 0x1,
	// The real opcode is stored in the first register field
	MIPS_BRANCH_CHERI = 0x12,

	MIPS_BRANCH_J     = 0x2,
	MIPS_BRANCH_JAL   = 0x3,

	MIPS_BRANCH_JR    = 0x8,
	MIPS_BRANCH_JALR  = 0x9,
	MIPS_BRANCH_BEQ   = 0x4,
	MIPS_BRANCH_BNE   = 0x5,
	MIPS_BRANCH_BLEZ  = 0x6,
	MIPS_BRANCH_BGTZ  = 0x7,
	MIPS_BRANCH_BEQL  = 0x14,
	MIPS_BRANCH_BNEL  = 0x15,
	MIPS_BRANCH_BLEZL = 0x16,
	MIPS_BRANCH_BGTZL = 0x17
};
/**
 * For some branches, the opcode is REGIMM, but the real opcode is stored in
 * the second register operand slot (bits 20--16).
 */
enum regimm_branch_ops
{
	MIPS_BRANCH_BLTZ    = 0x0,
	MIPS_BRANCH_BGEZ    = 0x1,
	MIPS_BRANCH_BLTZAL  = 0x10,
	MIPS_BRANCH_BGEZAL  = 0x11,
	MIPS_BRANCH_BLTZL   = 0x2,
	MIPS_BRANCH_BGEZL   = 0x3,
	MIPS_BRANCH_BLTZALL = 0x12,
	MIPS_BRANCH_BGEZALL = 0x13
};

/**
 * For CHERI branch instructions, the opcode is CP2OP and the real opcode is
 * stored in the first register operand slot (bits 25--21).
 */
enum cheri_branch_ops
{
	CHERI_BRANCH_CBTU   = 0x09, 
	CHERI_BRANCH_CBTS   = 0x0a,
	CHERI_BRANCH_CJR    = 0x07,
	CHERI_BRANCH_CJALR  = 0x08
};


/**
 * Returns the CHERI signal frame information associated with a context.
 */
static inline struct cheri_frame *
getCHERIFrame(mcontext_t *context)
{
#ifdef __CHERI_SANDBOX__
	return &context->mc_cheriframe;
#else
	assert_eq(context->mc_cp2state_len, sizeof(struct cheri_frame));
	return ((struct cheri_frame *)context->mc_cp2state);
#endif
}

/**
 * Sign extend a value to the size of a `register_t`, assuming that it is a
 * signed value of the low `size` bits of the `val` argument.
 */
static inline register_t
signExtend(register_t val, int size)
{
	int shift = ((sizeof(register_t)*8) - size);
	int64_t ext = val << shift;

	return (ext >> shift);
}


/**
 * Reads an immediate value from an instruction.
 */
static inline register_t
getImm(uint32_t instr, int start, int len)
{
	uint32_t mask = (0xffffffff >> (cap_size-len)) << (start - len + 1);

	return (instr & mask) >> (start - len + 1);
}

/**
 * Loads a capability register from the context.
 */
static inline void * __capability
getCapRegAtIndex(mcontext_t *context, int idx)
{
	struct cheri_frame *frame = getCHERIFrame(context);

	if (idx == 0xff)
	{
		return frame->cf_pcc;
	}
	_Static_assert(offsetof(struct cheri_frame, cf_ddc) == 0,
			"Layout of struct cheri_frame has changed!");
	_Static_assert(offsetof(struct cheri_frame, cf_pcc) == 27*sizeof(void * __capability),
			"Layout of struct cheri_frame has changed!");
	assert((idx < 26) && (idx >= 0) &&
	       "Invalid capability register index");
	return (((void * __capability*)frame)[idx]);
}

static inline uint32_t *
getAdjustedPc(mcontext_t *context, u_register_t pc)
{
	uint64_t base = __builtin_cheri_base_get(getCHERIFrame(context)->cf_pcc);
	uintptr_t pcc = (uintptr_t)getCHERIFrame(context)->cf_pcc;
	assert((base + pc) > base);
	assert(pc < __builtin_cheri_length_get(getCHERIFrame(context)->cf_pcc));
	pcc += (uint64_t)pc;
	return ((uint32_t*)pcc);
}

/**
 * Reads a register by loading the value from a register context based on an
 * opcode in an instruction.  The `opidx` parameter gives the bit index into
 * the instruction where the operand starts.
 */
static inline register_t
getReg(mcontext_t *context, uint32_t instr, int opidx)
{
	int regno = getImm(instr, opidx, 5);

	if (regno == 0)
	{
		return 0;
	}
	return (context->mc_regs[regno]);
}

/**
 * Reads a capability register by loading the value from a register context
 * based on an opcode in an instruction.  The `opidx` parameter gives the bit
 * index into the instruction where the operand starts.
 */
static inline void * __capability
getCapReg(mcontext_t *context, uint32_t instr, int opidx)
{
	int regno = getImm(instr, opidx, 5);

	return getCapRegAtIndex(context, regno);
}

/**
 * Reads a signed immediate value from an instruction.
 */
static inline register_t
getSImm(uint32_t instr, int start, int len)
{
	return signExtend(getImm(instr, start, len), len);
}

/**
 * Get the opcode field from an instruction (the first 6 bits)
 */
static inline register_t
getOpcode(uint32_t instr)
{

	return getImm(instr, 31, 6);
}

/**
 * Returns whether the current pc location is a branch delay slot.
 */
static inline bool
isInDelaySlot(mcontext_t *context)
{
	return getImm(context->cause, 31, 1);
}

/**
 * If we are in a branch delay slot, work out what the next instruction will
 * be.  This is either the branch target or the instruction immediately
 * following the delay slot, depending on whether the branch should have been
 * taken.
 */
static bool 
emulateBranch(mcontext_t *context, register_t pc)
{
	uint32_t instr = *getAdjustedPc(context, pc);
	// If the instruction isn't a branch, the following two will be nonsense
	// values, but we'll only use them in cases where they make sense and
	// computing them has no side effects so it simplifies the code to compute
	// them here.
	int64_t offset = getSImm(instr, 15, 16) << 2;
	// The destination for the branch, if it's a PC-relative branch with
	// immediate offset.
	register_t branchPc = ((int64_t)pc) + offset + 4;
	// The instruction immediately following the delay slot.
	register_t normalPc = pc + 8;

	// Similarly, the next two may be meaningless values, but again we're just
	// loading data from a structure, so it's safe to do the work redundantly.
	// The first register operand, if this is a two-GPR-operand instruction
	int64_t regVal = getReg(context, instr, 25);
	// The second register operand, if this is a two-GPR-operand instruction
	int64_t regVal2 = getReg(context, instr, 20);

	switch ((enum branch_ops)getOpcode(instr))
	{
		case MIPS_BRANCH_REGIMM:
		{
			switch ((enum regimm_branch_ops)getImm(instr, 20, 5))
			{
				case MIPS_BRANCH_BLTZL:
				case MIPS_BRANCH_BLTZALL:
					assert((regVal < 0) &&
					       "In delay slot for not-taken likely branch!");
				case MIPS_BRANCH_BLTZ:
				case MIPS_BRANCH_BLTZAL:
					context->mc_pc = ((regVal < 0) ? branchPc : normalPc);
					return true;
				case MIPS_BRANCH_BGEZL:
				case MIPS_BRANCH_BGEZ:
					assert((regVal < 0) &&
					       "In delay slot for not-taken likely branch!");
				case MIPS_BRANCH_BGEZAL:
				case MIPS_BRANCH_BGEZALL:
					context->mc_pc = ((regVal >= 0) ? branchPc : normalPc);
					return true;
			}
			break;
		}
		case MIPS_BRANCH_J:
		case MIPS_BRANCH_JAL:
			context->mc_pc = (getImm(instr, 25, 0)<<2) & ((pc >> 28) << 28);
			return true;
		case MIPS_BRANCH_JR:
		case MIPS_BRANCH_JALR:
			context->mc_pc = getReg(context, instr, 25);
			return true;
		case MIPS_BRANCH_BEQL:
		case MIPS_BRANCH_BEQ:
			context->mc_pc = ((regVal == regVal2) ? branchPc : normalPc);
			return true;
		case MIPS_BRANCH_BNEL:
		case MIPS_BRANCH_BNE:
			context->mc_pc = ((regVal != regVal2) ? branchPc : normalPc);
			return true;
		case MIPS_BRANCH_BLEZL:
		case MIPS_BRANCH_BLEZ:
			context->mc_pc = ((regVal <= 0) ? branchPc : normalPc);
			return true;
		case MIPS_BRANCH_BGTZL:
		case MIPS_BRANCH_BGTZ:
			context->mc_pc = ((regVal > 0) ? branchPc : normalPc);
			return true;
		case MIPS_BRANCH_CHERI:
		{
			switch ((enum cheri_branch_ops)getImm(instr, 25, 5))
			{
				case CHERI_BRANCH_CBTU:
				{
					void * __capability cap = getCapReg(context, instr, 20);
					bool tag = __builtin_mips_cheri_get_cap_tag(cap);
					context->mc_pc = (!tag ? branchPc : normalPc);
					return true;
				}
				case CHERI_BRANCH_CBTS:
				{
					void * __capability cap = getCapReg(context, instr, 20);
					bool tag = __builtin_mips_cheri_get_cap_tag(cap);
					context->mc_pc = (tag ? branchPc : normalPc);
					return true;
				}
				case CHERI_BRANCH_CJR:
				case CHERI_BRANCH_CJALR:
				{
					context->mc_pc = getReg(context, instr, 10);
					// FIXME: This is very ugly, but to fix it we need to
					// define a new structure to replace cheri_frame.
					struct cheri_frame *frame = getCHERIFrame(context);
					// Note: The /cap_size is safe here because if this is not
					// aligned then the load will fail anyway...
					int regno = offsetof(struct cheri_frame, cf_pcc) / cap_size;
					(((void * __capability*)frame)[regno]) =
						getCapReg(context, instr, 15);
					return true;
				}
			}
		}
	}
	return false;
}

/**
 * The SIGPROT handler.  Calls the test handler and skips the faulting
 * instruction.
 */
static void
capsighandler(int signo, siginfo_t *info __unused, ucontext_t *uap)
{
	mcontext_t *context = &uap->uc_mcontext;
	bool isDelaySlot = isInDelaySlot(context);
	register_t pc = context->mc_pc;
	struct cheri_frame *frame = getCHERIFrame(context);
	void * __capability reg = getCapRegAtIndex(context, frame->cf_capcause & 0xff);
	assert_eq(signo, SIGPROT);
	assert(test_fault_handler);

	test_fault_handler(reg, frame->cf_capcause >> 8);
	// If we're in a delay slot, then emulate the branch.  Otherwise, just
	// skip to the next instruction.
	if (isDelaySlot)
	{
		assert((pc > 4) && "Invalid delay slot PC!");
		if (!emulateBranch(context, pc))
		{
#ifndef NDEBUG
			fprintf(stderr, "Failed to emulate branch instruction: 0x%x",
					*getAdjustedPc(context, pc));
			abort();
#endif
		}
	}
	else
	{
		context->mc_pc += 4;
	}
}

void test_setup(void)
{
	struct sigaction action;

	action.sa_sigaction =
		(void (*)(int, struct __siginfo *, void *))capsighandler;
	sigemptyset(&action.sa_mask);
	action.sa_flags = SA_SIGINFO;
	if (sigaction(SIGPROT, &action, NULL))
	{
		assert(0);
	}
}

