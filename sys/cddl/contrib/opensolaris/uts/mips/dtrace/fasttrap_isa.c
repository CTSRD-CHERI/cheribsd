/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/fasttrap_isa.h>
#include <sys/fasttrap_impl.h>
#include <sys/dtrace.h>
#include <sys/dtrace_impl.h>
#include <cddl/dev/dtrace/dtrace_cddl.h>
#include <sys/proc.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <sys/rmlock.h>
#include <sys/sysent.h>

// mips opcodes
#include <machine/db_machdep.h>
#include <machine/md_var.h>
#include <machine/mips_opcode.h>
#include <ddb/db_sym.h>
#include <ddb/ddb.h>
#include <sys/kdb.h>

#include <cddl/contrib/opensolaris/uts/common/sys/fasttrap_impl.h>
#include <cddl/contrib/opensolaris/uts/mips/sys/fasttrap_isa.h>
#include <cddl/compat/opensolaris/sys/proc.h>
#include <cddl/contrib/opensolaris/uts/common/sys/fasttrap.h>
#include <cddl/contrib/opensolaris/uts/common/sys/dtrace.h>
#include <machine/regnum.h>

#define DEBUG_FASTTRAP

// TODO(nicomazz): maybe enable with ioctl? or, which is the best way to disable
// the printfs?
#ifdef DEBUG_FASTTRAP
#define ft_printf printf
#else
#define ft_printf
#endif
/*
 * This is not a complete implementation of fasttrap, but only aims at catching
 * the entry point of functions, and their parameters.
 * */
int
fasttrap_tracepoint_install(proc_t *p, fasttrap_tracepoint_t *tp)
{
	ft_printf("fasttrap: Installing tracepoint at %lx\n",(uint64_t)tp->ftt_pc);
	fasttrap_instr_t instr = FASTTRAP_INSTR;

	if (uwrite(p, &instr, 4, tp->ftt_pc) != 0)
		return (-1);

	return (0);
}

int
fasttrap_tracepoint_remove(proc_t *p, fasttrap_tracepoint_t *tp)
{
	ft_printf("fasttrap: removing tracepoint from %lx\n",(uint64_t)tp->ftt_pc);
	uint32_t instr;

	/*
	 * Distinguish between read or write failures and a changed
	 * instruction.
	 */
	if (uread(p, &instr, 4, tp->ftt_pc) != 0)
		return (0);
	if (instr != FASTTRAP_INSTR)
		return (0);
	if (uwrite(p, &tp->ftt_instr, 4, tp->ftt_pc) != 0)
		return (-1);

	return (0);
}
uint64_t
fasttrap_pid_getarg(void *arg, dtrace_id_t id, void *parg, int argno,
		    int aframes)
{
	printf("IMPLEMENT ME: %s\n", __func__);


	return 0;
}
uint64_t
fasttrap_usdt_getarg(void *arg, dtrace_id_t id, void *parg, int argno,
		     int aframes)
{
	printf("IMPLEMENT ME: %s\n", __func__);


	return 0;
}

// TODO(nicomazz): handle B instructions correctly, if they will be needed.
/*
 * get the type of instruction from the pc among:
 * FASTTRAP_T_COMMON
 * FASTTRAP_T_B
 * FASTTRAP_T_NOP
 */
int
fasttrap_tracepoint_init(proc_t *p, fasttrap_tracepoint_t *tp, uintptr_t pc,
    fasttrap_probe_type_t type)
{
	uint32_t instr;
	InstFmt _instr;
	/*
	 * Read the instruction at the given address out of the process's
	 * address space. We don't have to worry about a debugger
	 * changing this instruction before we overwrite it with our trap
	 * instruction since P_PR_LOCK is set.
	 */
	if (uread(p, &instr, 4, pc) != 0)
		return (-1);

	_instr.word = instr;
	/*
	 * Decode the instruction to fill in the probe flags. We can have
	 * the process execute most instructions on its own using a pc/npc
	 * trick, but pc-relative control transfer present a problem since
	 * we're relocating the instruction. We emulate these instructions
	 * in the kernel. We assume a default type and over-write that as
	 * needed.
	 *
	 * pc-relative instructions must be emulated for correctness;
	 * other instructions (which represent a large set of commonly traced
	 * instructions) are emulated or otherwise optimized for performance.
	 */
	tp->ftt_type = FASTTRAP_T_COMMON;
	tp->ftt_instr = instr;
	tp->single_stepping = 0;
	ft_printf("%s: precedent instr at pc 0x%lx: 0x%x\n",__func__,(uint64_t)pc,instr);

	/* TODO(nicomazz): See the instruction type and save it to ftt_type.
	 * This will be needed to "emulate" them when we place a breakpoint on
	 * them. */

	return (0);
}
// TODO(nicomazz): implement arguments with CTF. If a parameter is a pointer, it
//     has to be taken from a capability register. Otherwise, from a normal
//     register


// TODO(nicomazz): this is not currently used/tested, because we are only
//     supporting the entry probe
static void
fasttrap_return_common(
    struct reg *rp, uintcap_t pc, pid_t pid, uintptr_t new_pc)
{
	printf("IMPLEMENT ME: %s\n", __func__);
	// see how it is done for powerpc
}

static fasttrap_tracepoint_t *
fasttrap_find_tracepoint(pid_t pid, uintptr_t pc){
	fasttrap_tracepoint_t *tp;
	fasttrap_bucket_t * bucket = &fasttrap_tpoints.fth_table[FASTTRAP_TPOINTS_INDEX(pid, pc)];

	/*
	 * Lookup the tracepoint that the process just hit.
	 */
	for (tp = bucket->ftb_data; tp != NULL; tp = tp->ftt_next) {
		if (pid == tp->ftt_pid && pc == tp->ftt_pc &&
		    tp->ftt_proc->ftpc_acount != 0)
			break;
	}
	return tp;
}

static int
fasttrap_clear_single_step(proc_t * p, fasttrap_tracepoint_t *tp)
{
	int error = 0;
	fasttrap_instr_t instr = FASTTRAP_INSTR;

	error = fasttrap_tracepoint_install(p, tp);
	error |= uwrite(p, &tp->ftt_next_instr, 4, tp->ftt_pc + 4);
	tp->single_stepping = 0;
	if (error) {
		printf("Problems in writing back the original instructions\n");
		return -1;
	}

	ft_printf("single step cleaned!\n");

	return (0);
}
int
fasttrap_pid_probe(struct trapframe *frame)
{
	struct reg reg, *rp;
	struct capreg creg, *crp;
	struct rm_priotracker tracker;
	proc_t *p = curproc;
	uintptr_t pc;
	int pc_increment = 0;
	uintptr_t new_pc = 0;
	fasttrap_bucket_t *bucket;
	fasttrap_tracepoint_t *tp;
	pid_t pid;
	dtrace_icookie_t cookie;
	uint_t is_enabled = 0;

	fill_regs(curthread, &reg);
	fill_capregs(curthread, &creg);

	rp = &reg;
	crp = &creg;
	pc = TRAPF_PC(frame);
	pc_increment = 0;

	/*
	 * It's possible that a user (in a veritable orgy of bad planning)
	 * could redirect this thread's flow of control before it reached the
	 * return probe fasttrap. In this case we need to kill the process
	 * since it's in a unrecoverable state.
	 */
	if (curthread->t_dtrace_step) {
		ASSERT(curthread->t_dtrace_on);
		fasttrap_sigtrap(p, curthread, pc);
		return (0);
	}
	ft_printf("%s: received a break!\n",__func__);
	ft_printf("Initial PC: 0x%lx\n",(uint64_t)pc);

	/*
	 * Clear all user tracing flags.
	 */
	curthread->t_dtrace_ft = 0;
	curthread->t_dtrace_pc = 0;
	curthread->t_dtrace_npc = 0;
	curthread->t_dtrace_scrpc = 0;
	curthread->t_dtrace_astpc = 0;

	rm_rlock(&fasttrap_tp_lock, &tracker);
	pid = p->p_pid;

	// let's see if there is break due to step over breakpoint
	tp = fasttrap_find_tracepoint(pid,pc-4);
	if (tp && tp->single_stepping) {
		if (pget(pid, PGET_HOLD | PGET_NOTWEXIT, &p) != 0) {
			ft_printf("Error trying to hold the processs\n");
		}
		int error = fasttrap_clear_single_step(p, tp);
		rm_runlock(&fasttrap_tp_lock, &tracker);
		PRELE(p);
		return error;
	}

	tp = fasttrap_find_tracepoint(pid,pc);



	if (tp == NULL){
		rm_runlock(&fasttrap_tp_lock, &tracker);
		return (-1);
	}

	// if the exception occurred on the delay slot, maybe is because the
	// previous instruction was a branch, and had a trap
	if (tp->single_stepping) {
		if (pget(pid, PGET_HOLD | PGET_NOTWEXIT, &p) != 0) {
			ft_printf("Error trying to hold the processs\n");
		}
		// this means that it was a branch. Let's restore the original one, and remove the tracepoint
		int error = fasttrap_clear_single_step(p, tp);
		error |= fasttrap_tracepoint_remove(p,tp);
		rm_runlock(&fasttrap_tp_lock, &tracker);
		PRELE(p);
		return error;
	}

	/*
	 * Let's fire the various probes associated with this tracepoint
	 */
	if (tp->ftt_ids != NULL) {
		fasttrap_id_t *id;

		for (id = tp->ftt_ids; id != NULL; id = id->fti_next) {
			fasttrap_probe_t *probe = id->fti_probe;

			if (id->fti_ptype == DTFTP_ENTRY) {
				/*
				 * We note that this was an entry
				 * probe to help ustack() find the
				 * first caller.
				 */
				cookie = dtrace_interrupt_disable();
				DTRACE_CPUFLAG_SET(CPU_DTRACE_ENTRY);
				// TODO(nicomazz): fire a dtrace probe after
				//    fetching the correct parameters
				dtrace_probe(probe->ftp_id, rp->r_regs[A0],
				    rp->r_regs[A1], rp->r_regs[A2],
				    rp->r_regs[A3], rp->r_regs[A4]);
				DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_ENTRY);
				dtrace_interrupt_enable(cookie);
			} else if (id->fti_ptype == DTFTP_IS_ENABLED) {
				/*
				 * Note that in this case, we don't
				 * call dtrace_probe() since it's only
				 * an artificial probe meant to change
				 * the flow of control so that it
				 * encounters the true probe.
				 */
				is_enabled = 1;
			} else {
				// TODO(nicomazz): use CTF to understand where
				// to get the parameters from (cap registers or
				// normal ones). Look how it is done in
				// fbt_isa.c
				dtrace_probe(probe->ftp_id, rp->r_regs[A0],
				    rp->r_regs[A1], rp->r_regs[A2],
				    rp->r_regs[A3], rp->r_regs[A4]);
			}
		}
	}

	switch (tp->ftt_type) {
	case FASTTRAP_T_COMMON: {
		/* We remove the breakpoint, and place another one in the next
		 * instruction */
		if (pget(pid, PGET_HOLD | PGET_NOTWEXIT, &p) != 0) {
			ft_printf("Error trying to hold the processs\n");
			break;
		}

		int error;
		ft_printf(
		    "%s: replacing break instruction with original(0x%lx) at 0x%lx\n",
		    __func__, (uint64_t)tp->ftt_instr, (uint64_t)tp->ftt_pc);

		//error = uwrite(p, &(tp->ftt_instr), 4, tp->ftt_pc);
		uint32_t next_instruction = 0;
		error = fasttrap_tracepoint_remove(p,tp);
		error |= uread(p, &next_instruction, 4, tp->ftt_pc + 4);
		ft_printf(
		    "%s next instruction: 0x%x\n", __func__, next_instruction);
		fasttrap_instr_t instr = FASTTRAP_INSTR;
		error |= uwrite(p, &instr, 4, tp->ftt_pc + 4);
		if (error) {
			ft_printf(
			    "Some error occurred rewriting the instructions\n");
		} else {
			tp->ftt_next_instr = next_instruction;
			tp->single_stepping = 1;
		}
		pc_increment = 0;
		PRELE(p);
		break;
	}
	};
done:
	/*
	 * If there were no return probes when we first found the tracepoint,
	 * we should feel no obligation to honor any return probes that were
	 * subsequently enabled -- they'll just have to wait until the next
	 * time around.
	 */
	if (tp->ftt_retids != NULL) {
		/*
		 * We need to wait until the results of the instruction are
		 * apparent before invoking any return probes. If this
		 * instruction was emulated we can just call
		 * fasttrap_return_common(); if it needs to be executed, we
		 * need to wait until the user thread returns to the kernel.
		 */
		if (tp->ftt_type != FASTTRAP_T_COMMON) {
			fasttrap_return_common(rp, pc, pid, new_pc);
		} else {
			// TODO(nicomazz): is this code complete?
			ASSERT(curthread->t_dtrace_ret != 0);
			ASSERT(curthread->t_dtrace_pc == pc);
			ASSERT(curthread->t_dtrace_scrpc != 0);
			ASSERT(new_pc == curthread->t_dtrace_astpc);
		}
	}

	if (pc_increment != 0) {
		rp->r_regs[PT_REGS_PC] += pc_increment;
		ft_printf("Setting new pc from fasttrap_pid_probe: 0x%lx\n",
		    (uint64_t)rp->r_regs[PT_REGS_PC]);
		set_regs(curthread, rp);
	}
	rm_runlock(&fasttrap_tp_lock, &tracker);
	return (0);
}

int
fasttrap_return_probe(struct trapframe *tf)
{
	struct reg reg, *rp;
	proc_t *p = curproc;
	uintcap_t pc = curthread->t_dtrace_pc;
	uintcap_t npc = curthread->t_dtrace_npc;

	curthread->t_dtrace_pc = 0;
	curthread->t_dtrace_npc = 0;
	curthread->t_dtrace_scrpc = 0;
	curthread->t_dtrace_astpc = 0;

	fill_regs(curthread, &reg);
	rp = &reg;

	/*
	 * We set rp->pc to the address of the traced instruction so
	 * that it appears to dtrace_probe() that we're on the original
	 * instruction.
	 */

	TRAPF_PC_SET_ADDR(tf,pc);

	fasttrap_return_common(rp, pc, p->p_pid, npc);

	return (0);
}
