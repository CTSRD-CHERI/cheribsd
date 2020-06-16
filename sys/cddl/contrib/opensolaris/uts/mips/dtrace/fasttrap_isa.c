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


#ifdef DEBUG_FASTTRAP
#define ft_printf(fmt, ...)                 \
	do {                                \
		printf("%s: ", __func__);   \
		printf(fmt, ##__VA_ARGS__); \
	} while (0)
#else
#define ft_printf(fmt, ...)
#endif



// TODO(nicomazz): implement arguments with CTF. If a parameter is a pointer, it
//     has to be taken from a capability register. Otherwise, from a normal
//     register

/*
 * This is not a complete implementation of fasttrap, but only aims at catching
 * the entry point of functions, and their parameters.
 * */
int
fasttrap_tracepoint_install(proc_t *p, fasttrap_tracepoint_t *tp)
{
	ft_printf(
	    "fasttrap: Installing tracepoint at %lx\n", (uint64_t)tp->ftt_pc);
	fasttrap_instr_t instr = FASTTRAP_INSTR;

	if (uwrite(p, &instr, 4, tp->ftt_pc) != 0)
		return (-1);

	return (0);
}

int
fasttrap_tracepoint_remove(proc_t *p, fasttrap_tracepoint_t *tp)
{
	ft_printf(
	    "fasttrap: removing tracepoint from %lx\n", (uint64_t)tp->ftt_pc);
	uint32_t instr;

	/*
	 * Distinguish between read or write failures and a changed
	 * instruction.
	 */
	if (uread(p, &instr, 4, tp->ftt_pc) != 0)
		return (-1);
	if (instr != FASTTRAP_INSTR) {
		ft_printf(
		    "Error removing an instruction: there was another one: 0x%x\n",
		    instr);
		return (-1);
	}
	if (uwrite(p, &tp->ftt_instr, 4, tp->ftt_pc) != 0)
		return (-1);

	return (0);
}


static int
fasttrap_is_branch(fasttrap_instr_t i)
{
	InstFmt inst;
	inst.word = i;

	switch ((int)inst.JType.op) {
	case OP_SPECIAL:
	case OP_BCOND:
	case OP_J:
	case OP_JAL:
	case OP_BEQ:
	case OP_BEQL:
	case OP_BNE:
	case OP_BNEL:
	case OP_BLEZ:
	case OP_BLEZL:
	case OP_BGTZ:
	case OP_BGTZL:
	case OP_COP1:
		return 1;
#if __has_feature(capabilities)
	case OP_COP2:
		switch (inst.CType.fmt) {
		case OP_CJ:
		case OP_CBEZ:
		case OP_CBNZ:
		case OP_CBTS:
		case OP_CBTU:
			return 1;
		}
#endif
	}
	return 0;
}

int
fasttrap_tracepoint_init(proc_t *p, fasttrap_tracepoint_t *tp, uintptr_t pc,
    fasttrap_probe_type_t type)
{
	uint32_t instr;
	uint32_t prec_instr;
	InstFmt _instr;
	/*
	 * Read the instruction at the given address out of the process's
	 * address space. We don't have to worry about a debugger
	 * changing this instruction before we overwrite it with our trap
	 * instruction since P_PR_LOCK is set.
	 */
	if (uread(p, &instr, 4, pc) != 0)
		return (-1);

	if (uread(p, &prec_instr, 4, pc-4) != 0)
		return (-1);

	/* do not instrument branches */
	if (fasttrap_is_branch(instr) || fasttrap_is_branch(prec_instr))
		return (-1);

	_instr.word = instr;

        /* cjr $c17 */
        if (instr == 0x48111fff)
            return (-1);

	tp->ftt_instr = instr;
	tp->single_stepping = 0;

	return (0);
}

static fasttrap_tracepoint_t *
fasttrap_find_tracepoint(pid_t pid, uintptr_t pc)
{
	fasttrap_tracepoint_t *tp;
	fasttrap_bucket_t *bucket =
	    &fasttrap_tpoints.fth_table[FASTTRAP_TPOINTS_INDEX(pid, pc)];

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
fasttrap_clear_single_step(proc_t *p, fasttrap_tracepoint_t *tp)
{
	int error = 0;
	fasttrap_instr_t instr = FASTTRAP_INSTR;

	tp->single_stepping = 0;

	/* Restore the tracepoint*/
	if (fasttrap_tracepoint_install(p, tp) != 0)
		return -1;

	/* Restore the next instruction */
	if (uwrite(p, &tp->ftt_next_instr, 4, tp->ftt_next_instr_addr) != 0)
		return -1;

	ft_printf("Single step cleaned! 0x%x wrote to 0x%lx\n",
	    tp->ftt_next_instr, tp->ftt_next_instr_addr);

	return (0);
}

/* We remove the breakpoint, and place another one in the next
 * instruction
 * */
static int
fasttrap_single_step(
    proc_t *p, fasttrap_tracepoint_t *tp, struct trapframe *frame)
{
	uint32_t next_instr_val;
	uint64_t next_instr_addr;

	ft_printf("replacing break instruction  at 0x%lx with original 0x%lx\n",
	    (uint64_t)tp->ftt_pc, (uint64_t)tp->ftt_instr);

	if (fasttrap_is_branch(tp->ftt_instr)) {
		next_instr_addr = (__cheri_addr vaddr_t)MipsEmulateBranch(
		    frame, frame->pc, frame->fsr, &tp->ftt_instr);
		ft_printf(
		    "single stepping branch. pc: 0x%lx next_addr: 0x%lx\n",
		    (uint64_t)tp->ftt_pc, next_instr_addr);
	} else {
		next_instr_addr = tp->ftt_pc + 4;
	}

	/* restore original instruction */
	if (fasttrap_tracepoint_remove(p, tp) != 0)
		return -1;
	/* read original next instruction */
	if (uread(p, &next_instr_val, 4, next_instr_addr) != 0)
		return -1;

	ft_printf("Next instruction at 0x%lx: 0x%x\n", next_instr_addr,
	    next_instr_val);

	fasttrap_instr_t break_instruction = FASTTRAP_INSTR;
	if (uwrite(p, &break_instruction, 4, next_instr_addr) != 0)
		return -1;

	ft_printf("Single stepping instructions set.\n");

	tp->ftt_next_instr = next_instr_val;
	tp->ftt_next_instr_addr = next_instr_addr;
	tp->single_stepping = 1;
	return 0;
}

int
fasttrap_pid_probe(struct trapframe *frame)
{
	struct reg reg, *rp;
	struct rm_priotracker tracker;
	proc_t *p = curproc;
	uintptr_t pc;
	int pc_increment = 0;
	uintptr_t new_pc = 0;
	fasttrap_bucket_t *bucket;
	fasttrap_tracepoint_t *tp, *last_tp;
	pid_t pid;
	dtrace_icookie_t cookie;
	uint_t is_enabled = 0;
	int error = 0;

	fill_regs(curthread, &reg);

	rp = &reg;
	pc = TRAPF_PC(frame);
	pc_increment = 0;
	pid = p->p_pid;

	rm_rlock(&fasttrap_tp_lock, &tracker);

	/* Let's see if we are single stepping. If so, the tracepoint associated
	 * to the last pc has the `single_stepping` flag set to 1. |t_dtrace_pc|
	 * contains the pc of the last hit trace point.
	 * */
	last_tp = fasttrap_find_tracepoint(pid, curthread->t_dtrace_pc);

	ft_printf("\033[32m ==> received a break! Initial PC: 0x%lx\033[0m\n",
	    (uint64_t)pc);

	curthread->t_dtrace_pc = 0;

	if (pget(pid, PGET_HOLD | PGET_NOTWEXIT, &p) != 0) {
		ft_printf("Error trying to hold the process\n");
	}

	// let's see if there is break due to step over breakpoint
	if (last_tp && last_tp->single_stepping) {
		if (last_tp->ftt_next_instr_addr != pc) {
			ft_printf("Error with a precedent single stepping\n");
			error = -1;
			goto done;
		}
		ft_printf(
		    "Trying to clear single stepping at 0x%lx\n", (uint64_t)pc);
		error = fasttrap_clear_single_step(p, last_tp);
		goto done;
	}

	tp = fasttrap_find_tracepoint(pid, pc);
	if (tp == NULL) {
		ft_printf("Trace point not found at PC: 0x%lx\n", (uint64_t)pc);
		error = -1;
		goto done;
	}

	curthread->t_dtrace_pc = pc;

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
				printf("IMPLEMENT ME: %s DTFTP_IS_ENABLED\n",
				    __func__);

				/*
				 * Note that in this case, we don't
				 * call dtrace_probe() since it's only
				 * an artificial probe meant to change
				 * the flow of control so that it
				 * encounters the true probe.
				 */
				is_enabled = 1;
			} else if (id->fti_ptype == DTFTP_CSETBOUNDS) {
				struct capreg cr;
				fill_capregs(curthread,&cr);
				InstFmt _instr;
				_instr.word = tp->ftt_instr;

				void * __capability cd = cr.r_regs[_instr.CType.r1];
				void * __capability cb = cr.r_regs[_instr.CType.r2];
				uint64_t rt = 0;
				if (_instr.CType.fmt == 0x12)
					rt = reg.r_regs[_instr.CType.r3];
				else
					rt = _instr.CCMType.offset;

				dtrace_probe(probe->ftp_id, (uintcap_t) cd, (uintcap_t) cb, rt, 0, 0);
			} else { //offset or return probe
				// TODO(nicomazz): use CTF to understand where
				// to get the parameters from (cap registers or
				// normal ones). Look how it is done in
				// fbt_isa.c
				dtrace_probe(probe->ftp_id, tp->ftt_instr, rp->r_regs[A0],
				    rp->r_regs[A1], rp->r_regs[A2],
				    rp->r_regs[A3]);
			}
		}
	}

	if ((error = fasttrap_single_step(p, tp, frame)) != 0) {
		ft_printf("Error in single stepping!\n");
	}

done:
	rm_runlock(&fasttrap_tp_lock, &tracker);
	PRELE(p);
	if (error) {
		return (-1);
	}

	if (pc_increment != 0) {
		rp->r_regs[PT_REGS_PC] += pc_increment;
		ft_printf("Setting new pc from fasttrap_pid_probe: 0x%lx\n",
		    (uint64_t)rp->r_regs[PT_REGS_PC]);
		set_regs(curthread, rp);
	}

	return (0);
}

static void
fasttrap_return_common(
    struct reg *rp, uintcap_t pc, pid_t pid, uintptr_t new_pc)
{
	printf("IMPLEMENT ME: %s\n", __func__);
	// see how it is done for powerpc
}

int
fasttrap_return_probe(struct trapframe *tf)
{
	printf("IMPLEMENT ME: %s\n", __func__);

	return (-1);
}

uint64_t
fasttrap_pid_getarg(
    void *arg, dtrace_id_t id, void *parg, int argno, int aframes)
{
	printf("IMPLEMENT ME: %s\n", __func__);

	return 0;
}

uint64_t
fasttrap_usdt_getarg(
    void *arg, dtrace_id_t id, void *parg, int argno, int aframes)
{
	printf("IMPLEMENT ME: %s\n", __func__);

	return 0;
}