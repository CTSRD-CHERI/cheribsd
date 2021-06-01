/*	$OpenBSD: trap.c,v 1.19 1998/09/30 12:40:41 pefo Exp $	*/
/* tracked to 1.23 */
/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1988 University of Utah.
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department and Ralph Campbell.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * from: Utah Hdr: trap.c 1.32 91/04/06
 *
 *	from: @(#)trap.c	8.5 (Berkeley) 1/11/94
 *	JNPR: trap.c,v 1.13.2.2 2007/08/29 10:03:49 girish
 */
#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");
#define TRAP_DEBUG 1

#include "opt_ddb.h"
#include "opt_ktrace.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysent.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/signalvar.h>
#include <sys/syscall.h>
#include <sys/lock.h>
#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>
#include <vm/vm_param.h>
#include <sys/vmmeter.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/buf.h>
#include <sys/vnode.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/bus.h>
#ifdef KTRACE
#include <sys/ktrace.h>
#endif
#include <net/netisr.h>

#include <machine/trap.h>
#include <machine/cpu.h>
#include <machine/cpuinfo.h>
#include <machine/pte.h>
#include <machine/pmap.h>
#include <machine/md_var.h>
#include <machine/mips_opcode.h>
#include <machine/frame.h>
#include <machine/regnum.h>
#include <machine/tlb.h>
#include <machine/tls.h>

#ifdef CPU_CHERI
#include <cheri/cheri.h>
#include <cheri/cheric.h>
#include <machine/cheri_machdep.h>
#endif

#ifdef DDB
#include <machine/db_machdep.h>
#include <ddb/db_sym.h>
#include <ddb/ddb.h>
#include <sys/kdb.h>
#endif

_Static_assert(F0 * sizeof(register_t) == __offsetof(struct trapframe, f0),
	"Register offset mismatch between C and assembly");
_Static_assert(CAUSE * sizeof(register_t) ==
	__offsetof(struct trapframe, cause),
	"Register offset mismatch between C and assembly");

#ifdef KDTRACE_HOOKS
#include <sys/dtrace_bsd.h>
#endif

int log_bad_page_faults = 1;
SYSCTL_INT(_machdep, OID_AUTO, log_bad_page_faults, CTLFLAG_RW,
    &log_bad_page_faults, 1, "Print trap frame on bad page fault");
#ifdef TRAP_DEBUG
int trap_debug = 0;
SYSCTL_INT(_machdep, OID_AUTO, trap_debug, CTLFLAG_RW,
    &trap_debug, 0, "Debug information on all traps");
#endif
int stop_vm_trace_on_fault = 0;
SYSCTL_INT(_machdep, OID_AUTO, stop_vm_trace_on_fault, CTLFLAG_RW,
    &stop_vm_trace_on_fault, 0,
    "Disable VM instruction tracing when a fault is logged");
#ifdef CPU_CHERI
int log_user_cheri_exceptions = 1;
SYSCTL_INT(_machdep, OID_AUTO, log_user_cheri_exceptions, CTLFLAG_RW,
    &log_user_cheri_exceptions, 0,
    "Print registers and process details on user CHERI exceptions");

int log_cheri_registers = 1;
SYSCTL_INT(_machdep, OID_AUTO, log_cheri_registers, CTLFLAG_RW,
    &log_cheri_registers, 1, "Print CHERI registers for non-CHERI exceptions");
#endif

#ifdef CPU_QEMU_MALTA
extern u_int qemu_trace_buffered;
#endif

#define	lbu_macro(data, addr)						\
	__asm __volatile ("lbu %0, 0x0(%1)"				\
			: "=r" (data)	/* outputs */			\
			: "r" (addr));	/* inputs */

#define	lb_macro(data, addr)						\
	__asm __volatile ("lb %0, 0x0(%1)"				\
			: "=r" (data)	/* outputs */			\
			: "r" (addr));	/* inputs */

#define	lwl_macro(data, addr)						\
	__asm __volatile ("lwl %0, 0x0(%1)"				\
			: "+r" (data)	/* outputs */			\
			: "r" (addr));	/* inputs */

#define	lwr_macro(data, addr)						\
	__asm __volatile ("lwr %0, 0x0(%1)"				\
			: "+r" (data)	/* outputs */			\
			: "r" (addr));	/* inputs */

#define	ldl_macro(data, addr)						\
	__asm __volatile ("ldl %0, 0x0(%1)"				\
			: "+r" (data)	/* outputs */			\
			: "r" (addr));	/* inputs */

#define	ldr_macro(data, addr)						\
	__asm __volatile ("ldr %0, 0x0(%1)"				\
			: "+r" (data)	/* outputs */			\
			: "r" (addr));	/* inputs */

#define	sb_macro(data, addr)						\
	__asm __volatile ("sb %0, 0x0(%1)"				\
			:				/* outputs */	\
			: "r" (data), "r" (addr));	/* inputs */

#define	swl_macro(data, addr)						\
	__asm __volatile ("swl %0, 0x0(%1)"				\
			: 				/* outputs */	\
			: "r" (data), "r" (addr));	/* inputs */

#define	swr_macro(data, addr)						\
	__asm __volatile ("swr %0, 0x0(%1)"				\
			: 				/* outputs */	\
			: "r" (data), "r" (addr));	/* inputs */

#define	sdl_macro(data, addr)						\
	__asm __volatile ("sdl %0, 0x0(%1)"				\
			: 				/* outputs */	\
			: "r" (data), "r" (addr));	/* inputs */

#define	sdr_macro(data, addr)						\
	__asm __volatile ("sdr %0, 0x0(%1)"				\
			:				/* outputs */	\
			: "r" (data), "r" (addr));	/* inputs */

static void log_illegal_instruction(const char *, struct trapframe *);
static void log_bad_page_fault(char *, struct trapframe *, int);
#ifdef CPU_CHERI
static void log_c2e_exception(const char *, struct trapframe *, int);
#endif
static void log_frame_dump(struct trapframe *frame);
static void get_mapping_info(vm_offset_t, pd_entry_t **, pt_entry_t **);

int (*dtrace_invop_jump_addr)(struct trapframe *);

#ifdef TRAP_DEBUG
static void trap_frame_dump(struct trapframe *frame);
#endif

void (*machExceptionTable[]) (void)= {
/*
 * The kernel exception handlers.
 */
	MipsKernIntr,		/* external interrupt */
#if defined(MIPS_EXC_CNTRS)
	MipsTLBModException,	/* TLB modification */
#else
	MipsKernGenException,	/* TLB modification */
#endif
	MipsTLBInvalidException,/* TLB miss (load or instr. fetch) */
	MipsTLBInvalidException,/* TLB miss (store) */
	MipsKernGenException,	/* address error (load or I-fetch) */
	MipsKernGenException,	/* address error (store) */
	MipsKernGenException,	/* bus error (I-fetch) */
	MipsKernGenException,	/* bus error (load or store) */
	MipsKernGenException,	/* system call */
	MipsKernGenException,	/* breakpoint */
	MipsKernGenException,	/* reserved instruction */
	MipsKernGenException,	/* coprocessor unusable */
	MipsKernGenException,	/* arithmetic overflow */
	MipsKernGenException,	/* trap exception */
	MipsKernGenException,	/* virtual coherence exception inst */
	MipsKernGenException,	/* floating point exception */
	MipsKernGenException,	/* reserved */
	MipsKernGenException,	/* reserved */
	MipsKernGenException,	/* reserved */
	MipsKernGenException,	/* reserved */
	MipsKernGenException,	/* reserved */
	MipsKernGenException,	/* reserved */
	MipsKernGenException,	/* reserved */
	MipsKernGenException,	/* watch exception */
	MipsKernGenException,	/* reserved */
	MipsKernGenException,	/* reserved */
	MipsKernGenException,	/* reserved */
	MipsKernGenException,	/* reserved */
	MipsKernGenException,	/* reserved */
	MipsKernGenException,	/* reserved */
	MipsKernGenException,	/* reserved */
	MipsKernGenException,	/* virtual coherence exception data */
/*
 * The user exception handlers.
 */
	MipsUserIntr,		/* 0 */
	MipsUserGenException,	/* 1 */
	MipsTLBInvalidException,/* 2 */
	MipsTLBInvalidException,/* 3 */
	MipsUserGenException,	/* 4 */
	MipsUserGenException,	/* 5 */
	MipsUserGenException,	/* 6 */
	MipsUserGenException,	/* 7 */
	MipsUserGenException,	/* 8 */
	MipsUserGenException,	/* 9 */
	MipsUserGenException,	/* 10 */
	MipsUserGenException,	/* 11 */
	MipsUserGenException,	/* 12 */
	MipsUserGenException,	/* 13 */
	MipsUserGenException,	/* 14 */
	MipsUserGenException,	/* 15 */
	MipsUserGenException,	/* 16 */
	MipsUserGenException,	/* 17 */
	MipsUserGenException,	/* 18 */
	MipsUserGenException,	/* 19 */
	MipsUserGenException,	/* 20 */
	MipsUserGenException,	/* 21 */
	MipsUserGenException,	/* 22 */
	MipsUserGenException,	/* 23 */
	MipsUserGenException,	/* 24 */
	MipsUserGenException,	/* 25 */
	MipsUserGenException,	/* 26 */
	MipsUserGenException,	/* 27 */
	MipsUserGenException,	/* 28 */
	MipsUserGenException,	/* 29 */
	MipsUserGenException,	/* 20 */
	MipsUserGenException,	/* 31 */
};

char *trap_type[] = {
	"external interrupt",
	"TLB modification",
	"TLB miss (load or instr. fetch)",
	"TLB miss (store)",
	"address error (load or I-fetch)",
	"address error (store)",
	"bus error (I-fetch)",
	"bus error (load or store)",
	"system call",
	"breakpoint",
	"reserved instruction",
	"coprocessor unusable",
	"arithmetic overflow",
	"trap",
	"virtual coherency instruction",
	"floating point",
	"reserved 16",
	"reserved 17",
#ifdef CPU_CHERI
	"capability coprocessor exception",
#else
	"reserved 18",
#endif
	"reserved 19",
	"reserved 20",
	"reserved 21",
	"reserved 22",
	"watch",
	"machine check",
	"reserved 25",
	"reserved 26",
	"reserved 27",
	"reserved 28",
	"reserved 29",
	"reserved 30",
	"virtual coherency data",
};

#if !defined(SMP) && (defined(DDB) || defined(DEBUG))
struct trapdebug trapdebug[TRAPSIZE], *trp = trapdebug;
#endif

#define	KERNLAND(x)	((vm_offset_t)(x) >= VM_MIN_KERNEL_ADDRESS && (vm_offset_t)(x) < VM_MAX_KERNEL_ADDRESS)
#define	DELAYBRANCH(x)	((x) & MIPS_CR_BR_DELAY)

/*
 * MIPS load/store access type
 */
enum {
	MIPS_LHU_ACCESS = 1,
	MIPS_LH_ACCESS,
	MIPS_LWU_ACCESS,
	MIPS_LW_ACCESS,
	MIPS_LD_ACCESS,
	MIPS_SH_ACCESS,
	MIPS_SW_ACCESS,
	MIPS_SD_ACCESS
#ifdef CPU_CHERI
	,
	MIPS_CHERI_CLBU_ACCESS,
	MIPS_CHERI_CLHU_ACCESS,
	MIPS_CHERI_CLWU_ACCESS,
	MIPS_CHERI_CLDU_ACCESS,
	MIPS_CHERI_CLB_ACCESS,
	MIPS_CHERI_CLH_ACCESS,
	MIPS_CHERI_CLW_ACCESS,
	MIPS_CHERI_CLD_ACCESS,
	MIPS_CHERI_CSB_ACCESS,
	MIPS_CHERI_CSH_ACCESS,
	MIPS_CHERI_CSW_ACCESS,
	MIPS_CHERI_CSD_ACCESS
#endif
};

char *access_name[] = {
	"Load Halfword Unsigned",
	"Load Halfword",
	"Load Word Unsigned",
	"Load Word",
	"Load Doubleword",
	"Store Halfword",
	"Store Word",
	"Store Doubleword"
#ifdef CPU_CHERI
	,
	"Capability Load Byte Unsigned",
	"Capability Load Halfword Unsigned",
	"Capability Load Word Unsigned",
	"Capability Load Doubleword Unsigned",
	"Capability Load Byte",
	"Capability Load Halfword",
	"Capability Load Word",
	"Capability Load Doubleword",
	"Capability Store Byte",
	"Capability Store Halfword",
	"Capability Store Word",
	"Capability Store Doubleword"
#endif

};

#ifdef	CPU_CNMIPS
#include <machine/octeon_cop2.h>
#endif

/*
 * Unaligned access handling is completely broken if the trap happens in a
 * CHERI instructions. Since we are now running lots of CHERI purecap code and
 * the LLVM branch delay slot filler actually fills CHERI delay slots, having
 * this on by default makes it really hard to debug where something is going
 * wrong since we will just die with a completely unrelated exception later.
 */
static int allow_unaligned_acc = 1;

SYSCTL_INT(_vm, OID_AUTO, allow_unaligned_acc, CTLFLAG_RW,
    &allow_unaligned_acc, 0, "Allow unaligned accesses");

/*
 * FP emulation is assumed to work on O32, but the code is outdated and crufty
 * enough that it's a more sensible default to have it disabled when using
 * other ABIs.  At the very least, it needs a lot of help in using
 * type-semantic ABI-oblivious macros for everything it does.
 */
#if defined(__mips_o32)
static int emulate_fp = 1;
#else
static int emulate_fp = 0;
#endif
SYSCTL_INT(_machdep, OID_AUTO, emulate_fp, CTLFLAG_RW,
    &emulate_fp, 0, "Emulate unimplemented FPU instructions");

static int emulate_unaligned_access(struct trapframe *frame, int mode);

extern void fswintrberr(void); /* XXX */

static __inline trapf_pc_t
trapf_pc_from_kernel_code_ptr(void *ptr)
{
#if __has_feature(capabilities) && !defined(__CHERI_PURE_CAPABILITY__)
	/* In the hybrid kernel, we assume that addr is within $pcc bounds */
	 KASSERT(cheri_is_address_inbounds(cheri_getpcc(), (register_t)ptr),
	     ("Invalid ptr %p", ptr));
	return (cheri_setaddress(cheri_getpcc(), (register_t)ptr));
#else
	return ((trapf_pc_t)ptr);
#endif
}

/*
 * Fetch an instruction from near frame->pc (or frame->pcc for CHERI).
 * Returns the virtual address (relative to $pcc) that was used to fetch the
 * instruction.
 *
 * Warning: this clobbers td->td_pcb->pcb_onfault.
 */
static void * __capability
fetch_instr_near_pc(struct trapframe *frame, register_t offset_from_pc, int32_t *instr)
{
	void * __capability bad_inst_ptr;

	/* Should only be called from user mode */
	/* TODO: if KERNLAND() */
	KASSERT(curthread->td_pcb->pcb_onfault == NULL,
	    ("This function clobbers td->td_pcb->pcb_onfault"));
#ifdef CPU_CHERI
	bad_inst_ptr = (char * __capability)frame->pcc + offset_from_pc;
	if (!cheri_gettag(bad_inst_ptr)) {
		struct thread *td = curthread;
		struct proc *p = td->td_proc;
		log(LOG_ERR, "%s: pid %d tid %ld (%s), uid %d: Could not fetch "
		    "faulting instruction from untagged $pcc %p\n",  __func__,
		    p->p_pid, (long)td->td_tid, p->p_comm,
		    p->p_ucred ? p->p_ucred->cr_uid : -1,
		    (void*)(__cheri_addr vaddr_t)(bad_inst_ptr));
		*instr = -1;
		return (bad_inst_ptr);
	}
#else
	bad_inst_ptr = __USER_CODE_CAP((uint8_t*)(frame->pc) + offset_from_pc);
#endif
	if (fueword32(bad_inst_ptr, instr) != 0) {
		struct thread *td = curthread;
		struct proc *p = td->td_proc;
		log(LOG_ERR, "%s: pid %d tid %ld (%s), uid %d: Could not fetch "
		    "faulting instruction from %p\n",  __func__, p->p_pid,
		    (long)td->td_tid, p->p_comm,
		    p->p_ucred ? p->p_ucred->cr_uid : -1,
		    (void*)(__cheri_addr vaddr_t)(bad_inst_ptr));
		*instr = -1;
	}
	/* Should this be a kerncap instead instead of being indirected by $pcc? */
	return bad_inst_ptr;
}

/*
 * Fetch the branch instruction for a trap that happened in a branch delay slot.
 *
 * The instruction is stored in frame->badinstr_p.
 */
static void
fetch_bad_branch_instr(struct trapframe *frame)
{
	KASSERT(DELAYBRANCH(frame->cause),
	    ("%s called when not in delay branch", __func__));
	/*
	 * In a trap the pc will point to the branch instruction so we fetch
	 * at offset 0 from the pc.
	 */
	fetch_instr_near_pc(frame, 0, &frame->badinstr_p.inst);
}

/*
 * Fetch the instruction that caused a trap.
 *
 * The instruction is stored in frame->badinstr and the address (relative to)
 * pcc.base is returned.
 */
static void * __capability
fetch_bad_instr(struct trapframe *frame)
{
	register_t offset_from_pc;

	/*
	 * If the trap happenend in a delay slot pc will point to the branch
	 * instruction so in that case fetch from offset 0 from the pc.
	 */
	offset_from_pc = DELAYBRANCH(frame->cause) ? 4 : 0;
	return (fetch_instr_near_pc(frame, offset_from_pc, &frame->badinstr.inst));
}


int
cpu_fetch_syscall_args(struct thread *td)
{
	struct trapframe *locr0;
	struct sysentvec *se;
	struct syscall_args *sa;
	int error, nsaved;

	locr0 = td->td_frame;
	sa = &td->td_sa;

	bzero(sa->args, sizeof(sa->args));

	/* compute next PC after syscall instruction */
	td->td_pcb->pcb_tpc = locr0->pc; /* Remember if restart */
	if (DELAYBRANCH(locr0->cause)) { /* Check BD bit */
		fetch_bad_branch_instr(locr0);
		locr0->pc = MipsEmulateBranch(locr0, locr0->pc, 0,
		    &locr0->badinstr_p.inst);
	} else {
		TRAPF_PC_INCREMENT(locr0, sizeof(int));
	}
	sa->code = locr0->v0;

	switch (sa->code) {
	case SYS___syscall:
	case SYS_syscall:
		/*
		 * This is an indirect syscall, in which the code is the first argument.
		 */
#if (!defined(__mips_n32) && !defined(__mips_n64)) || defined(COMPAT_FREEBSD32)
		if (sa->code == SYS___syscall && SV_PROC_FLAG(td->td_proc, SV_ILP32)) {
			/*
			 * Like syscall, but code is a quad, so as to maintain alignment
			 * for the rest of the arguments.
			 */
			if (_QUAD_LOWWORD == 0)
				sa->code = locr0->a0;
			else
				sa->code = locr0->a1;
			sa->args[0] = locr0->a2;
			sa->args[1] = locr0->a3;
			nsaved = 2;
			break;
		} 
#endif
		/*
		 * This is either not a quad syscall, or is a quad syscall with a
		 * new ABI in which quads fit in a single register.
		 */
		sa->code = locr0->a0;
		sa->args[0] = locr0->a1;
		sa->args[1] = locr0->a2;
		sa->args[2] = locr0->a3;
		nsaved = 3;
#if defined(__mips_n32) || defined(__mips_n64)
#ifdef COMPAT_FREEBSD32
		if (!SV_PROC_FLAG(td->td_proc, SV_ILP32)) {
#endif
			/*
			 * Non-o32 ABIs support more arguments in registers.
			 */
			sa->args[3] = locr0->a4;
			sa->args[4] = locr0->a5;
			sa->args[5] = locr0->a6;
			sa->args[6] = locr0->a7;
			nsaved += 4;
#ifdef COMPAT_FREEBSD32
		}
#endif
#endif
		break;
	default:
		/*
		 * A direct syscall, arguments are just parameters to the syscall.
		 */
		sa->args[0] = locr0->a0;
		sa->args[1] = locr0->a1;
		sa->args[2] = locr0->a2;
		sa->args[3] = locr0->a3;
		nsaved = 4;
#if defined (__mips_n32) || defined(__mips_n64)
#ifdef COMPAT_FREEBSD32
		if (!SV_PROC_FLAG(td->td_proc, SV_ILP32)) {
#endif
			/*
			 * Non-o32 ABIs support more arguments in registers.
			 */
			sa->args[4] = locr0->a4;
			sa->args[5] = locr0->a5;
			sa->args[6] = locr0->a6;
			sa->args[7] = locr0->a7;
			nsaved += 4;
#ifdef COMPAT_FREEBSD32
		}
#endif
#endif
		break;
	}

#ifdef TRAP_DEBUG
	if (trap_debug)
		printf("SYSCALL #%d pid:%u\n", sa->code, td->td_proc->p_pid);
#endif

	se = td->td_proc->p_sysent;
	/*
	 * XXX
	 * Shouldn't this go before switching on the code?
	 */

	if (sa->code >= se->sv_size)
		sa->callp = &se->sv_table[0];
	else
		sa->callp = &se->sv_table[sa->code];

	if (sa->callp->sy_narg > nsaved) {
		char * __capability stack_args;

#if defined(__mips_n32) || defined(__mips_n64)
		/*
		 * XXX
		 * Is this right for new ABIs?  I think the 4 there
		 * should be 8, size there are 8 registers to skip,
		 * not 4, but I'm not certain.
		 */
#ifdef COMPAT_FREEBSD32
		if (!SV_PROC_FLAG(td->td_proc, SV_ILP32))
#endif
			printf("SYSCALL #%u pid:%u, narg (%u) > nsaved (%u).\n",
			    sa->code, td->td_proc->p_pid, sa->callp->sy_narg, nsaved);
#endif
#if (defined(__mips_n32) || defined(__mips_n64)) && defined(COMPAT_FREEBSD32)
		if (SV_PROC_FLAG(td->td_proc, SV_ILP32)) {
			unsigned i;
			int32_t arg;

			stack_args = __USER_CAP(locr0->sp + 4 * sizeof(int32_t),
			    (sa->callp->sy_narg - nsaved) * sizeof(int32_t));
			error = 0; /* XXX GCC is awful.  */
			for (i = nsaved; i < sa->callp->sy_narg; i++) {
				error = copyin(stack_args +
				    (i - nsaved) * sizeof(int32_t),
				    &arg, sizeof(arg));
				if (error != 0)
					break;
				sa->args[i] = arg;
			}
		} else
#endif
		{
			stack_args = __USER_CAP(locr0->sp +
			    4 * sizeof(register_t),
			    (sa->callp->sy_narg - nsaved) * sizeof(register_t));
			error = copyin(stack_args, &sa->args[nsaved],
			    (u_int)(sa->callp->sy_narg - nsaved) * sizeof(register_t));
		}
		if (error != 0) {
			locr0->v0 = error;
			locr0->a3 = 1;
		}
	} else
		error = 0;

	if (error == 0) {
		td->td_retval[0] = 0;
		td->td_retval[1] = locr0->v1;
	}

	return (error);
}

#undef __FBSDID
#define __FBSDID(x)
#include "../../kern/subr_syscall.c"

#ifdef CPU_CHERI
/*
 * Some CHERI faults are (or may be) used transparently and don't (or may not)
 * count as real faults.  This function returns true if it has handled the fault
 * and no further work is to be done.  If the function returns false, it will
 * have set *ftype to the appropriate fault code to pass to the VM subsystem for
 * it to try hiding the fault.
 *
 * At the moment, there's just the one, CHERI_EXCCODE_TLBSTORE, which we hook
 * to emulate capdirty tracking.  If the PTE for badvaddr permits transparent
 * upgrade to capdirty, then we do so and squash the rest of the fault handling;
 * otherwise, we indicate that this is a write fault that also needs to set a
 * capability tag.  This logic is identical to the TLB_MOD paths through trap(),
 * which call pmap_emulate_modified().
 *
 * In the future, this function will also hook capability load generation faults
 * and call into the revoker to check all the capabilities on the target page.
 */
static inline bool
c2e_fixup_fault(struct trapframe *trapframe, bool is_kernel,
    struct vmspace *uvms, vm_prot_t *ftype)
{
	vm_offset_t va = trapframe->badvaddr;
	register_t cause = trapframe->capcause;

	cause &= CHERI_CAPCAUSE_EXCCODE_MASK;
	cause >>= CHERI_CAPCAUSE_EXCCODE_SHIFT;

	if (cause == CHERI_EXCCODE_TLBSTORE) {
		*ftype = VM_PROT_WRITE | VM_PROT_WRITE_CAP;

		if (KERNLAND(va)) {
			return (is_kernel &&
			    !pmap_emulate_capdirty(kernel_pmap, va));
		} else {
			pmap_t upmap = vmspace_pmap(uvms);
			return (!pmap_emulate_capdirty(upmap, va));
		}
	}

	return (false);
}
#endif

/*
 * Handle an exception.
 * Called from MipsKernGenException() or MipsUserGenException()
 * when a processor trap occurs.
 * In the case of a kernel trap, we return the pc where to resume if
 * p->p_addr->u_pcb.pcb_onfault is set, otherwise, return old pc.
 */
trapf_pc_t
trap(struct trapframe *trapframe)
{
	int type, usermode;
	int i = 0;
	unsigned ucode = 0;
	struct thread *td = curthread;
	struct proc *p = curproc;
	vm_prot_t ftype;
	pmap_t pmap;
	int access_type;
	ksiginfo_t ksi;
	char *msg = NULL;
	char * __capability addr;
	trapf_pc_t pc;
	int cop, error;
	register_t *frame_regs;

	trapdebug_enter(trapframe, 0);
#ifdef KDB
	if (kdb_active) {
		kdb_reenter();
		return (0);
	}
#endif
	type = (trapframe->cause & MIPS_CR_EXC_CODE) >> MIPS_CR_EXC_CODE_SHIFT;
	if (TRAPF_USERMODE(trapframe)) {
		type |= T_USER;
		usermode = 1;
	} else {
		usermode = 0;
	}
#if 0
	/* XXXAR: reading the badinstr register here is too late, it may have
	 * been clobbered already. For now just use fuword instead
	 *
	 * XXXAR: We use a union for BadInstr/BadInstrP instead of register_t to
	 * avoid problems in case some CPU wrongly sign extends the register.
	 * This was the case for QEMU until recently.
	 */
	trapframe->badinstr.inst = cpuinfo.badinstr_reg ? mips_rd_badinstr(): 0;
	trapframe->badinstr_p.inst = 0;
	if (DELAYBRANCH(trapframe->cause) && cpuinfo.badinstr_p_reg)
		trapframe->badinstr_p.inst = mips_rd_badinstr_p();
#else
	trapframe->badinstr.pad = 0;
	trapframe->badinstr_p.inst = 0;
#endif

	/*
	 * Enable hardware interrupts if they were on before the trap. If it
	 * was off disable all so we don't accidently enable it when doing a
	 * return to userland.
	 */
	if (trapframe->sr & MIPS_SR_INT_IE) {
		set_intr_mask(trapframe->sr & MIPS_SR_INT_MASK);
		intr_enable();
	} else {
		intr_disable();
	}

#ifdef TRAP_DEBUG
	if (trap_debug) {
		static vm_offset_t last_badvaddr = 0;
		static vm_offset_t this_badvaddr = 0;
		static int count = 0;
		u_int32_t pid;

		printf("trap type %x (%s - ", type,
		    trap_type[type & (~T_USER)]);

		if (type & T_USER)
			printf("user mode)\n");
		else
			printf("kernel mode)\n");

#ifdef SMP
		printf("cpuid = %d\n", PCPU_GET(cpuid));
#endif
		pid = mips_rd_entryhi() & TLBHI_ASID_MASK;
		printf("badaddr = %#jx, pc = %#jx, ra = %#jx, sp = %#jx, sr = %jx, pid = %d, ASID = %u\n",
		    (intmax_t)trapframe->badvaddr, (intmax_t)TRAPF_PC(trapframe), (intmax_t)trapframe->ra,
		    (intmax_t)trapframe->sp, (intmax_t)trapframe->sr,
		    (curproc ? curproc->p_pid : -1), pid);

		switch (type & ~T_USER) {
		case T_TLB_MOD:
		case T_TLB_LD_MISS:
		case T_TLB_ST_MISS:
		case T_ADDR_ERR_LD:
		case T_ADDR_ERR_ST:
			this_badvaddr = trapframe->badvaddr;
			break;
		case T_SYSCALL:
			this_badvaddr = trapframe->ra;
			break;
		default:
			this_badvaddr = TRAPF_PC(trapframe);
			break;
		}
		if ((last_badvaddr == this_badvaddr) &&
		    ((type & ~T_USER) != T_SYSCALL) &&
		    ((type & ~T_USER) != T_COP_UNUSABLE)) {
			if (++count == 3) {
				trap_frame_dump(trapframe);
				panic("too many faults at %p\n", (void *)last_badvaddr);
			}
		} else {
			last_badvaddr = this_badvaddr;
			count = 0;
		}
	}
#endif

#ifdef KDTRACE_HOOKS
	/*
	 * A trap can occur while DTrace executes a probe. Before
	 * executing the probe, DTrace blocks re-scheduling and sets
	 * a flag in its per-cpu flags to indicate that it doesn't
	 * want to fault. On returning from the probe, the no-fault
	 * flag is cleared and finally re-scheduling is enabled.
	 *
	 * If the DTrace kernel module has registered a trap handler,
	 * call it and if it returns non-zero, assume that it has
	 * handled the trap and modified the trap frame so that this
	 * function can return normally.
	 */
	/*
	 * XXXDTRACE: add pid probe handler here (if ever)
	 */
	if (!usermode) {
		if (dtrace_trap_func != NULL &&
		    (*dtrace_trap_func)(trapframe, type) != 0)
			return (trapframe->pc);
	}
#endif

#ifdef CPU_CHERI
	addr = (void * __capability)trapframe->pcc;
#else
	addr = (void *)(uintptr_t)trapframe->pc;
#endif
	switch (type) {
	case T_MCHECK:
#ifdef DDB
		kdb_trap(type, 0, trapframe);
#endif
		panic("MCHECK\n");
		break;
	case T_MCHECK + T_USER:
		{
			uint32_t status = mips_rd_status();

			if (status & MIPS_SR_TS) {
				/*
				 * Machine Check exception caused by TLB
				 * detecting a match for multiple entries.
				 *
				 * Attempt to recover by flushing the user TLB
				 * and resetting the status bit.
				 */
				printf("Machine Check in User - Dup TLB entry. "
				    "Recovering...\n");
				pmap = &p->p_vmspace->vm_pmap;
				tlb_invalidate_all_user(pmap);
				mips_wr_status(status & ~MIPS_SR_TS);

				return (trapframe->pc);
			} else {
#ifdef DDB
				kdb_trap(type, 0, trapframe);
#endif
				panic("MCHECK\n");
			}
		}
		break;
	case T_TLB_MOD:
		if (td->td_critnest != 0 || td->td_intr_nesting_level != 0 ||
		    WITNESS_CHECK(WARN_SLEEPOK | WARN_GIANTOK, NULL,
		    "Kernel page fault") != 0)
			goto err;

		/* check for kernel address */
		if (KERNLAND(trapframe->badvaddr)) {
			if (pmap_emulate_modified(kernel_pmap, 
			    trapframe->badvaddr) != 0) {
				ftype = VM_PROT_WRITE;
				goto kernel_fault;
			}
			return (trapframe->pc);
		}
		/* FALLTHROUGH */

	case T_TLB_MOD + T_USER:
		pmap = &p->p_vmspace->vm_pmap;
		if (pmap_emulate_modified(pmap, trapframe->badvaddr) != 0) {
			ftype = VM_PROT_WRITE;
			goto dofault;
		}
		if (!usermode)
			return (trapframe->pc);
		goto out;

	case T_TLB_LD_MISS:
	case T_TLB_ST_MISS:
		if (td->td_critnest != 0 || td->td_intr_nesting_level != 0 ||
		    WITNESS_CHECK(WARN_SLEEPOK | WARN_GIANTOK, NULL,
		    "Kernel page fault") != 0)
			goto err;

		ftype = (type == T_TLB_ST_MISS) ? VM_PROT_WRITE : VM_PROT_READ;
		/* check for kernel address */
		if (KERNLAND(trapframe->badvaddr)) {
			vm_offset_t va;
			int rv;

	kernel_fault:
			va = (vm_offset_t)trapframe->badvaddr;
			rv = vm_fault_trap(kernel_map, va, ftype,
			    VM_FAULT_NORMAL, NULL, NULL);
			if (rv == KERN_SUCCESS)
				return (trapframe->pc);
			if (td->td_pcb->pcb_onfault != NULL) {
				pc = trapf_pc_from_kernel_code_ptr(td->td_pcb->pcb_onfault);
				td->td_pcb->pcb_onfault = NULL;
				return (pc);
			}
			goto err;
		}

		/*
		 * It is an error for the kernel to access user space except
		 * through the copyin/copyout routines.
		 */
		if (td->td_pcb->pcb_onfault == NULL)
			goto err;

		goto dofault;

	case T_TLB_LD_MISS + T_USER:
		ftype = VM_PROT_READ;
		goto dofault;

	case T_TLB_ST_MISS + T_USER:
		ftype = VM_PROT_WRITE;

dofault:
		{
			vm_offset_t va;
			struct vmspace *vm;
			vm_map_t map;
			int rv = 0;

			vm = p->p_vmspace;
			map = &vm->vm_map;
			va = (vm_offset_t)trapframe->badvaddr;
			if (KERNLAND(trapframe->badvaddr)) {
				/*
				 * Don't allow user-mode faults in kernel
				 * address space.
				 */
				goto nogo;
			}

			rv = vm_fault_trap(map, va, ftype, VM_FAULT_NORMAL,
			    &i, &ucode);
			/*
			 * XXXDTRACE: add dtrace_doubletrap_func here?
			 */
#ifdef VMFAULT_TRACE
			printf("vm_fault(%p (pmap %p), %p (%lx), %x, %d) -> %x at pc %p\n",
			    map, &vm->vm_pmap, (void *)va, trapframe->badvaddr,
			    ftype, VM_FAULT_NORMAL, rv,
			    (__cheri_fromcap void *)trapframe->pc);
#endif

			if (rv == KERN_SUCCESS) {
				if (!usermode) {
					return (trapframe->pc);
				}
				goto out;
			}
	nogo:
			if (!usermode) {
				if (td->td_pcb->pcb_onfault != NULL) {
					pc = trapf_pc_from_kernel_code_ptr(td->td_pcb->pcb_onfault);
					td->td_pcb->pcb_onfault = NULL;
					return (pc);
				}
				goto err;
			}
			addr = (void * __capability)(intcap_t)
			    trapframe->badvaddr;

			msg = "BAD_PAGE_FAULT";
			log_bad_page_fault(msg, trapframe, type);

			break;
		}

	case T_ADDR_ERR_LD + T_USER:	/* misaligned or kseg access */
	case T_ADDR_ERR_ST + T_USER:	/* misaligned or kseg access */
		if (trapframe->badvaddr < 0 ||
		    trapframe->badvaddr >= VM_MAXUSER_ADDRESS) {
			msg = "ADDRESS_SPACE_ERR";
		} else if (allow_unaligned_acc) {
			int mode;

			if (type == (T_ADDR_ERR_LD + T_USER))
				mode = VM_PROT_READ;
			else
				mode = VM_PROT_WRITE;

			access_type = emulate_unaligned_access(trapframe, mode);
			if (access_type != 0)
				goto out;
			msg = "ALIGNMENT_FIX_ERR";
		} else {
			msg = "ADDRESS_ERR";
		}

		/* FALL THROUGH */

	case T_BUS_ERR_IFETCH + T_USER:	/* BERR asserted to cpu */
	case T_BUS_ERR_LD_ST + T_USER:	/* BERR asserted to cpu */
		ucode = 0;	/* XXX should be VM_PROT_something */
		i = SIGBUS;
		if (!msg)
			msg = "BUS_ERR";
		log_bad_page_fault(msg, trapframe, type);
		break;

	case T_SYSCALL + T_USER:
		{
			syscallenter(td);

#if !defined(SMP) && (defined(DDB) || defined(DEBUG))
			if (trp == trapdebug)
				trapdebug[TRAPSIZE - 1].code = td->td_sa.code;
			else
				trp[-1].code = td->td_sa.code;
#endif
			trapdebug_enter(td->td_frame, -td->td_sa.code);

			/*
			 * The sync'ing of I & D caches for SYS_ptrace() is
			 * done by procfs_domem() through procfs_rwmem()
			 * instead of being done here under a special check
			 * for SYS_ptrace().
			 */
			syscallret(td);
			return (trapframe->pc);
		}

#if defined(KDTRACE_HOOKS) || defined(DDB)
	case T_BREAK:
#ifdef KDTRACE_HOOKS
		if (!usermode && dtrace_invop_jump_addr != NULL &&
		    dtrace_invop_jump_addr(trapframe) == 0)
			return (trapframe->pc);
#endif
#ifdef DDB
		kdb_trap(type, 0, trapframe);
		return (trapframe->pc);
#endif
#endif

	case T_BREAK + T_USER:
		{
			char * __capability va;
			uint32_t instr;

			i = SIGTRAP;
			ucode = TRAP_BRKPT;

			/* compute address of break instruction */
			va = addr;
			if (DELAYBRANCH(trapframe->cause))
				va += sizeof(int);
			addr = va;

			if (td->td_md.md_ss_addr != (__cheri_addr uintptr_t)va) {
				addr = va;
				break;
			}

			/* read break instruction */
			instr = fuword32(va);

			if (instr != MIPS_BREAK_SSTEP) {
				addr = va;
				break;
			}

			CTR3(KTR_PTRACE,
			    "trap: tid %d, single step at 0x%lx: %#08x",
			    td->td_tid, (__cheri_addr long)va, instr);
			PROC_LOCK(p);
			_PHOLD(p);
			error = ptrace_clear_single_step(td);
			_PRELE(p);
			PROC_UNLOCK(p);
			if (error == 0)
				ucode = TRAP_TRACE;
			break;
		}

	case T_IWATCH + T_USER:
	case T_DWATCH + T_USER:
			/* compute address of trapped instruction */
			if (DELAYBRANCH(trapframe->cause))
				addr += sizeof(int);
			printf("watch exception @ %p\n", (__cheri_fromcap void *)addr);
			i = SIGTRAP;
			ucode = TRAP_BRKPT;
			break;

	case T_TRAP + T_USER:
		{
			struct trapframe *locr0 = td->td_frame;

			addr = fetch_bad_instr(trapframe);

			if (DELAYBRANCH(trapframe->cause)) {	/* Check BD bit */
				/* fetch branch instruction */
				fetch_bad_branch_instr(trapframe);
				locr0->pc = MipsEmulateBranch(locr0, trapframe->pc,
				    0, &trapframe->badinstr_p.inst);
			} else {
				TRAPF_PC_INCREMENT(locr0, sizeof(int));
			}
			i = SIGEMT;	/* Stuff it with something for now */
			break;
		}

	case T_RES_INST + T_USER:
		{
			InstFmt inst;

			addr = fetch_bad_instr(trapframe);
			inst.word = trapframe->badinstr.inst;
			switch (inst.RType.op) {
			case OP_SPECIAL3:
				switch (inst.RType.func) {
				case OP_RDHWR:
					/* Register 29 used for TLS */
					if (inst.RType.rd == 29) {
						frame_regs = &(trapframe->zero);
						frame_regs[inst.RType.rt] = (register_t)(intptr_t)(__cheri_fromcap void *)td->td_md.md_tls;
						frame_regs[inst.RType.rt] += td->td_proc->p_md.md_tls_tcb_offset;
						TRAPF_PC_INCREMENT(trapframe, sizeof(int));
						goto out;
					}
				break;
				}
			break;
			}

			log_illegal_instruction("RES_INST", trapframe);
			i = SIGILL;
		}
		break;
#ifdef CPU_CHERI
	case T_C2E:
		ftype = 0;

		if (c2e_fixup_fault(trapframe, true, p->p_vmspace, &ftype))
			return (trapframe->pc);

		if (ftype != 0) {
			if (KERNLAND(trapframe->badvaddr))
				goto kernel_fault;
			else
				goto dofault;
		}

		if (td->td_pcb->pcb_onfault != NULL) {
			pc = trapf_pc_from_kernel_code_ptr(td->td_pcb->pcb_onfault);
			td->td_pcb->pcb_onfault = NULL;
			return (pc);
		}
		fetch_bad_instr(trapframe);
		log_c2e_exception("KERNEL_CHERI_EXCEPTION", trapframe, type);
		printf("badvaddr = %#jx, pc = %#jx, ra = %#jx, sr = %#jx\n",
		    (intmax_t)trapframe->badvaddr, (intmax_t)TRAPF_PC(trapframe),
		    (intmax_t)trapframe->ra, (intmax_t)trapframe->sr);
		goto err;
		break;

	case T_C2E + T_USER:
		msg = "USER_CHERI_EXCEPTION";
		ftype = 0;

		if (c2e_fixup_fault(trapframe, false, p->p_vmspace, &ftype))
			goto out;

		if (ftype != 0)
			goto dofault;

		fetch_bad_instr(trapframe);
		if (log_user_cheri_exceptions)
			log_c2e_exception(msg, trapframe, type);
		if (CHERI_CAPCAUSE_EXCCODE(trapframe->capcause) ==
		    CHERI_EXCCODE_TLBSTORE) {
			i = SIGSEGV;
			ucode = SEGV_STORETAG;
			addr = (void * __capability)(intcap_t)
			    trapframe->badvaddr;
		} else {
			i = SIGPROT;
			ucode = cheri_capcause_to_sicode(trapframe->capcause);
		}
		break;

#else
	case T_C2E:
	case T_C2E + T_USER:
		goto err;
		break;
#endif
	case T_COP_UNUSABLE:
		cop = (trapframe->cause & MIPS_CR_COP_ERR) >> MIPS_CR_COP_ERR_SHIFT;
#if defined(CPU_CHERI)
		/* XXXRW: CP2 state management here. */
#if 0 && defined(DDB)
		if (cop == 2)
			kdb_enter(KDB_WHY_CHERI, "T_COP_UNUSABLE exception");
#endif
		/*
		 * XXXRW: For reasons not fully understood, the COP_2 enable
		 * is getting cleared.  A hardware bug?  Software bug?
		 * Unclear, but turn it back on again and restart the
		 * instruction.
		 */
		if (cop == 2) {
			printf("%s: reenabling COP_2 for kernel\n", __func__);
			mips_wr_status(mips_rd_status() | MIPS_SR_COP_2_BIT);
			td->td_frame->sr |= MIPS_SR_COP_2_BIT;
			return (trapframe->pc);
		}
#endif
#ifdef	CPU_CNMIPS
		/* Handle only COP2 exception */
		if (cop != 2)
			goto err;

		addr = trapframe->pc;
		/* save userland cop2 context if it has been touched */
		if ((td->td_md.md_flags & MDTD_COP2USED) &&
		    (td->td_md.md_cop2owner == COP2_OWNER_USERLAND)) {
			if (td->td_md.md_ucop2)
				octeon_cop2_save(td->td_md.md_ucop2);
			else
				panic("COP2 was used in user mode but md_ucop2 is NULL");
		}

		if (td->td_md.md_cop2 == NULL) {
			td->td_md.md_cop2 = octeon_cop2_alloc_ctx();
			if (td->td_md.md_cop2 == NULL)
				panic("Failed to allocate COP2 context");
			memset(td->td_md.md_cop2, 0, sizeof(*td->td_md.md_cop2));
		}

		octeon_cop2_restore(td->td_md.md_cop2);
		
		/* Make userland re-request its context */
		td->td_frame->sr &= ~MIPS_SR_COP_2_BIT;
		td->td_md.md_flags |= MDTD_COP2USED;
		td->td_md.md_cop2owner = COP2_OWNER_KERNEL;
		/* Enable COP2, it will be disabled in cpu_switch */
		mips_wr_status(mips_rd_status() | MIPS_SR_COP_2_BIT);
		return (trapframe->pc);
#else
		goto err;
		break;
#endif

	case T_COP_UNUSABLE + T_USER:
		cop = (trapframe->cause & MIPS_CR_COP_ERR) >> MIPS_CR_COP_ERR_SHIFT;
#if defined(CPU_CHERI) && defined(DDB)
		/* XXXRW: CP2 state management here. */
		if (cop == 2)
			kdb_enter(KDB_WHY_CHERI,
			    "T_COP_UNUSABLE + T_USER exception");
#endif
		if (cop == 1) {
			/* FP (COP1) instruction */
			if (cpuinfo.fpu_id == 0) {
				log_illegal_instruction("COP1_UNUSABLE",
				    trapframe);
				i = SIGILL;
				break;
			}
			MipsSwitchFPState(PCPU_GET(fpcurthread), td->td_frame);
			PCPU_SET(fpcurthread, td);
#if defined(__mips_n32) || defined(__mips_n64)
			td->td_frame->sr |= MIPS_SR_COP_1_BIT | MIPS_SR_FR;
#else
			td->td_frame->sr |= MIPS_SR_COP_1_BIT;
#endif
			td->td_md.md_flags |= MDTD_FPUSED;
			goto out;
		}
#ifdef	CPU_CNMIPS
		else  if (cop == 2) {
			if ((td->td_md.md_flags & MDTD_COP2USED) &&
			    (td->td_md.md_cop2owner == COP2_OWNER_KERNEL)) {
				if (td->td_md.md_cop2)
					octeon_cop2_save(td->td_md.md_cop2);
				else
					panic("COP2 was used in kernel mode but md_cop2 is NULL");
			}

			if (td->td_md.md_ucop2 == NULL) {
				td->td_md.md_ucop2 = octeon_cop2_alloc_ctx();
				if (td->td_md.md_ucop2 == NULL)
					panic("Failed to allocate userland COP2 context");
				memset(td->td_md.md_ucop2, 0, sizeof(*td->td_md.md_ucop2));
			}

			octeon_cop2_restore(td->td_md.md_ucop2);

			td->td_frame->sr |= MIPS_SR_COP_2_BIT;
			td->td_md.md_flags |= MDTD_COP2USED;
			td->td_md.md_cop2owner = COP2_OWNER_USERLAND;
			goto out;
		}
#endif
		else {
			log_illegal_instruction("COPn_UNUSABLE", trapframe);
			i = SIGILL;	/* only FPU instructions allowed */
			break;
		}

	case T_FPE:
#if !defined(SMP) && (defined(DDB) || defined(DEBUG))
		trapDump("fpintr");
#else
		printf("FPU Trap: PC %#jx CR %x SR %x\n",
		    (intmax_t)TRAPF_PC(trapframe), (unsigned)trapframe->cause, (unsigned)trapframe->sr);
		goto err;
#endif

	case T_FPE + T_USER:
#if !defined(CPU_HAVEFPU)
		i = SIGILL;
		break;
#else
		if (!emulate_fp) {
			i = SIGFPE;
			break;
		}
		MipsFPTrap(trapframe->sr, trapframe->cause, trapframe->pc);
		goto out;
#endif

	case T_OVFLOW + T_USER:
		i = SIGFPE;
		break;

	case T_ADDR_ERR_LD:	/* misaligned access */
	case T_ADDR_ERR_ST:	/* misaligned access */
#ifdef TRAP_DEBUG
		if (trap_debug) {
			printf("+++ ADDR_ERR: type = %d, badvaddr = %#jx\n", type,
			    (intmax_t)trapframe->badvaddr);
		}
#endif
		/* Only allow emulation on a user address */
		if (allow_unaligned_acc &&
		    ((vm_offset_t)trapframe->badvaddr < VM_MAXUSER_ADDRESS)) {
			void *saved_onfault;
			int mode;

			/* emulate_unaligned_access() clobbers pcb_onfault. */
			saved_onfault = td->td_pcb->pcb_onfault;
			td->td_pcb->pcb_onfault = NULL;

			if (type == T_ADDR_ERR_LD)
				mode = VM_PROT_READ;
			else
				mode = VM_PROT_WRITE;

			access_type = emulate_unaligned_access(trapframe, mode);
			td->td_pcb->pcb_onfault = saved_onfault;
			if (access_type != 0)
				return (trapframe->pc);
		}
		/* FALLTHROUGH */

	case T_BUS_ERR_LD_ST:	/* BERR asserted to cpu */
		if (td->td_pcb->pcb_onfault != NULL) {
			pc = trapf_pc_from_kernel_code_ptr(td->td_pcb->pcb_onfault);
			td->td_pcb->pcb_onfault = NULL;
			return (pc);
		}

		/* FALLTHROUGH */

	default:
err:

#if !defined(SMP) && defined(DEBUG)
		trapDump("trap");
#endif
#ifdef SMP
		printf("cpu:%d-", PCPU_GET(cpuid));
#endif
		printf("Trap cause = %d (%s - ", type,
		    trap_type[type & (~T_USER)]);

		if (type & T_USER)
			printf("user mode)\n");
		else
			printf("kernel mode)\n");

#ifdef TRAP_DEBUG
		if (trap_debug)
			printf("badvaddr = %#jx, pc = %#jx, ra = %#jx, sr = %#jxx\n",
			       (intmax_t)trapframe->badvaddr, (intmax_t)TRAPF_PC(trapframe), (intmax_t)trapframe->ra,
			       (intmax_t)trapframe->sr);
#endif

#ifdef KDB
		if (debugger_on_trap) {
			kdb_why = KDB_WHY_TRAP;
			kdb_trap(type, 0, trapframe);
			kdb_why = KDB_WHY_UNSET;
		}
#endif
		panic("trap");
	}
	td->td_frame->pc = trapframe->pc;
	td->td_frame->cause = trapframe->cause;
	td->td_frame->badvaddr = trapframe->badvaddr;
	ksiginfo_init_trap(&ksi);
	ksi.ksi_signo = i;
	ksi.ksi_code = ucode;
	/* XXXBD: probably not quite right for CheriABI */
	ksi.ksi_addr = addr;
	ksi.ksi_trapno = type & ~T_USER;
#if defined(CPU_CHERI)
	if (i == SIGPROT)
		ksi.ksi_capreg = trapframe->capcause &
		    CHERI_CAPCAUSE_REGNUM_MASK;
#endif
#ifdef CPU_QEMU_MALTA
	if (qemu_trace_buffered)
		QEMU_FLUSH_TRACE_BUFFER;
#endif
	trapsignal(td, &ksi);
out:
	/*
	 * Note: we should only get here if returning to user mode.
	 */
	userret(td, trapframe);
#if defined(CPU_CHERI)
	/*
	 * XXXAR: These assertions will currently not hold since in some cases
	 *  we will only update pc but not pcc. However, this is fine since the
	 *  return path will set the offset before eret. We should only need the
	 *  assertion on entry to catch QEMU/FPGA bugs in EPC/EPCC handling.
	 *
	 * KASSERT(cheri_getoffset(td->td_frame->pcc) == td->td_frame->pc,
	 *  ("td->td_frame->pcc.offset (%jx) <-> td->td_frame->pc (%jx) mismatch:",
	 *   (uintmax_t)cheri_getoffset(td->td_frame->pcc), (uintmax_t)td->td_frame->pc));
	 *
	 * KASSERT(cheri_getoffset(trapframe->pcc) == trapframe->pc,
	 *    ("%s(exit): pcc.offset (%jx) <-> pc (%jx) mismatch:", __func__,
	 *    (uintmax_t)cheri_getoffset(trapframe->pcc), (uintmax_t)trapframe->pc));
	 */
#endif
	return (trapframe->pc);
}

#if !defined(SMP) && (defined(DDB) || defined(DEBUG))
void
trapDump(char *msg)
{
	register_t s;
	int i;

	s = intr_disable();
	printf("trapDump(%s)\n", msg);
	for (i = 0; i < TRAPSIZE; i++) {
		if (trp == trapdebug) {
			trp = &trapdebug[TRAPSIZE - 1];
		} else {
			trp--;
		}

		if (trp->cause == 0)
			break;

		printf("%s: ADR %jx PC %jx CR %jx SR %jx\n",
		    trap_type[(trp->cause & MIPS_CR_EXC_CODE) >> 
			MIPS_CR_EXC_CODE_SHIFT],
		    (intmax_t)trp->vadr, (intmax_t)trp->pc,
		    (intmax_t)trp->cause, (intmax_t)trp->status);

		printf("   RA %jx SP %jx code %d\n", (intmax_t)trp->ra,
		    (intmax_t)trp->sp, (int)trp->code);
	}
	intr_restore(s);
}
#endif

/*
 * Return the resulting PC as if the branch was executed.
 *
 * XXXAR: This needs to be fixed for ccall_fast
 */
trapf_pc_t
MipsEmulateBranch(struct trapframe *framePtr, trapf_pc_t _instPC, int fpcCSR,
    uint32_t *instptr)
{
	InstFmt inst;
	register_t *regsPtr = (register_t *)framePtr;
	/* Cast to uint8_t* for pointer arithmetic */
	uint8_t * __capability instPC = (uint8_t * __capability) _instPC;
#if __has_feature(capabilities)
	void * __capability *capRegsPtr = &framePtr->ddc;
#endif
	uint8_t * __capability retAddr = NULL;
	int condition;

#define	GetBranchDest(InstPtr, inst) \
	(InstPtr + 4 + ((short)inst.IType.imm << 2))

	if (instptr) {
		inst = *(InstFmt *) instptr;
	} else {
		if (!KERNLAND((__cheri_addr vaddr_t)instPC))
			inst.word = fuword32(instPC);  /* XXXAR: error check? */
		else
			memcpy_c(&inst, instPC, sizeof(InstFmt));
	}
	/* Save the bad branch instruction so we can log it */
	framePtr->badinstr_p.inst = inst.word;

	switch ((int)inst.JType.op) {
	case OP_SPECIAL:
		switch ((int)inst.RType.func) {
		case OP_JR:
		case OP_JALR: {
			vaddr_t ret_va = regsPtr[inst.RType.rs];
#if __has_feature(capabilities)
			retAddr = cheri_setoffset(instPC, ret_va);
#else
			retAddr = (uint8_t* __capability)ret_va;
#endif
			break;
		}

		default:
			retAddr = instPC + 4;
			break;
		}
		break;

	case OP_BCOND:
		switch ((int)inst.IType.rt) {
		case OP_BLTZ:
		case OP_BLTZL:
		case OP_BLTZAL:
		case OP_BLTZALL:
			if ((int)(regsPtr[inst.RType.rs]) < 0)
				retAddr = GetBranchDest(instPC, inst);
			else
				retAddr = instPC + 8;
			break;

		case OP_BGEZ:
		case OP_BGEZL:
		case OP_BGEZAL:
		case OP_BGEZALL:
			if ((int)(regsPtr[inst.RType.rs]) >= 0)
				retAddr = GetBranchDest(instPC, inst);
			else
				retAddr = instPC + 8;
			break;

		case OP_TGEI:
		case OP_TGEIU:
		case OP_TLTI:
		case OP_TLTIU:
		case OP_TEQI:
		case OP_TNEI:
			retAddr = instPC + 4;	/* Like syscall... */
			break;

		default:
			panic("MipsEmulateBranch: Bad branch cond");
		}
		break;

	case OP_J:
	case OP_JAL: {
		vaddr_t ret_va = (inst.JType.target << 2) |
		    (((__cheri_addr vaddr_t)instPC + 4) & 0xF0000000);
#if __has_feature(capabilities)
		retAddr = cheri_setoffset(instPC, ret_va);
#else
		retAddr = (uint8_t*)ret_va;
#endif
		break;
	}

	case OP_BEQ:
	case OP_BEQL:
		if (regsPtr[inst.RType.rs] == regsPtr[inst.RType.rt])
			retAddr = GetBranchDest(instPC, inst);
		else
			retAddr = instPC + 8;
		break;

	case OP_BNE:
	case OP_BNEL:
		if (regsPtr[inst.RType.rs] != regsPtr[inst.RType.rt])
			retAddr = GetBranchDest(instPC, inst);
		else
			retAddr = instPC + 8;
		break;

	case OP_BLEZ:
	case OP_BLEZL:
		if ((int)(regsPtr[inst.RType.rs]) <= 0)
			retAddr = GetBranchDest(instPC, inst);
		else
			retAddr = instPC + 8;
		break;

	case OP_BGTZ:
	case OP_BGTZL:
		if ((int)(regsPtr[inst.RType.rs]) > 0)
			retAddr = GetBranchDest(instPC, inst);
		else
			retAddr = instPC + 8;
		break;

	case OP_COP1:
		switch (inst.RType.rs) {
		case OP_BCx:
		case OP_BCy:
			if ((inst.RType.rt & COPz_BC_TF_MASK) == COPz_BC_TRUE)
				condition = fpcCSR & MIPS_FPU_COND_BIT;
			else
				condition = !(fpcCSR & MIPS_FPU_COND_BIT);
			if (condition)
				retAddr = GetBranchDest(instPC, inst);
			else
				retAddr = instPC + 8;
			break;

		default:
			retAddr = instPC + 4;
		}
		break;
#ifdef CPU_CHERI
	case OP_COP2:
		switch (inst.CType.fmt) {
		case OP_CJ:
			switch (inst.CType.r3) {
			case OP_CJALR:
				retAddr = capRegsPtr[inst.CType.r2];
				break;
			case OP_CJR:
				retAddr = capRegsPtr[inst.CType.r1];
				break;
			}
			if (retAddr != NULL)
				return (trapf_pc_t)(retAddr);
			break;
		case OP_CBEZ:
		case OP_CBNZ:
		case OP_CBTS:
		case OP_CBTU:
			switch (inst.BC2FType.fmt) {
			case OP_CBTU:
				condition = !cheri_gettag(
				    capRegsPtr[inst.BC2FType.cd]);
				break;
			case OP_CBTS:
				condition = cheri_gettag(
				    capRegsPtr[inst.BC2FType.cd]);
				break;
			case OP_CBEZ:
				condition =
				    (capRegsPtr[inst.BC2FType.cd] == NULL);
				break;
			case OP_CBNZ:
				condition =
				    (capRegsPtr[inst.BC2FType.cd] != NULL);
				break;
			}
			if (condition)
				retAddr = GetBranchDest(instPC, inst);
			else
				retAddr = instPC + 8;
			return (trapf_pc_t)(retAddr);
		}
		/* FALLTHROUGH */
#endif

	default:
		printf("Unhandled opcode in %s: 0x%x\n", __func__, inst.word);
#ifdef DDB
		/*
		 * Print some context for cases like jenkins where we don't
		 * have an interactive console:
		 */
		int32_t context_instr;
		fetch_instr_near_pc(framePtr, -8, &context_instr);
		db_printf("Instr at %p ($pc-8): %x   ", (char*)TRAPF_PC(framePtr) - 8, context_instr);
		db_disasm((db_addr_t)&context_instr, 0);
		fetch_instr_near_pc(framePtr, -4, &context_instr);
		db_printf("Instr at %p ($pc-4): %x   ", (char*)TRAPF_PC(framePtr) - 4, context_instr);
		db_disasm((db_addr_t)&context_instr, 0);
		fetch_instr_near_pc(framePtr, 0, &context_instr);
		db_printf("Instr at %p ($pc+0): %x   ", (char*)TRAPF_PC(framePtr) + 0, context_instr);
		db_disasm((db_addr_t)&context_instr, 0);
		fetch_instr_near_pc(framePtr, 4, &context_instr);
		db_printf("Instr at %p ($pc+4): %x   ", (char*)TRAPF_PC(framePtr) + 4, context_instr);
		db_disasm((db_addr_t)&context_instr, 0);
#endif

		/* retAddr = instPC + 4;  */
		/* log registers in trap frame */
		log_frame_dump(framePtr);
#ifdef CPU_CHERI
		if (log_cheri_registers)
			cheri_log_exception_registers(framePtr);
#endif
#ifdef DDB
		kdb_enter(KDB_WHY_CHERI, "BAD OPCODE in MipsEmulateBranch");
#endif
		/* Return to NULL to force a crash in the user program */
		retAddr = 0;
	}
	return (trapf_pc_t)(retAddr);
}

static void
log_frame_dump(struct trapframe *frame)
{

	/*
	 * Stop QEMU instruction tracing when we hit an exception
	 */
	if (stop_vm_trace_on_fault)
		__asm__ __volatile__("li $0, 0xdead");

	printf("Trapframe Register Dump:\n");
	printf("$0: %#-18jx at: %#-18jx v0: %#-18jx v1: %#-18jx\n",
	    (intmax_t)0, (intmax_t)frame->ast, (intmax_t)frame->v0, (intmax_t)frame->v1);

	printf("a0: %#-18jx a1: %#-18jx a2: %#-18jx a3: %#-18jx\n",
	    (intmax_t)frame->a0, (intmax_t)frame->a1, (intmax_t)frame->a2, (intmax_t)frame->a3);

#if defined(__mips_n32) || defined(__mips_n64)
	printf("a4: %#-18jx a5: %#-18jx a6: %#-18jx a7: %#-18jx\n",
	    (intmax_t)frame->a4, (intmax_t)frame->a5, (intmax_t)frame->a6, (intmax_t)frame->a7);

	printf("t0: %#-18jx t1: %#-18jx t2: %#-18jx t3: %#-18jx\n",
	    (intmax_t)frame->t0, (intmax_t)frame->t1, (intmax_t)frame->t2, (intmax_t)frame->t3);
#else
	printf("t0: %#-18jx t1: %#-18jx t2: %#-18jx t3: %#-18jx\n",
	    (intmax_t)frame->t0, (intmax_t)frame->t1, (intmax_t)frame->t2, (intmax_t)frame->t3);

	printf("t4: %#-18jx t5: %#-18jx t6: %#-18jx t7: %#-18jx\n",
	    (intmax_t)frame->t4, (intmax_t)frame->t5, (intmax_t)frame->t6, (intmax_t)frame->t7);
#endif
	printf("s0: %#-18jx s1: %#-18jx s2: %#-18jx s3: %#-18jx\n",
	    (intmax_t)frame->s0, (intmax_t)frame->s1, (intmax_t)frame->s2, (intmax_t)frame->s3);

	printf("s4: %#-18jx s5: %#-18jx s6: %#-18jx s7: %#-18jx\n",
	    (intmax_t)frame->s4, (intmax_t)frame->s5, (intmax_t)frame->s6, (intmax_t)frame->s7);

	printf("t8: %#-18jx t9: %#-18jx k0: %#-18jx k1: %#-18jx\n",
	    (intmax_t)frame->t8, (intmax_t)frame->t9, (intmax_t)frame->k0, (intmax_t)frame->k1);

	printf("gp: %#-18jx sp: %#-18jx s8: %#-18jx ra: %#-18jx\n",
	    (intmax_t)frame->gp, (intmax_t)frame->sp, (intmax_t)frame->s8, (intmax_t)frame->ra);

	printf("status: %#jx mullo: %#jx; mulhi: %#jx; badvaddr: %#jx\n",
	    (intmax_t)frame->sr, (intmax_t)frame->mullo, (intmax_t)frame->mulhi, (intmax_t)frame->badvaddr);

	printf("cause: %#jx; pc: %#jx\n",
	    (intmax_t)(uint32_t)frame->cause, (intmax_t)TRAPF_PC(frame));

#if 0
	/* XXXAR: this can KASSERT() for bad instruction fetches. See #276 */
	if (frame->badinstr.inst == 0)
		fetch_bad_instr(frame);
#endif
	if (frame->badinstr.inst != 0) {
		printf("BadInstr: %#x ", frame->badinstr.inst);
#ifdef DDB
		db_disasm((db_addr_t)&frame->badinstr.inst, 0);
#else
		printf("\n");
#endif
	}

	if (DELAYBRANCH(frame->cause)) {
#if 0
		/* XXXAR: this can KASSERT() for bad instruction fetches. See #276 */
		if (frame->badinstr_p.inst == 0)
			fetch_bad_branch_instr(frame);
#endif
		if (frame->badinstr_p.inst != 0) {
			printf("BadInstrP: %#x ", frame->badinstr_p.inst);
#ifdef DDB
			db_disasm((db_addr_t)&frame->badinstr_p.inst, 0);
#else
			printf("\n");
#endif
		}
	}
}

#ifdef TRAP_DEBUG
static void
trap_frame_dump(struct trapframe *frame)
{
	printf("Trapframe Register Dump:\n");
	printf("\tzero: %#jx\tat: %#jx\tv0: %#jx\tv1: %#jx\n",
	    (intmax_t)0, (intmax_t)frame->ast, (intmax_t)frame->v0, (intmax_t)frame->v1);

	printf("\ta0: %#jx\ta1: %#jx\ta2: %#jx\ta3: %#jx\n",
	    (intmax_t)frame->a0, (intmax_t)frame->a1, (intmax_t)frame->a2, (intmax_t)frame->a3);
#if defined(__mips_n32) || defined(__mips_n64)
	printf("\ta4: %#jx\ta5: %#jx\ta6: %#jx\ta7: %#jx\n",
	    (intmax_t)frame->a4, (intmax_t)frame->a5, (intmax_t)frame->a6, (intmax_t)frame->a7);

	printf("\tt0: %#jx\tt1: %#jx\tt2: %#jx\tt3: %#jx\n",
	    (intmax_t)frame->t0, (intmax_t)frame->t1, (intmax_t)frame->t2, (intmax_t)frame->t3);
#else
	printf("\tt0: %#jx\tt1: %#jx\tt2: %#jx\tt3: %#jx\n",
	    (intmax_t)frame->t0, (intmax_t)frame->t1, (intmax_t)frame->t2, (intmax_t)frame->t3);

	printf("\tt4: %#jx\tt5: %#jx\tt6: %#jx\tt7: %#jx\n",
	    (intmax_t)frame->t4, (intmax_t)frame->t5, (intmax_t)frame->t6, (intmax_t)frame->t7);
#endif
	printf("\tt8: %#jx\tt9: %#jx\ts0: %#jx\ts1: %#jx\n",
	    (intmax_t)frame->t8, (intmax_t)frame->t9, (intmax_t)frame->s0, (intmax_t)frame->s1);

	printf("\ts2: %#jx\ts3: %#jx\ts4: %#jx\ts5: %#jx\n",
	    (intmax_t)frame->s2, (intmax_t)frame->s3, (intmax_t)frame->s4, (intmax_t)frame->s5);

	printf("\ts6: %#jx\ts7: %#jx\tk0: %#jx\tk1: %#jx\n",
	    (intmax_t)frame->s6, (intmax_t)frame->s7, (intmax_t)frame->k0, (intmax_t)frame->k1);

	printf("\tgp: %#jx\tsp: %#jx\ts8: %#jx\tra: %#jx\n",
	    (intmax_t)frame->gp, (intmax_t)frame->sp, (intmax_t)frame->s8, (intmax_t)frame->ra);

	printf("\tsr: %#jx\tmullo: %#jx\tmulhi: %#jx\tbadvaddr: %#jx\n",
	    (intmax_t)frame->sr, (intmax_t)frame->mullo, (intmax_t)frame->mulhi, (intmax_t)frame->badvaddr);

	printf("\tcause: %#jx\tpc: %#jx\n",
	    (intmax_t)(uint32_t)frame->cause, (intmax_t)TRAPF_PC(frame));
}

#endif

static void
get_mapping_info(vm_offset_t va, pd_entry_t **pdepp, pt_entry_t **ptepp)
{
	pt_entry_t *ptep;
	pd_entry_t *pdep;
	struct proc *p = curproc;

	pdep = (&(p->p_vmspace->vm_pmap.pm_segtab[(va >> SEGSHIFT) & (NPDEPG - 1)]));
	if (*pdep)
		ptep = pmap_pte(&p->p_vmspace->vm_pmap, va);
	else
		ptep = (pt_entry_t *)0;

	*pdepp = pdep;
	*ptepp = ptep;
}

static void
log_illegal_instruction(const char *msg, struct trapframe *frame)
{
	pt_entry_t *ptep;
	pd_entry_t *pdep;
#ifndef CPU_CHERI
	unsigned int *addr, instr[4];
#endif
	struct thread *td;
	struct proc *p;
	register_t pc;

	td = curthread;
	p = td->td_proc;

#ifdef SMP
	printf("cpuid = %d\n", PCPU_GET(cpuid));
#endif
	pc = TRAPF_PC(frame) + (DELAYBRANCH(frame->cause) ? 4 : 0);
	log(LOG_ERR, "%s: pid %d tid %ld (%s), uid %d: pc %#jx ra %#jx\n",
	    msg, p->p_pid, (long)td->td_tid, p->p_comm,
	    p->p_ucred ? p->p_ucred->cr_uid : -1,
	    (intmax_t)pc,
	    (intmax_t)frame->ra);

	/* log registers in trap frame */
	log_frame_dump(frame);
#ifdef CPU_CHERI
	if (log_cheri_registers)
		cheri_log_exception_registers(frame);
#endif

	get_mapping_info((vm_offset_t)pc, &pdep, &ptep);

#ifndef CPU_CHERI
	/*
	 * Dump a few words around faulting instruction, if the addres is
	 * valid.
	 *
	 * XXXRW: Temporarily disabled in CHERI as this doesn't properly
	 * indirect through $c0 / $pcc.
	 */
	addr = (unsigned int *)(intptr_t)pc;
	if ((pc & 3) == 0 && copyin(addr, instr, sizeof(instr)) == 0) {
		/* dump page table entry for faulting instruction */
		log(LOG_ERR, "Page table info for pc address %#jx: pde = %p, pte = %#jx\n",
		    (intmax_t)pc, (void *)(intptr_t)*pdep, (uintmax_t)(ptep ? *ptep : 0));

		log(LOG_ERR, "Dumping 4 words starting at pc address %p: \n",
		    addr);
		log(LOG_ERR, "%08x %08x %08x %08x\n",
		    instr[0], instr[1], instr[2], instr[3]);
	} else {
		log(LOG_ERR, "pc address %#jx is inaccessible, pde = %p, pte = %#jx\n",
		    (intmax_t)pc, (void *)(intptr_t)*pdep, (uintmax_t)(ptep ? *ptep : 0));
	}
#endif
}

static void
log_bad_page_fault(char *msg, struct trapframe *frame, int trap_type)
{
	pt_entry_t *ptep;
	pd_entry_t *pdep;
#ifndef CPU_CHERI
	unsigned int *addr, instr[4];
#endif
	struct thread *td;
	struct proc *p;
	char *read_or_write;
	register_t pc;

	if (!log_bad_page_faults)
		return;

	trap_type &= ~T_USER;

	td = curthread;
	p = td->td_proc;

#ifdef SMP
	printf("cpuid = %d\n", PCPU_GET(cpuid));
#endif
	switch (trap_type) {
	case T_TLB_MOD:
	case T_TLB_ST_MISS:
	case T_ADDR_ERR_ST:
		read_or_write = "write";
		break;
	case T_TLB_LD_MISS:
	case T_ADDR_ERR_LD:
	case T_BUS_ERR_IFETCH:
		read_or_write = "read";
		break;
	default:
		read_or_write = "unknown";
	}

	pc = TRAPF_PC(frame) + (DELAYBRANCH(frame->cause) ? 4 : 0);
	log(LOG_ERR, "%s: pid %d tid %ld (%s), uid %d: pc %#jx got a %s fault "
	    "(type %#x) at %#jx\n",
	    msg, p->p_pid, (long)td->td_tid, p->p_comm,
	    p->p_ucred ? p->p_ucred->cr_uid : -1,
	    (intmax_t)pc,
	    read_or_write,
	    trap_type,
	    (intmax_t)frame->badvaddr);

	/* log registers in trap frame */
	log_frame_dump(frame);
#ifdef CPU_CHERI
	if (log_cheri_registers)
		cheri_log_exception_registers(frame);
#endif


	get_mapping_info((vm_offset_t)pc, &pdep, &ptep);

#ifndef CPU_CHERI
	/*
	 * Dump a few words around faulting instruction, if the address is
	 * valid.
	 *
	 * XXXRW: Temporarily disabled in CHERI as this doesn't properly
	 * indirect through $c0 / $pcc.
	 */
	addr = (unsigned int *)(intptr_t)pc;
	if ((pc & 3) == 0 && pc != frame->badvaddr &&
	    trap_type != T_BUS_ERR_IFETCH &&
	    copyin((caddr_t)(intptr_t)pc, instr, sizeof(instr)) == 0) {
		/* dump page table entry for faulting instruction */
		log(LOG_ERR, "Page table info for pc address %#jx: pde = %p, pte = %#jx\n",
		    (intmax_t)pc, (void *)(intptr_t)*pdep, (uintmax_t)(ptep ? *ptep : 0));

		log(LOG_ERR, "Dumping 4 words starting at pc address %p: \n",
		    addr);
		log(LOG_ERR, "%08x %08x %08x %08x\n",
		    instr[0], instr[1], instr[2], instr[3]);
	} else {
		log(LOG_ERR, "pc address %#jx is inaccessible, pde = %p, pte = %#jx\n",
		    (intmax_t)pc, (void *)(intptr_t)*pdep, (uintmax_t)(ptep ? *ptep : 0));
	}
#endif

	get_mapping_info((vm_offset_t)frame->badvaddr, &pdep, &ptep);
	log(LOG_ERR, "Page table info for bad address %#jx: pde = %p, pte = %#jx\n",
	    (intmax_t)frame->badvaddr, (void *)(intptr_t)*pdep, (uintmax_t)(ptep ? *ptep : 0));
}

#ifdef CPU_CHERI
/*
 * XXXRW: Possibly this should actually be a CHERI-independent logging
 * function, in which case only the CHERI-specific parts should be ifdef'd.
 */
static void
log_c2e_exception(const char *msg, struct trapframe *frame, int trap_type)
{

#ifdef SMP
	printf("cpuid = %d\n", PCPU_GET(cpuid));
#endif
	log(LOG_ERR, "%s: pid %d tid %ld (%s), uid %d: CP2 fault "
	    "(type %#x)\n",
	    msg, curproc->p_pid, (long)curthread->td_tid, curproc->p_comm,
	    curproc->p_ucred ? curproc->p_ucred->cr_uid : -1,
	    trap_type);
	/* Also print argv to help debugging */
	if (curproc->p_args) {
		char* args = curproc->p_args->ar_args;
		unsigned len = curproc->p_args->ar_length;
		log(LOG_ERR, "Process arguments: ");
		for (unsigned i = 0; i < len; i++) {
			if (args[i] == '\0')
				log(LOG_ERR, " ");
			else
				log(LOG_ERR, "%c", args[i]);
		}
		log(LOG_ERR, "\n");
	}


	/* log registers in trap frame */
	log_frame_dump(frame);
	cheri_log_exception(frame, trap_type);
}
#endif

/*
 * Unaligned load/store emulation
 */
static int
mips_unaligned_load_store(struct trapframe *frame, int mode, register_t addr, uint32_t inst)
{
	register_t *reg = (register_t *) frame;
	register_t value = 0;
	unsigned size;
	int src_regno;
	int op_type = 0;
	int is_store = 0;
	int sign_extend = 0;
#ifdef CPU_CHERI
	/**
	 * XXX: There is a potential race condition here for CHERI.  We rely on the
	 * fact that the ALIGNMENT_FIX_ERR exception has a lower priority than any
	 * of the CHERI exceptions to guarantee that the load or store should have
	 * succeeded, but a malicious program could generate an alignment trap and
	 * then substitute a different instruction...
	 */
#endif
	src_regno = MIPS_INST_RT(inst);

	/*
	 * ADDR_ERR faults have higher priority than TLB
	 * Miss faults.  Therefore, it is necessary to
	 * verify that the faulting address is a valid
	 * virtual address within the process' address space
	 * before trying to emulate the unaligned access.
	 */
	switch (MIPS_INST_OPCODE(inst)) {
#ifdef CPU_CHERI
	/*
	 * If there's an alignment error on a capability, then just fail.  It might
	 * be nice to emulate these and assume that the tag bit is unset, but for
	 * now we'll just let them fail as they probably indicate bugs.
	 */
	case OP_JALX:
	case OP_COP2: /* TODO: assert that it is a cjr/cjalr instruction */
	case OP_SDC2: case OP_LDC2:
		cheri_log_exception(frame, 0);
		return (0);
	/*
	 * If it's a capability load or store, then the last three bits indicate
	 * the size and extension, except that CLLD and CSCD (capability-relative
	 * load-linked and store-conditional on doublewords set all three low
	 * bits).  In all other cases, the low two bits are the base-2 log of the
	 * size of the operation.
	 */
	case OP_SWC2:
		is_store = 1;
	case OP_LWC2: {
		src_regno = MIPS_INST_RS(inst);
		u_int32_t fmt = inst & 7;
		u_int32_t size_field = inst & 3;
		KASSERT((size_field != 0),
			("Unaligned byte loads or stores should be impossible"));
		/*
		 * If this is a load-linked / store-conditional then we can't
		 * safely emulate it.
		 */
		if (fmt == 7)
			return (0);
		size = 1 << size_field;
		/* Bit 2 distinguishes signed / unsigned operations */
		sign_extend = fmt >> 2;
		if (MIPS_INST_OPCODE(inst) == OP_SWC2)
			op_type = MIPS_CHERI_CSB_ACCESS + fmt;
		else
			op_type = MIPS_CHERI_CLBU_ACCESS + fmt;
		break;
	}
#endif
	case OP_LH:
		sign_extend = 1;
	case OP_LHU:
		op_type = MIPS_LHU_ACCESS;
		size = 2;
		break;
	case OP_LW:
		sign_extend = 1;
	case OP_LWU:
		op_type = MIPS_LWU_ACCESS;
		size = 4;
		break;
	case OP_LD:
		op_type = MIPS_LD_ACCESS;
		size = 8;
		break;
	case OP_SH:
		op_type = MIPS_SH_ACCESS;
		is_store = 1;
		size = 2;
		break;
	case OP_SW:
		op_type = MIPS_SW_ACCESS;
		is_store = 1;
		size = 4;
		break;
	case OP_SD:
		op_type = MIPS_SD_ACCESS;
		is_store = 1;
		size = 8;
		break;
	/*
	 * We can't safely fix up LL/SC, so just give up and deliver the signal.
	 */
	case OP_SCD: case OP_SC: case OP_LLD: case OP_LL:
		return (0);
	default:
		printf("%s: unhandled opcode in address error: %#x\n", __func__, inst);
		return (0);
	}
	/* Fix up the op_type for unsigned versions */
	if ((op_type < MIPS_LD_ACCESS) && sign_extend)
		op_type++;

	if (is_store) {
		value = reg[src_regno];
		/*
		 * Stores don't have signed / unsigned variants, so just copy
		 * the data from the register to memory.  Less-than-doubleword
		 * stores store the low bits, so adjust the kernel pointer to
		 * the correct offset within the word first.
		 */
		char *kaddr = (char*)&value;
#if _BYTE_ORDER == _BIG_ENDIAN
		kaddr += sizeof(register_t) - size;
#endif
		int err;
		if ((err = copyout_implicit_cap(kaddr, (void*)addr, size))) {
			return (0);
		}
		return (op_type);
	} else {
		/* Get the value as a zero-extended version */
		value = 0;
		char *kaddr = (char*)&value;
#if _BYTE_ORDER == _BIG_ENDIAN
		kaddr += sizeof(register_t) - size;
#endif
		int err;
		if ((err = copyin_implicit_cap((void*)addr, kaddr, size))) {
			return (0);
		}
		/* If we need to sign extend it, then shift it so that the sign
		 * bit is in the correct place and then shift it back. */
		if (sign_extend) {
			int shift = (sizeof(register_t) - size) * 8;
			value = (value << shift) >> shift;
		}
		reg[src_regno] = value;
		return (op_type);
	}
	panic("%s: should not be reached.", __func__);
}

/*
 * XXX TODO: SMP?
 */
static struct timeval unaligned_lasterr;
static int unaligned_curerr;

static int unaligned_pps_log_limit = 0;

SYSCTL_INT(_machdep, OID_AUTO, unaligned_log_pps_limit, CTLFLAG_RWTUN,
    &unaligned_pps_log_limit, 0,
    "limit number of userland unaligned log messages per second");

static int
emulate_unaligned_access(struct trapframe *frame, int mode)
{
	register_t pc;
	int access_type = 0;
	struct thread *td = curthread;
	struct proc *p = curproc;

	pc = TRAPF_PC(frame) + (DELAYBRANCH(frame->cause) ? 4 : 0);

	/*
	 * Fall through if it's instruction fetch exception
	 */
	if (!((pc & 3) || (pc == frame->badvaddr))) {
		/*
		 * Handle unaligned load and store
		 */

		/*
		 * Return access type if the instruction was emulated.
		 * Otherwise restore pc and fall through.
		 */
		fetch_bad_instr(frame);
		access_type = mips_unaligned_load_store(frame,
		    mode, frame->badvaddr, frame->badinstr.inst);

		if (access_type) {
			if (DELAYBRANCH(frame->cause)) {
				fetch_bad_branch_instr(frame);
				frame->pc = MipsEmulateBranch(frame, frame->pc,
				    0, &frame->badinstr_p.inst);
			} else {
				TRAPF_PC_INCREMENT(frame, sizeof(int));
			}

			if (ppsratecheck(&unaligned_lasterr,
			    &unaligned_curerr, unaligned_pps_log_limit)) {
				/* XXX TODO: keep global/tid/pid counters? */
				log(LOG_INFO,
				    "Unaligned %s: pid=%ld (%s), tid=%ld, "
				    "pc=%#jx, badvaddr=%#jx\n",
				    access_name[access_type - 1],
				    (long) p->p_pid,
				    p->p_comm,
				    (long) td->td_tid,
				    (intmax_t)pc,
				    (intmax_t)frame->badvaddr);
			}
		}
	}
	return access_type;
}
// CHERI CHANGES START
// {
//   "updated": 20181114,
//   "target_type": "kernel",
//   "changes": [
//     "support"
//   ],
//   "change_comment": ""
// }
// CHERI CHANGES END
