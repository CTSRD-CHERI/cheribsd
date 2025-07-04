/*-
 * Copyright (c) 2015-2018 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * Portions of this software were developed by SRI International and the
 * University of Cambridge Computer Laboratory under DARPA/AFRL contract
 * FA8750-10-C-0237 ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Portions of this software were developed by the University of Cambridge
 * Computer Laboratory as part of the CTSRD Project, with support from the
 * UK Higher Education Innovation Fund (HEIF).
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
#include "opt_ddb.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/intr.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/sysent.h>
#ifdef KDB
#include <sys/kdb.h>
#endif

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_param.h>
#include <vm/vm_extern.h>

#if __has_feature(capabilities)
#include <sys/sysargmap.h>
#include <cheri/cheric.h>
#ifdef CHERI_CAPREVOKE
#include <vm/vm_cheri_revoke.h>
#endif
#endif

#include <machine/fpe.h>
#include <machine/frame.h>
#include <machine/pcb.h>
#include <machine/pcpu.h>

#include <machine/resource.h>

#ifdef KDTRACE_HOOKS
#include <sys/dtrace_bsd.h>
#endif

#ifdef DDB
#include <ddb/ddb.h>
#include <ddb/db_sym.h>
#endif

#if __has_feature(capabilities)
int log_user_cheri_exceptions = 0;
SYSCTL_INT(_machdep, OID_AUTO, log_user_cheri_exceptions, CTLFLAG_RWTUN,
    &log_user_cheri_exceptions, 0,
    "Print registers and process details on user CHERI exceptions");
#endif

int (*dtrace_invop_jump_addr)(struct trapframe *);

#ifdef CPU_QEMU_RISCV
extern u_int qemu_trace_buffered;
#endif

/* Called from exception.S */
void do_trap_supervisor(struct trapframe *);
void do_trap_user(struct trapframe *);

static __inline void
call_trapsignal(struct thread *td, int sig, int code, uintcap_t addr,
    int trapno, int capreg)
{
	ksiginfo_t ksi;

#ifdef CPU_QEMU_RISCV
	if (qemu_trace_buffered)
		QEMU_FLUSH_TRACE_BUFFER;
#endif

	ksiginfo_init_trap(&ksi);
	ksi.ksi_signo = sig;
	ksi.ksi_code = code;
	ksi.ksi_addr = (void * __capability)addr;
	ksi.ksi_capreg = capreg;
	ksi.ksi_trapno = trapno;
	trapsignal(td, &ksi);
}

int
cpu_fetch_syscall_args(struct thread *td)
{
	struct proc *p;
	syscallarg_t *ap, *dst_ap;
	struct syscall_args *sa;
#if __has_feature(capabilities)
	char * __capability stack_args = NULL;
	u_int i;
	int error;
#endif

	p = td->td_proc;
	sa = &td->td_sa;
	ap = &td->td_frame->tf_a[0];
	dst_ap = &sa->args[0];

	sa->code = td->td_frame->tf_t[0];
	sa->original_code = sa->code;

	if (__predict_false(sa->code == SYS_syscall || sa->code == SYS___syscall)) {
		sa->code = *ap++;

#if __has_feature(capabilities)
		/*
		 * For syscall() and __syscall(), the arguments are
		 * stored in a var args block on the stack.
		 */
		if (SV_PROC_FLAG(td->td_proc, SV_CHERI))
			stack_args = (char * __capability)td->td_frame->tf_sp;
#endif
	} else {
		*dst_ap++ = *ap++;
	}

	if (__predict_false(sa->code >= p->p_sysent->sv_size))
		sa->callp = &nosys_sysent;
	else
		sa->callp = &p->p_sysent->sv_table[sa->code];

	KASSERT(sa->callp->sy_narg <= nitems(sa->args),
	    ("Syscall %d takes too many arguments", sa->code));

#if __has_feature(capabilities)
	if (__predict_false(stack_args != NULL)) {
		register_t intval;
		int offset, ptrmask;

		if (sa->code >= nitems(sysargmask))
			ptrmask = 0;
		else
			ptrmask = sysargmask[sa->code];

		offset = 0;
		for (i = 0; i < sa->callp->sy_narg; i++) {
			if (ptrmask & (1 << i)) {
				offset = roundup2(offset, sizeof(uintcap_t));
				error = fuecap(stack_args + offset,
				    dst_ap);
				offset += sizeof(uintcap_t);
			} else {
				error = fueword(stack_args + offset, &intval);
				*dst_ap = intval;
				offset += sizeof(intval);
			}
			dst_ap++;
			if (error)
				return (error);
		}
	} else
#endif
	{
		memcpy(dst_ap, ap, (NARGREG - 1) * sizeof(*dst_ap));
	}

	td->td_retval[0] = 0;
	td->td_retval[1] = 0;

	return (0);
}

#include "../../kern/subr_syscall.c"

#if __has_feature(capabilities)
#define	CREG	"c"
#else
#define	CREG
#endif

static void
print_with_symbol(const char *name, uintcap_t value)
{
#ifdef DDB
	c_db_sym_t sym;
	db_expr_t sym_value;
	db_expr_t offset;
	const char *sym_name;
#endif

#if __has_feature(capabilities)
	printf("%7s: %#.16lp", name, (void * __capability)value);
#else
	printf("%7s: 0x%016lx", name, value);
#endif

#ifdef DDB
	if (value >= VM_MIN_KERNEL_ADDRESS) {
		sym = db_search_symbol(value, DB_STGY_ANY, &offset);
		if (sym != C_DB_SYM_NULL) {
			db_symbol_values(sym, &sym_name, &sym_value);
			if (offset != 0)
				printf(" (%s + 0x%lx)", sym_name, offset);
			else
				printf(" (%s)", sym_name);
		}
	}
#endif
	printf("\n");
}

static void
dump_regs(struct trapframe *frame)
{
	char name[6];
	u_int i;

	for (i = 0; i < nitems(frame->tf_t); i++) {
		snprintf(name, sizeof(name), CREG"t[%d]", i);
		print_with_symbol(name, frame->tf_t[i]);
	}

	for (i = 0; i < nitems(frame->tf_s); i++) {
		snprintf(name, sizeof(name), CREG"s[%d]", i);
		print_with_symbol(name, frame->tf_s[i]);
	}

	for (i = 0; i < nitems(frame->tf_a); i++) {
		snprintf(name, sizeof(name), CREG"a[%d]", i);
		print_with_symbol(name, frame->tf_a[i]);
	}

	print_with_symbol(CREG"ra", frame->tf_ra);
	print_with_symbol(CREG"sp", frame->tf_sp);
	print_with_symbol(CREG"gp", frame->tf_gp);
	print_with_symbol(CREG"tp", frame->tf_tp);
	print_with_symbol("sepc"CREG, frame->tf_sepc);
#if __has_feature(capabilities)
	print_with_symbol("ddc", frame->tf_ddc);
#endif
	printf("sstatus: 0x%016lx\n", frame->tf_sstatus);
	printf("stval  : 0x%016lx\n", frame->tf_stval);
}

#if __has_feature(capabilities)
static void
dump_cheri_exception(struct trapframe *frame)
{
	struct thread *td;
	struct proc *p;

	td = curthread;
	p = td->td_proc;
	printf("pid %d tid %d (%s), uid %d: ", p->p_pid, td->td_tid,
	    p->p_comm, td->td_ucred->cr_uid);
	switch (frame->tf_scause & SCAUSE_CODE) {
	case SCAUSE_LOAD_CAP_PAGE_FAULT:
		printf("LOAD CAP page fault");
		break;
	case SCAUSE_STORE_AMO_CAP_PAGE_FAULT:
		printf("STORE/AMO CAP page fault");
		break;
	case SCAUSE_CHERI:
		printf("CHERI fault (type %#lx), capidx %ld",
		    TVAL_CAP_CAUSE(frame->tf_stval),
		    TVAL_CAP_IDX(frame->tf_stval));
		break;
	default:
		printf("fault %ld", frame->tf_scause & SCAUSE_CODE);
		break;
	}
	printf("\n");
	if (p->p_args != NULL) {
		char *args;
		unsigned len;

		args = p->p_args->ar_args;
		len = p->p_args->ar_length;
		for (unsigned i = 0; i < len; i++) {
			if (args[i] == '\0')
				printf(" ");
			else
				printf("%c", args[i]);
		}
		printf("\n");
	}
	dump_regs(frame);
}
#endif

static void
ecall_handler(void)
{
	struct thread *td;

	td = curthread;

	syscallenter(td);
	syscallret(td);
}

static void
page_fault_handler(struct trapframe *frame, int usermode)
{
	struct vm_map *map;
	uint64_t stval;
	struct thread *td;
	struct pcb *pcb;
	vm_prot_t ftype;
	vm_offset_t va;
	struct proc *p;
	int error, sig, ucode;
#ifdef KDB
	bool handled;
#endif

#ifdef KDB
	if (kdb_active) {
		kdb_reenter();
		return;
	}
#endif

	td = curthread;
	p = td->td_proc;
	pcb = td->td_pcb;
	stval = frame->tf_stval;

	if (usermode) {
		if (!VIRT_IS_VALID(stval)) {
			call_trapsignal(td, SIGSEGV, SEGV_MAPERR, stval,
			    frame->tf_scause & SCAUSE_CODE, 0);
			goto done;
		}
		map = &p->p_vmspace->vm_map;
	} else {
		/*
		 * Enable interrupts for the duration of the page fault. For
		 * user faults this was done already in do_trap_user().
		 */
		if ((frame->tf_sstatus & SSTATUS_SIE) != 0)
			intr_enable();

		if (stval >= VM_MIN_KERNEL_ADDRESS) {
			map = kernel_map;
		} else {
			if (pcb->pcb_onfault == 0)
				goto fatal;
			map = &p->p_vmspace->vm_map;
		}
	}

	va = trunc_page(stval);

#ifdef CHERI_CAPREVOKE
	if ((frame->tf_scause == SCAUSE_LOAD_CAP_PAGE_FAULT) &&
	    (va < VM_MAX_USER_ADDRESS)) {
		if (vm_cheri_revoke_fault_visit(p->p_vmspace, va) ==
		    VM_CHERI_REVOKE_FAULT_RESOLVED)
			goto done;
		else {
			/*
			 * vm_cheri_revoke_fault_visit calls
			 * pmap_caploadgen_update, so if it's left us
			 * UNRESOLVED, then there's no point in trying the pmap
			 * again.
			 */
			ftype = VM_PROT_READ | VM_PROT_READ_CAP;
			goto skip_pmap;
		}
	}
#endif

	if (frame->tf_scause == SCAUSE_STORE_PAGE_FAULT) {
		ftype = VM_PROT_WRITE;
	} else if (frame->tf_scause == SCAUSE_INST_PAGE_FAULT) {
		ftype = VM_PROT_EXECUTE;
#if __has_feature(capabilities)
	} else if (frame->tf_scause == SCAUSE_STORE_AMO_CAP_PAGE_FAULT) {
		ftype = VM_PROT_WRITE | VM_PROT_WRITE_CAP;
	} else if (frame->tf_scause == SCAUSE_LOAD_CAP_PAGE_FAULT) {
		ftype = VM_PROT_READ | VM_PROT_READ_CAP;
#endif
	} else {
		ftype = VM_PROT_READ;
	}

	if (VIRT_IS_VALID(va) && pmap_fault(map->pmap, va, ftype))
		goto done;

#ifdef CHERI_CAPREVOKE
skip_pmap:
#endif
	if (td->td_critnest != 0 || td->td_intr_nesting_level != 0 ||
	    WITNESS_CHECK(WARN_SLEEPOK | WARN_GIANTOK, NULL,
	    "Kernel page fault") != 0)
		goto fatal;

	error = vm_fault_trap(map, va, ftype, VM_FAULT_NORMAL, &sig, &ucode);
	if (error != KERN_SUCCESS) {
		if (usermode) {
			call_trapsignal(td, sig, ucode, stval,
			    frame->tf_scause & SCAUSE_CODE, 0);
		} else {
			if (pcb->pcb_onfault != 0) {
				frame->tf_a[0] = error;
#if __has_feature(capabilities) && !defined(__CHERI_PURE_CAPABILITY__)
				frame->tf_sepc = cheri_setaddress(
				    frame->tf_sepc, pcb->pcb_onfault);
#else
				frame->tf_sepc = pcb->pcb_onfault;
#endif
				return;
			}
			goto fatal;
		}
	}

done:
	if (usermode)
		userret(td, frame);
	return;

fatal:
	dump_regs(frame);
#ifdef KDB
	if (debugger_on_trap) {
		kdb_why = KDB_WHY_TRAP;
		handled = kdb_trap(frame->tf_scause & SCAUSE_CODE, 0, frame);
		kdb_why = KDB_WHY_UNSET;
		if (handled)
			return;
	}
#endif
	panic("Fatal page fault at %#lx: %#lx", (unsigned long)frame->tf_sepc,
	    stval);
}

void
do_trap_supervisor(struct trapframe *frame)
{
	uint64_t exception;

	/* Ensure we came from supervisor mode, interrupts disabled */
	KASSERT((csr_read(sstatus) & (SSTATUS_SPP | SSTATUS_SIE)) ==
	    SSTATUS_SPP, ("Came from S mode with interrupts enabled"));

	KASSERT((csr_read(sstatus) & (SSTATUS_SUM)) == 0,
	    ("Came from S mode with SUM enabled"));

	exception = frame->tf_scause & SCAUSE_CODE;
	if ((frame->tf_scause & SCAUSE_INTR) != 0) {
		/* Interrupt */
		intr_irq_handler(frame, INTR_ROOT_IRQ);
		return;
	}

#ifdef KDTRACE_HOOKS
	if (dtrace_trap_func != NULL && (*dtrace_trap_func)(frame, exception))
		return;
#endif

	CTR4(KTR_TRAP, "%s: exception=%lu, sepc=%#lx, stval=%#lx", __func__,
	    exception, (unsigned long)frame->tf_sepc, frame->tf_stval);

	switch (exception) {
	case SCAUSE_LOAD_ACCESS_FAULT:
	case SCAUSE_STORE_ACCESS_FAULT:
	case SCAUSE_INST_ACCESS_FAULT:
		dump_regs(frame);
		panic("Memory access exception at %#lx: %#lx",
		    (unsigned long)frame->tf_sepc, frame->tf_stval);
		break;
	case SCAUSE_LOAD_MISALIGNED:
	case SCAUSE_STORE_MISALIGNED:
	case SCAUSE_INST_MISALIGNED:
		dump_regs(frame);
		panic("Misaligned address exception at %#lx: %#lx",
		    (unsigned long)frame->tf_sepc, frame->tf_stval);
		break;
	case SCAUSE_STORE_PAGE_FAULT:
	case SCAUSE_LOAD_PAGE_FAULT:
	case SCAUSE_INST_PAGE_FAULT:
#if __has_feature(capabilities)
	case SCAUSE_STORE_AMO_CAP_PAGE_FAULT:
#endif
		page_fault_handler(frame, 0);
		break;
	case SCAUSE_BREAKPOINT:
#ifdef KDTRACE_HOOKS
		if (dtrace_invop_jump_addr != NULL &&
		    dtrace_invop_jump_addr(frame) == 0)
				break;
#endif
#ifdef KDB
		kdb_trap(exception, 0, frame);
#else
		dump_regs(frame);
		panic("No debugger in kernel.");
#endif
		break;
	case SCAUSE_ILLEGAL_INSTRUCTION:
		dump_regs(frame);
		panic("Illegal instruction 0x%0*lx at %#lx",
		    (frame->tf_stval & 0x3) != 0x3 ? 4 : 8,
		    frame->tf_stval, (unsigned long)frame->tf_sepc);
		break;
#if __has_feature(capabilities)
	case SCAUSE_CHERI:
		if (curthread->td_pcb->pcb_onfault != 0) {
			frame->tf_a[0] = EPROT;
#ifndef __CHERI_PURE_CAPABILITY__
			frame->tf_sepc = cheri_setaddress(frame->tf_sepc,
			    curthread->td_pcb->pcb_onfault);
#else
			frame->tf_sepc = curthread->td_pcb->pcb_onfault;
#endif
			break;
		}
		dump_regs(frame);
		switch (exception) {
		default:
			panic("Fatal capability page fault %#016lx: %#016lx",
			    (unsigned long)frame->tf_sepc,
			    frame->tf_stval);
			break;
		case SCAUSE_CHERI:
		{
			u_int cap_cause = TVAL_CAP_CAUSE(frame->tf_stval);
			u_int cap_idx = TVAL_CAP_IDX(frame->tf_stval);

			panic("CHERI %s for %s at %#016lx\n",
			    cheri_exccode_string(cap_cause),
			    cheri_cap_idx_string(cap_idx),
			    (unsigned long)frame->tf_sepc);
			break;
		}
		}
#endif
	default:
		dump_regs(frame);
		panic("Unknown kernel exception %#lx trap value %#lx",
		    exception, frame->tf_stval);
	}
}

void
do_trap_user(struct trapframe *frame)
{
	uint64_t exception;
	struct thread *td;
	struct pcb *pcb;

	td = curthread;
	pcb = td->td_pcb;

	KASSERT(td->td_frame == frame,
	    ("%s: td_frame %p != frame %p", __func__, td->td_frame, frame));

	/* Ensure we came from usermode, interrupts disabled */
	KASSERT((csr_read(sstatus) & (SSTATUS_SPP | SSTATUS_SIE)) == 0,
	    ("Came from U mode with interrupts enabled"));

	KASSERT((csr_read(sstatus) & (SSTATUS_SUM)) == 0,
	    ("Came from U mode with SUM enabled"));

	exception = frame->tf_scause & SCAUSE_CODE;
	if ((frame->tf_scause & SCAUSE_INTR) != 0) {
		/* Interrupt */
		intr_irq_handler(frame, INTR_ROOT_IRQ);
		return;
	}
	intr_enable();

	CTR4(KTR_TRAP, "%s: exception=%lu, sepc=%#lx, stval=%#lx", __func__,
	    exception, (unsigned long)frame->tf_sepc, frame->tf_stval);

	switch (exception) {
	case SCAUSE_LOAD_ACCESS_FAULT:
	case SCAUSE_STORE_ACCESS_FAULT:
	case SCAUSE_INST_ACCESS_FAULT:
		call_trapsignal(td, SIGBUS, BUS_ADRERR, frame->tf_sepc,
		    exception, 0);
		userret(td, frame);
		break;
	case SCAUSE_LOAD_MISALIGNED:
	case SCAUSE_STORE_MISALIGNED:
	case SCAUSE_INST_MISALIGNED:
		call_trapsignal(td, SIGBUS, BUS_ADRALN, frame->tf_sepc,
		    exception, 0);
		userret(td, frame);
		break;
	case SCAUSE_STORE_PAGE_FAULT:
	case SCAUSE_LOAD_PAGE_FAULT:
	case SCAUSE_INST_PAGE_FAULT:
#if __has_feature(capabilities)
	case SCAUSE_STORE_AMO_CAP_PAGE_FAULT:
	case SCAUSE_LOAD_CAP_PAGE_FAULT:
#endif
		page_fault_handler(frame, 1);
		break;
	case SCAUSE_ECALL_USER:
		frame->tf_sepc += 4;	/* Next instruction */
		ecall_handler();
		break;
	case SCAUSE_ILLEGAL_INSTRUCTION:
		if ((pcb->pcb_fpflags & PCB_FP_STARTED) == 0) {
			/*
			 * May be a FPE trap. Enable FPE usage
			 * for this thread and try again.
			 */
			fpe_state_clear();
			frame->tf_sstatus &= ~SSTATUS_FS_MASK;
			frame->tf_sstatus |= SSTATUS_FS_CLEAN;
			pcb->pcb_fpflags |= PCB_FP_STARTED;
			break;
		}
		call_trapsignal(td, SIGILL, ILL_ILLTRP, frame->tf_sepc,
		    exception, 0);
		userret(td, frame);
		break;
	case SCAUSE_BREAKPOINT:
		call_trapsignal(td, SIGTRAP, TRAP_BRKPT, frame->tf_sepc,
		    exception, 0);
		userret(td, frame);
		break;
#if __has_feature(capabilities)
	case SCAUSE_CHERI:
		if (log_user_cheri_exceptions)
			dump_cheri_exception(frame);

		/*
		 * User accesses to invalid addresses in a compat64
		 * process raise SIGSEGV under a non-CHERI kernel via
		 * a page fault exception.  With CHERI however, those
		 * accesses can raise a capability abort if they are
		 * outside the bounds of the user DDC.  Map those
		 * accesses to SIGSEGV instead of SIGPROT.
		 */
		if (!SV_PROC_FLAG(td->td_proc, SV_CHERI) &&
		    TVAL_CAP_CAUSE(frame->tf_stval) == CHERI_EXCCODE_LENGTH) {
			if (TVAL_CAP_IDX(frame->tf_stval) == 32 /* PCC */ &&
			    cheri_getbase(frame->tf_sepc) ==
			    CHERI_CAP_USER_DATA_BASE &&
			    cheri_getlen(frame->tf_sepc) ==
			    CHERI_CAP_USER_DATA_LENGTH) {
				call_trapsignal(td, SIGSEGV, SEGV_MAPERR,
				    (ptraddr_t)frame->tf_sepc,
				    SCAUSE_INST_PAGE_FAULT, 0);
				userret(td, frame);
				break;
			}

			/*
			 * To fully mimic SIGSEGV, this would need to
			 * decode the instruction to compute the
			 * effective faulting address and access type
			 * (R/W) to determine the non-CHERI exception
			 * that would have been raised.
			 */
			if (TVAL_CAP_IDX(frame->tf_stval) == 33 /* DDC */ &&
			    cheri_getbase(frame->tf_ddc) ==
			    CHERI_CAP_USER_DATA_BASE &&
			    cheri_getlen(frame->tf_ddc) ==
			    CHERI_CAP_USER_DATA_LENGTH) {
				call_trapsignal(td, SIGSEGV, SEGV_MAPERR,
				    0 /* XXX */,
				    SCAUSE_LOAD_PAGE_FAULT /* XXX */, 0);
				userret(td, frame);
				break;
			}
		}

		call_trapsignal(td, SIGPROT,
		    cheri_stval_to_sicode(frame->tf_stval), frame->tf_sepc,
		    exception, TVAL_CAP_IDX(frame->tf_stval));
		userret(td, frame);
		break;
#endif
	default:
		dump_regs(frame);
		panic("Unknown userland exception %#lx, trap value %#lx",
		    exception, frame->tf_stval);
	}
}
/*
 * CHERI CHANGES START
 * {
 *   "updated": 20230509,
 *   "target_type": "kernel",
 *   "changes": [
 *     "support"
 *   ]
 * }
 * CHERI CHANGES END
 */
