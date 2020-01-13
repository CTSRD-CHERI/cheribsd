/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1992 Terrence R. Lambert.
 * Copyright (c) 1982, 1987, 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * William Jolitz.
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
 *	from: @(#)machdep.c	7.4 (Berkeley) 6/3/91
 *	from: src/sys/i386/i386/machdep.c,v 1.385.2.3 2000/05/10 02:04:46 obrien
 *	JNPR: pm_machdep.c,v 1.9.2.1 2007/08/16 15:59:10 girish
 */

#define	EXPLICIT_USER_ACCESS

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_ddb.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysent.h>
#include <sys/proc.h>
#include <sys/signalvar.h>
#include <sys/elf.h>
#include <sys/exec.h>
#include <sys/ktr.h>
#include <sys/imgact.h>
#include <sys/ucontext.h>
#include <sys/lock.h>
#include <sys/syscallsubr.h>
#include <sys/sysproto.h>
#include <sys/ptrace.h>
#include <sys/syslog.h>
#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_extern.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <machine/abi.h>
#include <machine/cpuinfo.h>
#include <machine/reg.h>
#include <machine/md_var.h>
#include <machine/sigframe.h>
#include <machine/tls.h>
#include <machine/vmparam.h>
#include <machine/tls.h>
#include <sys/vnode.h>
#include <fs/pseudofs/pseudofs.h>
#include <fs/procfs/procfs.h>

#ifdef CPU_CHERI
#include <cheri/cheri.h>
#include <cheri/cheric.h>
#include <machine/cheri_machdep.h>
#endif

#include <ddb/ddb.h>
#include <sys/kdb.h>

#define	UCONTEXT_MAGIC	0xACEDBADE

/*
 * Send an interrupt to process.
 *
 * Stack is set up to allow sigcode stored
 * at top to call routine, followed by kcall
 * to sigreturn routine below.	After sigreturn
 * resets the signal mask, the stack, and the
 * frame pointer, it returns to the user
 * specified pc, psl.
 */
void
sendsig(sig_t catcher, ksiginfo_t *ksi, sigset_t *mask)
{
	struct proc *p;
	struct thread *td;
	struct trapframe *regs;
	struct sigacts *psp;
	struct sigframe sf, * __capability sfp;
	uintcap_t sp;
#if __has_feature(capabilities)
	int cheri_is_sandboxed;
#endif
	int sig;
	int oonstack;

	td = curthread;
	p = td->td_proc;
	PROC_LOCK_ASSERT(p, MA_OWNED);
	sig = ksi->ksi_signo;
	psp = p->p_sigacts;
	mtx_assert(&psp->ps_mtx, MA_OWNED);

	regs = td->td_frame;

#if __has_feature(capabilities)
	/*
	 * XXXRW: We make an on-stack determination using the virtual address
	 * associated with the stack pointer, rather than using the full
	 * capability.  Should we compare the entire capability...?  Just
	 * pointer and bounds...?
	 */
	oonstack = sigonstack((__cheri_addr vaddr_t)regs->csp);
#else
	oonstack = sigonstack(regs->sp);
#endif

#if __has_feature(capabilities)
	/*
	 * CHERI affects signal delivery in the following ways:
	 *
	 * (1) Additional capability-coprocessor state is exposed via
	 *     extensions to the context frame placed on the stack.
	 *
	 * (2) If the user $pcc doesn't include CHERI_PERM_SYSCALL, then we
	 *     consider user state to be 'sandboxed' and therefore to require
	 *     special delivery handling which includes a domain-switch to the
	 *     thread's context-switch domain.  (This is done by
	 *     hybridabi_sendsig()).
	 *
	 * (3) If an alternative signal stack is not defined, and we are in a
	 *     'sandboxed' state, then we have two choices: (a) if the signal
	 *     is of type SA_SANDBOX_UNWIND, we will automatically unwind the
	 *     trusted stack by one frame; (b) otherwise, we will terminate
	 *     the process unconditionally.
	 */
	cheri_is_sandboxed = cheri_signal_sandboxed(td);

	/*
	 * We provide the ability to drop into the debugger in two different
	 * circumstances: (1) if the code running is sandboxed; and (2) if the
	 * fault is a CHERI protection fault.  Handle both here for the
	 * non-unwind case.  Do this before we rewrite any general-purpose or
	 * capability register state for the thread.
	 */
#if DDB
	if (cheri_is_sandboxed && security_cheri_debugger_on_sandbox_signal)
		kdb_enter(KDB_WHY_CHERI, "Signal delivery to CHERI sandbox");
	else if (sig == SIGPROT && security_cheri_debugger_on_sigprot)
		kdb_enter(KDB_WHY_CHERI,
		    "SIGPROT delivered outside sandbox");
#endif

	/*
	 * If a thread is running sandboxed, we can't rely on $sp which may
	 * not point at a valid stack in the ambient context, or even be
	 * maliciously manipulated.  We must therefore always use the
	 * alternative stack.  We are also therefore unable to tell whether we
	 * are on the alternative stack, so must clear 'oonstack' here.
	 *
	 * XXXRW: This requires significant further thinking; however, the net
	 * upshot is that it is not a good idea to do an object-capability
	 * invoke() from a signal handler, as with so many other things in
	 * life.
	 */
	if (cheri_is_sandboxed != 0)
		oonstack = 0;
#endif

	/* save user context */
	bzero(&sf, sizeof(struct sigframe));
	sf.sf_uc.uc_sigmask = *mask;
	sf.sf_uc.uc_stack = td->td_sigstk;
	sf.sf_uc.uc_mcontext.mc_onstack = (oonstack) ? 1 : 0;
	sf.sf_uc.uc_mcontext.mc_pc = TRAPF_PC_OFFSET(regs);
	sf.sf_uc.uc_mcontext.mullo = regs->mullo;
	sf.sf_uc.uc_mcontext.mulhi = regs->mulhi;
	sf.sf_uc.uc_mcontext.mc_tls = td->td_md.md_tls;
	sf.sf_uc.uc_mcontext.mc_regs[0] = UCONTEXT_MAGIC;  /* magic number */
	bcopy((void *)&regs->ast, (void *)&sf.sf_uc.uc_mcontext.mc_regs[1],
	    sizeof(sf.sf_uc.uc_mcontext.mc_regs) - sizeof(register_t));
	sf.sf_uc.uc_mcontext.mc_fpused = td->td_md.md_flags & MDTD_FPUSED;
#if defined(CPU_HAVEFPU)
	if (sf.sf_uc.uc_mcontext.mc_fpused) {
		/* if FPU has current state, save it first */
		if (td == PCPU_GET(fpcurthread))
			MipsSaveCurFPState(td);
		bcopy((void *)&td->td_frame->f0,
		    (void *)sf.sf_uc.uc_mcontext.mc_fpregs,
		    sizeof(sf.sf_uc.uc_mcontext.mc_fpregs));
	}
#endif
	/* XXXRW: sf.sf_uc.uc_mcontext.sr seems never to be set? */
	sf.sf_uc.uc_mcontext.cause = regs->cause;
#if __has_feature(capabilities)
	cheri_trapframe_to_cheriframe(regs,
	    &sf.sf_uc.uc_mcontext.mc_cheriframe);
#endif

	/* Allocate and validate space for the signal handler context. */
	if ((td->td_pflags & TDP_ALTSTACK) != 0 && !oonstack &&
	    SIGISMEMBER(psp->ps_sigonstack, sig)) {
		sp = (uintcap_t)td->td_sigstk.ss_sp + td->td_sigstk.ss_size;
	} else {
#if __has_feature(capabilities)
		/*
		 * Signals delivered when a CHERI sandbox is present must be
		 * delivered on the alternative stack rather than a local one.
		 * If an alternative stack isn't present, then terminate or
		 * risk leaking capabilities (and control) to the sandbox (or
		 * just crashing the sandbox).
		 */
		if (cheri_is_sandboxed) {
			mtx_unlock(&psp->ps_mtx);
			printf("pid %d, tid %d: signal in sandbox without "
			    "alternative stack defined\n", td->td_proc->p_pid,
			    td->td_tid);
			sigexit(td, SIGILL);
			/* NOTREACHED */
		}
		sp = (uintcap_t)regs->csp;
#else
		sp = (vm_offset_t)regs->sp;
#endif
	}
	sp -= sizeof(struct sigframe);
	sp = __builtin_align_down(sp, STACK_ALIGN);
	sfp = (struct sigframe * __capability)sp;
#if __has_feature(capabilities)
	sfp = cheri_andperm(sfp, CHERI_CAP_USER_DATA_PERMS);
#endif

	/* Build the argument list for the signal handler. */
	regs->a0 = sig;
#if __has_feature(capabilities)
	regs->c3 = cheri_csetbounds(&sfp->sf_uc, sizeof(sfp->sf_uc));
#else
	regs->a2 = (register_t)(intptr_t)&sfp->sf_uc;
#endif
	if (SIGISMEMBER(psp->ps_siginfo, sig)) {
		/* Signal handler installed with SA_SIGINFO. */
#if __has_feature(capabilities)
		regs->c4 = regs->c3;
		regs->c3 = cheri_csetbounds(&sfp->sf_si, sizeof(sfp->sf_si));
#else
		regs->a1 = (register_t)(intptr_t)&sfp->sf_si;
#endif
		/* sf.sf_ahu.sf_action = (__siginfohandler_t *)catcher; */

		/* fill siginfo structure */
		sf.sf_si = ksi->ksi_info;
		sf.sf_si.si_signo = sig;
	} else {
		/* Old FreeBSD-style arguments. */
		regs->a1 = ksi->ksi_code;
#if __has_feature(capabilities)
		/*
		 * XXX: Should this strip tags?
		 */
		regs->c4 = ksi->ksi_addr;
#else
		regs->a3 = (uintptr_t)ksi->ksi_addr;
#endif
		/* sf.sf_ahu.sf_handler = catcher; */
	}

	mtx_unlock(&psp->ps_mtx);
	PROC_UNLOCK(p);

	/*
	 * Copy the sigframe out to the user's stack.
	 */
	if (copyoutcap(&sf, sfp, sizeof(sf)) != 0) {
		/*
		 * Something is wrong with the stack pointer.
		 * ...Kill the process.
		 */
		PROC_LOCK(p);
		printf("pid %d, tid %d: could not copy out sigframe\n",
		    td->td_proc->p_pid, td->td_tid);
		sigexit(td, SIGILL);
		/* NOTREACHED */
	}

#if __has_feature(capabilities)
	/*
	 * Install CHERI signal-delivery register state for handler to run
	 * in.  As we don't install this in the CHERI frame on the user stack,
	 * it will be (generally) be removed automatically on sigreturn().
	 */
	regs->pc = (trapf_pc_t)catcher;
	regs->c12 = regs->pc;
	regs->csp = sfp;
	regs->c17 = td->td_pcb->pcb_cherisignal.csig_sigcode;

	/*
	 * For now only change IDC if we were sandboxed. This makes cap-table
	 * binaries work as expected (since they need cgp to remain the same).
	 *
	 * TODO: remove csigp->csig_idc
	 */
	if (cheri_is_sandboxed) {
		regs->ddc = td->td_pcb->pcb_cherisignal.csig_ddc;
		regs->idc = td->td_pcb->pcb_cherisignal.csig_idc;
	}
#else
	regs->pc = (trapf_pc_t)catcher;
	regs->t9 = (register_t)(intptr_t)catcher;
	regs->sp = (register_t)(intptr_t)sfp;
	if (p->p_sysent->sv_sigcode_base != 0) {
		/* Signal trampoline code is in the shared page */
		regs->ra = p->p_sysent->sv_sigcode_base;
	} else {
		/* Signal trampoline code is at base of user stack. */
		/* XXX: GC this code path once shared page is stable */
		regs->ra = (register_t)(intptr_t)PS_STRINGS -
		    *(p->p_sysent->sv_szsigcode);
	}
#endif
	PROC_LOCK(p);
	mtx_lock(&psp->ps_mtx);
}

/*
 * System call to cleanup state after a signal
 * has been taken.  Reset signal mask and
 * stack state from context left by sendsig (above).
 * Return to previous pc as specified by
 * context left by sendsig.
 */
int
sys_sigreturn(struct thread *td, struct sigreturn_args *uap)
{
	ucontext_t uc;
	int error;

	error = copyincap(uap->sigcntxp, &uc, sizeof(uc));
	if (error != 0)
	    return (error);

	error = set_mcontext(td, &uc.uc_mcontext);
	if (error != 0)
		return (error);

	kern_sigprocmask(td, SIG_SETMASK, &uc.uc_sigmask, NULL, 0);

	return (EJUSTRETURN);
}

int
ptrace_set_pc(struct thread *td, unsigned long addr)
{

#ifdef CPU_CHERI
	if (td->td_proc && SV_PROC_FLAG(td->td_proc, SV_CHERI) &&
	    !cheri_is_address_inbounds(td->td_frame->pcc, addr))
		return (EINVAL);
#endif
	TRAPF_PC_SET_ADDR(td->td_frame, (vaddr_t)addr);
	return 0;
}

static int
ptrace_read_int(struct thread *td, uintptr_t addr, int *v)
{

	if (proc_readmem(td, td->td_proc, addr, v, sizeof(*v)) != sizeof(*v))
		return (EFAULT);
	return (0);
}

static int
ptrace_write_int(struct thread *td, uintptr_t addr, int v)
{

	if (proc_writemem(td, td->td_proc, addr, &v, sizeof(v)) != sizeof(v))
		return (EFAULT);
	return (0);
}

int
ptrace_single_step(struct thread *td)
{
	uintptr_t va;
	struct trapframe *locr0 = td->td_frame;
	int error;
	int bpinstr = MIPS_BREAK_SSTEP;
	int curinstr;
	struct proc *p;

	p = td->td_proc;
	PROC_UNLOCK(p);
	/*
	 * Fetch what's at the current location.
	 */
	error = ptrace_read_int(td, TRAPF_PC(locr0), &curinstr);
	if (error)
		goto out;

	CTR3(KTR_PTRACE,
	    "ptrace_single_step: tid %d, current instr at %#lx: %#08x",
	    td->td_tid, locr0->pc, curinstr);

	/* compute next address after current location */
	if (locr0->cause & MIPS_CR_BR_DELAY) {
		va = (__cheri_addr vaddr_t)MipsEmulateBranch(
		    locr0, locr0->pc, locr0->fsr, &curinstr);
	} else {
		va = TRAPF_PC(locr0) + 4;
	}
	if (td->td_md.md_ss_addr) {
		printf("SS %s (%d): breakpoint already set at %p (va %p)\n",
		    p->p_comm, p->p_pid, (void *)td->td_md.md_ss_addr,
		    (void *)va); /* XXX */
		error = EFAULT;
		goto out;
	}
	td->td_md.md_ss_addr = va;
	/*
	 * Fetch what's at the current location.
	 */
	error = ptrace_read_int(td, (off_t)va, &td->td_md.md_ss_instr);
	if (error)
		goto out;

	/*
	 * Store breakpoint instruction at the "next" location now.
	 */
	error = ptrace_write_int(td, va, bpinstr);

	/*
	 * The sync'ing of I & D caches is done by proc_rwmem()
	 * through proc_writemem().
	 */

out:
	PROC_LOCK(p);
	if (error == 0)
		CTR3(KTR_PTRACE,
		    "ptrace_single_step: tid %d, break set at %#lx: (%#08x)",
		    td->td_tid, va, td->td_md.md_ss_instr); 
	return (error);
}


void
makectx(struct trapframe *tf, struct pcb *pcb)
{

	pcb->pcb_context[PCB_REG_RA] = tf->ra;
	pcb->pcb_context[PCB_REG_PC] = TRAPF_PC(tf);
	pcb->pcb_context[PCB_REG_SP] = tf->sp;
}

int
fill_regs(struct thread *td, struct reg *regs)
{
	memcpy(regs, td->td_frame, sizeof(struct reg));
#if __has_feature(capabilities)
	/*
	 * When targeting CHERI, we don't fill the PT_REGS_PC value
	 * since we only use $pcc and not $pc in trap handling.
	 * Copy it manually instead.
	 */
	regs->r_regs[PT_REGS_PC] = cheri_getoffset(td->td_frame->pc);
#endif
	return (0);
}

int
set_regs(struct thread *td, struct reg *regs)
{
	struct trapframe *f;
	register_t sr;

	f = (struct trapframe *) td->td_frame;
	/*
	 * Don't allow the user to change SR
	 */
	sr = f->sr;
	memcpy(td->td_frame, regs, sizeof(struct reg));
	f->sr = sr;
#if __has_feature(capabilities)
	/* When targeting CHERI, update the offset of $pcc from PT_REGS_PC. */
	td->td_frame->pc =
	    update_pcc_offset(td->td_frame->pc, regs->r_regs[PT_REGS_PC]);
#endif
	return (0);
}

int
get_mcontext(struct thread *td, mcontext_t *mcp, int flags)
{
	struct trapframe *tp;

	tp = td->td_frame;
	PROC_LOCK(curthread->td_proc);
#if __has_feature(capabilities)
	if (SV_PROC_FLAG(td->td_proc, SV_CHERI))
		mcp->mc_onstack = sigonstack((__cheri_addr vaddr_t)tp->csp);
	else
#endif
		mcp->mc_onstack = sigonstack(tp->sp);
	PROC_UNLOCK(curthread->td_proc);
	bcopy((void *)&td->td_frame->zero, (void *)&mcp->mc_regs,
	    sizeof(mcp->mc_regs));

	mcp->mc_fpused = td->td_md.md_flags & MDTD_FPUSED;
	if (mcp->mc_fpused) {
		bcopy((void *)&td->td_frame->f0, (void *)&mcp->mc_fpregs,
		    sizeof(mcp->mc_fpregs));
	}
	if (flags & GET_MC_CLEAR_RET) {
		mcp->mc_regs[V0] = 0;
		mcp->mc_regs[V1] = 0;
		mcp->mc_regs[A3] = 0;
#if __has_feature(capabilities)
		mcp->mc_cheriframe.cf_c3 = NULL;
#endif
	}

	mcp->mc_pc = TRAPF_PC_OFFSET(td->td_frame);
	mcp->mullo = td->td_frame->mullo;
	mcp->mulhi = td->td_frame->mulhi;
	mcp->mc_tls = td->td_md.md_tls;

#if __has_feature(capabilities)
	cheri_trapframe_to_cheriframe(&td->td_pcb->pcb_regs,
	    &mcp->mc_cheriframe);
#endif

	return (0);
}

int
set_mcontext(struct thread *td, mcontext_t *mcp)
{
	struct trapframe *tp;

	tp = td->td_frame;
	bcopy((void *)&mcp->mc_regs, (void *)&td->td_frame->zero,
	    sizeof(mcp->mc_regs));

	td->td_md.md_flags = (mcp->mc_fpused & MDTD_FPUSED)
#ifdef CPU_QEMU_MALTA
	    | (td->td_md.md_flags & MDTD_QTRACE)
#endif
	    ;
	if (mcp->mc_fpused) {
		bcopy((void *)&mcp->mc_fpregs, (void *)&td->td_frame->f0,
		    sizeof(mcp->mc_fpregs));
	}
	td->td_frame->pc =
	    update_pcc_offset(mcp->mc_cheriframe.cf_pcc, mcp->mc_pc);
	td->td_frame->mullo = mcp->mullo;
	td->td_frame->mulhi = mcp->mulhi;
	td->td_md.md_tls = mcp->mc_tls;
	/* Dont let user to set any bits in status and cause registers. */

#if __has_feature(capabilities)
	cheri_trapframe_from_cheriframe(tp, &mcp->mc_cheriframe);
#endif

	return (0);
}

int
fill_fpregs(struct thread *td, struct fpreg *fpregs)
{
#if defined(CPU_HAVEFPU)
	if (td == PCPU_GET(fpcurthread))
		MipsSaveCurFPState(td);
	memcpy(fpregs, &td->td_frame->f0, sizeof(struct fpreg));
	fpregs->r_regs[FIR_NUM] = cpuinfo.fpu_id;
#endif
	return 0;
}

int
set_fpregs(struct thread *td, struct fpreg *fpregs)
{
	if (PCPU_GET(fpcurthread) == td)
		PCPU_SET(fpcurthread, (struct thread *)0);
	memcpy(&td->td_frame->f0, fpregs, sizeof(struct fpreg));
	return 0;
}

#if __has_feature(capabilities)
int
fill_capregs(struct thread *td, struct capreg *capregs)
{

	cheri_trapframe_to_cheriframe_strip(&td->td_pcb->pcb_regs,
	    (struct cheri_frame *)capregs);
	return (0);
}

int
set_capregs(struct thread *td, struct capreg *capregs)
{
	return (ENOSYS);
}

static void * __capability
cheri_stack_pointer(struct thread *td, struct image_params *imgp, uintcap_t stack)
{
	vm_offset_t stackbase, stacktop;
	size_t stacklen;
	char * __capability csp;

	KASSERT((__cheri_addr vaddr_t)stack % sizeof(void * __capability) == 0,
	    ("CheriABI stack pointer not properly aligned"));

	/*
	 * Restrict the stack capability to the maximum region allowed
	 * for this process and adjust csp accordingly.
	 */
	stackbase = (vaddr_t)td->td_proc->p_vmspace->vm_maxsaddr;
	stacktop = (__cheri_addr vaddr_t)stack;
	KASSERT(stacktop > stackbase,
	    ("top of stack 0x%lx is below stack base 0x%lx", stacktop,
	    stackbase));
	stacklen = stacktop - stackbase;

	/*
	 * Round the stack down as required to make it representable.
	 */
	stacklen = rounddown2(stacklen, CHERI_REPRESENTABLE_ALIGNMENT(stacklen));
	KASSERT(stackbase == CHERI_REPRESENTABLE_BASE(stackbase, stacklen),
	    ("%s: rounded base != base", __func__));
	csp = cheri_setaddress((void * __capability)stack, stackbase);
	csp = cheri_csetbounds(csp, stacklen);
	return (csp + stacklen);
}

/*
 * Build a capability to describe the MMAP'able space from the end of
 * the program's heap to the bottom of the stack.
 *
 * XXX: We could probably use looser bounds and rely on the VM system
 * to manage the address space via vm_map instead of the more complex
 * calculations here.
 */
static void
cheri_mmap_capability(struct thread *td, struct image_params *imgp)
{
	vm_offset_t map_base, stack_base, text_end;
	size_t map_length;

	stack_base = cheri_getbase(td->td_frame->csp);
	text_end = roundup2(imgp->end_addr,
	    CHERI_SEALABLE_ALIGNMENT(imgp->end_addr - imgp->start_addr));

	/*
	 * Less confusing rounded up to a page and 256-bit
	 * requires no other rounding.
	 */
	text_end = roundup2(text_end, PAGE_SIZE);
	KASSERT(text_end <= stack_base,
	    ("text_end 0x%zx > stack_base 0x%lx", text_end, stack_base));

	map_base = (text_end == stack_base) ?
	    CHERI_CAP_USER_MMAP_BASE :
	    roundup2(text_end,
		CHERI_REPRESENTABLE_ALIGNMENT(stack_base - text_end));
	KASSERT(map_base < stack_base,
	    ("map_base 0x%zx >= stack_base 0x%lx", map_base, stack_base));
	map_length = stack_base - map_base;
	map_length = rounddown2(map_length,
	    CHERI_REPRESENTABLE_ALIGNMENT(map_length));

	/*
	 * Use cheri_capability_build_user_rwx so mmap() can return
	 * appropriate permissions derived from a single capability.
	 */
	td->td_md.md_cheri_mmap_cap = cheri_capability_build_user_rwx(
	    CHERI_CAP_USER_MMAP_PERMS, map_base, map_length,
	    CHERI_CAP_USER_MMAP_OFFSET);
	KASSERT(cheri_getperm(td->td_md.md_cheri_mmap_cap) &
	    CHERI_PERM_CHERIABI_VMMAP,
	    ("%s: mmap() cap lacks CHERI_PERM_CHERIABI_VMMAP", __func__));
}

static void * __capability
cheri_pcc(struct thread *td, struct image_params *imgp)
{
	vm_offset_t code_start, code_end;
	size_t code_length;

#ifdef CHERIABI_LEGACY_SUPPORT
#pragma message("Warning: Building kernel with LEGACY ABI support!")
	/*
	 * The legacy ABI needs a full address space $pcc (with base
	 * == 0) to create code capabilities using cgetpccsetoffset
	 */
	code_start = CHERI_CAP_USER_CODE_BASE;
	code_end = CHERI_CAP_USER_CODE_LENGTH;
#else
	/*
	 * If we are executing a static binary we use end_addr as the
	 * end of the text segment. If $pcc is the start of rtld we
	 * use interp_end.  If we are executing ld-cheri-elf.so.1
	 * directly we can use end_addr to find the end of the rtld
	 * mapping.
	 */
	code_end = imgp->interp_end ? imgp->interp_end : imgp->end_addr;

	/*
	 * Statically linked binaries need a base 0 code capability
	 * since otherwise crt_init_globals_will fail.
	 *
	 * XXXAR: TODO: is this still true??
	 */
	code_start = imgp->interp_end ? imgp->reloc_base : 0;
#endif

	/* Ensure CHERI128 representability */
	code_length = code_end - code_start;
	code_start = CHERI_REPRESENTABLE_BASE(code_start, code_length);
	code_length = CHERI_REPRESENTABLE_LENGTH(code_length);
	KASSERT(code_start + code_length >= code_end, ("%s: truncated PCC", __func__));
	return (cheri_capability_build_user_code(CHERI_CAP_USER_CODE_PERMS,
	    code_start, code_length, imgp->entry_addr - code_start));
}
#endif

/*
 * Clear registers on exec
 * $sp is set to the stack pointer passed in.  $pc is set to the entry
 * point given by the exec_package passed in, as is $t9 (used for PIC
 * code by the MIPS elf abi).
 */
void
exec_setregs(struct thread *td, struct image_params *imgp, uintcap_t stack)
{

	bzero((caddr_t)td->td_frame, sizeof(struct trapframe));

#if __has_feature(capabilities)
	if (SV_PROC_FLAG(td->td_proc, SV_CHERI)) {
		struct cheri_signal *csigp;
		Elf_Auxinfo * __capability auxv;

		td->td_frame->csp = cheri_stack_pointer(td, imgp, stack);
		cheri_mmap_capability(td, imgp);
#ifdef CHERIABI_LEGACY_SUPPORT
		/*
		 * XXXAR: data_length needs to be the full address
		 * space to allow legacy ABI to work since the TLS
		 * region will be beyond the end of the text section.
		 *
		 * TODO: Start with a NULL $ddc once we drop legacy
		 * ABI support.
		 *
		 * Having a full address space $ddc on startup does
		 * not matter for new binaries since they will all
		 * clear $ddc as one of the first user instructions
		 * anyway.
		 */
		td->td_frame->ddc = cheri_capability_build_user_data(
		    CHERI_CAP_USER_DATA_PERMS, CHERI_CAP_USER_DATA_BASE,
		    CHERI_CAP_USER_DATA_LENGTH, CHERI_CAP_USER_DATA_OFFSET);
#endif
		td->td_frame->pcc = cheri_pcc(td, imgp);
		td->td_frame->c12 = td->td_frame->pc;

		/*
		 * Set up CHERI-related state: most register state,
		 * signal delivery, sealing capabilities, trusted
		 * stack.
		 */
		cheriabi_newthread_init(td);

		/*
		 * Pass a pointer to the ELF auxiliary argument vector.
		 */
		auxv = (Elf_Auxinfo * __capability)
		    ((void * __capability * __capability)stack +
		    imgp->args->argc + 1 + imgp->args->envc + 1);
		td->td_frame->c3 = cheri_csetbounds(auxv,
		    AT_COUNT * sizeof(*auxv));

		/*
		 * Load relocbase for RTLD into $c4 so that rtld has a
		 * capability with the correct bounds available on
		 * startup
		 *
		 * XXXAR: this should not be necessary since it should
		 * be the same as auxv[AT_BASE] but trying to load
		 * that from $c3 crashes...
		 *
		 * TODO: load the AT_BASE value instead of using
		 * duplicated code!
		 */
		if (imgp->reloc_base) {
			vaddr_t rtld_base = imgp->reloc_base;
			vaddr_t rtld_end = imgp->interp_end;
			vaddr_t rtld_len = rtld_end - rtld_base;
			rtld_base = CHERI_REPRESENTABLE_BASE(rtld_base,
			    rtld_len);
			rtld_len = CHERI_REPRESENTABLE_LENGTH(rtld_len);
			td->td_frame->c4 = cheri_capability_build_user_data(
			    CHERI_CAP_USER_DATA_PERMS, rtld_base, rtld_len, 0);
		}

		/*
		 * Update privileged signal-delivery environment for
		 * actual stack.
		 *
		 * XXXRW: Not entirely clear whether we want an offset
		 * of 'stacklen' for csig_csp here.  Maybe we don't
		 * want to use csig_csp at all?  Possibly csig_csp
		 * should default to NULL...?
		 */
		csigp = &td->td_pcb->pcb_cherisignal;
		csigp->csig_csp = td->td_frame->csp;
		csigp->csig_default_stack = csigp->csig_csp;
#ifdef CHERIABI_LEGACY_SUPPORT
		csigp->csig_ddc = frame->ddc;
#endif
	} else
#endif
	{
		td->td_frame->sp = ((__cheri_addr register_t)stack) & ~(STACK_ALIGN - 1);

		/*
		 * If we're running o32 or n32 programs but have 64-bit registers,
		 * GCC may use stack-relative addressing near the top of user
		 * address space that, due to sign extension, will yield an
		 * invalid address.  For instance, if sp is 0x7fffff00 then GCC
		 * might do something like this to load a word from 0x7ffffff0:
		 *
		 * 	addu	sp, sp, 32768
		 * 	lw	t0, -32528(sp)
		 *
		 * On systems with 64-bit registers, sp is sign-extended to
		 * 0xffffffff80007f00 and the load is instead done from
		 * 0xffffffff7ffffff0.
		 *
		 * To prevent this, we subtract 64K from the stack pointer here
		 * for processes with 32-bit pointers.
		 */
#if defined(__mips_n32) || defined(__mips_n64)
		if (!SV_PROC_FLAG(td->td_proc, SV_LP64))
			td->td_frame->sp -= 65536;
#endif

		td->td_frame->t9 = imgp->entry_addr & ~3; /* abicall req */
#if __has_feature(capabilities)
		hybridabi_exec_setregs(td, imgp->entry_addr & ~3);
#else
		/* For CHERI $pcc is set by hybridabi_exec_setregs() */
		td->td_frame->pc = (trapf_pc_t)(uintptr_t)(imgp->entry_addr & ~3);
#endif

		/*
		 * Set up arguments for the rtld-capable crt0:
		 *	a0	stack pointer
		 *	a1	rtld cleanup (filled in by dynamic loader)
		 *	a2	rtld object (filled in by dynamic loader)
		 *	a3	ps_strings
		 */
		td->td_frame->a0 = (__cheri_addr register_t)stack;
		td->td_frame->a1 = 0;
		td->td_frame->a2 = 0;
		td->td_frame->a3 = (__cheri_addr register_t)imgp->ps_strings;
	}

	td->td_frame->sr = MIPS_SR_KSU_USER | MIPS_SR_EXL | MIPS_SR_INT_IE |
	    (mips_rd_status() & MIPS_SR_INT_MASK);
#if defined(__mips_n32) || defined(__mips_n64)
	td->td_frame->sr |= MIPS_SR_PX;
#endif
#if defined(__mips_n64)
	if (SV_PROC_FLAG(td->td_proc, SV_LP64))
		td->td_frame->sr |= MIPS_SR_UX;
	td->td_frame->sr |= MIPS_SR_KX;
#endif
#if __has_feature(capabilities)
	td->td_frame->sr |= MIPS_SR_COP_2_BIT;
#endif
	/*
	 * FREEBSD_DEVELOPERS_FIXME:
	 * Setup any other CPU-Specific registers (Not MIPS Standard)
	 * and/or bits in other standard MIPS registers (if CPU-Specific)
	 *  that are needed.
	 */

	td->td_md.md_flags &= ~MDTD_FPUSED;
	if (PCPU_GET(fpcurthread) == td)
	    PCPU_SET(fpcurthread, (struct thread *)0);
	td->td_md.md_ss_addr = 0;

#ifdef COMPAT_FREEBSD32
	if (SV_PROC_FLAG(td->td_proc, SV_ILP32))
		td->td_md.md_tls_tcb_offset = TLS_TP_OFFSET32 + TLS_TCB_SIZE32;
	else
#endif
#ifdef COMPAT_FREEBSD64
	if (SV_PROC_FLAG(td->td_proc, SV_CHERI | SV_LP64) == SV_LP64)
		td->td_md.md_tls_tcb_offset = TLS_TP_OFFSET64 + TLS_TCB_SIZE64;
	else
#endif
		td->td_md.md_tls_tcb_offset = TLS_TP_OFFSET + TLS_TCB_SIZE;
}

int
ptrace_clear_single_step(struct thread *td)
{
	struct proc *p;
	int error;

	p = td->td_proc;
	PROC_LOCK_ASSERT(p, MA_OWNED);
	if (!td->td_md.md_ss_addr)
		return EINVAL;

	/*
	 * Restore original instruction and clear BP
	 */
	PROC_UNLOCK(p);
	CTR3(KTR_PTRACE,
	    "ptrace_clear_single_step: tid %d, restore instr at %#lx: %#08x",
	    td->td_tid, td->td_md.md_ss_addr, td->td_md.md_ss_instr);
	error = ptrace_write_int(td, td->td_md.md_ss_addr,
	    td->td_md.md_ss_instr);
	PROC_LOCK(p);

	/* The sync'ing of I & D caches is done by proc_rwmem(). */

	if (error != 0) {
		log(LOG_ERR,
		    "SS %s %d: can't restore instruction at %p: %x\n",
		    p->p_comm, p->p_pid, (void *)td->td_md.md_ss_addr,
		    td->td_md.md_ss_instr);
	}
	td->td_md.md_ss_addr = 0;
	return 0;
}
// CHERI CHANGES START
// {
//   "updated": 20181114,
//   "target_type": "kernel",
//   "changes": [
//     "kernel_sig_types",
//     "support",
//     "user_capabilities"
//   ],
//   "change_comment": ""
// }
// CHERI CHANGES END
