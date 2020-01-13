/*-
 * Copyright (c) 1988 University of Utah.
 * Copyright (c) 1982, 1986, 1987, 1990, 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 * Copyright (c) 1989, 1990 William Jolitz
 * Copyright (c) 1992 Terrence R. Lambert.
 * Copyright (c) 1994 John Dyson
 * Copyright (c) 2015 SRI International
 * Copyright (c) 2016-2017 Robert N. M. Watson
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department and Ralph Campbell.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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
 * 4. Neither the name of the University nor the names of its contributors
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
 */

#define __ELF_WORD_SIZE 64
#define	EXPLICIT_USER_ACCESS

#include "opt_ddb.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/sysent.h>
#include <sys/signal.h>
#include <sys/proc.h>
#include <sys/imgact_elf.h>
#include <sys/imgact.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/syscallsubr.h>
#include <sys/sysproto.h>
#include <sys/ucontext.h>
#include <sys/user.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <machine/abi.h>
#include <machine/cpuinfo.h>
#include <machine/md_var.h>
#include <machine/pcb.h>
#include <machine/sigframe.h>
#include <machine/sysarch.h>
#include <machine/tls.h>

#include <compat/freebsd64/freebsd64.h>
#include <compat/freebsd64/freebsd64_proto.h>
#include <compat/freebsd64/freebsd64_syscall.h>
#include <compat/freebsd64/freebsd64_util.h>

#include <ddb/ddb.h>
#include <sys/kdb.h>

#define	DELAYBRANCH(x)	((int)(x) < 0)
#define	UCONTEXT_MAGIC	0xACEDBADE

static void	freebsd64_sendsig(sig_t, ksiginfo_t *, sigset_t *);

extern const char *freebsd64_syscallnames[];

struct sysentvec elf_freebsd_freebsd64_sysvec = {
	.sv_size	= FREEBSD64_SYS_MAXSYSCALL,
	.sv_table	= freebsd64_sysent,
	.sv_errsize	= 0,
	.sv_errtbl	= NULL,
	.sv_fixup	= __elfN(freebsd_fixup),
	.sv_sendsig	= freebsd64_sendsig,
	.sv_sigcode	= freebsd64_sigcode,
	.sv_szsigcode	= &freebsd64_szsigcode,
	.sv_name	= "FreeBSD ELF64",
	.sv_coredump	= __elfN(coredump),
	.sv_imgact_try	= NULL,
	.sv_minsigstksz	= MINSIGSTKSZ,
	.sv_minuser	= VM_MIN_ADDRESS,
	.sv_maxuser	= VM_MAXUSER_ADDRESS,
	.sv_usrstack	= USRSTACK,
	.sv_psstrings	= FREEBSD64_PS_STRINGS,
	.sv_stackprot	= VM_PROT_ALL,
	.sv_copyout_auxargs = __elfN(freebsd_copyout_auxargs),
	.sv_copyout_strings = freebsd64_copyout_strings,
	.sv_setregs	= exec_setregs,
	.sv_fixlimit	= NULL,
	.sv_maxssiz	= NULL,
	.sv_flags	= SV_ABI_FREEBSD | SV_LP64 | SV_ASLR |
#ifdef MIPS_SHAREDPAGE
	SV_SHP,
#else
	0,
#endif
	.sv_set_syscall_retval = cpu_set_syscall_retval,
	.sv_fetch_syscall_args = cpu_fetch_syscall_args,
	.sv_syscallnames = freebsd64_syscallnames,
#ifdef MIPS_SHAREDPAGE
	.sv_shared_page_base = SHAREDPAGE,
	.sv_shared_page_len = PAGE_SIZE,
#endif
	.sv_schedtail	= NULL,
	.sv_thread_detach = NULL,
	.sv_trap	= NULL,
};
INIT_SYSENTVEC(freebsd64_sysent, &elf_freebsd_freebsd64_sysvec);

#ifdef CPU_CHERI
static __inline boolean_t
mips_hybrid_check_cap_size(uint32_t bits, const char *execpath)
{
	static struct timeval lastfail;
	static int curfail;
	const uint32_t expected = CHERICAP_SIZE * 8;

	if (bits == expected)
		return TRUE;
	if (ppsratecheck(&lastfail, &curfail, 1))
		printf("warning: attempting to execute %d-bit hybrid binary "
		    "'%s' on a %d-bit kernel\n", bits, execpath, expected);
	return FALSE;
}

static boolean_t
mips_elf_header_supported(struct image_params * imgp)
{
	const Elf_Ehdr *hdr = (const Elf_Ehdr *)imgp->image_header;
	if ((hdr->e_flags & EF_MIPS_MACH) == EF_MIPS_MACH_CHERI128)
		return mips_hybrid_check_cap_size(128, imgp->execpath);
	if ((hdr->e_flags & EF_MIPS_MACH) == EF_MIPS_MACH_CHERI256)
		return mips_hybrid_check_cap_size(256, imgp->execpath);
	return TRUE;
}
#endif

static Elf64_Brandinfo freebsd_freebsd64_brand_info = {
	.brand		= ELFOSABI_FREEBSD,
	.machine	= EM_MIPS,
	.compat_3_brand	= "FreeBSD",
	.emul_path	= NULL,
	.interp_path	= "/libexec/ld-elf.so.1",
	.sysvec		= &elf_freebsd_freebsd64_sysvec,
	.interp_newpath = "/libexec/ld-elf64.so.1",
	.brand_note	= &elf64_freebsd_brandnote,
#ifdef CPU_CHERI
	.header_supported = mips_elf_header_supported,
#endif
	.flags		= BI_CAN_EXEC_DYN | BI_BRAND_NOTE,
};

SYSINIT(freebsd64, SI_SUB_EXEC, SI_ORDER_ANY,
    (sysinit_cfunc_t) elf64_insert_brand_entry,
    &freebsd_freebsd64_brand_info);

int
freebsd64_get_mcontext(struct thread *td, mcontext64_t *mcp, int flags)
{
	mcontext_t mc;
	unsigned i;
	int error;

	error = get_mcontext(td, &mc, flags);
	if (error != 0)
		return (error);

	mcp->mc_onstack = mc.mc_onstack;
	mcp->mc_pc = mc.mc_pc;
	for (i = 0; i < 32; i++)
		mcp->mc_regs[i] = mc.mc_regs[i];
	mcp->sr = mc.sr;
	mcp->mullo = mc.mullo;
	mcp->mulhi = mc.mulhi;
	mcp->mc_fpused = mc.mc_fpused;
	for (i = 0; i < 33; i++)
		mcp->mc_fpregs[i] = mc.mc_fpregs[i];
	mcp->mc_fpc_eir = mc.mc_fpc_eir;
	mcp->mc_tls = (__cheri_fromcap void *)mc.mc_tls;
	mcp->cause = mc.cause;

	/*
	 * We can't store cap registers here directly.  If the caller
	 * is using getcontextx(), that function will fetch the
	 * capability registers and initialize these fields in
	 * userland after getcontext() returns.
	 */
	mcp->mc_cp2state = 0;
	mcp->mc_cp2state_len = 0;

	return (0);
}

int
freebsd64_set_mcontext(struct thread *td, mcontext64_t *mcp)
{
	mcontext_t mc;
	unsigned i;
	int error;

	if (mcp->mc_cp2state != 0) {
		if (mcp->mc_cp2state_len != sizeof(mc.mc_cheriframe)) {
			printf("%s: invalid cp2 state length "
			    "(expected %zd, got %zd)\n", __func__,
			    sizeof(mc.mc_cheriframe), mcp->mc_cp2state_len);
			return (EINVAL);
		}
		error = copyincap(__USER_CAP((void *)mcp->mc_cp2state,
		    mcp->mc_cp2state_len), &mc.mc_cheriframe,
		    sizeof(mc.mc_cheriframe));
		if (error) {
			printf("%s: invalid pointer\n", __func__);
			return (error);
		}
	} else {
		/*
		 * Fetch current capability registers so that
		 * set_mcontext() has something to write.
		 */
		cheri_trapframe_to_cheriframe(&td->td_pcb->pcb_regs,
		    &mc.mc_cheriframe);
	}

	mc.mc_onstack = mcp->mc_onstack;
	mc.mc_pc = mcp->mc_pc;
	for (i = 0; i < 32; i++)
		mc.mc_regs[i] = mcp->mc_regs[i];
	mc.sr = mcp->sr;
	mc.mullo = mcp->mullo;
	mc.mulhi = mcp->mulhi;
	mc.mc_fpused = mcp->mc_fpused;
	for (i = 0; i < 33; i++)
		mc.mc_fpregs[i] = mcp->mc_fpregs[i];
	mc.mc_fpc_eir = mcp->mc_fpc_eir;

	/*
	 * XXX: Should this be relative to DDC saved in
	 * mc_cheriframe?
	 */
	mc.mc_tls = __USER_CAP_UNBOUND(mcp->mc_tls);

	return (set_mcontext(td, &mc));
}

static void
freebsd64_sendsig(sig_t catcher, ksiginfo_t *ksi, sigset_t *mask)
{

	struct proc *p;
	struct thread *td;
	struct trapframe *regs;
#ifdef CPU_CHERI
	struct cheri_frame *cfp;
#endif
	struct sigacts *psp;
	struct sigframe64 sf, *sfp;
	vm_offset_t sp;
#ifdef CPU_CHERI
	size_t cp2_len;
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
	oonstack = sigonstack(regs->sp);

#ifdef CPU_CHERI
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
	bzero(&sf, sizeof(sf));
	sf.sf_uc.uc_sigmask = *mask;
	sf.sf_uc.uc_stack.ss_sp = (__cheri_fromcap void *)td->td_sigstk.ss_sp;
	sf.sf_uc.uc_stack.ss_size = td->td_sigstk.ss_size;
	sf.sf_uc.uc_stack.ss_flags = td->td_sigstk.ss_flags;
	sf.sf_uc.uc_mcontext.mc_onstack = (oonstack) ? 1 : 0;
	sf.sf_uc.uc_mcontext.mc_pc = TRAPF_PC_OFFSET(regs);
	sf.sf_uc.uc_mcontext.mullo = regs->mullo;
	sf.sf_uc.uc_mcontext.mulhi = regs->mulhi;
	sf.sf_uc.uc_mcontext.mc_tls =
	    (__cheri_fromcap void *)td->td_md.md_tls;
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

	/* Allocate and validate space for the signal handler context. */
	if ((td->td_pflags & TDP_ALTSTACK) != 0 && !oonstack &&
	    SIGISMEMBER(psp->ps_sigonstack, sig)) {
		sp = (vm_offset_t)((__cheri_addr vaddr_t)td->td_sigstk.ss_sp +
		    td->td_sigstk.ss_size);
	} else {
#ifdef CPU_CHERI
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
#endif
		sp = (vm_offset_t)regs->sp;
	}
#ifdef CPU_CHERI
	cp2_len = sizeof(*cfp);
	sp -= cp2_len;
	sp = rounddown2(sp, CHERICAP_SIZE);
	sf.sf_uc.uc_mcontext.mc_cp2state = sp;
	sf.sf_uc.uc_mcontext.mc_cp2state_len = cp2_len;
#endif
	sp -= sizeof(sf);
	sp = rounddown2(sp, STACK_ALIGN);
	sfp = (struct sigframe64 *)sp;

	/* Build the argument list for the signal handler. */
	regs->a0 = sig;
	regs->a2 = (register_t)(intptr_t)&sfp->sf_uc;
	if (SIGISMEMBER(psp->ps_siginfo, sig)) {
		/* Signal handler installed with SA_SIGINFO. */
		regs->a1 = (register_t)(intptr_t)&sfp->sf_si;
		/* sf.sf_ahu.sf_action = (__siginfohandler_t *)catcher; */

		/* fill siginfo structure */
		siginfo_to_siginfo64(&ksi->ksi_info, &sf.sf_si);
		sf.sf_si.si_signo = sig;
	} else {
		/* Old FreeBSD-style arguments. */
		regs->a1 = ksi->ksi_code;
		regs->a3 = (__cheri_addr uintptr_t)ksi->ksi_addr;
		/* sf.sf_ahu.sf_handler = catcher; */
	}

	mtx_unlock(&psp->ps_mtx);
	PROC_UNLOCK(p);

	/*
	 * Copy the sigframe out to the user's stack.
	 */
#ifdef CPU_CHERI
	cfp = malloc(sizeof(*cfp), M_TEMP, M_WAITOK);
	cheri_trapframe_to_cheriframe(&td->td_pcb->pcb_regs, cfp);
	if (copyoutcap(cfp,
	    __USER_CAP((void *)(uintptr_t)sf.sf_uc.uc_mcontext.mc_cp2state,
	    cp2_len), cp2_len) != 0) {
		free(cfp, M_TEMP);
		PROC_LOCK(p);
		printf("pid %d, tid %d: could not copy out cheriframe\n",
		    td->td_proc->p_pid, td->td_tid);
		sigexit(td, SIGILL);
		/* NOTREACHED */
	}
	free(cfp, M_TEMP);
#endif
	if (copyout(&sf, __USER_CAP_OBJ(sfp), sizeof(sf)) != 0) {
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

#ifdef CPU_CHERI
	/*
	 * Install CHERI signal-delivery register state for handler to run
	 * in.  As we don't install this in the CHERI frame on the user stack,
	 * it will be (genrally) be removed automatically on sigreturn().
	 */
	hybridabi_sendsig(td);
#endif

	regs->pc = (trapf_pc_t)catcher;
	regs->t9 = TRAPF_PC_OFFSET(regs);
	regs->sp = (register_t)(intptr_t)sfp;
	if (p->p_sysent->sv_sigcode_base != 0) {
		/* Signal trampoline code is in the shared page */
		regs->ra = p->p_sysent->sv_sigcode_base;
	} else {
		/* Signal trampoline code is at base of user stack. */
		/* XXX: GC this code path once shared page is stable */
		regs->ra = (register_t)(intptr_t)FREEBSD64_PS_STRINGS -
		    *(p->p_sysent->sv_szsigcode);
	}
	PROC_LOCK(p);
	mtx_lock(&psp->ps_mtx);
}

int
freebsd64_sysarch(struct thread *td, struct freebsd64_sysarch_args *uap)
{
	int error;
#ifdef CPU_QEMU_MALTA
	int intval;
#endif
	int64_t tlsbase;

	switch (uap->op) {
	/*
	 * Operations shared with MIPS.
	 */
	case MIPS_SET_TLS:
		return (cpu_set_user_tls(td,
		    __USER_CAP_UNBOUND((void *)(intptr_t)uap->parms)));

	case MIPS_GET_TLS:
		tlsbase = (__cheri_addr int64_t)td->td_md.md_tls;
		error = copyout(&tlsbase, __USER_CAP(uap->parms,
		    sizeof(tlsbase)), sizeof(tlsbase));
		return (error);

#ifdef CPU_QEMU_MALTA
	case QEMU_GET_QTRACE:
		intval = (td->td_md.md_flags & MDTD_QTRACE) ? 1 : 0;
		error = copyout(&intval, __USER_CAP(uap->parms, sizeof(intval)),
		    sizeof(intval));
		return (error);

	case QEMU_SET_QTRACE:
		error = copyin(__USER_CAP(uap->parms, sizeof(intval)),
		    &intval, sizeof(intval));
		if (error)
			return (error);
		if (intval)
			td->td_md.md_flags |= MDTD_QTRACE;
		else
			td->td_md.md_flags &= ~MDTD_QTRACE;
		return (0);
#endif

	case CHERI_GET_SEALCAP:
		return (cheri_sysarch_getsealcap(td,
		    __USER_CAP(uap->parms, sizeof(void * __capability))));

	default:
		return (EINVAL);
	}
}

void
elf64_dump_thread(struct thread *td __unused, void *dst __unused,
    size_t *off __unused)
{
}
