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

#include "opt_ddb.h"

#define	EXPLICIT_USER_ACCESS

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

#include <machine/cpuinfo.h>
#include <machine/md_var.h>
#include <machine/pcb.h>
#include <machine/sigframe.h>
#include <machine/sysarch.h>
#include <machine/tls.h>

#include <compat/cheriabi/cheriabi.h>
#include <compat/cheriabi/cheriabi_proto.h>
#include <compat/cheriabi/cheriabi_syscall.h>
#include <compat/cheriabi/cheriabi_sysargmap.h>
#include <compat/cheriabi/cheriabi_util.h>

#include <ddb/ddb.h>
#include <sys/kdb.h>

#define	DELAYBRANCH(x)	((int)(x) < 0)
#define	UCONTEXT_MAGIC	0xACEDBADE

#ifdef CHERIABI_LEGACY_SUPPORT
static void	cheriabi_capability_set_user_ddc(void * __capability *,
		    size_t);
#endif
static int	cheriabi_fetch_syscall_args(struct thread *td);
static void	cheriabi_set_syscall_retval(struct thread *td, int error);
static void	cheriabi_sendsig(sig_t, ksiginfo_t *, sigset_t *);
static void	cheriabi_exec_setregs(struct thread *, struct image_params *,
		    u_long);
static __inline boolean_t cheriabi_check_cpu_compatible(uint32_t, const char *);
static boolean_t cheriabi_elf_header_supported(struct image_params *);

extern const char *cheriabi_syscallnames[];

struct sysentvec elf_freebsd_cheriabi_sysvec = {
	.sv_size	= CHERIABI_SYS_MAXSYSCALL,
	.sv_table	= cheriabi_sysent,
	.sv_errsize	= 0,
	.sv_errtbl	= NULL,
	.sv_fixup	= cheriabi_elf_fixup,
	.sv_sendsig	= cheriabi_sendsig,
	.sv_sigcode	= cheri_sigcode,
	.sv_szsigcode	= &szcheri_sigcode,
	.sv_name	= "CheriABI ELF64",
	.sv_coredump	= __elfN(coredump),
	.sv_imgact_try	= NULL,
	.sv_minsigstksz	= MINSIGSTKSZ,	/* XXXBD: or something bigger? */
	.sv_minuser	= PAGE_SIZE,	/* Disallow mapping at NULL */
	.sv_maxuser	= VM_MAXUSER_ADDRESS,
	.sv_usrstack	= USRSTACK,
	.sv_psstrings	= CHERIABI_PS_STRINGS,
	.sv_stackprot	= VM_PROT_READ|VM_PROT_WRITE,
	.sv_copyout_strings = cheriabi_copyout_strings,
	.sv_setregs	= cheriabi_exec_setregs,
	.sv_fixlimit	= NULL,
	.sv_maxssiz	= NULL,
	.sv_flags	= SV_ABI_FREEBSD | SV_LP64 | SV_CHERI | SV_SHP,
	.sv_set_syscall_retval = cheriabi_set_syscall_retval,
	.sv_fetch_syscall_args = cheriabi_fetch_syscall_args,
	.sv_syscallnames = cheriabi_syscallnames,
	.sv_shared_page_base = SHAREDPAGE,
	.sv_shared_page_len = PAGE_SIZE,
	.sv_schedtail	= NULL,
};
INIT_SYSENTVEC(cheriabi_sysent, &elf_freebsd_cheriabi_sysvec);

static Elf64_Brandinfo freebsd_cheriabi_brand_info = {
	.brand		= ELFOSABI_FREEBSD,
	.machine	= EM_MIPS,
	.compat_3_brand	= "FreeBSD",
	.emul_path	= NULL,
	.interp_path	= "/libexec/ld-elf.so.1",
	.sysvec		= &elf_freebsd_cheriabi_sysvec,
	.interp_newpath	= "/libexec/ld-cheri-elf.so.1",
	.flags		= BI_CAN_EXEC_DYN,
	.header_supported = cheriabi_elf_header_supported
};

SYSINIT(cheriabi, SI_SUB_EXEC, SI_ORDER_ANY,
    (sysinit_cfunc_t) elf64c_insert_brand_entry,
    &freebsd_cheriabi_brand_info);


static __inline boolean_t
cheriabi_check_cpu_compatible(uint32_t bits, const char *execpath)
{
	static struct timeval lastfail;
	static int curfail;
	const uint32_t expected = CHERICAP_SIZE * 8;

	if (bits == expected)
		return TRUE;
	if (ppsratecheck(&lastfail, &curfail, 1))
		printf("warning: attempting to execute %d-bit CheriABI "
		    "binary '%s' on a %d-bit kernel\n", bits, execpath,
		    expected);
	return FALSE;
}

static int allow_cheriabi_version_mismatch = 0;
SYSCTL_DECL(_compat_cheriabi);
SYSCTL_INT(_compat_cheriabi, OID_AUTO, allow_abi_version_mismatch,
    CTLFLAG_RW, &allow_cheriabi_version_mismatch, 0,
    "Allow loading CheriABI binaries with the wrong ABI version");

static boolean_t
cheriabi_elf_header_supported(struct image_params *imgp)
{
	const Elf_Ehdr *hdr = (const Elf_Ehdr *)imgp->image_header;
	const uint32_t machine = hdr->e_flags & EF_MIPS_MACH;

	if (!use_cheriabi)
		return FALSE;
	if ((hdr->e_flags & EF_MIPS_ABI) != EF_MIPS_ABI_CHERIABI)
		return FALSE;

	/* TODO: add a sysctl to allow loading old binaries */
	if (hdr->e_ident[EI_ABIVERSION] != ELF_CHERIABI_ABIVERSION) {
		printf("warning: attempting to execute CheriABI binary '%s'"
		    " with ABI version %d on a system expecting version %d\n",
		    imgp->execpath, hdr->e_ident[EI_ABIVERSION],
		    ELF_CHERIABI_ABIVERSION);
		return (boolean_t)allow_cheriabi_version_mismatch;
	}

	if (machine == EF_MIPS_MACH_CHERI128)
		return cheriabi_check_cpu_compatible(128, imgp->execpath);
	else if (machine == EF_MIPS_MACH_CHERI256)
		return cheriabi_check_cpu_compatible(256, imgp->execpath);
	return FALSE;
}

static int
cheriabi_fetch_syscall_args(struct thread *td)
{
	struct trapframe *locr0 = td->td_frame;	 /* aka td->td_pcb->pcv_regs */
	struct sysentvec *se;
	struct syscall_args *sa;
	int error, i, ptrmask;

	error = 0;

	sa = &td->td_sa;
	bzero(sa->args, sizeof(sa->args));

	/* compute next PC after syscall instruction */
	td->td_pcb->pcb_tpc = sa->trapframe->pc; /* Remember if restart */
	if (DELAYBRANCH(sa->trapframe->cause))	 /* Check BD bit */
		locr0->pc = MipsEmulateBranch(locr0, sa->trapframe->pc, 0, 0);
	else
		locr0->pc += sizeof(int);

	sa->code = locr0->v0;
	sa->argoff = 0;
	if (sa->code == SYS_syscall || sa->code == SYS___syscall) {
		sa->code = locr0->a0;
		sa->argoff = 1;
	}

	se = td->td_proc->p_sysent;

	if (sa->code >= se->sv_size)
		sa->callp = &se->sv_table[0];
	else
		sa->callp = &se->sv_table[sa->code];

	sa->narg = sa->callp->sy_narg;

	if (sa->code >= nitems(cheriabi_sysargmask))
		ptrmask = 0;
	else
		ptrmask = cheriabi_sysargmask[sa->code];

	/*
	 * For syscall() and __syscall(), the arguments are stored in a
	 * var args block pointed to by c13.
	 */
	if (td->td_sa.argoff == 1) {
		uint64_t intval;
		int offset;

		offset = 0;
		for (i = 0; i < sa->narg; i++) {
			if (ptrmask & (1 << i)) {
				offset = roundup2(offset, sizeof(uintcap_t));
				error = copyincap(
				    (char * __capability)locr0->c13 + offset,
				    &sa->args[i], sizeof(sa->args[i]));
				offset += sizeof(uintcap_t);
			} else {
				error = copyin(
				    (char * __capability)locr0->c13 + offset,
				    &intval, sizeof(intval));
				sa->args[i] = intval;
				offset += sizeof(uint64_t);
			}
			if (error)
				break;
		}
	} else {
		int intreg_offset, ptrreg_offset;

		intreg_offset = 0;
		ptrreg_offset = 0;
		for (i = 0; i < sa->narg; i++) {
			if (ptrmask & (1 << i)) {
				if (ptrreg_offset > 7)
					panic(
				    "%s: pointer argument %d out of range",
					    __func__, ptrreg_offset);
				sa->args[i] = (intcap_t)(&locr0->c3)[ptrreg_offset];
				ptrreg_offset++;
			} else {
				sa->args[i] = (&locr0->a0)[intreg_offset];
				intreg_offset++;
			}
		}
	}

	td->td_retval[0] = 0;
	td->td_retval[1] = locr0->v1;

	return (error);
}

static void
cheriabi_set_syscall_retval(struct thread *td, int error)
{
	struct trapframe *locr0 = td->td_frame;

	switch (error) {
	case 0:
		KASSERT(cheri_gettag((void * __capability)td->td_retval[0]) == 0 ||
		    td->td_sa.code == CHERIABI_SYS_cheriabi_mmap ||
		    td->td_sa.code == CHERIABI_SYS_cheriabi_shmat,
		    ("trying to return capability from integer returning "
		    "syscall (%u)", td->td_sa.code));

		locr0->v0 = td->td_retval[0];
		locr0->v1 = td->td_retval[1];
		locr0->c3 = (void * __capability)td->td_retval[0];
		locr0->a3 = 0;
		break;

	case ERESTART:
		locr0->pc = td->td_pcb->pcb_tpc;
		break;

	case EJUSTRETURN:
		break;  /* nothing to do */

	default:
		locr0->v0 = error;
		locr0->a3 = 1;
		break;
	}
}

int
cheriabi_get_mcontext(struct thread *td, mcontext_c_t *mcp, int flags)
{
	struct trapframe *tp;

	tp = td->td_frame;
	PROC_LOCK(curthread->td_proc);
	mcp->mc_onstack = sigonstack((__cheri_addr vaddr_t)tp->csp);
	PROC_UNLOCK(curthread->td_proc);
	bcopy((void *)&td->td_frame->zero, (void *)&mcp->mc_regs,
	    sizeof(mcp->mc_regs));

	mcp->mc_fpused = td->td_md.md_flags & MDTD_FPUSED;
	if (mcp->mc_fpused) {
		bcopy((void *)&td->td_frame->f0, (void *)&mcp->mc_fpregs,
		    sizeof(mcp->mc_fpregs));
	}
	cheri_trapframe_to_cheriframe(&td->td_pcb->pcb_regs,
	    &mcp->mc_cheriframe);
	if (flags & GET_MC_CLEAR_RET) {
		mcp->mc_regs[V0] = 0;
		mcp->mc_regs[V1] = 0;
		mcp->mc_regs[A3] = 0;
		mcp->mc_cheriframe.cf_c3 = NULL;
	}

	mcp->mc_pc = td->td_frame->pc;
	mcp->mullo = td->td_frame->mullo;
	mcp->mulhi = td->td_frame->mulhi;
	mcp->mc_tls = td->td_md.md_tls;

	return (0);
}

int
cheriabi_set_mcontext(struct thread *td, mcontext_c_t *mcp)
{
	struct trapframe *tp;
	int tag;

	tp = td->td_frame;
	cheri_trapframe_from_cheriframe(tp, &mcp->mc_cheriframe);
	bcopy((void *)&mcp->mc_regs, (void *)&td->td_frame->zero,
	    sizeof(mcp->mc_regs));
	td->td_md.md_flags = (mcp->mc_fpused & MDTD_FPUSED)
#ifdef CPU_QEMU_MALTA
	    | (td->td_md.md_flags & MDTD_QTRACE)
#endif
	    ;
	if (mcp->mc_fpused)
		bcopy((void *)&mcp->mc_fpregs, (void *)&td->td_frame->f0,
		    sizeof(mcp->mc_fpregs));
	td->td_frame->pc = mcp->mc_pc;
	td->td_frame->mullo = mcp->mullo;
	td->td_frame->mulhi = mcp->mulhi;

	td->td_md.md_tls =  mcp->mc_tls;
	tag = cheri_gettag(mcp->mc_tls);

	/* Dont let user to set any bits in status and cause registers.  */

	return (0);
}

/*
 * The CheriABI version of sendsig(9) largely borrows from the MIPS version,
 * and it is important to keep them in sync.  It differs primarily in that it
 * must also be aware of user stack-handling ABIs, so is also sensitive to our
 * (fluctuating) design choices in how $csp and $sp interact.  In the current
 * model, $csp encapsulates the bounds and stack pointer itself, and the
 * historic $sp register is simply a general-puprose register.  As such, there
 * should be no mention of $sp (in its role as a stack pointer) in CheriABI
 * code.
 *
 * This code, as with the CHERI-aware MIPS code, makes a privilege
 * determination in order to decide whether to trust the stack exposed by the
 * user code for the purposes of signal handling.  We must use the alternative
 * stack if there is any indication that using the user thread's stack state
 * might violate the userspace compartmentalisation model.
 */
static void
cheriabi_sendsig(sig_t catcher, ksiginfo_t *ksi, sigset_t *mask)
{
	struct proc *p;
	struct thread *td;
	struct trapframe *regs;
	struct sigacts *psp;
	struct sigframe_c sf, * __capability sfp;
	struct cheri_signal *csigp;
	char * __capability csp;
	int cheri_is_sandboxed;
	int sig;
	int oonstack;

	KASSERT(cheri_gettag(catcher), ("signal handler is untagged!"));

	td = curthread;
	p = td->td_proc;
	PROC_LOCK_ASSERT(p, MA_OWNED);
	sig = ksi->ksi_signo;
	psp = p->p_sigacts;
	mtx_assert(&psp->ps_mtx, MA_OWNED);
	csigp = &td->td_pcb->pcb_cherisignal;

	/*
	 * XXXRW: We make an on-stack determination using the virtual address
	 * associated with the stack pointer, rather than using the full
	 * capability.  Should we compare the entire capability...?  Just
	 * pointer and bounds...?
	 */
	regs = td->td_frame;
	oonstack = sigonstack((__cheri_addr vaddr_t)regs->csp);

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
	 *     cheri_sendsig()).
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
	 * If a thread is running sandboxed, we can't rely on $csp which may
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

	/* save user context */
	bzero(&sf, sizeof(sf));
	sf.sf_uc.uc_sigmask = *mask;
#if 0
	/*
	 * XXX-BD: stack_t type differs and we can't just fake a capabilty.
	 * We don't restore the value so what purpose does it serve?
	 */
	sf.sf_uc.uc_stack = td->td_sigstk;
#endif
	sf.sf_uc.uc_mcontext.mc_onstack = (oonstack) ? 1 : 0;
	sf.sf_uc.uc_mcontext.mc_pc = regs->pc;
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
	cheri_trapframe_to_cheriframe(regs,
	    &sf.sf_uc.uc_mcontext.mc_cheriframe);

	/*
	 * Allocate and validate space for the signal handler context.
	 *
	 * XXXRW: It seems like it would be nice to both the regular and
	 * alternative stack calculations in the same place.  However, we need
	 * oonstack sooner.  We should clean this up later.
	 */
	if ((td->td_pflags & TDP_ALTSTACK) != 0 && !oonstack &&
	    SIGISMEMBER(psp->ps_sigonstack, sig)) {
		csp = (char * __capability)td->td_sigstk.ss_sp + td->td_sigstk.ss_size;
	} else {
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
		csp = regs->csp;
	}
	csp -= sizeof(struct sigframe_c);
	/* For CHERI, keep the stack pointer capability aligned. */
	csp = __builtin_align_down(csp, CHERICAP_SIZE);
	sfp = (struct sigframe_c * __capability)csp;

	/* Build the argument list for the signal handler. */
	regs->a0 = sig;
	if (SIGISMEMBER(psp->ps_siginfo, sig)) {
		/*
		 * Signal handler installed with SA_SIGINFO.
		 *
		 * XXXRW: We would ideally synthesise these from the
		 * user-originated stack capability, rather than $kdc, to be
		 * on the safe side.
		 */
		regs->c3 = cheri_capability_build_user_data(
		    CHERI_CAP_USER_DATA_PERMS, (__cheri_addr vaddr_t)&sfp->sf_si,
		    sizeof(sfp->sf_si), 0);
		regs->c4 = cheri_capability_build_user_data(
		    CHERI_CAP_USER_DATA_PERMS, (__cheri_addr vaddr_t)&sfp->sf_uc,
		    sizeof(sfp->sf_uc), 0);
		/* sf.sf_ahu.sf_action = (__siginfohandler_t *)catcher; */

		/* fill siginfo structure */
		sf.sf_si.si_signo = sig;
		sf.sf_si.si_code = ksi->ksi_code;
		sf.sf_si.si_value.sival_int =
		    ksi->ksi_info.si_value.sival_int;
		/*
		 * Write out badvaddr, but don't create a valid capability
		 * since that might allow privilege amplification.
		 *
		 * XXXRW: I think there's some argument that anything
		 * receiving this signal is fairly privileged.  But we could
		 * generate a $ddc-relative (or $pcc-relative) capability, if
		 * possible.  (Using versions if $ddc and $pcc for the
		 * signal-handling context rather than that which caused the
		 * signal).  I'd be tempted to deliver badvaddr as the offset
		 * of that capability.  If badvaddr is not in range, then we
		 * should just deliver an untagged NULL-derived version
		 * (perhaps)?
		 *
		 * XXXBD: We really need a regs->badcap here.  There's no
		 * sensable value to derive in the CheriABI context.
		 */
		sf.sf_si.si_addr = (void * __capability)(intcap_t)regs->badvaddr;
	}
	/*
	 * XXX: No support for undocumented arguments to old style handlers.
	 */

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

	/*
	 * Re-acquire process locks necessary to access suitable pcb fields.
	 * However, arguably, these operations should be atomic with the
	 * initial inspection of 'psp'.
	 */
	PROC_LOCK(p);
	mtx_lock(&psp->ps_mtx);

	/*
	 * Install CHERI signal-delivery register state for handler to run
	 * in.  As we don't install this in the CHERI frame on the user stack,
	 * it will be (generally) be removed automatically on sigreturn().
	 *
	 * Note: regs->pc should currently be the same as the offset of pcc and
	 * not the virtual address.
	 * TODO: add an update_trapframe_pc(void* __kerncap) that guarantees
	 * this invariant always holds.
	 */
	regs->pc = (__cheri_offset register_t)catcher;
	regs->pcc = catcher;
	regs->csp = sfp;
	regs->c12 = catcher;
	regs->c17 = td->td_pcb->pcb_cherisignal.csig_sigcode;
	/*
	 * For now only change IDC if we were sandboxed. This makes cap-table
	 * binaries work as expected (since they need cgp to remain the same).
	 *
	 * TODO: remove csigp->csig_idc
	 */
	if (cheri_is_sandboxed) {
		regs->ddc = csigp->csig_ddc;
		regs->idc = csigp->csig_idc;
	}
}

#ifdef CHERIABI_LEGACY_SUPPORT
static void
cheriabi_capability_set_user_ddc(void * __capability *cp, size_t length)
{

	*cp = cheri_capability_build_user_data(CHERI_CAP_USER_DATA_PERMS,
	    CHERI_CAP_USER_DATA_BASE, length, CHERI_CAP_USER_DATA_OFFSET);
}
#endif

/*
 * Common per-thread CHERI state initialisation across execve(2) and
 * additional thread creation.
 */
static void
cheriabi_newthread_init(struct thread *td)
{
	struct cheri_signal *csigp;
	struct trapframe *frame;

	/*
	 * We assume that the caller has initialised the trapframe to zeroes
	 * and then set idc, and pcc appropriatly. We might want to check
	 * this with a more thorough set of assertions in the future.
	 */
	frame = &td->td_pcb->pcb_regs;
	KASSERT(frame->pcc != NULL, ("%s: NULL $epcc", __func__));

	/*
	 * Initialise signal-handling state; this can't yet be modified
	 * by userspace, but the principle is that signal handlers should run
	 * with ambient authority unless given up by the userspace runtime
	 * explicitly.  The caller will initialise the stack fields.
	 *
	 * Note that some fields are overwritten later in
	 * cheriabi_exec_setregs() for the initial thread.
	 */
	csigp = &td->td_pcb->pcb_cherisignal;
	bzero(csigp, sizeof(*csigp));
	/* Note: csig_{ddc,idc,pcc} are set to NULL in the pure-capability abi */
	cheri_capability_set_user_sigcode(&csigp->csig_sigcode,
	    td->td_proc->p_sysent);

	/*
	 * Set up root for the userspace object-type sealing capability tree.
	 * This can be queried using sysarch(2).
	 */
	cheri_capability_set_user_sealcap(&td->td_proc->p_md.md_cheri_sealcap);
}

static void
cheriabi_exec_setregs(struct thread *td, struct image_params *imgp, u_long stack)
{
	struct cheri_signal *csigp;
	struct trapframe *frame;
	u_long auxv, stackbase, stacklen;
	size_t map_base, map_length, text_end, code_start, code_end, code_length;
#ifdef CHERIABI_LEGACY_SUPPORT
	size_t data_length;
#endif
	struct rlimit rlim_stack;
	/* const bool is_dynamic_binary = imgp->interp_end != 0; */
	/* const bool is_rtld_direct_exec = imgp->reloc_base == imgp->start_addr; */

	bzero((caddr_t)td->td_frame, sizeof(struct trapframe));

	KASSERT(stack % sizeof(void * __capability) == 0,
	    ("CheriABI stack pointer not properly aligned"));

	/*
	 * Restrict the stack capability to the maximum region allowed for
	 * this process and adjust csp accordingly.
	 */
	CTASSERT(CHERI_CAP_USER_DATA_BASE == 0);
	PROC_LOCK(td->td_proc);
	lim_rlimit_proc(td->td_proc, RLIMIT_STACK, &rlim_stack);
	PROC_UNLOCK(td->td_proc);
	stackbase = td->td_proc->p_sysent->sv_usrstack - rlim_stack.rlim_max;
	KASSERT(stack > stackbase,
	    ("top of stack 0x%lx is below stack base 0x%lx", stack, stackbase));
	stacklen = stack - stackbase;
	/*
	 * Round the stack down as required to make it representable.
	 */
	stacklen = rounddown2(stacklen, CHERI_REPRESENTABLE_ALIGNMENT(stacklen));
	td->td_frame->csp = cheri_capability_build_user_data(
	    CHERI_CAP_USER_DATA_PERMS, stackbase, stacklen, stacklen);


	/* Using addr as length means ddc base must be 0. */
	CTASSERT(CHERI_CAP_USER_DATA_BASE == 0);
	if (imgp->end_addr != 0) {
		text_end = roundup2(imgp->end_addr,
		    CHERI_SEALABLE_ALIGNMENT(imgp->end_addr - imgp->start_addr));
		/*
		 * Less confusing rounded up to a page and 256-bit
		 * requires no other rounding.
		 */
		text_end = roundup2(text_end, PAGE_SIZE);
	} else {
		text_end = rounddown2(stackbase,
		    CHERI_SEALABLE_ALIGNMENT(stackbase));
	}
	KASSERT(text_end <= stackbase,
	    ("text_end 0x%zx > stackbase 0x%lx", text_end, stackbase));

	map_base = (text_end == stackbase) ?
	    CHERI_CAP_USER_MMAP_BASE :
	    roundup2(text_end, CHERI_REPRESENTABLE_ALIGNMENT(stackbase - text_end));
	KASSERT(map_base < stackbase,
	    ("map_base 0x%zx >= stackbase 0x%lx", map_base, stackbase));
	map_length = stackbase - map_base;
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

	td->td_frame->pc = imgp->entry_addr;
	td->td_frame->sr = MIPS_SR_KSU_USER | MIPS_SR_EXL | MIPS_SR_INT_IE |
	    (mips_rd_status() & MIPS_SR_INT_MASK) |
	    MIPS_SR_PX | MIPS_SR_UX | MIPS_SR_KX | MIPS_SR_COP_2_BIT;

	frame = &td->td_pcb->pcb_regs;
#ifdef CHERIABI_LEGACY_SUPPORT
	/*
	 * XXXAR: data_length needs to be the full address space to allow
	 * legacy ABI to work since the TLS region will be beyond the end of
	 * the text section.
	 *
	 * TODO: Start with a NULL $ddc once we drop legacy ABI support.
	 *
	 * Having a full address space $ddc on startup does not matter for new
	 * binaries since they will all clear $ddc as one of the first user
	 * instructions anyway.
	 */
	data_length = CHERI_CAP_USER_DATA_LENGTH; /* Always representable */
	cheriabi_capability_set_user_ddc(&frame->ddc, data_length);
#endif

	/*
	 * XXXRW: Set $pcc and $c12 to the entry address -- for now, also with
	 * broad bounds, but in the future, limited as appropriate to the
	 * run-time linker or statically linked binary?
	 *
	 */
#ifdef CHERIABI_LEGACY_SUPPORT
#pragma message("Warning: Building kernel with LEGACY ABI support!")
	/*
	 * The legacy ABI needs a full address space $pcc (with base == 0)
	 * to create code capabilities using cgetpccsetoffset
	 */
	code_start = CHERI_CAP_USER_CODE_BASE;
	code_end = CHERI_CAP_USER_CODE_LENGTH;
#else
	/*
	 * If we are executing a static binary we use text_end as the end of
	 * the text segment. If $pcc is the start of rtld we use interp_end.
	 * If we are executing ld-cheri-elf.so.1 directly we can use text_end
	 * to find the end of the rtld mapping.
	 */
	code_end = imgp->interp_end ? imgp->interp_end : text_end;
	/*
	 * Statically linked binaries need a base 0 code capability since
	 * otherwise crt_init_globals_will fail.
	 *
	 * XXXAR: TODO: is this still true??
	 */
	code_start = imgp->interp_end ? imgp->reloc_base : 0;
#endif
	/* Ensure CHERI128 representability */
	code_length = code_end - code_start;
	code_start = CHERI_REPRESENTABLE_BASE(code_start, code_length);
	code_length = CHERI_REPRESENTABLE_LENGTH(code_length);
	code_end = code_start + code_length;
	frame->pcc = cheri_capability_build_user_code(CHERI_CAP_USER_CODE_PERMS,
	    code_start, code_end - code_start, imgp->entry_addr - code_start);
	/* Ensure that frame->pc is the offset of frame->pcc (needed for eret) */
	frame->pc = cheri_getoffset(frame->pcc);
	frame->c12 = frame->pcc;

	/*
	 * Set up CHERI-related state: most register state, signal delivery,
	 * sealing capabilities, trusted stack.
	 */
	cheriabi_newthread_init(td);

	/*
	 * Pass a pointer to the ELF auxiliary argument vector.
	 */
	auxv = stack + (imgp->args->argc + 1 + imgp->args->envc + 1) *
	    sizeof(void * __capability);
	td->td_frame->c3 = cheri_capability_build_user_data(
	    CHERI_CAP_USER_DATA_PERMS, auxv,
	    AT_COUNT * 2 * sizeof(void * __capability), 0);
	/*
	 * Load relocbase for RTLD into $c4 so that rtld has a capability with
	 * the correct bounds available on startup
	 *
	 * XXXAR: this should not be necessary since it should be the same as
	 * auxv[AT_BASE] but trying to load that from $c3 crashes...
	 *
	 * TODO: load the AT_BASE value instead of using duplicated code!
	 */
	if (imgp->reloc_base) {
		vaddr_t rtld_base = imgp->reloc_base;
		vaddr_t rtld_end = imgp->interp_end ? imgp->interp_end : imgp->end_addr;
		vaddr_t rtld_len = rtld_end - rtld_base;
		rtld_base = CHERI_REPRESENTABLE_BASE(rtld_base, rtld_len);
		rtld_len = CHERI_REPRESENTABLE_LENGTH(rtld_len);
		td->td_frame->c4 = cheri_capability_build_user_data(
		    CHERI_CAP_USER_DATA_PERMS, rtld_base, rtld_len, 0);
	}

	/*
	 * Update privileged signal-delivery environment for actual stack.
	 *
	 * XXXRW: Not entirely clear whether we want an offset of 'stacklen'
	 * for csig_csp here.  Maybe we don't want to use csig_csp at all?
	 * Possibly csig_csp should default to NULL...?
	 */
	csigp = &td->td_pcb->pcb_cherisignal;
	csigp->csig_csp = td->td_frame->csp;
	csigp->csig_default_stack = csigp->csig_csp;
#ifdef CHERIABI_LEGACY_SUPPORT
	csigp->csig_ddc = frame->ddc;
#endif


	td->td_md.md_flags &= ~MDTD_FPUSED;
	if (PCPU_GET(fpcurthread) == td)
		PCPU_SET(fpcurthread, (struct thread *)0);
	td->td_md.md_ss_addr = 0;

	td->td_md.md_tls_tcb_offset = TLS_TP_OFFSET_C + TLS_TCB_SIZE_C;
}

/*
 * The CheriABI equivalent of cpu_set_upcall().
 */
void
cheriabi_set_threadregs(struct thread *td, struct thr_param_c *param)
{
	struct cheri_signal *csigp;
	struct trapframe *frame;

	frame = td->td_frame;
	bzero(frame, sizeof(*frame));

	/*
	 * Keep interrupt mask
	 *
	 * XXX-BD: See XXXRW comment in cpu_set_upcall().
	 */
	td->td_frame->sr = MIPS_SR_KSU_USER | MIPS_SR_EXL | MIPS_SR_INT_IE |
	    (mips_rd_status() & MIPS_SR_INT_MASK) |
	    MIPS_SR_PX | MIPS_SR_UX | MIPS_SR_KX | MIPS_SR_COP_2_BIT;

	/*
	 * XXX-BD: cpu_copy_thread() copies the cheri_signal struct.  Do we
	 * want to point it at our stack instead?
	 */
	frame->pc = cheri_getoffset(param->start_func);
	frame->pcc = param->start_func;
	frame->c12 = param->start_func;
	frame->c3 = param->arg;


	/*
	 * Copy the $cgp for the current thread to the new one. This will work
	 * both if the target function is in the current shared object (so the
	 * $cgp value will be the same) or in a different one (in which case it
	 * will point to a PLT stub that loads $cgp).
	 *
	 * XXXAR: could this break anything if sandboxes create threads?
	 */
	frame->idc = curthread->td_frame->idc;

	/*
	 * Set up CHERI-related state: register state, signal delivery,
	 * sealing capabilities, trusted stack.
	 */
	cheriabi_newthread_init(td);

	/*
	 * We don't perform validation on the new pcc or stack capabilities
	 * and just let the caller fail on return if they are bogus.
	 */
	frame->csp = param->stack_base + param->stack_size;

	/*
	 * Update privileged signal-delivery environment for actual stack.
	 *
	 * XXXRW: Not entirely clear whether we want an offset of 'stacklen'
	 * for csig_csp here.  Maybe we don't want to use csig_csp at all?
	 * Possibly csig_csp should default to NULL...?
	 */
	csigp = &td->td_pcb->pcb_cherisignal;
	csigp->csig_csp = td->td_frame->csp;
	csigp->csig_default_stack = csigp->csig_csp;
#ifdef CHERIABI_LEGACY_SUPPORT
	/* Setup $ddc when targeting the legacy ABI */
	frame->ddc = td->td_frame->ddc;
	csigp->csig_ddc = td->td_frame->ddc;
#endif
}

int
cheriabi_set_user_tls(struct thread *td, void * __capability tls_base)
{

	td->td_md.md_tls_tcb_offset = TLS_TP_OFFSET_C + TLS_TCB_SIZE_C;
	/* XXX-AR: add a TLS alignment check here */
	td->td_md.md_tls = tls_base;
	/* XXX-JC: only use cwritehwr */
	if (curthread == td) {
		__asm __volatile ("cwritehwr %0, $chwr_userlocal"
				  :
				  : "C" ((char * __capability)td->td_md.md_tls +
				      td->td_md.md_tls_tcb_offset));
	}
#ifdef CHERIABI_LEGACY_SUPPORT
#pragma message("Warning: Building with support for LEGACY TLS")
	if (curthread == td && cpuinfo.userlocal_reg == true) {
		/*
		 * If there is an user local register implementation
		 * (ULRI) update it as well.  Add the TLS and TCB
		 * offsets so the value in this register is
		 * adjusted like in the case of the rdhwr trap()
		 * instruction handler.
		 *
		 * The user local register needs the TLS and TCB
		 * offsets because the compiler simply generates a
		 * 'rdhwr reg, $29' instruction to access thread local
		 * storage (i.e., variables with the '_thread'
		 * attribute).
		 */
		mips_wr_userlocal((__cheri_addr u_long)td->td_md.md_tls +
		    td->td_md.md_tls_tcb_offset);
	}
#endif

	return (0);
}

int
cheriabi_sysarch(struct thread *td, struct cheriabi_sysarch_args *uap)
{
	int error;
#ifdef CPU_QEMU_MALTA
	int intval;
#endif

	switch (uap->op) {
	/*
	 * Operations shared with MIPS.
	 */
	case MIPS_SET_TLS:
		return (cheriabi_set_user_tls(td, uap->parms));

	case MIPS_GET_TLS:
		error = copyoutcap(&td->td_md.md_tls, uap->parms,
		    sizeof(void * __capability));
		return (error);

#ifdef CPU_QEMU_MALTA
	case QEMU_GET_QTRACE:
		intval = (td->td_md.md_flags & MDTD_QTRACE) ? 1 : 0;
		error = copyout(&intval, uap->parms, sizeof(intval));
		return (error);

	case QEMU_SET_QTRACE:
		error = copyin(uap->parms, &intval, sizeof(intval));
		if (error)
			return (error);
		if (intval)
			td->td_md.md_flags |= MDTD_QTRACE;
		else
			td->td_md.md_flags &= ~MDTD_QTRACE;
		return (0);
#endif

	case CHERI_GET_SEALCAP:
		return (cheri_sysarch_getsealcap(td, uap->parms));

	/*
	 * CheriABI specific operations.
	 */
	case CHERI_MMAP_GETBASE: {
		size_t base;

		base = cheri_getbase(td->td_md.md_cheri_mmap_cap);
		if (suword(uap->parms, base) != 0)
			return (EFAULT);
		return (0);
	}

	case CHERI_MMAP_GETLEN: {
		size_t len;

		len = cheri_getlen(td->td_md.md_cheri_mmap_cap);
		if (suword(uap->parms, len) != 0)
			return (EFAULT);
		return (0);
	}

	case CHERI_MMAP_GETOFFSET: {
		ssize_t offset;

		offset = cheri_getoffset(td->td_md.md_cheri_mmap_cap);
		if (suword(uap->parms, offset) != 0)
			return (EFAULT);
		return (0);
	}

	case CHERI_MMAP_GETPERM: {
		uint64_t perms;

		perms = cheri_getperm(td->td_md.md_cheri_mmap_cap);
		if (suword64(uap->parms, perms) != 0)
			return (EFAULT);
		return (0);
	}

	case CHERI_MMAP_ANDPERM: {
		uint64_t perms;
		perms = fuword64(uap->parms);

		if (perms == -1)
			return (EINVAL);
		td->td_md.md_cheri_mmap_cap =
		    cheri_andperm(td->td_md.md_cheri_mmap_cap, perms);
		perms = cheri_getperm(td->td_md.md_cheri_mmap_cap);
		if (suword64(uap->parms, perms) != 0)
			return (EFAULT);
		return (0);
	}

	case CHERI_MMAP_SETOFFSET: {
		size_t len;
		ssize_t offset;

		offset = fuword(uap->parms);
		/* Reject errors and misaligned offsets */
		if (offset == -1 || (offset & PAGE_MASK) != 0)
			return (EINVAL);
		len = cheri_getlen(td->td_md.md_cheri_mmap_cap);
		/* Don't allow out of bounds offsets, they aren't useful */
		if (offset < 0 || offset > len) {
			return (EINVAL);
		}
		td->td_md.md_cheri_mmap_cap =
		    cheri_setoffset(td->td_md.md_cheri_mmap_cap,
		    (register_t)offset);
		return (0);
	}

	case CHERI_MMAP_SETBOUNDS: {
		size_t len, olen;
		ssize_t offset;

		len = fuword(uap->parms);
		/* Reject errors or misaligned lengths */
		if (len == (size_t)-1 || (len & PAGE_MASK) != 0)
			return (EINVAL);
		olen = cheri_getlen(td->td_md.md_cheri_mmap_cap);
		offset = cheri_getoffset(td->td_md.md_cheri_mmap_cap);
		/* Don't try to set out of bounds lengths */
		if (offset > olen || len > olen - offset) {
			return (EINVAL);
		}
		td->td_md.md_cheri_mmap_cap =
		    cheri_csetbounds(td->td_md.md_cheri_mmap_cap,
		    (register_t)len);
		return (0);
	}

	default:
		return (EINVAL);
	}
}
