/*-
 * Copyright (c) 2014 Andrew Turner
 * Copyright (c) 2015-2017 Ruslan Bukin <br@bsdpad.com>
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
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/exec.h>
#include <sys/imgact.h>
#include <sys/kdb.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/rwlock.h>
#include <sys/sched.h>
#include <sys/signalvar.h>
#include <sys/syscallsubr.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/ucontext.h>

#include <machine/cpu.h>
#include <machine/kdb.h>
#include <machine/pcb.h>
#include <machine/pte.h>
#include <machine/riscvreg.h>
#include <machine/sbi.h>
#include <machine/trap.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>

#ifdef FPE
#include <machine/fpe.h>
#endif

static void get_fpcontext(struct thread *td, mcontext_t *mcp);
static void set_fpcontext(struct thread *td, mcontext_t *mcp);

#if __has_feature(capabilities)
_Static_assert(sizeof(mcontext_t) == 1152, "mcontext_t size incorrect");
_Static_assert(sizeof(ucontext_t) == 1248, "ucontext_t size incorrect");
_Static_assert(sizeof(siginfo_t) == 112, "siginfo_t size incorrect");
#else
_Static_assert(sizeof(mcontext_t) == 864, "mcontext_t size incorrect");
_Static_assert(sizeof(ucontext_t) == 936, "ucontext_t size incorrect");
_Static_assert(sizeof(siginfo_t) == 80, "siginfo_t size incorrect");
#endif

/*
 * XXX: CHERI TODO: Eventually 'struct reg' should use capregs for purecap
 * which would make this much cleaner.
 */
int
fill_regs(struct thread *td, struct reg *regs)
{
	struct trapframe *frame;
#if __has_feature(capabilities)
	u_int i;
#endif

	frame = td->td_frame;
	regs->sepc = (__cheri_addr register_t)frame->tf_sepc;
	regs->sstatus = frame->tf_sstatus;
	regs->ra = (__cheri_addr register_t)frame->tf_ra;
	regs->sp = (__cheri_addr register_t)frame->tf_sp;
	regs->gp = (__cheri_addr register_t)frame->tf_gp;
	regs->tp = (__cheri_addr register_t)frame->tf_tp;

#if __has_feature(capabilities)
	for (i = 0; i < nitems(regs->t); i++)
		regs->t[i] = (__cheri_addr register_t)frame->tf_t[i];
	for (i = 0; i < nitems(regs->s); i++)
		regs->s[i] = (__cheri_addr register_t)frame->tf_s[i];
	for (i = 0; i < nitems(regs->a); i++)
		regs->a[i] = (__cheri_addr register_t)frame->tf_a[i];
#else
	memcpy(regs->t, frame->tf_t, sizeof(regs->t));
	memcpy(regs->s, frame->tf_s, sizeof(regs->s));
	memcpy(regs->a, frame->tf_a, sizeof(regs->a));
#endif

	return (0);
}

int
set_regs(struct thread *td, struct reg *regs)
{
	struct trapframe *frame;
#if __has_feature(capabilities)
	u_int i;
#endif

	frame = td->td_frame;
#if __has_feature(capabilities)
	frame->tf_sepc = cheri_setaddress(frame->tf_sepc, regs->sepc);
#else
	frame->tf_sepc = regs->sepc;
#endif
	frame->tf_ra = (uintcap_t)regs->ra;
	frame->tf_sp = (uintcap_t)regs->sp;
	frame->tf_gp = (uintcap_t)regs->gp;
	frame->tf_tp = (uintcap_t)regs->tp;

#if __has_feature(capabilities)
	for (i = 0; i < nitems(regs->t); i++)
		frame->tf_t[i] = (uintcap_t)regs->t[i];
	for (i = 0; i < nitems(regs->s); i++)
		frame->tf_s[i] = (uintcap_t)regs->s[i];
	for (i = 0; i < nitems(regs->a); i++)
		frame->tf_a[i] = (uintcap_t)regs->a[i];
#else
	memcpy(frame->tf_t, regs->t, sizeof(frame->tf_t));
	memcpy(frame->tf_s, regs->s, sizeof(frame->tf_s));
	memcpy(frame->tf_a, regs->a, sizeof(frame->tf_a));
#endif

	return (0);
}

int
fill_fpregs(struct thread *td, struct fpreg *regs)
{
#ifdef FPE
	struct pcb *pcb;

	pcb = td->td_pcb;

	if ((pcb->pcb_fpflags & PCB_FP_STARTED) != 0) {
		/*
		 * If we have just been running FPE instructions we will
		 * need to save the state to memcpy it below.
		 */
		if (td == curthread)
			fpe_state_save(td);

		memcpy(regs->fp_x, pcb->pcb_x, sizeof(regs->fp_x));
		regs->fp_fcsr = pcb->pcb_fcsr;
	} else
#endif
		memset(regs, 0, sizeof(*regs));

	return (0);
}

int
set_fpregs(struct thread *td, struct fpreg *regs)
{
#ifdef FPE
	struct trapframe *frame;
	struct pcb *pcb;

	frame = td->td_frame;
	pcb = td->td_pcb;

	memcpy(pcb->pcb_x, regs->fp_x, sizeof(regs->fp_x));
	pcb->pcb_fcsr = regs->fp_fcsr;
	pcb->pcb_fpflags |= PCB_FP_STARTED;
	frame->tf_sstatus &= ~SSTATUS_FS_MASK;
	frame->tf_sstatus |= SSTATUS_FS_CLEAN;
#endif

	return (0);
}

int
fill_dbregs(struct thread *td, struct dbreg *regs)
{

	panic("fill_dbregs");
}

int
set_dbregs(struct thread *td, struct dbreg *regs)
{

	panic("set_dbregs");
}

#if __has_feature(capabilities)
/* Number of capability registers in 'struct capreg'. */
#define	NCAPREGS	(offsetof(struct capreg, tagmask) / sizeof(uintcap_t))

int
fill_capregs(struct thread *td, struct capreg *regs)
{
	struct trapframe *frame;
	uintcap_t *pcap;
	u_int i;

	frame = td->td_frame;
	memset(regs, 0, sizeof(*regs));
	regs->cra = frame->tf_ra;
	regs->csp = frame->tf_sp;
	regs->cgp = frame->tf_gp;
	regs->ctp = frame->tf_tp;
	memcpy(regs->ct, frame->tf_t, sizeof(regs->ct));
	memcpy(regs->cs, frame->tf_s, sizeof(regs->cs));
	memcpy(regs->ca, frame->tf_a, sizeof(regs->ca));
	regs->sepcc = frame->tf_sepc;
	regs->ddc = frame->tf_ddc;
	pcap = (uintcap_t *)regs;
	for (i = 0; i < NCAPREGS; i++) {
		if (cheri_gettag(pcap[i]))
			regs->tagmask |= (uint64_t)1 << i;
	}
	return (0);
}

int
set_capregs(struct thread *td, struct capreg *regs)
{

	return (EOPNOTSUPP);
}
#endif

void
exec_setregs(struct thread *td, struct image_params *imgp, uintcap_t stack)
{
	struct trapframe *tf;
	struct pcb *pcb;

	tf = td->td_frame;
	pcb = td->td_pcb;

	memset(tf, 0, sizeof(struct trapframe));

#if __has_feature(capabilities)
	if (SV_PROC_FLAG(td->td_proc, SV_CHERI)) {
		tf->tf_a[0] = (uintcap_t)imgp->auxv;
		tf->tf_sp = stack;
		tf->tf_sepc = (uintcap_t)cheri_exec_pcc(td, imgp);
		td->td_proc->p_md.md_sigcode = cheri_sigcode_capability(td);
	} else
#endif
	{
		tf->tf_a[0] = (__cheri_addr ptraddr_t)stack;
		tf->tf_sp = STACKALIGN((__cheri_addr ptraddr_t)stack);
#if __has_feature(capabilities)
		hybridabi_thread_setregs(td, imgp->entry_addr);
#else
		tf->tf_sepc = imgp->entry_addr;
#endif
	}
	tf->tf_ra = tf->tf_sepc;

	pcb->pcb_fpflags &= ~PCB_FP_STARTED;
}

/* Sanity check these are the same size, they will be memcpy'd to and fro */
#if __has_feature(capabilities)
CTASSERT(sizeof(((struct trapframe *)0)->tf_a) ==
    sizeof((struct capregs *)0)->cp_ca);
CTASSERT(sizeof(((struct trapframe *)0)->tf_s) ==
    sizeof((struct capregs *)0)->cp_cs);
CTASSERT(sizeof(((struct trapframe *)0)->tf_t) ==
    sizeof((struct capregs *)0)->cp_ct);
#else
CTASSERT(sizeof(((struct trapframe *)0)->tf_a) ==
    sizeof((struct gpregs *)0)->gp_a);
CTASSERT(sizeof(((struct trapframe *)0)->tf_s) ==
    sizeof((struct gpregs *)0)->gp_s);
CTASSERT(sizeof(((struct trapframe *)0)->tf_t) ==
    sizeof((struct gpregs *)0)->gp_t);
CTASSERT(sizeof(((struct trapframe *)0)->tf_a) ==
    sizeof((struct reg *)0)->a);
CTASSERT(sizeof(((struct trapframe *)0)->tf_s) ==
    sizeof((struct reg *)0)->s);
CTASSERT(sizeof(((struct trapframe *)0)->tf_t) ==
    sizeof((struct reg *)0)->t);
#endif

int
get_mcontext(struct thread *td, mcontext_t *mcp, int clear_ret)
{
	struct trapframe *tf = td->td_frame;

#if __has_feature(capabilities)
	memcpy(mcp->mc_capregs.cp_ct, tf->tf_t, sizeof(mcp->mc_capregs.cp_ct));
	memcpy(mcp->mc_capregs.cp_cs, tf->tf_s, sizeof(mcp->mc_capregs.cp_cs));
	memcpy(mcp->mc_capregs.cp_ca, tf->tf_a, sizeof(mcp->mc_capregs.cp_ca));

	if (clear_ret & GET_MC_CLEAR_RET) {
		mcp->mc_capregs.cp_ca[0] = 0;
		mcp->mc_capregs.cp_ct[0] = 0; /* clear syscall error */
	}

	mcp->mc_capregs.cp_cra = tf->tf_ra;
	mcp->mc_capregs.cp_csp = tf->tf_sp;
	mcp->mc_capregs.cp_cgp = tf->tf_gp;
	mcp->mc_capregs.cp_ctp = tf->tf_tp;
	mcp->mc_capregs.cp_sepcc = tf->tf_sepc;
	mcp->mc_capregs.cp_ddc = tf->tf_ddc;
	mcp->mc_capregs.cp_sstatus = tf->tf_sstatus;
#else
	memcpy(mcp->mc_gpregs.gp_t, tf->tf_t, sizeof(mcp->mc_gpregs.gp_t));
	memcpy(mcp->mc_gpregs.gp_s, tf->tf_s, sizeof(mcp->mc_gpregs.gp_s));
	memcpy(mcp->mc_gpregs.gp_a, tf->tf_a, sizeof(mcp->mc_gpregs.gp_a));

	if (clear_ret & GET_MC_CLEAR_RET) {
		mcp->mc_gpregs.gp_a[0] = 0;
		mcp->mc_gpregs.gp_t[0] = 0; /* clear syscall error */
	}

	mcp->mc_gpregs.gp_ra = tf->tf_ra;
	mcp->mc_gpregs.gp_sp = tf->tf_sp;
	mcp->mc_gpregs.gp_gp = tf->tf_gp;
	mcp->mc_gpregs.gp_tp = tf->tf_tp;
	mcp->mc_gpregs.gp_sepc = tf->tf_sepc;
	mcp->mc_gpregs.gp_sstatus = tf->tf_sstatus;
#endif
	get_fpcontext(td, mcp);

	return (0);
}

int
set_mcontext(struct thread *td, mcontext_t *mcp)
{
	struct trapframe *tf;
	register_t new_sstatus;

	tf = td->td_frame;

#if __has_feature(capabilities)
	new_sstatus = mcp->mc_capregs.cp_sstatus;
#else
	new_sstatus = mcp->mc_gpregs.gp_sstatus;
#endif

	/*
	 * Permit changes to the USTATUS bits of SSTATUS.
	 *
	 * Ignore writes to read-only bits (SD, XS).
	 *
	 * Ignore writes to the FS field as set_fpcontext() will set
	 * it explicitly.
	 */
	if (((new_sstatus ^ tf->tf_sstatus) &
	    ~(SSTATUS_SD | SSTATUS_XS_MASK | SSTATUS_FS_MASK | SSTATUS_UPIE |
	    SSTATUS_UIE)) != 0)
		return (EINVAL);

#if __has_feature(capabilities)
	memcpy(tf->tf_t, mcp->mc_capregs.cp_ct, sizeof(tf->tf_t));
	memcpy(tf->tf_s, mcp->mc_capregs.cp_cs, sizeof(tf->tf_s));
	memcpy(tf->tf_a, mcp->mc_capregs.cp_ca, sizeof(tf->tf_a));

	tf->tf_ra = mcp->mc_capregs.cp_cra;
	tf->tf_sp = mcp->mc_capregs.cp_csp;
	tf->tf_gp = mcp->mc_capregs.cp_cgp;
	tf->tf_sepc = mcp->mc_capregs.cp_sepcc;
	tf->tf_ddc = mcp->mc_capregs.cp_ddc;
	tf->tf_sstatus = mcp->mc_capregs.cp_sstatus;
#else
	memcpy(tf->tf_t, mcp->mc_gpregs.gp_t, sizeof(tf->tf_t));
	memcpy(tf->tf_s, mcp->mc_gpregs.gp_s, sizeof(tf->tf_s));
	memcpy(tf->tf_a, mcp->mc_gpregs.gp_a, sizeof(tf->tf_a));

	tf->tf_ra = mcp->mc_gpregs.gp_ra;
	tf->tf_sp = mcp->mc_gpregs.gp_sp;
	tf->tf_gp = mcp->mc_gpregs.gp_gp;
	tf->tf_sepc = mcp->mc_gpregs.gp_sepc;
	tf->tf_sstatus = mcp->mc_gpregs.gp_sstatus;
#endif
	set_fpcontext(td, mcp);

	return (0);
}

static void
get_fpcontext(struct thread *td, mcontext_t *mcp)
{
#ifdef FPE
	struct pcb *curpcb;

	critical_enter();

	curpcb = curthread->td_pcb;

	KASSERT(td->td_pcb == curpcb, ("Invalid fpe pcb"));

	if ((curpcb->pcb_fpflags & PCB_FP_STARTED) != 0) {
		/*
		 * If we have just been running FPE instructions we will
		 * need to save the state to memcpy it below.
		 */
		fpe_state_save(td);

		KASSERT((curpcb->pcb_fpflags & ~PCB_FP_USERMASK) == 0,
		    ("Non-userspace FPE flags set in get_fpcontext"));
		memcpy(mcp->mc_fpregs.fp_x, curpcb->pcb_x,
		    sizeof(mcp->mc_fpregs.fp_x));
		mcp->mc_fpregs.fp_fcsr = curpcb->pcb_fcsr;
		mcp->mc_fpregs.fp_flags = curpcb->pcb_fpflags;
		mcp->mc_flags |= _MC_FP_VALID;
	}

	critical_exit();
#endif
}

static void
set_fpcontext(struct thread *td, mcontext_t *mcp)
{
#ifdef FPE
	struct pcb *curpcb;
#endif

	td->td_frame->tf_sstatus &= ~SSTATUS_FS_MASK;
	td->td_frame->tf_sstatus |= SSTATUS_FS_OFF;

#ifdef FPE
	critical_enter();

	if ((mcp->mc_flags & _MC_FP_VALID) != 0) {
		curpcb = curthread->td_pcb;
		/* FPE usage is enabled, override registers. */
		memcpy(curpcb->pcb_x, mcp->mc_fpregs.fp_x,
		    sizeof(mcp->mc_fpregs.fp_x));
		curpcb->pcb_fcsr = mcp->mc_fpregs.fp_fcsr;
		curpcb->pcb_fpflags = mcp->mc_fpregs.fp_flags & PCB_FP_USERMASK;
		td->td_frame->tf_sstatus |= SSTATUS_FS_CLEAN;
	}

	critical_exit();
#endif
}

int
sys_sigreturn(struct thread *td, struct sigreturn_args *uap)
{
	ucontext_t uc;
	int error;

	if (copyincap(uap->sigcntxp, &uc, sizeof(uc)))
		return (EFAULT);

	error = set_mcontext(td, &uc.uc_mcontext);
	if (error != 0)
		return (error);

	/* Restore signal mask. */
	kern_sigprocmask(td, SIG_SETMASK, &uc.uc_sigmask, NULL, 0);

	return (EJUSTRETURN);
}

void
sendsig(sig_t catcher, ksiginfo_t *ksi, sigset_t *mask)
{
	struct sigframe * __capability fp, frame;
#if !__has_feature(capabilities)
	struct sysentvec *sysent;
#endif
	struct trapframe *tf;
	struct sigacts *psp;
	struct thread *td;
	struct proc *p;
	int onstack;
	int sig;

	td = curthread;
	p = td->td_proc;
	PROC_LOCK_ASSERT(p, MA_OWNED);

	sig = ksi->ksi_signo;
	psp = p->p_sigacts;
	mtx_assert(&psp->ps_mtx, MA_OWNED);

	tf = td->td_frame;

	/*
	 * XXXCHERI: We make an on-stack determination using the
	 * virtual address associated with the stack pointer, rather
	 * than using the full capability.  Should we compare the
	 * entire capability...?  Just pointer and bounds...?
	 */
	onstack = sigonstack(tf->tf_sp);

	CTR4(KTR_SIG, "sendsig: td=%p (%s) catcher=%p sig=%d", td, p->p_comm,
	    (__cheri_addr ptraddr_t)catcher, sig);

	/* Allocate and validate space for the signal handler context. */
	if ((td->td_pflags & TDP_ALTSTACK) != 0 && !onstack &&
	    SIGISMEMBER(psp->ps_sigonstack, sig)) {
		fp = (struct sigframe * __capability)((uintcap_t)td->td_sigstk.ss_sp +
		    td->td_sigstk.ss_size);
	} else {
		fp = (struct sigframe * __capability)td->td_frame->tf_sp;
	}

	/* Make room, keeping the stack aligned */
	fp--;
	fp = STACKALIGN(fp);

	/* Fill in the frame to copy out */
	bzero(&frame, sizeof(frame));
	get_mcontext(td, &frame.sf_uc.uc_mcontext, 0);
	frame.sf_si = ksi->ksi_info;
	frame.sf_uc.uc_sigmask = *mask;
	frame.sf_uc.uc_stack = td->td_sigstk;
	frame.sf_uc.uc_stack.ss_flags = (td->td_pflags & TDP_ALTSTACK) != 0 ?
	    (onstack ? SS_ONSTACK : 0) : SS_DISABLE;
	mtx_unlock(&psp->ps_mtx);
	PROC_UNLOCK(td->td_proc);

	/* Copy the sigframe out to the user's stack. */
	if (copyoutcap(&frame, fp, sizeof(*fp)) != 0) {
		/* Process has trashed its stack. Kill it. */
		CTR2(KTR_SIG, "sendsig: sigexit td=%p fp=%p", td,
				(__cheri_addr ptraddr_t)fp);
		PROC_LOCK(p);
		sigexit(td, SIGILL);
	}

	tf->tf_a[0] = sig;
#if __has_feature(capabilities)
	tf->tf_a[1] = (uintcap_t)cheri_setbounds(&fp->sf_si,
	    sizeof(fp->sf_si));
	tf->tf_a[2] = (uintcap_t)cheri_setbounds(&fp->sf_uc,
	    sizeof(fp->sf_uc));
#else
	tf->tf_a[1] = (register_t)&fp->sf_si;
	tf->tf_a[2] = (register_t)&fp->sf_uc;
#endif

	tf->tf_sepc = (uintcap_t)catcher;
	tf->tf_sp = (uintcap_t)fp;

#if __has_feature(capabilities)
	tf->tf_ra = (uintcap_t)p->p_md.md_sigcode;
#else
	sysent = p->p_sysent;
	if (PROC_HAS_SHP(p))
		tf->tf_ra = (register_t)PROC_SIGCODE(p);
	else
		tf->tf_ra = (register_t)(PROC_PS_STRINGS(p) -
		    *(sysent->sv_szsigcode));
#endif

	CTR3(KTR_SIG, "sendsig: return td=%p pc=%#x sp=%#x", td, tf->tf_sepc,
	    tf->tf_sp);

	PROC_LOCK(p);
	mtx_lock(&psp->ps_mtx);
}
