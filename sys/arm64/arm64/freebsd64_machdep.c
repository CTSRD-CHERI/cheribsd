/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 1996-1998 John D. Polstra.
 * All rights reserved.
 * Copyright (c) 2015 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 * Copyright (c) 2016 Yukishige Shibata <y-shibat@mtd.biglobe.ne.jp>
 * All rights reserved.
 * Copyright (c) 2020 John Baldwin
 *
 * Portions of this software were developed by SRI International and the
 * University of Cambridge Computer Laboratory under DARPA/AFRL contract
 * FA8750-10-C-0237 ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Portions of this software were developed by the University of Cambridge
 * Computer Laboratory as part of the CTSRD Project, with support from the
 * UK Higher Education Innovation Fund (HEIF).
 *
 * Portions of this software were developed by SRI International and the
 * University of Cambridge Computer Laboratory (Department of Computer
 * Science and Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"),
 * as part of the DARPA SSITH research programme.
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

#define __ELF_WORD_SIZE 64

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/imgact.h>
#include <sys/imgact_elf.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/proc.h>
#include <sys/syscallsubr.h>
#include <sys/sysent.h>
#include <sys/ucontext.h>

#include <machine/md_var.h>

#include <cheri/cheric.h>

#include <compat/freebsd64/freebsd64_proto.h>
#include <compat/freebsd64/freebsd64_syscall.h>
#include <compat/freebsd64/freebsd64_util.h>

extern u_long elf_hwcap;

static void	freebsd64_sendsig(sig_t, ksiginfo_t *, sigset_t *);

extern const char *freebsd64_syscallnames[];

struct sysentvec elf_freebsd_freebsd64_sysvec = {
	.sv_size	= FREEBSD64_SYS_MAXSYSCALL,
	.sv_table	= freebsd64_sysent,
	.sv_errsize	= 0,
	.sv_errtbl	= NULL,
	.sv_transtrap	= NULL,
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
	.sv_stackprot	= VM_PROT_READ | VM_PROT_WRITE,
	.sv_copyout_auxargs = __elfN(freebsd_copyout_auxargs),
	.sv_copyout_strings = freebsd64_copyout_strings,
	.sv_setregs	= exec_setregs,
	.sv_fixlimit	= NULL,
	.sv_maxssiz	= NULL,
	.sv_flags	= SV_SHP | SV_ABI_FREEBSD | SV_LP64 |
	    SV_ASLR,
	.sv_set_syscall_retval = cpu_set_syscall_retval,
	.sv_fetch_syscall_args = cpu_fetch_syscall_args,
	.sv_syscallnames = freebsd64_syscallnames,
	.sv_shared_page_base = SHAREDPAGE,
	.sv_shared_page_len = PAGE_SIZE,
	.sv_schedtail	= NULL,
	.sv_thread_detach = NULL,
	.sv_trap	= NULL,
	.sv_hwcap	= &elf_hwcap,
};
INIT_SYSENTVEC(freebsd64_sysent, &elf_freebsd_freebsd64_sysvec);

static Elf64_Brandinfo freebsd_freebsd64_brand_info = {
	.brand		= ELFOSABI_FREEBSD,
	.machine	= EM_AARCH64,
	.compat_3_brand	= "FreeBSD",
	.emul_path	= NULL,
	.interp_path	= "/libexec/ld-elf.so.1",
	.sysvec		= &elf_freebsd_freebsd64_sysvec,
	.interp_newpath = "/libexec/ld-elf64.so.1",
	.brand_note	= &elf64_freebsd_brandnote,
	.flags		= BI_CAN_EXEC_DYN | BI_BRAND_NOTE,
};

SYSINIT(freebsd64, SI_SUB_EXEC, SI_ORDER_ANY,
    (sysinit_cfunc_t) elf64_insert_brand_entry,
    &freebsd_freebsd64_brand_info);

static void
get_fpcontext64(struct thread *td, mcontext64_t *mcp)
{
#ifdef VFP
	struct pcb *curpcb;

	critical_enter();

	curpcb = curthread->td_pcb;

	if ((curpcb->pcb_fpflags & PCB_FP_STARTED) != 0) {
		/*
		 * If we have just been running VFP instructions we will
		 * need to save the state to memcpy it below.
		 */
		vfp_save_state(td, curpcb);

		KASSERT(curpcb->pcb_fpusaved == &curpcb->pcb_fpustate,
		    ("Called get_fpcontext while the kernel is using the VFP"));
		KASSERT((curpcb->pcb_fpflags & ~PCB_FP_USERMASK) == 0,
		    ("Non-userspace FPU flags set in get_fpcontext"));
		memcpy(mcp->mc_fpregs.fp_q, curpcb->pcb_fpustate.vfp_regs,
		    sizeof(mcp->mc_fpregs));
		mcp->mc_fpregs.fp_cr = curpcb->pcb_fpustate.vfp_fpcr;
		mcp->mc_fpregs.fp_sr = curpcb->pcb_fpustate.vfp_fpsr;
		mcp->mc_fpregs.fp_flags = curpcb->pcb_fpflags;
		mcp->mc_flags |= _MC_FP_VALID;
	}

	critical_exit();
#endif
}

static void
set_fpcontext64(struct thread *td, mcontext64_t *mcp)
{
#ifdef VFP
	struct pcb *curpcb;

	critical_enter();

	if ((mcp->mc_flags & _MC_FP_VALID) != 0) {
		curpcb = curthread->td_pcb;

		/*
		 * Discard any vfp state for the current thread, we
		 * are about to override it.
		 */
		vfp_discard(td);

		KASSERT(curpcb->pcb_fpusaved == &curpcb->pcb_fpustate,
		    ("Called set_fpcontext while the kernel is using the VFP"));
		memcpy(curpcb->pcb_fpustate.vfp_regs, mcp->mc_fpregs.fp_q,
		    sizeof(mcp->mc_fpregs));
		curpcb->pcb_fpustate.vfp_fpcr = mcp->mc_fpregs.fp_cr;
		curpcb->pcb_fpustate.vfp_fpsr = mcp->mc_fpregs.fp_sr;
		curpcb->pcb_fpflags = mcp->mc_fpregs.fp_flags & PCB_FP_USERMASK;
	}

	critical_exit();
#endif
}

int
freebsd64_get_mcontext(struct thread *td, mcontext64_t *mcp, int flags)
{
	struct trapframe *tf = td->td_frame;
	int i;

	if (flags & GET_MC_CLEAR_RET) {
		mcp->mc_gpregs.gp_x[0] = 0;
		mcp->mc_gpregs.gp_spsr = tf->tf_spsr & ~PSR_C;
	} else {
		mcp->mc_gpregs.gp_x[0] = tf->tf_x[0];
		mcp->mc_gpregs.gp_spsr = tf->tf_spsr;
	}

	for (i = 1; i < nitems(tf->tf_x); i++)
		mcp->mc_gpregs.gp_x[i] = tf->tf_x[i];

	mcp->mc_gpregs.gp_sp = tf->tf_sp;
	mcp->mc_gpregs.gp_lr = tf->tf_lr;
	mcp->mc_gpregs.gp_elr = tf->tf_elr;
	get_fpcontext64(td, mcp);

	return (0);
}

int
freebsd64_set_mcontext(struct thread *td, mcontext64_t *mcp)
{
	struct trapframe *tf = td->td_frame;
	uint32_t spsr;
	int i;

	spsr = mcp->mc_gpregs.gp_spsr;
	if ((spsr & PSR_M_MASK) != PSR_M_EL0t ||
	    (spsr & PSR_AARCH32) != 0 ||
	    (spsr & PSR_DAIF) != (td->td_frame->tf_spsr & PSR_DAIF))
		return (EINVAL);

	for (i = 0; i < nitems(tf->tf_x); i++)
		tf->tf_x[i] = mcp->mc_gpregs.gp_x[i];

	tf->tf_sp = mcp->mc_gpregs.gp_sp;
	tf->tf_lr = mcp->mc_gpregs.gp_lr;
	tf->tf_elr = mcp->mc_gpregs.gp_elr;
	tf->tf_spsr = mcp->mc_gpregs.gp_spsr;
	set_fpcontext64(td, mcp);

	return (0);
}

static void
freebsd64_sendsig(sig_t catcher, ksiginfo_t *ksi, sigset_t *mask)
{
	struct sigframe64 *fp, frame;
	//mcontext64_t mc;
	struct sysentvec *sysent;
	struct trapframe *tf;
	struct sigacts *psp;
	struct thread *td;
	struct proc *p;
	vm_offset_t sp; //, capregs;
	int onstack;
	int sig;

	td = curthread;
	p = td->td_proc;
	PROC_LOCK_ASSERT(p, MA_OWNED);

	sig = ksi->ksi_signo;
	psp = p->p_sigacts;
	mtx_assert(&psp->ps_mtx, MA_OWNED);

	tf = td->td_frame;
	onstack = sigonstack(tf->tf_sp);

	CTR4(KTR_SIG, "sendsig: td=%p (%s) catcher=%p sig=%d", td, p->p_comm,
	    catcher, sig);

	/* Allocate and validate space for the signal handler context. */
	if ((td->td_pflags & TDP_ALTSTACK) != 0 && !onstack &&
	    SIGISMEMBER(psp->ps_sigonstack, sig)) {
		sp = ((__cheri_addr uintptr_t)td->td_sigstk.ss_sp +
		    td->td_sigstk.ss_size);
	} else {
		sp = (__cheri_addr uintptr_t)td->td_frame->tf_sp;
	}

#if 0
	/* Allocate room for the capability register context. */
	sp -= sizeof(mc.mc_capregs);
	sp = rounddown2(sp, sizeof(uintcap_t));
	capregs = sp;
#endif

	/* Make room, keeping the stack aligned */
	sp -= sizeof(*fp);
	sp = STACKALIGN(sp);
	fp = (struct sigframe64 *)sp;

	/* Fill in the frame to copy out */
	bzero(&frame, sizeof(frame));
	freebsd64_get_mcontext(td, &frame.sf_uc.uc_mcontext, 0);
	//frame.sf_uc.uc_mcontext.mc_flags |= _MC_CAP_VALID;
	//frame.sf_uc.uc_mcontext.mc_capregs = capregs;
	siginfo_to_siginfo64(&ksi->ksi_info, &frame.sf_si);
	frame.sf_uc.uc_sigmask = *mask;
	frame.sf_uc.uc_stack.ss_sp = (__cheri_addr uintptr_t)td->td_sigstk.ss_sp;
	frame.sf_uc.uc_stack.ss_size = td->td_sigstk.ss_size;
	frame.sf_uc.uc_stack.ss_flags = (td->td_pflags & TDP_ALTSTACK) != 0 ?
	    (onstack ? SS_ONSTACK : 0) : SS_DISABLE;
	mtx_unlock(&psp->ps_mtx);
	PROC_UNLOCK(td->td_proc);

#if 0
	/* Copy the capability registers out to the user's stack. */
	if (copyoutcap(&mc.mc_capregs, __USER_CAP(capregs,
	    sizeof(mc.mc_capregs)), sizeof(mc.mc_capregs)) != 0) {
		PROC_LOCK(p);
		printf("pid %d, tid %d: could not copy out cap registers\n",
		    td->td_proc->p_pid, td->td_tid);
		sigexit(td, SIGILL);
		/* NOTREACHED */
	}
#endif

	/* Copy the sigframe out to the user's stack. */
	if (copyoutcap(&frame, __USER_CAP_OBJ(fp), sizeof(*fp)) != 0) {
		/* Process has trashed its stack. Kill it. */
		CTR2(KTR_SIG, "sendsig: sigexit td=%p fp=%p", td, fp);
		PROC_LOCK(p);
		sigexit(td, SIGILL);
	}

	tf->tf_x[0]= sig;
	tf->tf_x[1] = (uintcap_t)&fp->sf_si;
	tf->tf_x[2] = (uintcap_t)&fp->sf_uc;

	tf->tf_elr = (uintcap_t)catcher;
	tf->tf_sp = (uintcap_t)fp;

	sysent = p->p_sysent;
	if (sysent->sv_sigcode_base != 0)
		tf->tf_lr = (register_t)sysent->sv_sigcode_base;
	else
		tf->tf_lr = (register_t)(sysent->sv_psstrings -
		    *(sysent->sv_szsigcode));

	CTR3(KTR_SIG, "sendsig: return td=%p pc=%#x sp=%#x", td, tf->tf_sepc,
	    tf->tf_sp);

	PROC_LOCK(p);
	mtx_lock(&psp->ps_mtx);
}

int
freebsd64_sigreturn(struct thread *td, struct freebsd64_sigreturn_args *uap)
{
	ucontext64_t uc;
	int error;

	error = copyincap(__USER_CAP_OBJ(uap->sigcntxp), &uc, sizeof(uc));
	if (error != 0)
		return (error);

	error = freebsd64_set_mcontext(td, &uc.uc_mcontext);
	if (error != 0)
		return (error);

	kern_sigprocmask(td, SIG_SETMASK, &uc.uc_sigmask, NULL, 0);

	return (EJUSTRETURN);
}

int
freebsd64_sysarch(struct thread *td, struct freebsd64_sysarch_args *uap)
{

	return (ENOTSUP);
}

void
elf64_dump_thread(struct thread *td __unused, void *dst __unused,
    size_t *off __unused)
{
}
