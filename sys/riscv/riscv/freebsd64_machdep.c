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
#include <sys/reg.h>
#include <sys/syscallsubr.h>
#include <sys/sysent.h>
#include <sys/ucontext.h>

#include <machine/md_var.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>

#include <cheri/cheric.h>

#include <compat/freebsd64/freebsd64_proto.h>
#include <compat/freebsd64/freebsd64_syscall.h>
#include <compat/freebsd64/freebsd64_util.h>

_Static_assert(sizeof(mcontext64_t) == 864, "mcontext64_t size incorrect");
_Static_assert(sizeof(ucontext64_t) == 936, "ucontext64_t size incorrect");
_Static_assert(sizeof(struct siginfo64) == 80, "struct siginfo64 size incorrect");

static const char *freebsd64_riscv_machine_arch(struct proc *p);
static void	freebsd64_sendsig(sig_t, ksiginfo_t *, sigset_t *);

extern const char *freebsd64_syscallnames[];

struct sysentvec elf_freebsd_freebsd64_sysvec = {
	.sv_size	= FREEBSD64_SYS_MAXSYSCALL,
	.sv_table	= freebsd64_sysent,
	.sv_fixup	= __elfN(freebsd_fixup),
	.sv_sendsig	= freebsd64_sendsig,
	.sv_sigcode	= freebsd64_sigcode,
	.sv_szsigcode	= &freebsd64_szsigcode,
	.sv_name	= "FreeBSD ELF64",
	.sv_coredump	= __elfN(coredump),
	.sv_elf_core_osabi = ELFOSABI_FREEBSD,
	.sv_elf_core_abi_vendor = FREEBSD_ABI_VENDOR,
	.sv_elf_core_prepare_notes = __elfN(prepare_notes),
	.sv_imgact_try	= NULL,
	.sv_minsigstksz	= MINSIGSTKSZ,
	.sv_minuser	= VM_MIN_ADDRESS,
	.sv_maxuser	= 0,	/* Filled in during boot. */
	.sv_usrstack	= 0,	/* Filled in during boot. */
	.sv_psstringssz	= sizeof(struct freebsd64_ps_strings),
	.sv_stackprot	= VM_PROT_RW_CAP,
	.sv_copyout_auxargs = __elfN(freebsd_copyout_auxargs),
	.sv_copyout_strings = freebsd64_copyout_strings,
	.sv_setregs	= exec_setregs,
	.sv_fixlimit	= NULL,
	.sv_maxssiz	= NULL,
	.sv_flags	= SV_ABI_FREEBSD | SV_LP64 | SV_SHP | SV_TIMEKEEP |
	    SV_ASLR | SV_RNG_SEED_VER,
	.sv_set_syscall_retval = cpu_set_syscall_retval,
	.sv_fetch_syscall_args = cpu_fetch_syscall_args,
	.sv_syscallnames = freebsd64_syscallnames,
	.sv_shared_page_base = 0,	/* Filled in during boot. */
	.sv_shared_page_len = PAGE_SIZE,
	.sv_schedtail	= NULL,
	.sv_thread_detach = NULL,
	.sv_trap	= NULL,
	.sv_hwcap	= &elf_hwcap,
	.sv_machine_arch = freebsd64_riscv_machine_arch,
	.sv_onexec_old	= exec_onexec_old,
	.sv_onexit	= exit_onexit,
	.sv_regset_begin = SET_BEGIN(__elfN(regset)),
	.sv_regset_end	= SET_LIMIT(__elfN(regset)),
};
INIT_SYSENTVEC(freebsd64_sysent, &elf_freebsd_freebsd64_sysvec);

static const char *
freebsd64_riscv_machine_arch(struct proc *p)
{

	if ((p->p_elf_flags & EF_RISCV_FLOAT_ABI_MASK) ==
	    EF_RISCV_FLOAT_ABI_SOFT)
		return (MACHINE_ARCH64SF);
	return (MACHINE_ARCH64);
}

static Elf64_Brandinfo freebsd_freebsd64_brand_info = {
	.brand		= ELFOSABI_FREEBSD,
	.machine	= EM_RISCV,
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

SYSINIT(freebsd64_register_sysvec, SI_SUB_VM, SI_ORDER_ANY,
    elf64_register_sysvec, &elf_freebsd_freebsd64_sysvec);

/*
 * Number of GPRs in mc_gpregs that are mirrored in mc_capregs up to,
 * but not including sepc.
 */
#define	CONTEXT64_GPREGS	(offsetof(struct gpregs, gp_sepc) / sizeof(register_t))

static void
mcontext_to_mcontext64(mcontext_t *mc, mcontext64_t *mc64)
{
	const uintcap_t *creg;
	register_t *greg;
	u_int i;

	memset(mc64, 0, sizeof(*mc64));
	creg = (uintcap_t *)&mc->mc_capregs;
	greg = (register_t *)&mc64->mc_gpregs;
	for (i = 0; i < CONTEXT64_GPREGS; i++)
		greg[i] = (__cheri_addr register_t)creg[i];
	mc64->mc_gpregs.gp_sepc =
	    (__cheri_offset register_t)mc->mc_capregs.cp_sepcc;
	mc64->mc_gpregs.gp_sstatus = mc->mc_capregs.cp_sstatus;
	mc64->mc_flags = mc->mc_flags;
	if (mc->mc_flags & _MC_FP_VALID)
		mc64->mc_fpregs = mc->mc_fpregs;
}

int
freebsd64_get_mcontext(struct thread *td, mcontext64_t *mcp, int flags)
{
	mcontext_t mc;
	int error;

	error = get_mcontext(td, &mc, flags);
	if (error != 0)
		return (error);

	mcontext_to_mcontext64(&mc, mcp);
	return (0);
}

int
freebsd64_set_mcontext(struct thread *td, mcontext64_t *mcp)
{
	mcontext_t mc;
	uintcap_t *creg;
	const register_t *greg;
	int error;
	u_int i;

	memset(&mc, 0, sizeof(mc));
	if (mcp->mc_flags & _MC_CAP_VALID) {
		error = copyincap(__USER_CAP(mcp->mc_capregs,
		    sizeof(mc.mc_capregs)), &mc.mc_capregs,
		    sizeof(mc.mc_capregs));
		if (error)
			return (error);

		/* XXX: Permit userland to change GPRs for sigreturn? */

		/* Honor 64-bit PC. */
		mc.mc_capregs.cp_sepcc = cheri_setoffset(
		    mc.mc_capregs.cp_sepcc, mcp->mc_gpregs.gp_sepc);
	} else {
		creg = (uintcap_t *)&mc.mc_capregs;
		greg = (register_t *)&mcp->mc_gpregs;
		for (i = 0; i < CONTEXT64_GPREGS; i++)
			creg[i] = (uintcap_t)greg[i];

		mc.mc_capregs.cp_sepcc = cheri_setoffset(
		    td->td_frame->tf_sepc, mcp->mc_gpregs.gp_sepc);
		mc.mc_capregs.cp_ddc = td->td_frame->tf_ddc;
		mc.mc_capregs.cp_sstatus = mcp->mc_gpregs.gp_sstatus;
	}

	mc.mc_flags = mcp->mc_flags & ~_MC_CAP_VALID;
	if (mcp->mc_flags & _MC_FP_VALID)
		mc.mc_fpregs = mcp->mc_fpregs;

	return (set_mcontext(td, &mc));
}

static void
freebsd64_sendsig(sig_t catcher, ksiginfo_t *ksi, sigset_t *mask)
{
	struct sigframe64 frame;
	mcontext_t mc;
	struct sysentvec *sysent;
	struct trapframe *tf;
	struct sigacts *psp;
	struct thread *td;
	struct proc *p;
	vm_offset_t capregs, fp, sp;
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
	    (__cheri_addr ptraddr_t)catcher, sig);

	/* Allocate and validate space for the signal handler context. */
	if ((td->td_pflags & TDP_ALTSTACK) != 0 && !onstack &&
	    SIGISMEMBER(psp->ps_sigonstack, sig)) {
		sp = ((__cheri_addr ptraddr_t)td->td_sigstk.ss_sp +
		    td->td_sigstk.ss_size);
	} else {
		sp = (__cheri_addr ptraddr_t)td->td_frame->tf_sp;
	}

	/* Allocate room for the capability register context. */
	sp -= sizeof(mc.mc_capregs);
	sp = rounddown2(sp, sizeof(uintcap_t));
	capregs = sp;

	/* Make room, keeping the stack aligned */
	sp -= sizeof(frame);
	sp = STACKALIGN(sp);
	fp = sp;

	/* Fill in the frame to copy out */
	bzero(&frame, sizeof(frame));
	get_mcontext(td, &mc, 0);
	mcontext_to_mcontext64(&mc, &frame.sf_uc.uc_mcontext);
	frame.sf_uc.uc_mcontext.mc_flags |= _MC_CAP_VALID;
	frame.sf_uc.uc_mcontext.mc_capregs = capregs;
	siginfo_to_siginfo64(&ksi->ksi_info, &frame.sf_si);
	frame.sf_uc.uc_sigmask = *mask;
	frame.sf_uc.uc_stack.ss_sp = (__cheri_addr ptraddr_t)td->td_sigstk.ss_sp;
	frame.sf_uc.uc_stack.ss_size = td->td_sigstk.ss_size;
	frame.sf_uc.uc_stack.ss_flags = (td->td_pflags & TDP_ALTSTACK) != 0 ?
	    (onstack ? SS_ONSTACK : 0) : SS_DISABLE;
	mtx_unlock(&psp->ps_mtx);
	PROC_UNLOCK(td->td_proc);

	/* Copy the capability registers out to the user's stack. */
	if (copyoutcap(&mc.mc_capregs, __USER_CAP(capregs,
	    sizeof(mc.mc_capregs)), sizeof(mc.mc_capregs)) != 0) {
		PROC_LOCK(p);
		printf("pid %d, tid %d: could not copy out cap registers\n",
		    td->td_proc->p_pid, td->td_tid);
		sigexit(td, SIGILL);
		/* NOTREACHED */
	}

	/* Copy the sigframe out to the user's stack. */
	if (copyoutcap(&frame, __USER_CAP(fp, sizeof(frame)), sizeof(frame)) !=
	    0) {
		/* Process has trashed its stack. Kill it. */
		CTR2(KTR_SIG, "sendsig: sigexit td=%p fp=%p", td, fp);
		PROC_LOCK(p);
		sigexit(td, SIGILL);
	}

	tf->tf_a[0] = sig;
	tf->tf_a[1] = (register_t)fp + offsetof(struct sigframe64, sf_si);
	tf->tf_a[2] = (register_t)fp + offsetof(struct sigframe64, sf_uc);

	tf->tf_sepc = (uintcap_t)catcher;
	tf->tf_sp = (register_t)fp;

	sysent = p->p_sysent;
	if (PROC_HAS_SHP(p))
		tf->tf_ra = (register_t)PROC_SIGCODE(p);
	else
		tf->tf_ra = (register_t)(PROC_PS_STRINGS(p) -
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
