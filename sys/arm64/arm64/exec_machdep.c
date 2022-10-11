/*-
 * Copyright (c) 2014 Andrew Turner
 * All rights reserved.
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
 *
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
#include <sys/signalvar.h>
#include <sys/syscallsubr.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/ucontext.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>

#include <machine/armreg.h>
#include <machine/kdb.h>
#include <machine/md_var.h>
#include <machine/pcb.h>

#ifdef VFP
#include <machine/vfp.h>
#endif

#if __has_feature(capabilities)
_Static_assert(sizeof(mcontext_t) == 1152, "mcontext_t size incorrect");
_Static_assert(sizeof(ucontext_t) == 1248, "ucontext_t size incorrect");
_Static_assert(sizeof(siginfo_t) == 112, "siginfo_t size incorrect");
#else
_Static_assert(sizeof(mcontext_t) == 880, "mcontext_t size incorrect");
_Static_assert(sizeof(ucontext_t) == 960, "ucontext_t size incorrect");
_Static_assert(sizeof(siginfo_t) == 80, "siginfo_t size incorrect");
#endif

static void get_fpcontext(struct thread *td, mcontext_t *mcp);
static void set_fpcontext(struct thread *td, mcontext_t *mcp);

int
fill_regs(struct thread *td, struct reg *regs)
{
	struct trapframe *frame;
#if __has_feature(capabilities)
	int i;
#endif

	frame = td->td_frame;
	regs->sp = frame->tf_sp;
	regs->lr = frame->tf_lr;
	regs->elr = frame->tf_elr;
	regs->spsr = frame->tf_spsr;

#if __has_feature(capabilities)
	for (i = 0; i < nitems(frame->tf_x); i++)
		regs->x[i] = frame->tf_x[i];
#else
	memcpy(regs->x, frame->tf_x, sizeof(regs->x));
#endif

#ifdef COMPAT_FREEBSD32
	/*
	 * We may be called here for a 32bits process, if we're using a
	 * 64bits debugger. If so, put PC and SPSR where it expects it.
	 */
	if (SV_PROC_FLAG(td->td_proc, SV_ILP32)) {
		regs->x[15] = frame->tf_elr;
		regs->x[16] = frame->tf_spsr;
	}
#endif
	return (0);
}

int
set_regs(struct thread *td, struct reg *regs)
{
	struct trapframe *frame;
#if __has_feature(capabilities)
	int i;
#endif

	frame = td->td_frame;
	frame->tf_sp = regs->sp;
	frame->tf_lr = regs->lr;

#if __has_feature(capabilities)
	for (i = 0; i < nitems(frame->tf_x); i++)
		frame->tf_x[i] = regs->x[i];
#else
	memcpy(frame->tf_x, regs->x, sizeof(frame->tf_x));
#endif

#ifdef COMPAT_FREEBSD32
	if (SV_PROC_FLAG(td->td_proc, SV_ILP32)) {
		/*
		 * We may be called for a 32bits process if we're using
		 * a 64bits debugger. If so, get PC and SPSR from where
		 * it put it.
		 */
		frame->tf_elr = regs->x[15];
		frame->tf_spsr &= ~PSR_SETTABLE_32;
		frame->tf_spsr |= regs->x[16] & PSR_SETTABLE_32;
		/* Don't allow userspace to ask to continue single stepping.
		 * The SPSR.SS field doesn't exist when the EL1 is AArch32.
		 * As the SPSR.DIT field has moved in its place don't
		 * allow userspace to set the SPSR.SS field.
		 */
	} else
#endif
	{
		frame->tf_elr = regs->elr;
		frame->tf_spsr &= ~PSR_SETTABLE_64;
		frame->tf_spsr |= regs->spsr & PSR_SETTABLE_64;
		/* Enable single stepping if userspace asked fot it */
		if ((frame->tf_spsr & PSR_SS) != 0) {
			td->td_pcb->pcb_flags |= PCB_SINGLE_STEP;

			WRITE_SPECIALREG(mdscr_el1,
			    READ_SPECIALREG(mdscr_el1) | MDSCR_SS);
			isb();
		}
	}
	return (0);
}

int
fill_fpregs(struct thread *td, struct fpreg *regs)
{
#ifdef VFP
	struct pcb *pcb;

	pcb = td->td_pcb;
	if ((pcb->pcb_fpflags & PCB_FP_STARTED) != 0) {
		/*
		 * If we have just been running VFP instructions we will
		 * need to save the state to memcpy it below.
		 */
		if (td == curthread)
			vfp_save_state(td, pcb);

		KASSERT(pcb->pcb_fpusaved == &pcb->pcb_fpustate,
		    ("Called fill_fpregs while the kernel is using the VFP"));
		memcpy(regs->fp_q, pcb->pcb_fpustate.vfp_regs,
		    sizeof(regs->fp_q));
		regs->fp_cr = pcb->pcb_fpustate.vfp_fpcr;
		regs->fp_sr = pcb->pcb_fpustate.vfp_fpsr;
	} else
#endif
		memset(regs, 0, sizeof(*regs));
	return (0);
}

int
set_fpregs(struct thread *td, struct fpreg *regs)
{
#ifdef VFP
	struct pcb *pcb;

	pcb = td->td_pcb;
	KASSERT(pcb->pcb_fpusaved == &pcb->pcb_fpustate,
	    ("Called set_fpregs while the kernel is using the VFP"));
	memcpy(pcb->pcb_fpustate.vfp_regs, regs->fp_q, sizeof(regs->fp_q));
	pcb->pcb_fpustate.vfp_fpcr = regs->fp_cr;
	pcb->pcb_fpustate.vfp_fpsr = regs->fp_sr;
#endif
	return (0);
}

int
fill_dbregs(struct thread *td, struct dbreg *regs)
{
	struct debug_monitor_state *monitor;
	int i;
	uint8_t debug_ver, nbkpts, nwtpts;

	memset(regs, 0, sizeof(*regs));

	extract_user_id_field(ID_AA64DFR0_EL1, ID_AA64DFR0_DebugVer_SHIFT,
	    &debug_ver);
	extract_user_id_field(ID_AA64DFR0_EL1, ID_AA64DFR0_BRPs_SHIFT,
	    &nbkpts);
	extract_user_id_field(ID_AA64DFR0_EL1, ID_AA64DFR0_WRPs_SHIFT,
	    &nwtpts);

	/*
	 * The BRPs field contains the number of breakpoints - 1. Armv8-A
	 * allows the hardware to provide 2-16 breakpoints so this won't
	 * overflow an 8 bit value. The same applies to the WRPs field.
	 */
	nbkpts++;
	nwtpts++;

	regs->db_debug_ver = debug_ver;
	regs->db_nbkpts = nbkpts;
	regs->db_nwtpts = nwtpts;

	monitor = &td->td_pcb->pcb_dbg_regs;
	if ((monitor->dbg_flags & DBGMON_ENABLED) != 0) {
		for (i = 0; i < nbkpts; i++) {
			regs->db_breakregs[i].dbr_addr = monitor->dbg_bvr[i];
			regs->db_breakregs[i].dbr_ctrl = monitor->dbg_bcr[i];
		}
		for (i = 0; i < nwtpts; i++) {
			regs->db_watchregs[i].dbw_addr = monitor->dbg_wvr[i];
			regs->db_watchregs[i].dbw_ctrl = monitor->dbg_wcr[i];
		}
	}

	return (0);
}

int
set_dbregs(struct thread *td, struct dbreg *regs)
{
	struct debug_monitor_state *monitor;
	uint64_t addr;
	uint32_t ctrl;
	int i;

	monitor = &td->td_pcb->pcb_dbg_regs;
	monitor->dbg_enable_count = 0;

	for (i = 0; i < DBG_BRP_MAX; i++) {
		addr = regs->db_breakregs[i].dbr_addr;
		ctrl = regs->db_breakregs[i].dbr_ctrl;

		/*
		 * Don't let the user set a breakpoint on a kernel or
		 * non-canonical user address.
		 */
		if (addr >= VM_MAXUSER_ADDRESS)
			return (EINVAL);

		/*
		 * The lowest 2 bits are ignored, so record the effective
		 * address.
		 */
		addr = rounddown2(addr, 4);

		/*
		 * Some control fields are ignored, and other bits reserved.
		 * Only unlinked, address-matching breakpoints are supported.
		 *
		 * XXX: fields that appear unvalidated, such as BAS, have
		 * constrained undefined behaviour. If the user mis-programs
		 * these, there is no risk to the system.
		 */
		ctrl &= DBGBCR_EN | DBGBCR_PMC | DBGBCR_BAS;
		if ((ctrl & DBGBCR_EN) != 0) {
			/* Only target EL0. */
			if ((ctrl & DBGBCR_PMC) != DBGBCR_PMC_EL0)
				return (EINVAL);

			monitor->dbg_enable_count++;
		}

		monitor->dbg_bvr[i] = addr;
		monitor->dbg_bcr[i] = ctrl;
	}

	for (i = 0; i < DBG_WRP_MAX; i++) {
		addr = regs->db_watchregs[i].dbw_addr;
		ctrl = regs->db_watchregs[i].dbw_ctrl;

		/*
		 * Don't let the user set a watchpoint on a kernel or
		 * non-canonical user address.
		 */
		if (addr >= VM_MAXUSER_ADDRESS)
			return (EINVAL);

		/*
		 * Some control fields are ignored, and other bits reserved.
		 * Only unlinked watchpoints are supported.
		 */
		ctrl &= DBGWCR_EN | DBGWCR_PAC | DBGWCR_LSC | DBGWCR_BAS |
		    DBGWCR_MASK;

		if ((ctrl & DBGWCR_EN) != 0) {
			/* Only target EL0. */
			if ((ctrl & DBGWCR_PAC) != DBGWCR_PAC_EL0)
				return (EINVAL);

			/* Must set at least one of the load/store bits. */
			if ((ctrl & DBGWCR_LSC) == 0)
				return (EINVAL);

			/*
			 * When specifying the address range with BAS, the MASK
			 * field must be zero.
			 */
			if ((ctrl & DBGWCR_BAS) != DBGWCR_BAS &&
			    (ctrl & DBGWCR_MASK) != 0)
				return (EINVAL);

			monitor->dbg_enable_count++;
		}
		monitor->dbg_wvr[i] = addr;
		monitor->dbg_wcr[i] = ctrl;
	}

	if (monitor->dbg_enable_count > 0)
		monitor->dbg_flags |= DBGMON_ENABLED;

	return (0);
}

#ifdef COMPAT_FREEBSD32
int
fill_regs32(struct thread *td, struct reg32 *regs)
{
	int i;
	struct trapframe *tf;

	tf = td->td_frame;
	for (i = 0; i < 13; i++)
		regs->r[i] = tf->tf_x[i];
	/* For arm32, SP is r13 and LR is r14 */
	regs->r_sp = tf->tf_x[13];
	regs->r_lr = tf->tf_x[14];
	regs->r_pc = tf->tf_elr;
	regs->r_cpsr = tf->tf_spsr;

	return (0);
}

int
set_regs32(struct thread *td, struct reg32 *regs)
{
	int i;
	struct trapframe *tf;

	tf = td->td_frame;
	for (i = 0; i < 13; i++)
		tf->tf_x[i] = regs->r[i];
	/* For arm 32, SP is r13 an LR is r14 */
	tf->tf_x[13] = regs->r_sp;
	tf->tf_x[14] = regs->r_lr;
	tf->tf_elr = regs->r_pc;
	tf->tf_spsr &= ~PSR_SETTABLE_32;
	tf->tf_spsr |= regs->r_cpsr & PSR_SETTABLE_32;

	return (0);
}

/* XXX fill/set dbregs/fpregs are stubbed on 32-bit arm. */
int
fill_fpregs32(struct thread *td, struct fpreg32 *regs)
{

	memset(regs, 0, sizeof(*regs));
	return (0);
}

int
set_fpregs32(struct thread *td, struct fpreg32 *regs)
{

	return (0);
}

int
fill_dbregs32(struct thread *td, struct dbreg32 *regs)
{

	memset(regs, 0, sizeof(*regs));
	return (0);
}

int
set_dbregs32(struct thread *td, struct dbreg32 *regs)
{

	return (0);
}
#endif

#if __has_feature(capabilities)
int
fill_capregs(struct thread *td, struct capreg *regs)
{
	struct trapframe *frame;
	int i;

	frame = td->td_frame;
	regs->csp = frame->tf_sp;
	regs->clr = frame->tf_lr;
	regs->celr = frame->tf_elr;
	regs->ddc = frame->tf_ddc;
	regs->ctpidr = td->td_pcb->pcb_tpidr_el0;
	regs->ctpidrro = td->td_pcb->pcb_tpidrro_el0;
	regs->cid = td->td_pcb->pcb_cid_el0;
	regs->rcsp = td->td_pcb->pcb_rcsp_el0;
	regs->rddc = td->td_pcb->pcb_rddc_el0;
	regs->rctpidr = td->td_pcb->pcb_rctpidr_el0;

	for (i = 0; i < nitems(frame->tf_x); i++) {
		regs->c[i] = frame->tf_x[i];
		if (cheri_gettag((void * __capability)frame->tf_x[i]))
			regs->tagmask |= (uint64_t)1 << i;
	}
	if (cheri_gettag((void * __capability)frame->tf_lr))
		regs->tagmask |= (uint64_t)1 << i;
	i++;
	if (cheri_gettag((void * __capability)frame->tf_sp))
		regs->tagmask |= (uint64_t)1 << i;
	i++;
	if (cheri_gettag((void * __capability)frame->tf_elr))
		regs->tagmask |= (uint64_t)1 << i;
	i++;
	if (cheri_gettag((void * __capability)frame->tf_ddc))
		regs->tagmask |= (uint64_t)1 << i;
	i++;
	if (cheri_gettag((void * __capability)regs->ctpidr))
		regs->tagmask |= (uint64_t)1 << i;
	i++;
	if (cheri_gettag((void * __capability)regs->ctpidrro))
		regs->tagmask |= (uint64_t)1 << i;
	i++;
	if (cheri_gettag((void * __capability)regs->cid))
		regs->tagmask |= (uint64_t)1 << i;
	i++;
	if (cheri_gettag((void * __capability)regs->rcsp))
		regs->tagmask |= (uint64_t)1 << i;
	i++;
	if (cheri_gettag((void * __capability)regs->rddc))
		regs->tagmask |= (uint64_t)1 << i;
	i++;
	if (cheri_gettag((void * __capability)regs->rctpidr))
		regs->tagmask |= (uint64_t)1 << i;

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
	struct trapframe *tf = td->td_frame;
	struct pcb *pcb = td->td_pcb;

	memset(tf, 0, sizeof(struct trapframe));

#if __has_feature(capabilities)
	if (SV_PROC_FLAG(td->td_proc, SV_CHERI)) {
		tf->tf_x[0] = (uintcap_t)imgp->auxv;
		tf->tf_sp = stack;
		tf->tf_lr = (uintcap_t)cheri_exec_pcc(td, imgp);
		trapframe_set_elr(tf, tf->tf_lr);
		td->td_proc->p_md.md_sigcode = cheri_sigcode_capability(td);
	} else
#endif
	{
		tf->tf_x[0] = (register_t)stack;
		tf->tf_sp = STACKALIGN((register_t)stack);
		tf->tf_lr = imgp->entry_addr;
#if __has_feature(capabilities)
		hybridabi_thread_setregs(td, imgp->entry_addr);
#else
		tf->tf_elr = imgp->entry_addr;
#endif
	}

	td->td_pcb->pcb_tpidr_el0 = 0;
	td->td_pcb->pcb_tpidrro_el0 = 0;
#if __has_feature(capabilities)
	WRITE_SPECIALREG_CAP(ctpidrro_el0, 0);
	WRITE_SPECIALREG_CAP(ctpidr_el0, 0);
#else
	WRITE_SPECIALREG(tpidrro_el0, 0);
	WRITE_SPECIALREG(tpidr_el0, 0);
#endif

#if __has_feature(capabilities)
	td->td_pcb->pcb_cid_el0 = 0;
	td->td_pcb->pcb_rcsp_el0 = 0;
	td->td_pcb->pcb_rddc_el0 = 0;
	td->td_pcb->pcb_rctpidr_el0 = 0;
	WRITE_SPECIALREG_CAP(cid_el0, 0);
	WRITE_SPECIALREG_CAP(rcsp_el0, 0);
	WRITE_SPECIALREG_CAP(rddc_el0, 0);
	WRITE_SPECIALREG_CAP(rctpidr_el0, 0);
#endif

#ifdef VFP
	vfp_reset_state(td, pcb);
#endif

	/*
	 * Clear debug register state. It is not applicable to the new process.
	 */
	bzero(&pcb->pcb_dbg_regs, sizeof(pcb->pcb_dbg_regs));

#ifdef PAC
	/* Generate new pointer authentication keys */
	ptrauth_exec(td);
#endif
}

/* Sanity check these are the same size, they will be memcpy'd to and fro */
#if __has_feature(capabilities)
CTASSERT(sizeof(((struct trapframe *)0)->tf_x) ==
    sizeof((struct capregs *)0)->cap_x);
CTASSERT(sizeof(((struct trapframe *)0)->tf_x) ==
    sizeof((struct capreg *)0)->c);
#else
CTASSERT(sizeof(((struct trapframe *)0)->tf_x) ==
    sizeof((struct gpregs *)0)->gp_x);
CTASSERT(sizeof(((struct trapframe *)0)->tf_x) ==
    sizeof((struct reg *)0)->x);
#endif

#if __has_feature(capabilities)
int
get_mcontext(struct thread *td, mcontext_t *mcp, int clear_ret)
{
	struct trapframe *tf = td->td_frame;

	if (clear_ret & GET_MC_CLEAR_RET) {
		mcp->mc_capregs.cap_x[0] = 0;
		mcp->mc_spsr = tf->tf_spsr & ~PSR_C;
	} else {
		mcp->mc_capregs.cap_x[0] = tf->tf_x[0];
		mcp->mc_spsr = tf->tf_spsr;
	}

	memcpy(&mcp->mc_capregs.cap_x[1], &tf->tf_x[1],
	    sizeof(mcp->mc_capregs.cap_x[1]) *
	    (nitems(mcp->mc_capregs.cap_x) - 1));

	mcp->mc_capregs.cap_sp = tf->tf_sp;
	mcp->mc_capregs.cap_lr = tf->tf_lr;
	mcp->mc_capregs.cap_elr = tf->tf_elr;
	mcp->mc_capregs.cap_ddc = tf->tf_ddc;
	get_fpcontext(td, mcp);

	return (0);
}

int
set_mcontext(struct thread *td, mcontext_t *mcp)
{
	struct trapframe *tf = td->td_frame;
	uint32_t spsr;

	spsr = mcp->mc_spsr;
	if ((spsr & PSR_M_MASK) != PSR_M_EL0t ||
	    (spsr & PSR_AARCH32) != 0 ||
	    (spsr & PSR_DAIF) != (td->td_frame->tf_spsr & PSR_DAIF))
		return (EINVAL);

	memcpy(tf->tf_x, mcp->mc_capregs.cap_x, sizeof(tf->tf_x));

	tf->tf_sp = mcp->mc_capregs.cap_sp;
	tf->tf_lr = mcp->mc_capregs.cap_lr;
	tf->tf_elr = mcp->mc_capregs.cap_elr;
	tf->tf_ddc = mcp->mc_capregs.cap_ddc;
	tf->tf_spsr = mcp->mc_spsr;
	set_fpcontext(td, mcp);

	return (0);
}
#else
int
get_mcontext(struct thread *td, mcontext_t *mcp, int clear_ret)
{
	struct trapframe *tf = td->td_frame;

	if (clear_ret & GET_MC_CLEAR_RET) {
		mcp->mc_gpregs.gp_x[0] = 0;
		mcp->mc_gpregs.gp_spsr = tf->tf_spsr & ~PSR_C;
	} else {
		mcp->mc_gpregs.gp_x[0] = tf->tf_x[0];
		mcp->mc_gpregs.gp_spsr = tf->tf_spsr;
	}

	memcpy(&mcp->mc_gpregs.gp_x[1], &tf->tf_x[1],
	    sizeof(mcp->mc_gpregs.gp_x[1]) * (nitems(mcp->mc_gpregs.gp_x) - 1));

	mcp->mc_gpregs.gp_sp = tf->tf_sp;
	mcp->mc_gpregs.gp_lr = tf->tf_lr;
	mcp->mc_gpregs.gp_elr = tf->tf_elr;
	get_fpcontext(td, mcp);

	return (0);
}

int
set_mcontext(struct thread *td, mcontext_t *mcp)
{
	struct trapframe *tf = td->td_frame;
	uint32_t spsr;

	spsr = mcp->mc_gpregs.gp_spsr;
	if ((spsr & PSR_M_MASK) != PSR_M_EL0t ||
	    (spsr & PSR_AARCH32) != 0 ||
	    (spsr & PSR_DAIF) != (td->td_frame->tf_spsr & PSR_DAIF))
		return (EINVAL); 

	memcpy(tf->tf_x, mcp->mc_gpregs.gp_x, sizeof(tf->tf_x));

	tf->tf_sp = mcp->mc_gpregs.gp_sp;
	tf->tf_lr = mcp->mc_gpregs.gp_lr;
	tf->tf_elr = mcp->mc_gpregs.gp_elr;
	tf->tf_spsr = mcp->mc_gpregs.gp_spsr;
	if ((tf->tf_spsr & PSR_SS) != 0) {
		td->td_pcb->pcb_flags |= PCB_SINGLE_STEP;

		WRITE_SPECIALREG(mdscr_el1,
		    READ_SPECIALREG(mdscr_el1) | MDSCR_SS);
		isb();
	}
	set_fpcontext(td, mcp);

	return (0);
}
#endif

static void
get_fpcontext(struct thread *td, mcontext_t *mcp)
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
		    sizeof(mcp->mc_fpregs.fp_q));
		mcp->mc_fpregs.fp_cr = curpcb->pcb_fpustate.vfp_fpcr;
		mcp->mc_fpregs.fp_sr = curpcb->pcb_fpustate.vfp_fpsr;
		mcp->mc_fpregs.fp_flags = curpcb->pcb_fpflags;
		mcp->mc_flags |= _MC_FP_VALID;
	}

	critical_exit();
#endif
}

static void
set_fpcontext(struct thread *td, mcontext_t *mcp)
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
		    sizeof(mcp->mc_fpregs.fp_q));
		curpcb->pcb_fpustate.vfp_fpcr = mcp->mc_fpregs.fp_cr;
		curpcb->pcb_fpustate.vfp_fpsr = mcp->mc_fpregs.fp_sr;
		curpcb->pcb_fpflags = mcp->mc_fpregs.fp_flags & PCB_FP_USERMASK;
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
	struct thread *td;
	struct proc *p;
	struct trapframe *tf;
	struct sigframe * __capability fp, frame;
	struct sigacts *psp;
	int onstack, sig;

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
		fp = (struct sigframe * __capability)((uintcap_t)td->td_sigstk.ss_sp +
		    td->td_sigstk.ss_size);
#if defined(COMPAT_43)
		td->td_sigstk.ss_flags |= SS_ONSTACK;
#endif
	} else {
		fp = (struct sigframe * __capability)td->td_frame->tf_sp;
	}

	/* Make room, keeping the stack aligned */
	fp--;
	fp = (struct sigframe * __capability)STACKALIGN(fp);

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
		CTR2(KTR_SIG, "sendsig: sigexit td=%p fp=%p", td, fp);
		PROC_LOCK(p);
		sigexit(td, SIGILL);
	}

	tf->tf_x[0] = sig;
#if __has_feature(capabilities)
	tf->tf_x[1] = (uintcap_t)cheri_setbounds(&fp->sf_si,
	    sizeof(fp->sf_si));
	tf->tf_x[2] = (uintcap_t)cheri_setbounds(&fp->sf_uc,
	    sizeof(fp->sf_uc));
#else
	tf->tf_x[1] = (register_t)&fp->sf_si;
	tf->tf_x[2] = (register_t)&fp->sf_uc;
#endif
	tf->tf_x[8] = (uintcap_t)catcher;
	tf->tf_sp = (uintcap_t)fp;
#if __has_feature(capabilities)
	trapframe_set_elr(tf, (uintcap_t)p->p_md.md_sigcode);
#else
	tf->tf_elr = (register_t)PROC_SIGCODE(p);
#endif

	/* Clear the single step flag while in the signal handler */
	if ((td->td_pcb->pcb_flags & PCB_SINGLE_STEP) != 0) {
		td->td_pcb->pcb_flags &= ~PCB_SINGLE_STEP;
		WRITE_SPECIALREG(mdscr_el1,
		    READ_SPECIALREG(mdscr_el1) & ~MDSCR_SS);
		isb();
	}

	CTR3(KTR_SIG, "sendsig: return td=%p pc=%#x sp=%#x", td, tf->tf_elr,
	    tf->tf_sp);

	PROC_LOCK(p);
	mtx_lock(&psp->ps_mtx);
}
