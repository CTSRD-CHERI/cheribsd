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

#include "opt_ddb.h"
#include "opt_platform.h"

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/bus.h>
#include <sys/cons.h>
#include <sys/cpu.h>
#include <sys/devmap.h>
#include <sys/exec.h>
#include <sys/imgact.h>
#include <sys/kdb.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/limits.h>
#include <sys/linker.h>
#include <sys/msgbuf.h>
#include <sys/pcpu.h>
#include <sys/physmem.h>
#include <sys/proc.h>
#include <sys/ptrace.h>
#include <sys/reboot.h>
#include <sys/rwlock.h>
#include <sys/sched.h>
#include <sys/signalvar.h>
#include <sys/syscallsubr.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/tslog.h>
#include <sys/ucontext.h>
#include <sys/vmmeter.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_phys.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_pager.h>

#include <machine/cpu.h>
#include <machine/intr.h>
#include <machine/kdb.h>
#include <machine/machdep.h>
#include <machine/metadata.h>
#include <machine/pcb.h>
#include <machine/pte.h>
#include <machine/reg.h>
#include <machine/riscvreg.h>
#include <machine/sbi.h>
#include <machine/trap.h>
#include <machine/vmparam.h>

#ifdef FPE
#include <machine/fpe.h>
#endif

#if __has_feature(capabilities)
#include <cheri/cheric.h>
#endif

#ifdef FDT
#include <contrib/libfdt/libfdt.h>
#include <dev/fdt/fdt_common.h>
#include <dev/ofw/openfirm.h>
#endif

static void get_fpcontext(struct thread *td, mcontext_t *mcp);
static void set_fpcontext(struct thread *td, mcontext_t *mcp);

struct pcpu __pcpu[MAXCPU];

static struct trapframe proc0_tf;

int early_boot = 1;
int cold = 1;

#define	DTB_SIZE_MAX	(1024 * 1024)

vm_paddr_t physmap[PHYS_AVAIL_ENTRIES];
u_int physmap_idx;

struct kva_md_info kmi;

int64_t dcache_line_size;	/* The minimum D cache line size */
int64_t icache_line_size;	/* The minimum I cache line size */
int64_t idcache_line_size;	/* The minimum cache line size */

uint32_t boot_hart;	/* The hart we booted on. */
cpuset_t all_harts;

extern int *end;

/*
 * When emulating RISC-V boards under QEMU, ISA-level tracing can be enabled and
 * disabled using special NOP instructions. By default this is a simple global
 * setting that the kernel doesn't interfere with, allowing userspace to turn
 * on and off tracing as it sees fit. If this sysctl is set, then the kernel
 * will use a per-thread flag (td->td_md.md_flags & MDTD_QTRACE) to pause
 * and resume tracing during context switching. The flag can be set and queried
 * using the sysarch system call.
 *
 * NB: This is a QEMU-CHERI feature.
 */
#ifdef CPU_QEMU_RISCV
u_int	qemu_trace_perthread;
SYSCTL_UINT(_hw, OID_AUTO, qemu_trace_perthread, CTLFLAG_RW,
    &qemu_trace_perthread, 0, "Per-thread Qemu ISA-level tracing configured");
#endif

static void
cpu_startup(void *dummy)
{

	sbi_print_version();
	identify_cpu();

	printf("real memory  = %ju (%ju MB)\n", ptoa((uintmax_t)realmem),
	    ptoa((uintmax_t)realmem) / (1024 * 1024));

	/*
	 * Display any holes after the first chunk of extended memory.
	 */
	if (bootverbose) {
		int indx;

		printf("Physical memory chunk(s):\n");
		for (indx = 0; phys_avail[indx + 1] != 0; indx += 2) {
			vm_paddr_t size;

			size = phys_avail[indx + 1] - phys_avail[indx];
			printf(
			    "0x%016jx - 0x%016jx, %ju bytes (%ju pages)\n",
			    (uintmax_t)phys_avail[indx],
			    (uintmax_t)phys_avail[indx + 1] - 1,
			    (uintmax_t)size, (uintmax_t)size / PAGE_SIZE);
		}
	}

	vm_ksubmap_init(&kmi);

	printf("avail memory = %ju (%ju MB)\n",
	    ptoa((uintmax_t)vm_free_count()),
	    ptoa((uintmax_t)vm_free_count()) / (1024 * 1024));
	if (bootverbose)
		devmap_print_table();

	bufinit();
	vm_pager_bufferinit();
}

SYSINIT(cpu, SI_SUB_CPU, SI_ORDER_FIRST, cpu_startup, NULL);

int
cpu_idle_wakeup(int cpu)
{

	return (0);
}

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
	frame->tf_sepc = (uintcap_t)cheri_setaddress(
	    (void * __capability)frame->tf_sepc, regs->sepc);
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
		if (cheri_gettag((void * __capability)pcap[i]))
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

int
ptrace_set_pc(struct thread *td, u_long addr)
{

#if __has_feature(capabilities)
	if (SV_PROC_FLAG(td->td_proc, SV_CHERI) &&
	    !cheri_is_address_inbounds(
	    (void * __capability)td->td_frame->tf_sepc, addr))
		return (EINVAL);
	td->td_frame->tf_sepc = (uintcap_t)cheri_setaddress(
	    (void * __capability)td->td_frame->tf_sepc, addr);
#else
	td->td_frame->tf_sepc = addr;
#endif
	return (0);
}

int
ptrace_single_step(struct thread *td)
{

	/* TODO; */
	return (EOPNOTSUPP);
}

int
ptrace_clear_single_step(struct thread *td)
{

	/* TODO; */
	return (EOPNOTSUPP);
}

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
		tf->tf_a[0] = (uintcap_t)cheri_auxv_capability(imgp, stack);
		tf->tf_sp = (uintcap_t)cheri_exec_stack_pointer(imgp, stack);
		cheri_set_mmap_capability(td, imgp,
		    (void * __capability)tf->tf_sp);

		/*
		 * XXX: RISC-V needs purecap mode enabled in flags.
		 * Our current set of macros from <machine/cherireg.h>
		 * don't provide a way to handle this, so fix it up
		 * here.
		 */
		tf->tf_sepc = (uintcap_t)cheri_setflags(cheri_exec_pcc(imgp),
		    CHERI_FLAGS_CAP_MODE);
		td->td_proc->p_md.md_sigcode = cheri_sigcode_capability(td);
	} else
#endif
	{
		tf->tf_a[0] = (__cheri_addr uintptr_t)stack;
		tf->tf_sp = STACKALIGN((__cheri_addr uintptr_t)stack);
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

/* Support for FDT configurations only. */
CTASSERT(FDT);

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
		    sizeof(mcp->mc_fpregs));
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
		    sizeof(mcp->mc_fpregs));
		curpcb->pcb_fcsr = mcp->mc_fpregs.fp_fcsr;
		curpcb->pcb_fpflags = mcp->mc_fpregs.fp_flags & PCB_FP_USERMASK;
		td->td_frame->tf_sstatus |= SSTATUS_FS_CLEAN;
	}

	critical_exit();
#endif
}

void
cpu_idle(int busy)
{

	spinlock_enter();
	if (!busy)
		cpu_idleclock();
	if (!sched_runnable())
		__asm __volatile(
		    "fence \n"
		    "wfi   \n");
	if (!busy)
		cpu_activeclock();
	spinlock_exit();
}

void
cpu_halt(void)
{

	/*
	 * Try to power down using the HSM SBI extension and fall back to a
	 * simple wfi loop.
	 */
	intr_disable();
	if (sbi_probe_extension(SBI_EXT_ID_HSM) != 0)
		sbi_hsm_hart_stop();
	for (;;)
		__asm __volatile("wfi");
	/* NOTREACHED */
}

/*
 * Flush the D-cache for non-DMA I/O so that the I-cache can
 * be made coherent later.
 */
void
cpu_flush_dcache(void *ptr, size_t len)
{

	/* TBD */
}

/* Get current clock frequency for the given CPU ID. */
int
cpu_est_clockrate(int cpu_id, uint64_t *rate)
{

	panic("cpu_est_clockrate");
}

void
cpu_pcpu_init(struct pcpu *pcpu, int cpuid, size_t size)
{
}

void
spinlock_enter(void)
{
	struct thread *td;
	register_t reg;

	td = curthread;
	if (td->td_md.md_spinlock_count == 0) {
		reg = intr_disable();
		td->td_md.md_spinlock_count = 1;
		td->td_md.md_saved_sstatus_ie = reg;
		critical_enter();
	} else
		td->td_md.md_spinlock_count++;
}

void
spinlock_exit(void)
{
	struct thread *td;
	register_t sstatus_ie;

	td = curthread;
	sstatus_ie = td->td_md.md_saved_sstatus_ie;
	td->td_md.md_spinlock_count--;
	if (td->td_md.md_spinlock_count == 0) {
		critical_exit();
		intr_restore(sstatus_ie);
	}
}

#ifndef	_SYS_SYSPROTO_H_
struct sigreturn_args {
	ucontext_t *ucp;
};
#endif

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

/*
 * Construct a PCB from a trapframe. This is called from kdb_trap() where
 * we want to start a backtrace from the function that caused us to enter
 * the debugger. We have the context in the trapframe, but base the trace
 * on the PCB. The PCB doesn't have to be perfect, as long as it contains
 * enough for a backtrace.
 */
void
makectx(struct trapframe *tf, struct pcb *pcb)
{

	memcpy(pcb->pcb_s, tf->tf_s, sizeof(tf->tf_s));

	pcb->pcb_ra = tf->tf_sepc;
	pcb->pcb_sp = tf->tf_sp;
	pcb->pcb_gp = tf->tf_gp;
	pcb->pcb_tp = tf->tf_tp;
}

void
sendsig(sig_t catcher, ksiginfo_t *ksi, sigset_t *mask)
{
	struct sigframe * __capability fp, frame;
	struct sysentvec *sysent;
	struct trapframe *tf;
	struct sigacts *psp;
	struct thread *td;
	struct proc *p;
#if __has_feature(capabilities)
	int cheri_is_sandboxed;
#endif
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
	onstack = sigonstack((__cheri_addr vaddr_t)tf->tf_sp);

#if __has_feature(capabilities)
	/*
	 * CHERI affects signal delivery in the following ways:
	 *
	 * (1) Additional capability state is exposed via extensions
	 *     to the context frame placed on the stack.
	 *
	 * (2) If the user $pcc doesn't include CHERI_PERM_SYSCALL,
	 *     then we consider user state to be 'sandboxed'.
	 *
	 * (3) If an alternative signal stack is not defined, and we
	 *     are in a 'sandboxed' state, then we will terminate the
	 *     process unconditionally.
	 */
	cheri_is_sandboxed = cheri_signal_sandboxed(td);

	/*
	 * We provide the ability to drop into the debugger in two different
	 * circumstances: (1) if the code running is sandboxed; and (2) if the
	 * fault is a CHERI protection fault.  Handle both here for the
	 * non-unwind case.  Do this before we rewrite any general-purpose or
	 * capability register state for the thread.
	 */
#ifdef DDB
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
		onstack = 0;
#endif

	CTR4(KTR_SIG, "sendsig: td=%p (%s) catcher=%p sig=%d", td, p->p_comm,
	    catcher, sig);

	/* Allocate and validate space for the signal handler context. */
	if ((td->td_pflags & TDP_ALTSTACK) != 0 && !onstack &&
	    SIGISMEMBER(psp->ps_sigonstack, sig)) {
		fp = (struct sigframe * __capability)((uintcap_t)td->td_sigstk.ss_sp +
		    td->td_sigstk.ss_size);
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
#endif
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
		CTR2(KTR_SIG, "sendsig: sigexit td=%p fp=%p", td, fp);
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

	sysent = p->p_sysent;
#if __has_feature(capabilities)
	tf->tf_ra = (uintcap_t)p->p_md.md_sigcode;
#else
	if (sysent->sv_sigcode_base != 0)
		tf->tf_ra = (register_t)sysent->sv_sigcode_base;
	else
		tf->tf_ra = (register_t)(sysent->sv_psstrings -
		    *(sysent->sv_szsigcode));
#endif

	CTR3(KTR_SIG, "sendsig: return td=%p pc=%#x sp=%#x", td, tf->tf_sepc,
	    tf->tf_sp);

	PROC_LOCK(p);
	mtx_lock(&psp->ps_mtx);
}

static void
init_proc0(vm_offset_t kstack)
{
	struct pcpu *pcpup;

	pcpup = &__pcpu[0];

	proc_linkup0(&proc0, &thread0);
	thread0.td_kstack = kstack;
	thread0.td_kstack_pages = KSTACK_PAGES;
	thread0.td_pcb = (struct pcb *)(thread0.td_kstack +
	    thread0.td_kstack_pages * PAGE_SIZE) - 1;
	thread0.td_pcb->pcb_fpflags = 0;
	thread0.td_frame = &proc0_tf;
	pcpup->pc_curpcb = thread0.td_pcb;
}

#ifdef FDT
static void
try_load_dtb(caddr_t kmdp)
{
	vm_offset_t dtbp;

	dtbp = MD_FETCH(kmdp, MODINFOMD_DTBP, vm_offset_t);

#if defined(FDT_DTB_STATIC)
	/*
	 * In case the device tree blob was not retrieved (from metadata) try
	 * to use the statically embedded one.
	 */
	if (dtbp == (vm_offset_t)NULL)
		dtbp = (vm_offset_t)&fdt_static_dtb;
#endif

	if (dtbp == (vm_offset_t)NULL) {
		printf("ERROR loading DTB\n");
		return;
	}

	if (OF_install(OFW_FDT, 0) == FALSE)
		panic("Cannot install FDT");

	if (OF_init((void *)dtbp) != 0)
		panic("OF_init failed with the found device tree");
}
#endif

static void
cache_setup(void)
{

	/* TODO */

	dcache_line_size = 0;
	icache_line_size = 0;
	idcache_line_size = 0;
}

/*
 * Fake up a boot descriptor table.
 * RISCVTODO: This needs to be done via loader (when it's available).
 */
vm_offset_t
fake_preload_metadata(struct riscv_bootparams *rvbp)
{
	static uint32_t fake_preload[35];
#ifdef DDB
#if 0
	vm_offset_t zstart = 0, zend = 0;
#endif
#endif
	vm_offset_t lastaddr;
	size_t dtb_size;
	int i;

	i = 0;

	fake_preload[i++] = MODINFO_NAME;
	fake_preload[i++] = strlen("kernel") + 1;
	strcpy((char*)&fake_preload[i++], "kernel");
	i += 1;
	fake_preload[i++] = MODINFO_TYPE;
	fake_preload[i++] = strlen("elf64 kernel") + 1;
	strcpy((char*)&fake_preload[i++], "elf64 kernel");
	i += 3;
	fake_preload[i++] = MODINFO_ADDR;
	fake_preload[i++] = sizeof(vm_offset_t);
	*(vm_offset_t *)&fake_preload[i++] =
	    (vm_offset_t)(KERNBASE + KERNENTRY);
	i += 1;
	fake_preload[i++] = MODINFO_SIZE;
	fake_preload[i++] = sizeof(vm_offset_t);
	fake_preload[i++] = (vm_offset_t)&end -
	    (vm_offset_t)(KERNBASE + KERNENTRY);
	i += 1;
#ifdef DDB
#if 0
	/* RISCVTODO */
	if (*(uint32_t *)KERNVIRTADDR == MAGIC_TRAMP_NUMBER) {
		fake_preload[i++] = MODINFO_METADATA|MODINFOMD_SSYM;
		fake_preload[i++] = sizeof(vm_offset_t);
		fake_preload[i++] = *(uint32_t *)(KERNVIRTADDR + 4);
		fake_preload[i++] = MODINFO_METADATA|MODINFOMD_ESYM;
		fake_preload[i++] = sizeof(vm_offset_t);
		fake_preload[i++] = *(uint32_t *)(KERNVIRTADDR + 8);
		lastaddr = *(uint32_t *)(KERNVIRTADDR + 8);
		zend = lastaddr;
		zstart = *(uint32_t *)(KERNVIRTADDR + 4);
		db_fetch_ksymtab(zstart, zend);
	} else
#endif
#endif
		lastaddr = (vm_offset_t)&end;

	/* Copy the DTB to KVA space. */
	lastaddr = roundup(lastaddr, sizeof(int));
	fake_preload[i++] = MODINFO_METADATA | MODINFOMD_DTBP;
	fake_preload[i++] = sizeof(vm_offset_t);
	*(vm_offset_t *)&fake_preload[i] = (vm_offset_t)lastaddr;
	i += sizeof(vm_offset_t) / sizeof(uint32_t);
	dtb_size = fdt_totalsize(rvbp->dtbp_virt);
	memmove((void *)lastaddr, (const void *)rvbp->dtbp_virt, dtb_size);
	lastaddr = roundup(lastaddr + dtb_size, sizeof(int));

	fake_preload[i++] = 0;
	fake_preload[i] = 0;
	preload_metadata = (void *)fake_preload;

	KASSERT(i < nitems(fake_preload), ("Too many fake_preload items"));

	return (lastaddr);
}

void
initriscv(struct riscv_bootparams *rvbp)
{
	struct mem_region mem_regions[FDT_MEM_REGIONS];
	struct pcpu *pcpup;
	int mem_regions_sz;
	vm_offset_t lastaddr;
	vm_size_t kernlen;
	caddr_t kmdp;

	TSRAW(&thread0, TS_ENTER, __func__, NULL);

	/* Set the pcpu data, this is needed by pmap_bootstrap */
	pcpup = &__pcpu[0];
	pcpu_init(pcpup, 0, sizeof(struct pcpu));
	pcpup->pc_hart = boot_hart;

	/* Set the pcpu pointer */
	__asm __volatile("mv tp, %0" :: "r"(pcpup));

	PCPU_SET(curthread, &thread0);

	/* Initialize SBI interface. */
	sbi_init();

	/* Set the module data location */
	lastaddr = fake_preload_metadata(rvbp);

	/* Find the kernel address */
	kmdp = preload_search_by_type("elf kernel");
	if (kmdp == NULL)
		kmdp = preload_search_by_type("elf64 kernel");

	boothowto = RB_VERBOSE | RB_SINGLE;
	boothowto = RB_VERBOSE;

	kern_envp = NULL;

#ifdef FDT
	try_load_dtb(kmdp);

	/*
	 * Exclude reserved memory specified by the device tree. Typically,
	 * this contains an entry for memory used by the runtime SBI firmware.
	 */
	if (fdt_get_reserved_mem(mem_regions, &mem_regions_sz) == 0) {
		physmem_exclude_regions(mem_regions, mem_regions_sz,
		    EXFLAG_NODUMP | EXFLAG_NOALLOC);
	}

	/* Grab physical memory regions information from device tree. */
	if (fdt_get_mem_regions(mem_regions, &mem_regions_sz, NULL) != 0) {
		panic("Cannot get physical memory regions");
	}
	physmem_hardware_regions(mem_regions, mem_regions_sz);
#endif

	/* Do basic tuning, hz etc */
	init_param1();

	cache_setup();

	/* Bootstrap enough of pmap to enter the kernel proper */
	kernlen = (lastaddr - KERNBASE);
	pmap_bootstrap(rvbp->kern_l1pt, rvbp->kern_phys, kernlen);

#ifdef FDT
	/*
	 * XXX: Exclude the lowest 2MB of physical memory, if it hasn't been
	 * already, as this area is assumed to contain the SBI firmware. This
	 * is a little fragile, but it is consistent with the platforms we
	 * support so far.
	 *
	 * TODO: remove this when the all regular booting methods properly
	 * report their reserved memory in the device tree.
	 */
	if (mem_regions[0].mr_start == physmap[0]) {
		physmem_exclude_region(mem_regions[0].mr_start, L2_SIZE,
		    EXFLAG_NODUMP | EXFLAG_NOALLOC);
	}
#endif
	physmem_init_kernel_globals();

	/* Establish static device mappings */
	devmap_bootstrap(0, NULL);

	cninit();

	init_proc0(rvbp->kern_stack);

	msgbufinit(msgbufp, msgbufsize);
	mutex_init();
	init_param2(physmem);
	kdb_init();

	if (boothowto & RB_VERBOSE)
		physmem_print_tables();

	early_boot = 0;

	TSEXIT();
}

#undef bzero
void
bzero(void *buf, size_t len)
{
	uint8_t *p;

	p = buf;
	while(len-- > 0)
		*p++ = 0;
}
