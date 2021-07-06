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
#include <sys/boot.h>
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

#ifdef DDB
#include <ddb/ddb.h>
#endif

#if __has_feature(capabilities)
#include <machine/cheri.h>
#include <cheri/cheric.h>
#ifdef CHERI_CAPREVOKE
#include <cheri/revoke.h>
#include <vm/vm_cheri_revoke.h>
#endif
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

#define BOOT_HART_INVALID	0xffffffff
uint32_t boot_hart = BOOT_HART_INVALID;	/* The hart we booted on. */

cpuset_t all_harts;

extern int *end;

#ifdef FDT
static char static_kenv[PAGE_SIZE];
#endif

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

/*
 * QEMU ISA-level tracing in buffered mode.
 * The trace entries are stored in a ring buffer and only emitted
 * upon request. This is currently done on trap.
 */
u_int	qemu_trace_buffered;

static int
sysctl_hw_qemu_buffered(SYSCTL_HANDLER_ARGS)
{
	int error;

	error = sysctl_handle_int(oidp, &qemu_trace_buffered, 0, req);
	if (error || !req->newptr)
		return (error);
	if (qemu_trace_buffered)
		QEMU_SET_TRACE_BUFFERED_MODE;
	else
		QEMU_CLEAR_TRACE_BUFFERED_MODE;
	return (0);
}

SYSCTL_PROC(_hw, OID_AUTO, qemu_trace_buffered, CTLTYPE_INT | CTLFLAG_RW,
    0, 0, sysctl_hw_qemu_buffered, "", "Qemu tracing runs in buffered mode");
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

int
ptrace_set_pc(struct thread *td, u_long addr)
{

#if __has_feature(capabilities)
	if (SV_PROC_FLAG(td->td_proc, SV_CHERI) &&
	    !cheri_is_address_inbounds(
	    (void * __capability)td->td_frame->tf_sepc, addr))
		return (EINVAL);
	td->td_frame->tf_sepc = cheri_setaddress(td->td_frame->tf_sepc, addr);
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
		tf->tf_a[0] = (uintcap_t)imgp->auxv;
		tf->tf_sp = stack;
		tf->tf_sepc = (uintcap_t)cheri_exec_pcc(td, imgp);
		td->td_proc->p_md.md_sigcode = cheri_sigcode_capability(td);
	} else
#endif
	{
		tf->tf_a[0] = (__cheri_addr vaddr_t)stack;
		tf->tf_sp = STACKALIGN((__cheri_addr vaddr_t)stack);
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
	    (__cheri_addr vaddr_t)catcher, sig);

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
				(__cheri_addr vaddr_t)fp);
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
		tf->tf_ra = (register_t)(p->p_psstrings -
		    *(sysent->sv_szsigcode));
#endif

	CTR3(KTR_SIG, "sendsig: return td=%p pc=%#x sp=%#x", td, tf->tf_sepc,
	    tf->tf_sp);

	PROC_LOCK(p);
	mtx_lock(&psp->ps_mtx);
}

static void
init_proc0(vm_pointer_t kstack)
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
	vm_pointer_t dtbp;

	dtbp = MD_FETCH(kmdp, MODINFOMD_DTBP, vm_offset_t);
#ifdef __CHERI_PURE_CAPABILITY__
	if (dtbp != (vm_pointer_t)NULL) {
		dtbp = (vm_pointer_t)cheri_andperm(cheri_setaddress(
		    kernel_root_cap, dtbp), CHERI_PERMS_KERNEL_DATA);
		dtbp = (vm_pointer_t)cheri_setbounds((void *)dtbp,
		    fdt_totalsize((void *)dtbp));
	}
#endif

#if defined(FDT_DTB_STATIC)
	/*
	 * In case the device tree blob was not retrieved (from metadata) try
	 * to use the statically embedded one.
	 */
	if (dtbp == (vm_pointer_t)NULL)
		dtbp = (vm_pointer_t)&fdt_static_dtb;
#endif

	if (dtbp == (vm_pointer_t)NULL) {
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
 */
static void
fake_preload_metadata(struct riscv_bootparams *rvbp)
{
	static uint32_t fake_preload[48];
	vm_offset_t lastaddr;
	size_t fake_size, dtb_size;

#define PRELOAD_PUSH_VALUE(type, value) do {			\
	*(type *)((char *)fake_preload + fake_size) = (value);	\
	fake_size += sizeof(type);				\
} while (0)

#define PRELOAD_PUSH_STRING(str) do {				\
	uint32_t ssize;						\
	ssize = strlen(str) + 1;				\
	PRELOAD_PUSH_VALUE(uint32_t, ssize);			\
	strcpy(((char *)fake_preload + fake_size), str);	\
	fake_size += ssize;					\
	fake_size = roundup(fake_size, sizeof(u_long));		\
} while (0)

	fake_size = 0;
	lastaddr = (vm_offset_t)&end;

	PRELOAD_PUSH_VALUE(uint32_t, MODINFO_NAME);
	PRELOAD_PUSH_STRING("kernel");
	PRELOAD_PUSH_VALUE(uint32_t, MODINFO_TYPE);
	PRELOAD_PUSH_STRING("elf kernel");

	PRELOAD_PUSH_VALUE(uint32_t, MODINFO_ADDR);
	PRELOAD_PUSH_VALUE(uint32_t, sizeof(vm_offset_t));
	PRELOAD_PUSH_VALUE(uint64_t, KERNBASE);

	PRELOAD_PUSH_VALUE(uint32_t, MODINFO_SIZE);
	PRELOAD_PUSH_VALUE(uint32_t, sizeof(size_t));
	PRELOAD_PUSH_VALUE(uint64_t, (size_t)((vm_offset_t)&end - KERNBASE));

	/*
	 * XXX: Storing a capability here is problematic due to the
	 * layout of metadata, and the issue of needing the boot
	 * loader to eventually pass in caps here.  However, do round
	 * up to ensure the DTB area is a representable pointer even
	 * if we have to rederive it later.
	 */

	/* Copy the DTB to KVA space. */
	dtb_size = fdt_totalsize(rvbp->dtbp_virt);
#ifdef __CHERI_PURE_CAPABILITY__
	lastaddr = roundup2(lastaddr, CHERI_REPRESENTABLE_ALIGNMENT(dtb_size));
#else
	lastaddr = roundup(lastaddr, sizeof(int));
#endif
	PRELOAD_PUSH_VALUE(uint32_t, MODINFO_METADATA | MODINFOMD_DTBP);
	PRELOAD_PUSH_VALUE(uint32_t, sizeof(vm_offset_t));
	PRELOAD_PUSH_VALUE(vm_offset_t, lastaddr);
#ifdef __CHERI_PURE_CAPABILITY__
	void *dtbp = cheri_setbounds(cheri_setaddress(kernel_root_cap,
	    lastaddr), dtb_size);
	memmove(dtbp, (const void *)rvbp->dtbp_virt, dtb_size);
	lastaddr = roundup(lastaddr + cheri_getlen(dtbp), sizeof(int));
#else
	memmove((void *)lastaddr, (const void *)rvbp->dtbp_virt, dtb_size);
	lastaddr = roundup(lastaddr + dtb_size, sizeof(int));
#endif

	PRELOAD_PUSH_VALUE(uint32_t, MODINFO_METADATA | MODINFOMD_KERNEND);
	PRELOAD_PUSH_VALUE(uint32_t, sizeof(vm_offset_t));
	PRELOAD_PUSH_VALUE(vm_offset_t, lastaddr);

	PRELOAD_PUSH_VALUE(uint32_t, MODINFO_METADATA | MODINFOMD_HOWTO);
	PRELOAD_PUSH_VALUE(uint32_t, sizeof(int));
	PRELOAD_PUSH_VALUE(int, RB_VERBOSE);

	/* End marker */
	PRELOAD_PUSH_VALUE(uint32_t, 0);
	PRELOAD_PUSH_VALUE(uint32_t, 0);
	preload_metadata = (caddr_t)fake_preload;

	/* Check if bootloader clobbered part of the kernel with the DTB. */
	KASSERT(rvbp->dtbp_phys + dtb_size <= rvbp->kern_phys ||
		rvbp->dtbp_phys >= rvbp->kern_phys + (lastaddr - KERNBASE),
	    ("FDT (%lx-%lx) and kernel (%lx-%lx) overlap", rvbp->dtbp_phys,
		rvbp->dtbp_phys + dtb_size, rvbp->kern_phys,
		rvbp->kern_phys + (lastaddr - KERNBASE)));
	KASSERT(fake_size < sizeof(fake_preload),
	    ("Too many fake_preload items"));

	if (boothowto & RB_VERBOSE)
		printf("FDT phys (%lx-%lx), kernel phys (%lx-%lx)\n",
		    rvbp->dtbp_phys, rvbp->dtbp_phys + dtb_size,
		    rvbp->kern_phys, rvbp->kern_phys + (lastaddr - KERNBASE));
}

#ifdef FDT
static void
parse_fdt_bootargs(void)
{
	char bootargs[512];

	bootargs[sizeof(bootargs) - 1] = '\0';
	if (fdt_get_chosen_bootargs(bootargs, sizeof(bootargs) - 1) == 0) {
		boothowto |= boot_parse_cmdline(bootargs);
	}
}
#endif

static vm_offset_t
parse_metadata(void)
{
	caddr_t kmdp;
	vm_offset_t lastaddr;
#ifdef DDB
	vm_pointer_t ksym_start, ksym_end;
#endif
	char *kern_envp;

	/* Find the kernel address */
	kmdp = preload_search_by_type("elf kernel");
	if (kmdp == NULL)
		kmdp = preload_search_by_type("elf64 kernel");
	KASSERT(kmdp != NULL, ("No preload metadata found!"));

	/* Read the boot metadata */
	boothowto = MD_FETCH(kmdp, MODINFOMD_HOWTO, int);
	lastaddr = MD_FETCH(kmdp, MODINFOMD_KERNEND, vm_offset_t);
	kern_envp = MD_FETCH(kmdp, MODINFOMD_ENVP, char *);
	if (kern_envp != NULL)
		init_static_kenv(kern_envp, 0);
	else
		init_static_kenv(static_kenv, sizeof(static_kenv));
#ifdef DDB
	ksym_start = MD_FETCH(kmdp, MODINFOMD_SSYM, uintptr_t);
	ksym_end = MD_FETCH(kmdp, MODINFOMD_ESYM, uintptr_t);
	db_fetch_ksymtab(ksym_start, ksym_end, 0);
#endif
#ifdef FDT
	try_load_dtb(kmdp);
	if (kern_envp == NULL) {
		init_static_kenv(static_kenv, sizeof(static_kenv));
		parse_fdt_bootargs();
	}
#endif
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
#ifdef FDT
	phandle_t chosen;
	uint32_t hart;
#endif
	char *env;

	TSRAW(&thread0, TS_ENTER, __func__, NULL);

	/* Set the pcpu data, this is needed by pmap_bootstrap */
	pcpup = &__pcpu[0];
	pcpu_init(pcpup, 0, sizeof(struct pcpu));

	/* Set the pcpu pointer */
#ifdef __CHERI_PURE_CAPABILITY__
	__asm __volatile("cmove ctp, %0" :: "C"(pcpup));
#else
	__asm __volatile("mv tp, %0" :: "r"(pcpup));
#endif

	PCPU_SET(curthread, &thread0);

	/* Initialize SBI interface. */
	sbi_init();

	/* Parse the boot metadata. */
	if (rvbp->modulep != 0) {
		preload_metadata = (caddr_t)rvbp->modulep;
	} else {
		fake_preload_metadata(rvbp);
	}
	lastaddr = parse_metadata();

#ifdef FDT
	/*
	 * Look for the boot hart ID. This was either passed in directly from
	 * the SBI firmware and handled by locore, or was stored in the device
	 * tree by an earlier boot stage.
	 */
	chosen = OF_finddevice("/chosen");
	if (OF_getencprop(chosen, "boot-hartid", &hart, sizeof(hart)) != -1) {
		boot_hart = hart;
	}
#endif
	if (boot_hart == BOOT_HART_INVALID) {
		panic("Boot hart ID was not properly set");
	}
	pcpup->pc_hart = boot_hart;

#ifdef FDT
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

	/*
	 * Dump the boot metadata. We have to wait for cninit() since console
	 * output is required. If it's grossly incorrect the kernel will never
	 * make it this far.
	 */
	if (getenv_is_true("debug.dump_modinfo_at_boot"))
		preload_dump();

	init_proc0(rvbp->kern_stack);

	msgbufinit(msgbufp, msgbufsize);
	mutex_init();
	init_param2(physmem);
	kdb_init();

	env = kern_getenv("kernelname");
	if (env != NULL)
		strlcpy(kernelname, env, sizeof(kernelname));

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

#ifdef CHERI_CAPREVOKE
void
cheri_revoke_td_frame(struct thread *td,
    const struct vm_cheri_revoke_cookie *crc)
{
	CHERI_REVOKE_STATS_FOR(crst, crc);

#define CHERI_REVOKE_REG(r) \
	do { if (cheri_gettag(r)) { \
		CHERI_REVOKE_STATS_BUMP(crst, caps_found); \
		if (vm_cheri_revoke_test(crc, r)) { \
			r = cheri_revoke(r); \
			CHERI_REVOKE_STATS_BUMP(crst, caps_cleared); \
		} \
	    }} while(0)

	CHERI_REVOKE_REG(td->td_frame->tf_ra);
	CHERI_REVOKE_REG(td->td_frame->tf_sp);
	CHERI_REVOKE_REG(td->td_frame->tf_gp);
	CHERI_REVOKE_REG(td->td_frame->tf_tp);
	CHERI_REVOKE_REG(td->td_frame->tf_t[0]);
	CHERI_REVOKE_REG(td->td_frame->tf_t[1]);
	CHERI_REVOKE_REG(td->td_frame->tf_t[2]);
	CHERI_REVOKE_REG(td->td_frame->tf_t[3]);
	CHERI_REVOKE_REG(td->td_frame->tf_t[4]);
	CHERI_REVOKE_REG(td->td_frame->tf_t[5]);
	CHERI_REVOKE_REG(td->td_frame->tf_t[6]);
	CHERI_REVOKE_REG(td->td_frame->tf_s[0]);
	CHERI_REVOKE_REG(td->td_frame->tf_s[1]);
	CHERI_REVOKE_REG(td->td_frame->tf_s[2]);
	CHERI_REVOKE_REG(td->td_frame->tf_s[3]);
	CHERI_REVOKE_REG(td->td_frame->tf_s[4]);
	CHERI_REVOKE_REG(td->td_frame->tf_s[5]);
	CHERI_REVOKE_REG(td->td_frame->tf_s[6]);
	CHERI_REVOKE_REG(td->td_frame->tf_s[7]);
	CHERI_REVOKE_REG(td->td_frame->tf_s[8]);
	CHERI_REVOKE_REG(td->td_frame->tf_s[9]);
	CHERI_REVOKE_REG(td->td_frame->tf_s[10]);
	CHERI_REVOKE_REG(td->td_frame->tf_s[11]);
	CHERI_REVOKE_REG(td->td_frame->tf_a[0]);
	CHERI_REVOKE_REG(td->td_frame->tf_a[1]);
	CHERI_REVOKE_REG(td->td_frame->tf_a[2]);
	CHERI_REVOKE_REG(td->td_frame->tf_a[3]);
	CHERI_REVOKE_REG(td->td_frame->tf_a[4]);
	CHERI_REVOKE_REG(td->td_frame->tf_a[5]);
	CHERI_REVOKE_REG(td->td_frame->tf_a[6]);
	CHERI_REVOKE_REG(td->td_frame->tf_a[7]);
	CHERI_REVOKE_REG(td->td_frame->tf_sepc); /* This could be real exciting! */
	CHERI_REVOKE_REG(td->td_frame->tf_ddc);

#undef CHERI_REVOKE_REG

	return;
}
#endif

// CHERI CHANGES START
// {
//   "updated": 20200803,
//   "target_type": "kernel",
//   "changes_purecap": [
//     "pointer_as_integer",
//     "pointer_provenance"
//   ]
// }
// CHERI CHANGES END
