/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1982, 1986 The Regents of the University of California.
 * Copyright (c) 1989, 1990 William Jolitz
 * Copyright (c) 1994 John Dyson
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department, and William Jolitz.
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
 *	from: @(#)vm_machdep.c	7.3 (Berkeley) 5/13/91
 *	Utah $Hdr: vm_machdep.c 1.16.1.1 89/06/23$
 *	from: src/sys/i386/i386/vm_machdep.c,v 1.132.2.2 2000/08/26 04:19:26 yokota
 *	JNPR: vm_machdep.c,v 1.8.2.2 2007/08/16 15:59:17 girish
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_ddb.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/syscall.h>
#include <sys/sysent.h>
#include <sys/buf.h>
#include <sys/vnode.h>
#include <sys/vmmeter.h>
#include <sys/kernel.h>
#include <sys/rwlock.h>
#include <sys/sysctl.h>
#include <sys/unistd.h>
#include <sys/vmem.h>

#include <machine/_inttypes.h>
#include <machine/abi.h>
#include <machine/cache.h>
#include <machine/clock.h>
#include <machine/cpu.h>
#include <machine/cpufunc.h>
#include <machine/cpuinfo.h>
#include <machine/md_var.h>
#include <machine/pcb.h>
#include <machine/tls.h>

#ifdef CPU_CHERI
#include <cheri/cheri.h>
#include <cheri/cheric.h>
#endif

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/vm_param.h>
#include <vm/uma.h>
#include <vm/uma_int.h>

#include <sys/stdatomic.h>
#include <sys/user.h>
#include <sys/mbuf.h>

#ifdef CHERI_CAPREVOKE
#include <sys/caprevoke.h>
#include <vm/vm_caprevoke.h>
#endif

/*
 * Finish a fork operation, with process p2 nearly set up.
 * Copy and update the pcb, set up the stack so that the child
 * ready to run and return to user mode.
 */
void
cpu_fork(struct thread *td1, struct proc *p2, struct thread *td2, int flags)
{
	struct pcb *pcb2;

	if ((flags & RFPROC) == 0)
		return;
	/* It is assumed that the vm_thread_alloc called
	 * cpu_thread_alloc() before cpu_fork is called.
	 */

	/* Point the pcb to the top of the stack */
	pcb2 = td2->td_pcb;

	/* Copy td1's pcb, note that in this case
	 * our pcb also includes the td_frame being copied
	 * too. The older mips2 code did an additional copy
	 * of the td_frame, for us that's not needed any
	 * longer (this copy does them both) 
	 */
#ifndef CPU_CHERI
	bcopy(td1->td_pcb, pcb2, sizeof(*pcb2));
#else
	cheri_bcopy(td1->td_pcb, pcb2, sizeof(*pcb2));
	cheri_signal_copy(pcb2, td1->td_pcb);
	cheri_sealcap_copy(p2, td1->td_proc);
#endif

	/* Point mdproc and then copy over td1's contents */
	td2->td_md.md_flags = td1->td_md.md_flags & MDTD_FPUSED;

	/* Inherit Qemu ISA-level tracing from parent. */
#ifdef CPU_CPU_QEMU_MALTA
	td2->td_md.md_flags |= td1->td_md.md_flags & MDTD_QTRACE;
#endif

	/*
	 * Set up return-value registers as fork() libc stub expects.
	 */
	td2->td_frame->v0 = 0;
	td2->td_frame->v1 = 1;
	td2->td_frame->a3 = 0;

#if defined(CPU_HAVEFPU)
	if (td1 == PCPU_GET(fpcurthread))
		MipsSaveCurFPState(td1);
#endif

	pcb2->pcb_context[PCB_REG_RA] = (register_t)(intptr_t)fork_trampoline;
	/* Make sp 64-bit aligned */
	pcb2->pcb_context[PCB_REG_SP] = (register_t)(((vm_offset_t)td2->td_pcb &
#ifdef CPU_CHERI
	    ~(CHERICAP_SIZE - 1))
#else
	    ~(sizeof(__int64_t) - 1))
#endif
	    - CALLFRAME_SIZ);
	pcb2->pcb_context[PCB_REG_S0] = (register_t)(intptr_t)fork_return;
	pcb2->pcb_context[PCB_REG_S1] = (register_t)(intptr_t)td2;
	pcb2->pcb_context[PCB_REG_S2] = (register_t)(intptr_t)td2->td_frame;
	pcb2->pcb_context[PCB_REG_SR] = mips_rd_status() &
	    (MIPS_SR_KX | MIPS_SR_UX | MIPS_SR_INT_MASK);
	/*
	 * FREEBSD_DEVELOPERS_FIXME:
	 * Setup any other CPU-Specific registers (Not MIPS Standard)
	 * and/or bits in other standard MIPS registers (if CPU-Specific)
	 *  that are needed.
	 */

	td2->td_md.md_tls = td1->td_md.md_tls;
	td2->td_md.md_tls_tcb_offset = td1->td_md.md_tls_tcb_offset;
	td2->td_md.md_saved_intr = MIPS_SR_INT_IE;
	td2->td_md.md_spinlock_count = 1;
#ifdef CPU_CHERI
#ifdef COMPAT_CHERIABI
	td2->td_md.md_cheri_mmap_cap = td1->td_md.md_cheri_mmap_cap;
#endif
	/*
	 * XXXRW: Ensure capability coprocessor is enabled for both kernel and
	 * userspace in child.
	 */
	td2->td_frame->sr |= MIPS_SR_COP_2_BIT;
	pcb2->pcb_context[PCB_REG_SR] |= MIPS_SR_COP_2_BIT;
#endif
#ifdef CPU_CNMIPS
	if (td1->td_md.md_flags & MDTD_COP2USED) {
		if (td1->td_md.md_cop2owner == COP2_OWNER_USERLAND) {
			if (td1->td_md.md_ucop2)
				octeon_cop2_save(td1->td_md.md_ucop2);
			else
				panic("cpu_fork: ucop2 is NULL but COP2 is enabled");
		}
		else {
			if (td1->td_md.md_cop2)
				octeon_cop2_save(td1->td_md.md_cop2);
			else
				panic("cpu_fork: cop2 is NULL but COP2 is enabled");
		}
	}

	if (td1->td_md.md_cop2) {
		td2->td_md.md_cop2 = octeon_cop2_alloc_ctx();
		memcpy(td2->td_md.md_cop2, td1->td_md.md_cop2, 
			sizeof(*td1->td_md.md_cop2));
	}
	if (td1->td_md.md_ucop2) {
		td2->td_md.md_ucop2 = octeon_cop2_alloc_ctx();
		memcpy(td2->td_md.md_ucop2, td1->td_md.md_ucop2, 
			sizeof(*td1->td_md.md_ucop2));
	}
	td2->td_md.md_cop2owner = td1->td_md.md_cop2owner;
	pcb2->pcb_context[PCB_REG_SR] |= MIPS_SR_PX | MIPS_SR_UX | MIPS_SR_KX | MIPS_SR_SX;
	/* Clear COP2 bits for userland & kernel */
	td2->td_frame->sr &= ~MIPS_SR_COP_2_BIT;
	pcb2->pcb_context[PCB_REG_SR] &= ~MIPS_SR_COP_2_BIT;
#endif
}

/*
 * Intercept the return address from a freshly forked process that has NOT
 * been scheduled yet.
 *
 * This is needed to make kernel threads stay in kernel mode.
 */
void
cpu_fork_kthread_handler(struct thread *td, void (*func)(void *), void *arg)
{
	/*
	 * Note that the trap frame follows the args, so the function
	 * is really called like this:	func(arg, frame);
	 */
	td->td_pcb->pcb_context[PCB_REG_S0] = (register_t)(intptr_t)func;
	td->td_pcb->pcb_context[PCB_REG_S1] = (register_t)(intptr_t)arg;
}

void
cpu_exit(struct thread *td)
{
}

void
cpu_thread_exit(struct thread *td)
{

	if (PCPU_GET(fpcurthread) == td)
		PCPU_GET(fpcurthread) = (struct thread *)0;
#ifdef  CPU_CNMIPS
	if (td->td_md.md_cop2)
		memset(td->td_md.md_cop2, 0,
			sizeof(*td->td_md.md_cop2));
	if (td->td_md.md_ucop2)
		memset(td->td_md.md_ucop2, 0,
			sizeof(*td->td_md.md_ucop2));
#endif
}

void
cpu_thread_free(struct thread *td)
{
#ifdef  CPU_CNMIPS
	if (td->td_md.md_cop2)
		octeon_cop2_free_ctx(td->td_md.md_cop2);
	if (td->td_md.md_ucop2)
		octeon_cop2_free_ctx(td->td_md.md_ucop2);
	td->td_md.md_cop2 = NULL;
	td->td_md.md_ucop2 = NULL;
#endif
}

void
cpu_thread_clean(struct thread *td)
{
}

void
cpu_thread_swapin(struct thread *td)
{
	pt_entry_t *pte;

	/*
	 * The kstack may be at a different physical address now.
	 * Cache the PTEs for the Kernel stack in the machine dependent
	 * part of the thread struct so cpu_switch() can quickly map in
	 * the pcb struct and kernel stack.
	 */
#ifdef KSTACK_LARGE_PAGE
	/* Just one entry for one large kernel page. */
	pte = pmap_pte(kernel_pmap, td->td_kstack);
	td->td_md.md_upte[0] = PTE_G;   /* Guard Page */
	td->td_md.md_upte[1] = *pte & ~TLBLO_SWBITS_MASK;

#else

	int i;

	for (i = 0; i < KSTACK_PAGES; i++) {
		pte = pmap_pte(kernel_pmap, td->td_kstack + i * PAGE_SIZE);
		td->td_md.md_upte[i] = *pte & ~TLBLO_SWBITS_MASK;
	}
#endif /* ! KSTACK_LARGE_PAGE */
}

void
cpu_thread_swapout(struct thread *td)
{
}

void
cpu_thread_alloc(struct thread *td)
{
	pt_entry_t *pte;

#ifdef KSTACK_LARGE_PAGE
	KASSERT((td->td_kstack & (KSTACK_PAGE_SIZE - 1) ) == 0,
	    ("kernel stack must be aligned to 16K boundary."));
#else
	KASSERT((td->td_kstack & ((KSTACK_PAGE_SIZE * 2) - 1) ) == 0,
	    ("kernel stack must be aligned."));
#endif
	td->td_pcb = (struct pcb *)(td->td_kstack +
	    td->td_kstack_pages * PAGE_SIZE) - 1;
	td->td_frame = &td->td_pcb->pcb_regs;
#ifdef KSTACK_LARGE_PAGE
	/* Just one entry for one large kernel page. */
	pte = pmap_pte(kernel_pmap, td->td_kstack);
	td->td_md.md_upte[0] = PTE_G;   /* Guard Page */
	td->td_md.md_upte[1] = *pte & ~TLBLO_SWBITS_MASK;

#else

	{
		int i;

		for (i = 0; i < KSTACK_PAGES; i++) {
			pte = pmap_pte(kernel_pmap, td->td_kstack + i *
			    PAGE_SIZE);
			td->td_md.md_upte[i] = *pte & ~TLBLO_SWBITS_MASK;
		}
	}
#endif /* ! KSTACK_LARGE_PAGE */
}

void
cpu_set_syscall_retval(struct thread *td, int error)
{
	struct trapframe *locr0 = td->td_frame;
	unsigned int code;
	int quad_syscall;

	code = locr0->v0;
	quad_syscall = 0;
#if defined(__mips_n32) || defined(__mips_n64)
#ifdef COMPAT_FREEBSD32
	if (code == SYS___syscall && SV_PROC_FLAG(td->td_proc, SV_ILP32))
		quad_syscall = 1;
#endif
#else
	if (code == SYS___syscall)
		quad_syscall = 1;
#endif

	if (code == SYS_syscall)
		code = locr0->a0;
	else if (code == SYS___syscall) {
		if (quad_syscall)
			code = _QUAD_LOWWORD ? locr0->a1 : locr0->a0;
		else
			code = locr0->a0;
	}

	switch (error) {
	case 0:
		if (quad_syscall && code != SYS_lseek) {
			/*
			 * System call invoked through the
			 * SYS___syscall interface but the
			 * return value is really just 32
			 * bits.
			 */
			locr0->v0 = td->td_retval[0];
			if (_QUAD_LOWWORD)
				locr0->v1 = td->td_retval[0];
			locr0->a3 = 0;
		} else {
			locr0->v0 = td->td_retval[0];
			locr0->v1 = td->td_retval[1];
			locr0->a3 = 0;
		}
		break;

	case ERESTART:
		locr0->pc = td->td_pcb->pcb_tpc;
		break;

	case EJUSTRETURN:
		break;	/* nothing to do */

	default:
		if (quad_syscall && code != SYS_lseek) {
			locr0->v0 = error;
			if (_QUAD_LOWWORD)
				locr0->v1 = error;
			locr0->a3 = 1;
		} else {
			locr0->v0 = error;
			locr0->a3 = 1;
		}
	}
}

/*
 * Initialize machine state, mostly pcb and trap frame for a new
 * thread, about to return to userspace.  Put enough state in the new
 * thread's PCB to get it to go back to the fork_return(), which
 * finalizes the thread state and handles peculiarities of the first
 * return to userspace for the new thread.
 */
void
cpu_copy_thread(struct thread *td, struct thread *td0)
{
	struct pcb *pcb2;

	/* Point the pcb to the top of the stack. */
	pcb2 = td->td_pcb;

	/*
	 * Copy the upcall pcb.  This loads kernel regs.
	 * Those not loaded individually below get their default
	 * values here.
	 *
	 * XXXKSE It might be a good idea to simply skip this as
	 * the values of the other registers may be unimportant.
	 * This would remove any requirement for knowing the KSE
	 * at this time (see the matching comment below for
	 * more analysis) (need a good safe default).
	 * In MIPS, the trapframe is the first element of the PCB
	 * and gets copied when we copy the PCB. No separate copy
	 * is needed.
	 */
#ifndef CPU_CHERI
	bcopy(td0->td_pcb, pcb2, sizeof(*pcb2));
#else
	cheri_bcopy(td0->td_pcb, pcb2, sizeof(*pcb2));
	cheri_signal_copy(pcb2, td0->td_pcb);
#endif

	/*
	 * Set registers for trampoline to user mode.
	 */

	pcb2->pcb_context[PCB_REG_RA] = (register_t)(intptr_t)fork_trampoline;
	/* Make sp 64-bit aligned */
	pcb2->pcb_context[PCB_REG_SP] = (register_t)(((vm_offset_t)td->td_pcb &
#ifdef CPU_CHERI
	    ~(CHERICAP_SIZE - 1))
#else
	    ~(sizeof(__int64_t) - 1))
#endif
	    - CALLFRAME_SIZ);
	pcb2->pcb_context[PCB_REG_S0] = (register_t)(intptr_t)fork_return;
	pcb2->pcb_context[PCB_REG_S1] = (register_t)(intptr_t)td;
	pcb2->pcb_context[PCB_REG_S2] = (register_t)(intptr_t)td->td_frame;
	/* Dont set IE bit in SR. sched lock release will take care of it */
	pcb2->pcb_context[PCB_REG_SR] = mips_rd_status() &
	    (MIPS_SR_PX | MIPS_SR_KX | MIPS_SR_UX | MIPS_SR_INT_MASK);

#ifdef CPU_CHERI
	/*
	 * XXXRW: Interesting that we just set pcb_context here and not also
	 * the trap frame.
	 *
	 * XXXRW: With CPU_CNMIPS parts moved, does this still belong here?
	 */
	pcb2->pcb_context[PCB_REG_SR] |= MIPS_SR_COP_2_BIT;
#endif

	/*
	 * FREEBSD_DEVELOPERS_FIXME:
	 * Setup any other CPU-Specific registers (Not MIPS Standard)
	 * that are needed.
	 */

	/* Setup to release spin count in in fork_exit(). */
	td->td_md.md_spinlock_count = 1;
	td->td_md.md_saved_intr = MIPS_SR_INT_IE;
#if defined(CPU_CHERI) && defined(COMPAT_CHERIABI)
	td->td_md.md_cheri_mmap_cap = td0->td_md.md_cheri_mmap_cap;
#endif
#if 0
	    /* Maybe we need to fix this? */
	td->td_md.md_saved_sr = ( (MIPS_SR_COP_2_BIT | MIPS_SR_COP_0_BIT) |
	                          (MIPS_SR_PX | MIPS_SR_UX | MIPS_SR_KX | MIPS_SR_SX) |
	                          (MIPS_SR_INT_IE | MIPS_HARD_INT_MASK));
#endif
}

/*
 * Set that machine state for performing an upcall that starts
 * the entry function with the given argument.
 */
void
cpu_set_upcall(struct thread *td, void (*entry)(void *), void *arg,
    stack_t *stack)
{
	struct trapframe *tf;
	register_t sp;

	sp = (((__cheri_addr vaddr_t)stack->ss_sp + stack->ss_size) & ~(STACK_ALIGN - 1)) -
	    CALLFRAME_SIZ;

	/*
	 * Set the trap frame to point at the beginning of the uts
	 * function.
	 */
	tf = td->td_frame;
	bzero(tf, sizeof(struct trapframe));
	tf->sp = sp;
	tf->pc = (register_t)(intptr_t)entry;
	/* 
	 * MIPS ABI requires T9 to be the same as PC 
	 * in subroutine entry point
	 */
	tf->t9 = (register_t)(intptr_t)entry; 
	tf->a0 = (register_t)(intptr_t)arg;

	/*
	 * Keep interrupt mask
	 *
	 * XXXRW: I'm a bit puzzled by the code below and feel that even if it
	 * works, it can't really be right.
	 */
	td->td_frame->sr = MIPS_SR_KSU_USER | MIPS_SR_EXL | MIPS_SR_INT_IE |
	    (mips_rd_status() & MIPS_SR_INT_MASK);
#if defined(__mips_n32) 
	td->td_frame->sr |= MIPS_SR_PX;
#elif  defined(__mips_n64)
	td->td_frame->sr |= MIPS_SR_PX | MIPS_SR_UX | MIPS_SR_KX;
#endif

	 /* XXXRW: With CNMIPS moved, does this still belong here? */
#ifdef CPU_CHERI
	/*
	 * For the MIPS ABI, we can derive any required CHERI state from
	 * the completed MIPS trapframe and existing process state.
	 */
	tf->sr |= MIPS_SR_COP_2_BIT;
	hybridabi_newthread_setregs(td, (uintptr_t)entry);
#endif
/*	tf->sr |= (ALL_INT_MASK & idle_mask) | SR_INT_ENAB; */
	/**XXX the above may now be wrong -- mips2 implements this as panic */
	/*
	 * FREEBSD_DEVELOPERS_FIXME:
	 * Setup any other CPU-Specific registers (Not MIPS Standard)
	 * that are needed.
	 */
}

bool
cpu_exec_vmspace_reuse(struct proc *p __unused, vm_map_t map __unused)
{

	return (true);
}

int
cpu_procctl(struct thread *td __unused, int idtype __unused, id_t id __unused,
    int com __unused, void * __capability data __unused)
{

	return (EINVAL);
}

/*
 * Software interrupt handler for queued VM system processing.
 */
void
swi_vm(void *dummy)
{

	if (busdma_swi_pending)
		busdma_swi();
}

int
cpu_set_user_tls(struct thread *td, void *tls_base)
{

#if defined(__mips_n64) && defined(COMPAT_FREEBSD32)
	if (td->td_proc && SV_PROC_FLAG(td->td_proc, SV_ILP32))
		td->td_md.md_tls_tcb_offset = TLS_TP_OFFSET + TLS_TCB_SIZE32;
	else
#endif
#if defined (COMPAT_CHERIABI)
	/*
	 * XXX-AR: should cheriabi_set_user_tls just delegate to this
	 * function?
	 */
	if (td->td_proc && SV_PROC_FLAG(td->td_proc, SV_CHERI))
		panic("cpu_set_user_tls(%p) should not be called from CHERIABI\n", td);
	else
#endif
	td->td_md.md_tls_tcb_offset = TLS_TP_OFFSET + TLS_TCB_SIZE;
	td->td_md.md_tls = __USER_CAP_UNBOUND(tls_base);
	if (td == curthread && cpuinfo.userlocal_reg == true) {
		mips_wr_userlocal((unsigned long)tls_base +
		    td->td_md.md_tls_tcb_offset);
	}

	return (0);
}

#ifdef CHERI_CAPREVOKE

static inline int
vm_test_caprevoke_mem(const struct vm_caprevoke_cookie *crc,
		      const void * __capability cut)
{
	/*
	 * Find appropriate bitmap bits.  We use the base so that even if
	 * the cursor is out of bounds, we find the true status of the
	 * allocation under test.
	 */

	vm_offset_t va = cheri_getbase(cut);

	/*
	 * All capabilities are checked against the coarse MAP bitmap, unless
	 * we're instructed not to, as we might be if we know that there are
	 * no bits set anywhere in that map.  Since this map is under the
	 * kernel's control, this is a reasonable possibility.
	 */
	if ((crc->flags & VM_CAPREVOKE_CF_NO_COARSE) == 0)
	{
		uint8_t bmbits;
		const uint8_t * __capability bmloc;

		bmloc = crc->crshadow
			+ (VM_CAPREVOKE_BM_MEM_MAP - VM_CAPREVOKE_BM_BASE)
			+ (va / VM_CAPREVOKE_GSZ_MEM_MAP / 8);

		bmbits = fubyte_c(bmloc);

		if (bmbits & (1 << ((va / VM_CAPREVOKE_GSZ_MEM_NOMAP) % 8))) {
			return 1;
		}
	}

	if ((cheri_getperm(cut) & CHERI_PERM_CHERIABI_VMMAP) == 0) {
		/*
		 * This is a non-VMMAP-bearing capability.  Also check the
		 * NOMAP bitmap
		 */

		uint8_t bmbits;
		const uint8_t * __capability bmloc;

		bmloc = crc->crshadow
			+ (VM_CAPREVOKE_BM_MEM_NOMAP - VM_CAPREVOKE_BM_BASE)
			+ (va / VM_CAPREVOKE_GSZ_MEM_NOMAP / 8);

		bmbits = fubyte_c(bmloc);

		if (bmbits & (1 << ((va / VM_CAPREVOKE_GSZ_MEM_NOMAP) % 8))) {
			return 1;
		}
	}

	return 0;
}

int
vm_test_caprevoke(const struct vm_caprevoke_cookie *crc,
		  const void * __capability cut)
{
	int res = 0;
	int perms = cheri_getperm(cut);

	if ((perms & (CHERI_PERMS_HWALL_MEMORY | CHERI_PERM_CHERIABI_VMMAP))
	    != 0) {
		res |= vm_test_caprevoke_mem(crc, cut);
	}

	// TODO: if ((perms & CHERI_PERMS_HWALL_OTYPE) != 0)

	// TODO: if ((perms & CHERI_PERMS_HWALL_CID) != 0)

	return res;
}

/*
 * The Capability Under Test Pointer needs to be a capability because we
 * don't have a LLC instruction, just a CLLC one.
 */
static int
vm_do_caprevoke(const struct vm_caprevoke_cookie *crc,
		void * __capability * __capability cutp)
{
	CAPREVOKE_STATS_FOR(crst, crc);
	void * __capability cut;
	int res = 0;

	cut = *cutp;

	KASSERT(cheri_gettag(cut), ("untagged in vm_do_caprevoke"));

	if (vm_test_caprevoke(crc, cut)) {
		void * __capability cscratch;
		int ok;

		void * __capability cutr = cheri_revoke(cut);

		CAPREVOKE_STATS_BUMP(crst, caps_found);

		/*
		 * Load-link the position under test; verify that it matches
		 * our previous load; store conditionally the revoked
		 * version back.  If the verification fails, don't try
		 * anything fancy, just modify the return value to flag the
		 * page as dirty.
		 *
		 * It's possible that this CAS will fail because the pointer
		 * has changed during our test.  That's fine, if this is not
		 * a stop-the-world scan; we'll catch it in the next go
		 * around.  However, because CAS can fail for reasons other
		 * than an actual data failure, return an indicator that the
		 * page should not be considered clean.
		 *
		 * Because revoked capabilities are still tagged, one might
		 * worry that this would reset the capdirty bits.  That's
		 * not true, tho', because we're storing via the direct
		 * mapping of physical memory.
		 */
		__asm__ __volatile__ (
			"cllc %[cscratch], %[cutp]\n\t"
			"cexeq %[ok], %[cscratch], %[cut]\n\t"
			"beqz %[ok], 1f\n\t"
			"nop\n\t"
			"cscc %[ok], %[cutr], %[cutp]\n\t"
			"1:\n\t"
		  : [ok] "=r" (ok), [cscratch] "=&C" (cscratch)
		  : [cut] "C" (cut), [cutp] "C" (cutp), [cutr] "C" (cutr)
		  : "memory");

		if (__builtin_expect(ok,1)) {
			CAPREVOKE_STATS_BUMP(crst, caps_cleared);
			/* Don't count a revoked cap as HASCAPS */
		} else {
			res = VM_CAPREVOKE_PAGE_DIRTY
				| VM_CAPREVOKE_PAGE_HASCAPS ;
		}
	} else {
		/* Again, don't count a revoked cap as HASCAPS */
		if ((cheri_getperm(cut) != 0) || (cheri_getsealed(cut) != 0)) {
			CAPREVOKE_STATS_BUMP(crst, caps_found);
			res = VM_CAPREVOKE_PAGE_HASCAPS;
		}
		// XXX else crc->stats->caps_found_revoked++;
	}

	return res;
}

static bool caprevoke_use_cloadtags = 1;
SYSCTL_BOOL(_vm, OID_AUTO, caprevoke_use_cloadtags, CTLFLAG_RW,
    &caprevoke_use_cloadtags, 0,
    "XXX");

uint8_t cloadtags_stride;
SYSCTL_U8(_vm, OID_AUTO, cloadtags_stride, 0, &cloadtags_stride, 0, "XXX");

static void
measure_cloadtags_stride(void *ignored)
{
	(void)ignored;

	void * __capability buf[64] __attribute__((aligned(PAGE_SIZE)));
	int i;
	
	/* Fill with capabilities */
	for (i = 0; i < 64; i++) {
	        buf[i] = cheri_getkdc();
	}

	uint64_t tags = __builtin_cheri_cap_load_tags(buf);
	switch(tags) {
	case 0x0001:  cloadtags_stride = 1;  break;
	case 0x0003:  cloadtags_stride = 2;  break;
	case 0x000F:  cloadtags_stride = 4;  break;
	case 0x00FF:  cloadtags_stride = 8;  break;
	case 0xFFFF:  cloadtags_stride = 16; break;
	default:
		panic("Bad cloadtags result 0x%" PRIx64, tags);
	}
}
SYSINIT(cloadtags_stride, SI_SUB_VM, SI_ORDER_ANY,
        measure_cloadtags_stride, NULL);

int
vm_caprevoke_page(const struct vm_caprevoke_cookie *crc, vm_page_t m)
{
#ifdef CHERI_CAPREVOKE_STATS
	CAPREVOKE_STATS_FOR(crst, crc);
	uint32_t cyc_start = cheri_get_cyclecount();
#endif

	vm_paddr_t mpa = VM_PAGE_TO_PHYS(m);
	vm_offset_t mva;
	vm_offset_t mve;
	void * __capability * __capability mvu;
	/* XXX NWF Is this what we want? */
	void * __capability kdc = cheri_getkdc();
	int res = 0;

	/*
	 * XXX NWF
	 * Hopefully m being xbusy'd means it's not about to go away on us.
	 * I don't yet understand all the interlocks in the vm subsystem.
	 */
	KASSERT(MIPS_DIRECT_MAPPABLE(mpa),
		("Revoke not directly map swept page?"));
	mva = MIPS_PHYS_TO_DIRECT(mpa);
	mve = mva + pagesizes[m->psind];

	mvu = cheri_setaddress(kdc, mva);

	if (caprevoke_use_cloadtags) {
		for( ; cheri_getaddress(mvu) < mve; mvu += cloadtags_stride ) {
			void * __capability * __capability mvt = mvu;
			uint64_t tags;

			tags = __builtin_cheri_cap_load_tags(mvt);

			for(; tags != 0; (tags >>= 1), mvt += 1) {
				if (!(tags & 1))
					continue;

				res |= vm_do_caprevoke(crc, mvt);
			}
		}
	} else {
		for( ; cheri_getaddress(mvu) < mve; mvu++) {
			void * __capability cut = *mvu;
			if (cheri_gettag(cut)) {
				res |= vm_do_caprevoke(crc, mvu);
			}
		}
	}

#ifdef CHERI_CAPREVOKE_STATS
	uint32_t cyc_end = cheri_get_cyclecount();
	CAPREVOKE_STATS_INC(crst, page_scan_cycles, cyc_end - cyc_start);
#endif

	return res;
}

/*
 * Like vm_caprevoke_page, but does not write to the page in question
 *
 * VM_CAPREVOKE_PAGE_DIRTY in the result means that we would like to store
 * back, but can't, rather than that we lost a LL/SC race.  We will return
 * early if this becomes set: there's no reason to continue probing once we
 * know the answer.
 *
 * VM_CAPREVOKE_PAGE_HASCAPS continues to mean what it meant before: we
 * saw at least one capability on this page.
 */
int
vm_caprevoke_page_ro(const struct vm_caprevoke_cookie *crc, vm_page_t m)
{
#ifdef CHERI_CAPREVOKE_STATS
	uint32_t cyc_start = cheri_get_cyclecount();
	CAPREVOKE_STATS_FOR(crst, crc);
#endif

	vm_paddr_t mpa = VM_PAGE_TO_PHYS(m);
	vm_offset_t mva;
	vm_offset_t mve;
	void * __capability * __capability mvu;
	void * __capability kdc = cheri_getkdc();
	int res = 0;

	KASSERT(MIPS_DIRECT_MAPPABLE(mpa),
		("Revoke not directly map swept page?"));
	mva = MIPS_PHYS_TO_DIRECT(mpa);
	mve = mva + pagesizes[m->psind];

	mvu = cheri_setaddress(kdc, mva);

	if (caprevoke_use_cloadtags) {
		for( ; cheri_getaddress(mvu) < mve; mvu += cloadtags_stride ) {
			void * __capability * __capability mvt = mvu;
			uint64_t tags;

			tags = __builtin_cheri_cap_load_tags(mvt);

			if (tags != 0)
				res |= VM_CAPREVOKE_PAGE_HASCAPS;

			for(; tags != 0; (tags >>= 1), mvt += 1) {
				if (!(tags & 1))
					continue;
				if (vm_test_caprevoke(crc, *mvt)) {
					return VM_CAPREVOKE_PAGE_DIRTY
						| VM_CAPREVOKE_PAGE_HASCAPS;
				}
			}
		}
	} else {
		for( ; cheri_getaddress(mvu) < mve; mvu++) {
			void * __capability cut = *mvu;
			if (cheri_gettag(cut)) {
				res |= VM_CAPREVOKE_PAGE_HASCAPS;
				if (vm_test_caprevoke(crc, cut)) {
					return VM_CAPREVOKE_PAGE_DIRTY
						| VM_CAPREVOKE_PAGE_HASCAPS;
				}
			}
		}
	}

#ifdef CHERI_CAPREVOKE_STATS
	uint32_t cyc_end = cheri_get_cyclecount();
	crst->page_scan_cycles += cyc_end - cyc_start;
#endif

	return res;
}

/*
 * Map a capability revocation shadow
 */
int
vm_map_install_caprevoke_shadow(vm_map_t map)
{
	int error = KERN_SUCCESS;
	vm_object_t vmo;
	vm_offset_t start = VM_CAPREVOKE_BM_BASE;
	vm_offset_t end = VM_CAPREVOKE_BM_TOP;

	vmo = vm_object_allocate(OBJT_DEFAULT, end - start);
	vmo->flags |= OBJ_NOLOADTAGS | OBJ_NOSTORETAGS;

	vm_map_lock(map);

	if (map->vm_caprev_sh != NULL) {
		error = KERN_PROTECTION_FAILURE;
		goto out;
	}

	error = vm_map_insert(map, vmo, 0, start, end,
				VM_PROT_READ | VM_PROT_WRITE,
				VM_PROT_READ | VM_PROT_WRITE,
				0);

	if (error != KERN_SUCCESS) {
		goto out;
	}

	map->vm_caprev_sh = vmo;
	map->vm_caprev_shva = start;

out:
	vm_map_unlock(map);

	if (error) {
		vm_object_deallocate(vmo);
	}
	return error;
}

#define ERRNO_CAP(v) ((void * __capability)(__intptr_t)(v))

/*
 * Grant access to a capability shadow
 */
void * __capability
vm_caprevoke_shadow_cap(int sel, vm_offset_t base, vm_offset_t size, int pmask)
{
	switch(sel) {
	/* Accessible to userspace */
	case CAPREVOKE_SHADOW_NOVMMAP: {
		vm_offset_t shadow_base, shadow_size;

		/* Require at least byte granularity in the shadow space */
		if ((base & ((VM_CAPREVOKE_GSZ_MEM_NOMAP * 8) - 1)) != 0)
			return ERRNO_CAP(EINVAL);
		if ((size & ((VM_CAPREVOKE_GSZ_MEM_NOMAP * 8) - 1)) != 0)
			return ERRNO_CAP(EINVAL);

		shadow_base = VM_CAPREVOKE_BM_MEM_NOMAP
		            + (base / VM_CAPREVOKE_GSZ_MEM_NOMAP / 8);
		shadow_size = size / VM_CAPREVOKE_GSZ_MEM_NOMAP / 8;

		return cheri_capability_build_user_data(
			pmask & (CHERI_PERM_LOAD | CHERI_PERM_STORE)
				| CHERI_PERM_GLOBAL,
			shadow_base, shadow_size, 0);
	}	
	case CAPREVOKE_SHADOW_OTYPE: {
		vm_offset_t shadow_base, shadow_size;

		shadow_base = VM_CAPREVOKE_BM_OTYPE
		            + (base / VM_CAPREVOKE_GSZ_OTYPE / 8);
		shadow_size = size / VM_CAPREVOKE_GSZ_OTYPE / 8;

		/* Require at least byte granularity in the shadow space */
		if ((base & ((VM_CAPREVOKE_GSZ_OTYPE * 8) - 1)) != 0)
			return ERRNO_CAP(EINVAL);
		if ((size & ((VM_CAPREVOKE_GSZ_OTYPE * 8) - 1)) != 0)
			return ERRNO_CAP(EINVAL);

		return cheri_capability_build_user_data(
			CHERI_PERM_LOAD | CHERI_PERM_STORE | CHERI_PERM_GLOBAL,
			shadow_base, shadow_size, 0);
	}
	/* Kernel-only */
	// XXX CAPREVOKE_SHADOW_MAP:
	//
	default:
		return ERRNO_CAP(EINVAL);
	}
}

#endif /* CHERI_CAPREVOKE */

#ifdef DDB
#include <ddb/ddb.h>

#define DB_PRINT_REG(ptr, regname)			\
	db_printf("  %-12s %p\n", #regname, (void *)(intptr_t)((ptr)->regname))

#define DB_PRINT_REG_ARRAY(ptr, arrname, regname)	\
	db_printf("  %-12s %p\n", #regname, (void *)(intptr_t)((ptr)->arrname[regname]))

static void
dump_trapframe(struct trapframe *trapframe)
{

	db_printf("Trapframe at %p\n", trapframe);

	DB_PRINT_REG(trapframe, zero);
	DB_PRINT_REG(trapframe, ast);
	DB_PRINT_REG(trapframe, v0);
	DB_PRINT_REG(trapframe, v1);
	DB_PRINT_REG(trapframe, a0);
	DB_PRINT_REG(trapframe, a1);
	DB_PRINT_REG(trapframe, a2);
	DB_PRINT_REG(trapframe, a3);
#if defined(__mips_n32) || defined(__mips_n64)
	DB_PRINT_REG(trapframe, a4);
	DB_PRINT_REG(trapframe, a5);
	DB_PRINT_REG(trapframe, a6);
	DB_PRINT_REG(trapframe, a7);
	DB_PRINT_REG(trapframe, t0);
	DB_PRINT_REG(trapframe, t1);
	DB_PRINT_REG(trapframe, t2);
	DB_PRINT_REG(trapframe, t3);
#else
	DB_PRINT_REG(trapframe, t0);
	DB_PRINT_REG(trapframe, t1);
	DB_PRINT_REG(trapframe, t2);
	DB_PRINT_REG(trapframe, t3);
	DB_PRINT_REG(trapframe, t4);
	DB_PRINT_REG(trapframe, t5);
	DB_PRINT_REG(trapframe, t6);
	DB_PRINT_REG(trapframe, t7);
#endif
	DB_PRINT_REG(trapframe, s0);
	DB_PRINT_REG(trapframe, s1);
	DB_PRINT_REG(trapframe, s2);
	DB_PRINT_REG(trapframe, s3);
	DB_PRINT_REG(trapframe, s4);
	DB_PRINT_REG(trapframe, s5);
	DB_PRINT_REG(trapframe, s6);
	DB_PRINT_REG(trapframe, s7);
	DB_PRINT_REG(trapframe, t8);
	DB_PRINT_REG(trapframe, t9);
	DB_PRINT_REG(trapframe, k0);
	DB_PRINT_REG(trapframe, k1);
	DB_PRINT_REG(trapframe, gp);
	DB_PRINT_REG(trapframe, sp);
	DB_PRINT_REG(trapframe, s8);
	DB_PRINT_REG(trapframe, ra);
	DB_PRINT_REG(trapframe, sr);
	DB_PRINT_REG(trapframe, mullo);
	DB_PRINT_REG(trapframe, mulhi);
	DB_PRINT_REG(trapframe, badvaddr);
	DB_PRINT_REG(trapframe, cause);
	DB_PRINT_REG(trapframe, pc);
}

DB_SHOW_COMMAND(pcb, ddb_dump_pcb)
{
	struct thread *td;
	struct pcb *pcb;
	struct trapframe *trapframe;

	/* Determine which thread to examine. */
	if (have_addr)
		td = db_lookup_thread(addr, true);
	else
		td = curthread;
	
	pcb = td->td_pcb;

	db_printf("Thread %d at %p\n", td->td_tid, td);

	db_printf("PCB at %p\n", pcb);

	trapframe = &pcb->pcb_regs;
	dump_trapframe(trapframe);

	db_printf("PCB Context:\n");
	DB_PRINT_REG_ARRAY(pcb, pcb_context, PCB_REG_S0);
	DB_PRINT_REG_ARRAY(pcb, pcb_context, PCB_REG_S1);
	DB_PRINT_REG_ARRAY(pcb, pcb_context, PCB_REG_S2);
	DB_PRINT_REG_ARRAY(pcb, pcb_context, PCB_REG_S3);
	DB_PRINT_REG_ARRAY(pcb, pcb_context, PCB_REG_S4);
	DB_PRINT_REG_ARRAY(pcb, pcb_context, PCB_REG_S5);
	DB_PRINT_REG_ARRAY(pcb, pcb_context, PCB_REG_S6);
	DB_PRINT_REG_ARRAY(pcb, pcb_context, PCB_REG_S7);
	DB_PRINT_REG_ARRAY(pcb, pcb_context, PCB_REG_SP);
	DB_PRINT_REG_ARRAY(pcb, pcb_context, PCB_REG_S8);
	DB_PRINT_REG_ARRAY(pcb, pcb_context, PCB_REG_RA);
	DB_PRINT_REG_ARRAY(pcb, pcb_context, PCB_REG_SR);
	DB_PRINT_REG_ARRAY(pcb, pcb_context, PCB_REG_GP);
	DB_PRINT_REG_ARRAY(pcb, pcb_context, PCB_REG_PC);

	db_printf("PCB onfault = %p\n", pcb->pcb_onfault);
	db_printf("md_saved_intr = 0x%0lx\n", (long)td->td_md.md_saved_intr);
	db_printf("md_spinlock_count = %d\n", td->td_md.md_spinlock_count);

	if (td->td_frame != trapframe) {
		db_printf("td->td_frame %p is not the same as pcb_regs %p\n",
			  td->td_frame, trapframe);
	}
}

/*
 * Dump the trapframe beginning at address specified by first argument.
 */
DB_SHOW_COMMAND(trapframe, ddb_dump_trapframe)
{
	
	if (!have_addr)
		return;

	dump_trapframe((struct trapframe *)addr);
}

#endif	/* DDB */
// CHERI CHANGES START
// {
//   "updated": 20181114,
//   "target_type": "kernel",
//   "changes": [
//     "support"
//   ],
//   "change_comment": ""
// }
// CHERI CHANGES END
