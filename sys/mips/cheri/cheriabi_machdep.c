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
#include <sys/sysargmap.h>
#include <sys/syscallsubr.h>
#include <sys/sysproto.h>
#include <sys/ucontext.h>
#include <sys/user.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <machine/cpuinfo.h>
#include <machine/cheri_machdep.h>
#include <machine/md_var.h>
#include <machine/pcb.h>
#include <machine/sigframe.h>
#include <machine/sysarch.h>
#include <machine/tls.h>

#include <compat/cheriabi/cheriabi.h>
#include <compat/cheriabi/cheriabi_proto.h>
#include <compat/cheriabi/cheriabi_syscall.h>
#include <compat/cheriabi/cheriabi_util.h>

#include <vm/vm.h>
#include <vm/vm_map.h>

#include <ddb/ddb.h>
#include <sys/kdb.h>

#define	DELAYBRANCH(x)	((int)(x) < 0)
#define	UCONTEXT_MAGIC	0xACEDBADE

static void	cheriabi_set_syscall_retval(struct thread *td, int error);
static __inline boolean_t cheriabi_check_cpu_compatible(uint32_t, const char *);
static boolean_t cheriabi_elf_header_supported(struct image_params *);

extern const char *cheriabi_syscallnames[];

struct sysentvec elf_freebsd_cheriabi_sysvec = {
	.sv_size	= CHERIABI_SYS_MAXSYSCALL,
	.sv_table	= cheriabi_sysent,
	.sv_errsize	= 0,
	.sv_errtbl	= NULL,
	.sv_fixup	= __elfN(freebsd_fixup),
	.sv_sendsig	= sendsig,
	.sv_sigcode	= sigcode,
	.sv_szsigcode	= &szsigcode,
	.sv_name	= "CheriABI ELF64",
	.sv_coredump	= __elfN(coredump),
	.sv_imgact_try	= NULL,
	.sv_minsigstksz	= MINSIGSTKSZ,	/* XXXBD: or something bigger? */
	.sv_minuser	= PAGE_SIZE,	/* Disallow mapping at NULL */
	.sv_maxuser	= VM_MAXUSER_ADDRESS,
	.sv_usrstack	= USRSTACK,
	.sv_psstrings	= CHERIABI_PS_STRINGS,
	.sv_stackprot	= VM_PROT_READ|VM_PROT_WRITE,
	.sv_copyout_auxargs = __elfN(freebsd_copyout_auxargs),
	.sv_copyout_strings = exec_copyout_strings,
	.sv_setregs	= exec_setregs,
	.sv_fixlimit	= NULL,
	.sv_maxssiz	= NULL,
	.sv_flags	= SV_ABI_FREEBSD | SV_LP64 | SV_CHERI | SV_SHP,
	.sv_set_syscall_retval = cpu_set_syscall_retval,
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

	/* TODO: add a sysctl to allow loading old binaries */
	if (hdr->e_ident[EI_ABIVERSION] != ELF_CHERIABI_ABIVERSION) {
		printf("warning: attempting to execute CheriABI binary '%s'"
		    " with ABI version %d on a system expecting version %d\n",
		    imgp->execpath, hdr->e_ident[EI_ABIVERSION],
		    ELF_CHERIABI_ABIVERSION);
		return (boolean_t)allow_cheriabi_version_mismatch;
	}

	if (machine == EF_MIPS_MACH_CHERI128)
		return TRUE;
	return FALSE;
}

int
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
		TRAPF_PC_INCREMENT(locr0, sizeof(int));

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

	if (sa->code >= nitems(sysargmask))
		ptrmask = 0;
	else
		ptrmask = sysargmask[sa->code];

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
cheriabi_get_mcontext(struct thread *td, mcontext_t *mcp, int flags)
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

	mcp->mc_pc = TRAPF_PC_OFFSET(td->td_frame);
	mcp->mullo = td->td_frame->mullo;
	mcp->mulhi = td->td_frame->mulhi;
	mcp->mc_tls = td->td_md.md_tls;

	return (0);
}

int
cheriabi_set_mcontext(struct thread *td, mcontext_t *mcp)
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
	td->td_frame->pc = update_pcc_offset(mcp->mc_cheriframe.cf_pcc, mcp->mc_pc);
	td->td_frame->mullo = mcp->mullo;
	td->td_frame->mulhi = mcp->mulhi;

	td->td_md.md_tls =  mcp->mc_tls;
	tag = cheri_gettag(mcp->mc_tls);

	/* Dont let user to set any bits in status and cause registers.  */

	return (0);
}

/*
 * Common per-thread CHERI state initialisation across execve(2) and
 * additional thread creation.
 */
void
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
	 * exec_setregs() for the initial thread.
	 */
	csigp = &td->td_pcb->pcb_cherisignal;
	bzero(csigp, sizeof(*csigp));
	/* Note: csig_{ddc,idc,pcc} are set to NULL in the pure-capability abi */
	csigp->csig_sigcode = cheri_sigcode_capability(td);

	/*
	 * Set up root for the userspace object-type sealing capability tree.
	 * This can be queried using sysarch(2).
	 */
	cheri_capability_set_user_sealcap(&td->td_proc->p_md.md_cheri_sealcap);
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
		return (cpu_set_user_tls(td, uap->parms));

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

		base = cheri_getbase(td->td_cheri_mmap_cap);
		if (suword(uap->parms, base) != 0)
			return (EFAULT);
		return (0);
	}

	case CHERI_MMAP_GETLEN: {
		size_t len;

		len = cheri_getlen(td->td_cheri_mmap_cap);
		if (suword(uap->parms, len) != 0)
			return (EFAULT);
		return (0);
	}

	case CHERI_MMAP_GETOFFSET: {
		ssize_t offset;

		offset = cheri_getoffset(td->td_cheri_mmap_cap);
		if (suword(uap->parms, offset) != 0)
			return (EFAULT);
		return (0);
	}

	case CHERI_MMAP_GETPERM: {
		uint64_t perms;

		perms = cheri_getperm(td->td_cheri_mmap_cap);
		if (suword64(uap->parms, perms) != 0)
			return (EFAULT);
		return (0);
	}

	case CHERI_MMAP_ANDPERM: {
		uint64_t perms;
		perms = fuword64(uap->parms);

		if (perms == -1)
			return (EINVAL);
		td->td_cheri_mmap_cap =
		    cheri_andperm(td->td_cheri_mmap_cap, perms);
		perms = cheri_getperm(td->td_cheri_mmap_cap);
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
		len = cheri_getlen(td->td_cheri_mmap_cap);
		/* Don't allow out of bounds offsets, they aren't useful */
		if (offset < 0 || offset > len) {
			return (EINVAL);
		}
		td->td_cheri_mmap_cap =
		    cheri_setoffset(td->td_cheri_mmap_cap,
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
		olen = cheri_getlen(td->td_cheri_mmap_cap);
		offset = cheri_getoffset(td->td_cheri_mmap_cap);
		/* Don't try to set out of bounds lengths */
		if (offset > olen || len > olen - offset) {
			return (EINVAL);
		}
		td->td_cheri_mmap_cap =
		    cheri_setbounds(td->td_cheri_mmap_cap,
		    (register_t)len);
		return (0);
	}

	default:
		return (EINVAL);
	}
}
