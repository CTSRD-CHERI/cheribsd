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

_Static_assert(sizeof(mcontext64_t) == sizeof(mcontext_t),
    "mcontext_t and mcontext64_t aren't compatiable");
int
freebsd64_get_mcontext(struct thread *td, mcontext64_t *mcp, int flags)
{

	return (get_mcontext(td, (mcontext_t *)mcp, flags));
}

int
freebsd64_set_mcontext(struct thread *td, mcontext64_t *mcp)
{

	return (set_mcontext(td, (mcontext_t *)mcp));
}

static void
freebsd64_sendsig(sig_t catcher, ksiginfo_t *ksi, sigset_t *mask)
{

	sendsig(catcher, ksi, mask);
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
		error = copyout(&tlsbase, uap->parms, sizeof(tlsbase));
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
