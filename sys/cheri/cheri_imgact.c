/*-
 * Copyright (c) 2018 Alfredo Mazzinghi
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#define	EXPLICIT_USER_ACCESS

#include <sys/param.h>
#include <sys/cheriabi.h>
#include <sys/imgact.h>
#include <sys/imgact_elf.h>
#include <sys/jail.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/smp.h>
#include <sys/sysent.h>
#include <sys/systm.h>
#include <sys/vdso.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <machine/cpu.h>
#include <machine/elf.h>

/*
 * This macro uses cheri_capability_build_user_rwx() because it can
 * create both types of capabilities (and currently creates W|X caps).
 * Its use should be replaced.
 */
#define sucap(uaddr, base, offset, length, perms)			\
	do {								\
		void * __capability _tmpcap;				\
		_tmpcap = cheri_capability_build_user_rwx((perms),	\
		    (base), (length), (offset));			\
		KASSERT(cheri_gettag(_tmpcap), ("Created invalid cap"	\
		    "from base=%zx, offset=%#zx, length=%#zx, "		\
		    "perms=%#zx", (size_t)(base), (size_t)(offset),	\
		    (size_t)(length), (size_t)(perms)));		\
		copyoutcap(&_tmpcap, uaddr, sizeof(_tmpcap));		\
	} while(0)

#define	AUXARGS_ENTRY_NOCAP(pos, id, val)				\
	{suword(pos++, id); suword(pos++, val);}
#define	AUXARGS_ENTRY_CAP(pos, id, base, offset, len, perm) do {	\
		suword(pos++, id);					\
		sucap(pos++, base, offset, len, perm);			\
	} while(0)

static void
cheriabi_set_auxargs(void * __capability * __capability pos,
    struct image_params *imgp)
{
	Elf_Auxargs *args = (Elf_Auxargs *)imgp->auxargs;
	unsigned long prog_base, prog_len;
	unsigned long rtld_base, rtld_len;

	/* printf("%s: start=%#lx, end=%#lx, base=%#lx, interp_end=%#lx\n", __func__,
		imgp->start_addr, imgp->end_addr, args->base, imgp->interp_end); */
	prog_base = rounddown2(imgp->start_addr,
	    1ULL << CHERI_ALIGN_SHIFT(imgp->start_addr));
	prog_len = roundup2(imgp->end_addr - prog_base,
	    1ULL << CHERI_ALIGN_SHIFT(imgp->end_addr - prog_base));


	if (imgp->interp_end) {
		rtld_base = rounddown2(args->base,
		    1ULL << CHERI_ALIGN_SHIFT(args->base));
		rtld_len = roundup2(imgp->interp_end - rtld_base,
		    1ULL << CHERI_ALIGN_SHIFT(imgp->interp_end - rtld_base));
	} else {
		rtld_base = 0;
		rtld_len = CHERI_CAP_USER_CODE_LENGTH;
	}

	if (args->execfd != -1)
		AUXARGS_ENTRY_NOCAP(pos, AT_EXECFD, args->execfd);
	CTASSERT(CHERI_CAP_USER_CODE_BASE == 0);
	/*
	 * AT_ENTRY gives an executable cap for the whole program and
	 * AT_PHDR a writable one. RTLD is reposible for seting bounds.
	 */
	AUXARGS_ENTRY_CAP(pos, AT_PHDR, prog_base, args->phdr - prog_base,
	    prog_len, CHERI_CAP_USER_DATA_PERMS);
	AUXARGS_ENTRY_NOCAP(pos, AT_PHENT, args->phent);
	AUXARGS_ENTRY_NOCAP(pos, AT_PHNUM, args->phnum);
	AUXARGS_ENTRY_NOCAP(pos, AT_PAGESZ, args->pagesz);
	AUXARGS_ENTRY_NOCAP(pos, AT_FLAGS, args->flags);
	AUXARGS_ENTRY_CAP(pos, AT_ENTRY, prog_base, args->entry - prog_base,
	    prog_len, CHERI_CAP_USER_CODE_PERMS);
	/*
	 * XXX-BD: grant code and data perms to allow textrel fixups.
	 */
	AUXARGS_ENTRY_CAP(pos, AT_BASE, rtld_base, args->base - rtld_base,
	    rtld_len, CHERI_CAP_USER_DATA_PERMS | CHERI_CAP_USER_CODE_PERMS);
#ifdef AT_EHDRFLAGS
	AUXARGS_ENTRY_NOCAP(pos, AT_EHDRFLAGS, args->hdr_eflags);
#endif
	if (imgp->execpathp != 0)
		AUXARGS_ENTRY_CAP(pos, AT_EXECPATH, imgp->execpathp, 0,
		    strlen(imgp->execpath) + 1,
		    CHERI_CAP_USER_DATA_PERMS);
	AUXARGS_ENTRY_NOCAP(pos, AT_OSRELDATE,
	    imgp->proc->p_ucred->cr_prison->pr_osreldate);
	if (imgp->canary != 0) {
		AUXARGS_ENTRY_CAP(pos, AT_CANARY, imgp->canary, 0,
		    imgp->canarylen, CHERI_CAP_USER_DATA_PERMS);
		AUXARGS_ENTRY_NOCAP(pos, AT_CANARYLEN, imgp->canarylen);
	}
	AUXARGS_ENTRY_NOCAP(pos, AT_NCPUS, mp_ncpus);
	if (imgp->pagesizes != 0) {
		AUXARGS_ENTRY_CAP(pos, AT_PAGESIZES, imgp->pagesizes, 0,
		   imgp->pagesizeslen, CHERI_CAP_USER_DATA_PERMS);
		AUXARGS_ENTRY_NOCAP(pos, AT_PAGESIZESLEN, imgp->pagesizeslen);
	}
	if (imgp->sysent->sv_timekeep_base != 0) {
		AUXARGS_ENTRY_CAP(pos, AT_TIMEKEEP,
		    imgp->sysent->sv_timekeep_base, 0,
		    sizeof(struct vdso_timekeep) +
		    sizeof(struct vdso_timehands) * VDSO_TH_NUM,
		    CHERI_CAP_USER_DATA_PERMS); /* XXX: readonly? */
	}
	AUXARGS_ENTRY_NOCAP(pos, AT_STACKPROT, imgp->sysent->sv_shared_page_obj
	    != NULL && imgp->stack_prot != 0 ? imgp->stack_prot :
	    imgp->sysent->sv_stackprot);

	AUXARGS_ENTRY_NOCAP(pos, AT_ARGC, imgp->args->argc);
	/* XXX-BD: Includes terminating NULL.  Should it? */
	AUXARGS_ENTRY_CAP(pos, AT_ARGV, (vaddr_t)imgp->args->argv, 0,
	   sizeof(void * __capability) * (imgp->args->argc + 1),
	   CHERI_CAP_USER_DATA_PERMS);
	AUXARGS_ENTRY_NOCAP(pos, AT_ENVC, imgp->args->envc);
	AUXARGS_ENTRY_CAP(pos, AT_ENVV, (vaddr_t)imgp->args->envv, 0,
	   sizeof(void * __capability) * (imgp->args->envc + 1),
	   CHERI_CAP_USER_DATA_PERMS);

	AUXARGS_ENTRY_NOCAP(pos, AT_NULL, 0);

	free(imgp->auxargs, M_TEMP);
	imgp->auxargs = NULL;
}

int
cheriabi_elf_fixup(register_t **stack_base, struct image_params *imgp)
{
	size_t argenvcount;
	void * __capability * __capability base;

	KASSERT(((vaddr_t)*stack_base & (sizeof(void * __capability) - 1)) == 0,
	    ("*stack_base (%p) is not capability aligned", *stack_base));

	argenvcount = imgp->args->argc + 1 + imgp->args->envc + 1;
	base = cheri_capability_build_user_data(
	    CHERI_CAP_USER_DATA_PERMS, (vaddr_t)*stack_base,
	    (argenvcount + (AT_COUNT * 2)) * sizeof(void * __capability),
	    0);
	base += imgp->args->argc + 1 + imgp->args->envc + 1;

	cheriabi_set_auxargs(base, imgp);

	return (0);
}
