/*-
 * Copyright (c) 2011-2017 Robert N. M. Watson
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/cheri_serial.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>

#include <ddb/ddb.h>
#include <sys/kdb.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <machine/atomic.h>
#include <machine/cherireg.h>
#include <machine/pcb.h>
#include <machine/proc.h>
#include <machine/sysarch.h>

static void	cheri_capability_set_user_ddc(void * __capability *);
static void	cheri_capability_set_user_stc(void * __capability *);
static void	cheri_capability_set_user_pcc(void * __capability *);
static void	cheri_capability_set_user_entry(void * __capability *,
		    unsigned long);
static void	cheri_capability_set_user_sigcode(void * __capability *,
		   struct sysentvec *);

static void
cheri_capability_set_user_ddc(void * __capability *cp)
{

	cheri_capability_set(cp, CHERI_CAP_USER_DATA_PERMS,
	    CHERI_CAP_USER_DATA_BASE, CHERI_CAP_USER_DATA_LENGTH,
	    CHERI_CAP_USER_DATA_OFFSET);
}

static void
cheri_capability_set_user_stc(void * __capability *cp)
{

	/*
	 * For now, initialise stack as ambient with identical rights as $ddc.
	 * In the future, we will may want to change this to be local
	 * (non-global).
	 */
	cheri_capability_set_user_ddc(cp);
}

static void
cheri_capability_set_user_idc(void * __capability *cp)
{

	/*
	 * The default invoked data capability is also identical to $ddc.
	 */
	cheri_capability_set_user_ddc(cp);
}

static void
cheri_capability_set_user_pcc(void * __capability *cp)
{

	cheri_capability_set(cp, CHERI_CAP_USER_CODE_PERMS,
	    CHERI_CAP_USER_CODE_BASE, CHERI_CAP_USER_CODE_LENGTH,
	    CHERI_CAP_USER_CODE_OFFSET);
}

static void
cheri_capability_set_user_entry(void * __capability *cp,
    unsigned long entry_addr)
{

	/*
	 * Set the jump target regigster for the pure capability calling
	 * convention.
	 */
	cheri_capability_set(cp, CHERI_CAP_USER_CODE_PERMS,
	    CHERI_CAP_USER_CODE_BASE, CHERI_CAP_USER_CODE_LENGTH, entry_addr);
}

static void
cheri_capability_set_user_sigcode(void * __capability *cp, struct sysentvec *se)
{
	uintptr_t base;
	int szsigcode = *se->sv_szsigcode;

	if (se->sv_sigcode_base != 0) {
		base = se->sv_sigcode_base;
	} else {
		/*
		 * XXX: true for mips64 and mip64-cheriabi without shared-page
		 * support...
		 */
		base = (uintptr_t)se->sv_psstrings - szsigcode;
		base = rounddown2(base, sizeof(struct chericap));
	}

	cheri_capability_set(cp, CHERI_CAP_USER_CODE_PERMS, base,
	    szsigcode, 0);
}

static void
cheri_capability_set_user_sealcap(void * __capability *cp)
{

	cheri_capability_set(cp, CHERI_SEALCAP_USERSPACE_PERMS,
	    CHERI_SEALCAP_USERSPACE_BASE, CHERI_SEALCAP_USERSPACE_LENGTH,
	    CHERI_SEALCAP_USERSPACE_OFFSET);
}

/*
 * Set per-thread CHERI register state for MIPS ABI processes.  In
 * particular, we need to set up the CHERI register state for MIPS ABI
 * processes with suitable capabilities.
 *
 * XXX: I also wonder if we should be inheriting signal-handling state...?
 */
void
cheri_newthread_setregs(struct thread *td, unsigned long entry_addr)
{
	struct trapframe *frame;

	/*
	 * We assume that the caller has initialised the trapframe to zeroes
	 * -- but do a quick assertion or two to catch programmer error.  We
	 * might want to check this with a more thorough set of assertions in
	 * the future.
	 */
	frame = &td->td_pcb->pcb_regs;
	KASSERT(*(uint64_t *)&frame->ddc == 0, ("%s: non-zero initial $ddc",
	    __func__));
	KASSERT(*(uint64_t *)&frame->pcc == 0, ("%s: non-zero initial $epcc",
	    __func__));

	/*
	 * XXXRW: Experimental CheriABI initialises $ddc with full user
	 * privilege, and all other user-accessible capability registers with
	 * no rights at all.  The runtime linker/compiler/application can
	 * propagate around rights as required.
	 */
	cheri_capability_set_user_ddc(&frame->ddc);
	cheri_capability_set_user_stc(&frame->stc);
	cheri_capability_set_user_idc(&frame->idc);
	cheri_capability_set_user_entry(&frame->pcc, entry_addr);
	cheri_capability_set_user_entry(&frame->c12, entry_addr);
}

/*
 * Set per-process CHERI state for MIPS ABI processes after exec.
 * Initializes process-wide state as well as per-thread state for the
 * process' initial thread.
 */
void
cheri_exec_setregs(struct thread *td, unsigned long entry_addr)
{
	struct cheri_signal *csigp;

	cheri_newthread_setregs(td, entry_addr);

	/*
	 * Initialise signal-handling state; this can't yet be modified
	 * by userspace, but the principle is that signal handlers should run
	 * with ambient authority unless given up by the userspace runtime
	 * explicitly.
	 */
	csigp = &td->td_pcb->pcb_cherisignal;
	bzero(csigp, sizeof(*csigp));
	cheri_capability_set_user_ddc(&csigp->csig_ddc);
	cheri_capability_set_user_stc(&csigp->csig_stc);
	cheri_capability_set_user_stc(&csigp->csig_default_stack);
	cheri_capability_set_user_idc(&csigp->csig_idc);
	cheri_capability_set_user_pcc(&csigp->csig_pcc);
	cheri_capability_set_user_sigcode(&csigp->csig_sigcode,
	    td->td_proc->p_sysent);

	/*
	 * Set up root for the userspace object-type sealing capability tree.
	 * This can be queried using sysarch(2).
	 */
	cheri_capability_set_user_sealcap(&td->td_proc->p_md.md_cheri_sealcap);
}
