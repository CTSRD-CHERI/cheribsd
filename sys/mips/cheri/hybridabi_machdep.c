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

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/sysent.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <machine/pcb.h>
#include <machine/proc.h>
#include <machine/vmparam.h>

static void	hybridabi_capability_set_user_entry(struct thread *td,
		    void * __capability *, unsigned long);
static void	hybridabi_thread_init(struct thread *td, unsigned long);

void * __capability
hybridabi_user_ddc(void)
{
	return (cheri_capability_build_user_rwx(
	    CHERI_CAP_USER_DATA_PERMS | CHERI_PERM_CHERIABI_VMMAP,
	    CHERI_CAP_USER_DATA_BASE, CHERI_CAP_USER_DATA_LENGTH,
	    CHERI_CAP_USER_DATA_OFFSET));
}

static void
hybridabi_capability_set_user_entry(struct thread *td,
    void * __capability *cp, unsigned long entry_addr)
{

	/*
	 * Set the jump target register for the pure capability calling
	 * convention.
	 */
	*cp = cheri_capability_build_user_code(td, CHERI_CAP_USER_CODE_PERMS,
	    CHERI_CAP_USER_CODE_BASE, CHERI_CAP_USER_CODE_LENGTH, entry_addr);
}

/*
 * Common per-thread CHERI state initialisation across execve(2) and
 * additional thread creation.
 */
static void
hybridabi_thread_init(struct thread *td, unsigned long entry_addr)
{
	struct cheri_signal *csigp;
	struct trapframe *frame;

	/*
	 * We assume that the caller has initialised the trapframe to zeroes
	 * -- but do a quick assertion or two to catch programmer error.  We
	 * might want to check this with a more thorough set of assertions in
	 * the future.
	 */
	frame = &td->td_pcb->pcb_regs;
	KASSERT(frame->ddc == 0, ("%s: non-zero initial $ddc",
	    __func__));
	KASSERT(frame->pc == 0, ("%s: non-zero initial $epcc",
	    __func__));

	/*
	 * Hybrid processes use $ddc and $pcc with full user
	 * privilege, and all other user-accessible capability
	 * registers with no rights at all.
	 */
	frame->ddc = hybridabi_user_ddc();
	hybridabi_capability_set_user_entry(td, (void * __capability *)&frame->pc, entry_addr);

	/*
	 * Initialise signal-handling state; this can't yet be modified
	 * by userspace, but the principle is that signal handlers should run
	 * with ambient authority unless given up by the userspace runtime
	 * explicitly.
	 */
	csigp = &td->td_pcb->pcb_cherisignal;
	bzero(csigp, sizeof(*csigp));
}

/*
 * Set per-thread CHERI register state for MIPS ABI processes.  In
 * particular, we need to set up the CHERI register state for MIPS ABI
 * processes with suitable capabilities.
 *
 * XXX: I also wonder if we should be inheriting signal-handling state...?
 */
void
hybridabi_newthread_setregs(struct thread *td, unsigned long entry_addr)
{

	hybridabi_thread_init(td, entry_addr);
}

/*
 * Set per-process CHERI state for MIPS ABI processes after exec.
 * Initializes process-wide state as well as per-thread state for the
 * process' initial thread.
 */
void
hybridabi_exec_setregs(struct thread *td, unsigned long entry_addr)
{

	hybridabi_thread_init(td, entry_addr);
}
