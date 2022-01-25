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

#include <cheri/cheri.h>
#include <cheri/cheric.h>

void * __capability
hybridabi_user_ddc(void)
{
	return (cheri_capability_build_user_rwx(
	    CHERI_CAP_USER_DATA_PERMS | CHERI_PERM_SW_VMEM,
	    CHERI_CAP_USER_DATA_BASE, CHERI_CAP_USER_DATA_LENGTH,
	    CHERI_CAP_USER_DATA_OFFSET));
}

/*
 * Common per-thread CHERI state initialisation across execve(2) and
 * additional thread creation.
 */
void
hybridabi_thread_setregs(struct thread *td, unsigned long entry_addr)
{
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
	frame->pc = (trapf_pc_t)cheri_capability_build_user_code(td,
	    CHERI_CAP_USER_CODE_PERMS, CHERI_CAP_USER_CODE_BASE,
	    CHERI_CAP_USER_CODE_LENGTH, entry_addr);
}
