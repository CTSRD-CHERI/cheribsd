/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 John Baldwin
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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
#include <sys/kernel.h>
#include <sys/proc.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <machine/frame.h>
#include <machine/riscvreg.h>
#include <machine/vmparam.h>

extern void * __capability userspace_cap;

void
cheri_init_capabilities(void * __capability kroot)
{
	void * __capability ctemp;

	ctemp = cheri_setaddress(kroot, CHERI_CAP_USER_DATA_BASE);
	ctemp = cheri_setbounds(ctemp, CHERI_CAP_USER_DATA_LENGTH);
	ctemp = cheri_andperm(ctemp, CHERI_CAP_USER_DATA_PERMS |
	    CHERI_CAP_USER_CODE_PERMS);
	userspace_cap = ctemp;
}

void
hybridabi_thread_setregs(struct thread *td, unsigned long entry_addr)
{
	struct trapframe *tf;

	tf = td->td_frame;

	/* Set DDC to full user privilege. */
	tf->tf_ddc = (uintcap_t)cheri_capability_build_user_data(
	    CHERI_CAP_USER_DATA_PERMS, CHERI_CAP_USER_DATA_BASE,
	    CHERI_CAP_USER_DATA_LENGTH, CHERI_CAP_USER_DATA_OFFSET);

	/* Use 'entry_addr' as offset of PCC. */
	tf->tf_sepc = (uintcap_t)cheri_capability_build_user_code(
	    td, CHERI_CAP_USER_CODE_PERMS, CHERI_CAP_USER_CODE_BASE,
	    CHERI_CAP_USER_CODE_LENGTH, entry_addr);
}

/*
 * As with system calls, handling signal delivery connotes special authority
 * in the runtime environment.  In the signal delivery code, we need to
 * determine whether to trust the executing thread to have valid stack state,
 * and use this function to query whether the execution environment is
 * suitable for direct handler execution, or if (in effect) a security-domain
 * transition is required first.
 */
int
cheri_signal_sandboxed(struct thread *td)
{
	uintmax_t c_perms;

	c_perms = cheri_getperm((void * __capability)td->td_frame->tf_sepc);
	if ((c_perms & CHERI_PERM_SYSCALL) == 0) {
		atomic_add_int(&security_cheri_sandboxed_signals, 1);
		return (ECAPMODE);
	}
	return (0);
}
