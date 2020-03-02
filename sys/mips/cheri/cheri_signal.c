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
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>

#include <ddb/ddb.h>
#include <sys/kdb.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <machine/atomic.h>
#include <machine/pcb.h>
#include <machine/sysarch.h>

/*
 * When new threads are forked, by default simply replicate the parent
 * thread's CHERI-related signal-handling state.
 *
 * XXXRW: Is this, in fact, the right thing?
 */
void
cheri_signal_copy(struct pcb *dst, struct pcb *src)
{

	memcpy(&dst->pcb_cherisignal, &src->pcb_cherisignal,
	    sizeof(dst->pcb_cherisignal));
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

	c_perms = cheri_getperm(td->td_pcb->pcb_regs.pcc);
	if ((c_perms & CHERI_PERM_SYSCALL) == 0) {
		atomic_add_int(&security_cheri_sandboxed_signals, 1);
		return (ECAPMODE);
	}
	return (0);
}
