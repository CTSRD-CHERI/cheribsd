/*-
 * Copyright (c) 2015, 2017 Robert N. M. Watson
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
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/sysproto.h>

#include <ddb/ddb.h>
#include <sys/kdb.h>

#include <cheri/cheri.h>

#include <machine/atomic.h>
#include <machine/pcb.h>
#include <machine/sysarch.h>

/*
 * Propagate the root object-type sealing capability across fork().
 */
void
cheri_sealcap_copy(struct proc *dst, struct proc *src)
{

	memcpy(&dst->p_md.md_cheri_sealcap, &src->p_md.md_cheri_sealcap,
	    sizeof(dst->p_md.md_cheri_sealcap));
}

/*
 * Allow userspace to query a root object-type sealing capability using
 * sysarch(2).
 */
int
cheri_sysarch_getsealcap(struct thread *td, void * __capability ucap)
{

	return (copyoutcap(&td->td_proc->p_md.md_cheri_sealcap, ucap,
	    sizeof(td->td_proc->p_md.md_cheri_sealcap)));
}
