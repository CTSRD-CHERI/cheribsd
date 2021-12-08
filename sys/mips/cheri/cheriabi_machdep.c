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

#include <sys/types.h>
#include <sys/sysent.h>
#include <sys/proc.h>
#include <sys/syscall.h>
#include <sys/sysargmap.h>

#include <cheri/cheri.h>

#include <machine/md_var.h>

#define	DELAYBRANCH(x)	((int)(x) < 0)

int
cheriabi_fetch_syscall_args(struct thread *td)
{
	struct trapframe *locr0 = td->td_frame;	 /* aka td->td_pcb->pcv_regs */
	struct sysentvec *se;
	struct syscall_args *sa;
	int argoff, error, i, ptrmask;

	error = 0;

	sa = &td->td_sa;
	bzero(sa->args, sizeof(sa->args));

	/* compute next PC after syscall instruction */
	td->td_pcb->pcb_tpc = locr0->pc; /* Remember if restart */
	if (DELAYBRANCH(locr0->cause))	 /* Check BD bit */
		locr0->pc = MipsEmulateBranch(locr0, locr0->pc, 0, 0);
	else
		TRAPF_PC_INCREMENT(locr0, sizeof(int));

	sa->code = locr0->v0;
	argoff = 0;
	if (sa->code == SYS_syscall || sa->code == SYS___syscall) {
		sa->code = locr0->a0;
		argoff = 1;
	}

	se = td->td_proc->p_sysent;

	if (sa->code >= se->sv_size)
		sa->callp = &se->sv_table[0];
	else
		sa->callp = &se->sv_table[sa->code];

	if (sa->code >= nitems(sysargmask))
		ptrmask = 0;
	else
		ptrmask = sysargmask[sa->code];

	/*
	 * For syscall() and __syscall(), the arguments are stored in a
	 * var args block pointed to by c13.
	 */
	if (argoff == 1) {
		uint64_t intval;
		int offset;

		offset = 0;
		for (i = 0; i < sa->callp->sy_narg; i++) {
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
		for (i = 0; i < sa->callp->sy_narg; i++) {
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
