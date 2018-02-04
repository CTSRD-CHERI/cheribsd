/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2005 Wojciech A. Koszek
 * All rights reserved.
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/proc.h>
#include <sys/sbuf.h>
#include <sys/syslog.h>

#include <compat/cheriabi/cheriabi_proto.h>

int
cheriabi_abort2(struct thread *td, struct cheriabi_abort2_args *uap)
{
	struct proc *p = td->td_proc;
	struct sbuf *sb;
	void * __capability uargs[16];
	int error, i, sig;

	/*
	 * Do it right now so we can log either proper call of abort2(), or
	 * note, that invalid argument was passed. 512 is big enough to
	 * handle 16 arguments' descriptions with additional comments.
	 */
	sb = sbuf_new(NULL, NULL, 512, SBUF_FIXEDLEN);
	sbuf_clear(sb);
	sbuf_printf(sb, "%s(pid %d uid %d) aborted: ",
	    p->p_comm, p->p_pid, td->td_ucred->cr_uid);
	/*
	 * Since we can't return from abort2(), send SIGKILL in cases, where
	 * abort2() was called improperly
	 */
	sig = SIGKILL;
	/* Prevent from DoSes from user-space. */
	if (uap->nargs < 0 || uap->nargs > 16)
		goto out;
	if (uap->nargs > 0) {
		if (uap->args == NULL)
			goto out;
		error = copyin_c(uap->args, &uargs[0],
		    uap->nargs * sizeof(void *));
		if (error != 0)
			goto out;
	}
	/*
	 * Limit size of 'reason' string to 128. Will fit even when
	 * maximal number of arguments was chosen to be logged.
	 */
	if (uap->why != NULL) {
		error = sbuf_copyin(sb, uap->why, 128);
		if (error < 0)
			goto out;
	} else {
		sbuf_printf(sb, "(null)");
	}
	if (uap->nargs > 0) {
		sbuf_printf(sb, "(");
		for (i = 0; i < uap->nargs; i++) {
			/*
			 * XXX-CHERI: fromcap is safe because we're not
			 * dereferencing, but should we print more
			 * pointer details?
			 */
			sbuf_printf(sb, "%s%p", i == 0 ? "" : ", ",
			    (__cheri_fromcap void *)uargs[i]);
		}
		sbuf_printf(sb, ")");
	}
	/*
	 * Final stage: arguments were proper, string has been
	 * successfully copied from userspace, and copying pointers
	 * from user-space succeed.
	 */
	sig = SIGABRT;
out:
	if (sig == SIGKILL) {
		sbuf_trim(sb);
		sbuf_printf(sb, " (Reason text inaccessible)");
	}
	sbuf_cat(sb, "\n");
	sbuf_finish(sb);
	log(LOG_INFO, "%s", sbuf_data(sb));
	sbuf_delete(sb);
	exit1(td, 0, sig);
	return (0);
}
