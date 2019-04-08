/*-
 * Copyright (c) 2002 Doug Rabson
 * Copyright (c) 2015-2018 SRI International
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_ktrace.h"
#include "opt_posix.h"

#define	EXPLICIT_USER_ACCESS

#include <sys/param.h>
#include <sys/signal.h>
#include <sys/syscallsubr.h>
#include <sys/user.h>
#include <sys/vnode.h>

#include <cheri/cheri.h>

#include <compat/cheriabi/cheriabi.h>
#include <compat/cheriabi/cheriabi_signal.h>
#include <compat/cheriabi/cheriabi_util.h>
#include <compat/cheriabi/cheriabi_proto.h>

#ifdef CHERIABI_NEEDS_UPDATE
CTASSERT(sizeof(struct sigaltstack32) == 12);
#endif

int
cheriabi_sigaction(struct thread *td, struct cheriabi_sigaction_args *uap)
{
	struct sigaction_c act, oact;
	struct sigaction_c *actp, *oactp;
	int error;

	actp = (uap->act != NULL) ? &act : NULL;
	oactp = (uap->oact != NULL) ? &oact : NULL;
	if (actp) {
		error = copyincap(uap->act, &act, sizeof(act));
		if (error)
			return (error);
	}
	error = kern_sigaction(td, uap->sig, actp, oactp, 0);
	if (oactp && !error)
		error = copyoutcap(&oact, uap->oact, sizeof(oact));
	return (error);
}

int
cheriabi_sigprocmask(struct thread *td, struct cheriabi_sigprocmask_args *uap)
{

	return (user_sigprocmask(td, uap->how, uap->set, uap->oset));
}

int
cheriabi_sigwait(struct thread *td, struct cheriabi_sigwait_args *uap)
{

	return (user_sigwait(td, uap->set, uap->sig));
}

int
cheriabi_sigtimedwait(struct thread *td, struct cheriabi_sigtimedwait_args *uap)
{
	struct timespec ts;
	struct timespec *timeout;
	sigset_t set;
	ksiginfo_t ksi;
	int error;

	if (uap->timeout) {
		error = copyin(uap->timeout, &ts, sizeof(ts));
		if (error)
			return (error);
		timeout = &ts;
	} else
		timeout = NULL;

	error = copyin(uap->set, &set, sizeof(set));
	if (error)
		return (error);

	error = kern_sigtimedwait(td, set, &ksi, timeout);
	if (error)
		return (error);

	if (uap->info != NULL)
		error = copyout(&ksi.ksi_info, uap->info,
		    sizeof(struct siginfo_c));

	if (error == 0)
		td->td_retval[0] = ksi.ksi_signo;
	return (error);
}

int
cheriabi_sigwaitinfo(struct thread *td, struct cheriabi_sigwaitinfo_args *uap)
{
	ksiginfo_t ksi;
	sigset_t set;
	int error;

	error = copyin(uap->set, &set, sizeof(set));
	if (error)
		return (error);

	error = kern_sigtimedwait(td, set, &ksi, NULL);
	if (error)
		return (error);

	if (uap->info != NULL)
		error = copyout(&ksi.ksi_info, uap->info,
		    sizeof(struct siginfo_c));
	if (error == 0)
		td->td_retval[0] = ksi.ksi_signo;
	return (error);
}

int
cheriabi_sigpending(struct thread *td, struct cheriabi_sigpending_args *uap)
{
	struct proc *p = td->td_proc;
	sigset_t pending;

	PROC_LOCK(p);
	pending = p->p_sigqueue.sq_signals;
	SIGSETOR(pending, td->td_sigqueue.sq_signals);
	PROC_UNLOCK(p);
	return (copyout(&pending, uap->set, sizeof(sigset_t)));
}

int
cheriabi_sigsuspend(struct thread *td, struct cheriabi_sigsuspend_args *uap)
{
	sigset_t mask;
	int error;

	error = copyin(uap->sigmask, &mask, sizeof(mask));
	if (error)
		return (error);
	return (kern_sigsuspend(td, mask));
}

int
cheriabi_sigaltstack(struct thread *td,
    struct cheriabi_sigaltstack_args *uap)
{
	struct sigaltstack ss, oss;
	int error;

	if (uap->ss != NULL) {
		error = copyincap(uap->ss, &ss, sizeof(ss));
		if (error != 0)
			return (error);
	}
	error = kern_sigaltstack(td, (uap->ss != NULL) ? &ss : NULL,
	    (uap->oss != NULL) ? &oss : NULL);
	if (error != 0)
		return (error);
	if (uap->oss != NULL)
		error = copyoutcap(&oss, uap->oss, sizeof(oss));
	return (error);
}

int
cheriabi_sigqueue(struct thread *td, struct cheriabi_sigqueue_args *uap)
{
	union sigval_c	value_union;
	ksigval_union	sv;
	int		flags = 0, tag;

	value_union.sival_ptr = uap->value;
	if (uap->pid == td->td_proc->p_pid) {
		sv.sival_ptr_c = value_union.sival_ptr;
	} else {
		/*
		 * Cowardly refuse to send capabilities to other
		 * processes.
		 *
		 * XXX-BD: allow untagged capablities between
		 * CheriABI processess? (Would have to happen in
		 * delivery code to avoid a race).
		 */
		tag = cheri_gettag(value_union.sival_ptr);
		if (tag)
			return (EPROT);
		sv.sival_int = value_union.sival_int;
	}
	return (kern_sigqueue(td, uap->pid, uap->signum, &sv, flags));
}
