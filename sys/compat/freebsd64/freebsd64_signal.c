/*-
 * Copyright (c) 2015-2019 SRI International
 * Copyright (c) 2002 Doug Rabson
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of
 * the DARPA SSITH research programme.
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

#include <sys/param.h>
#include <sys/signal.h>
#include <sys/syscallsubr.h>
#include <sys/user.h>
#include <sys/vnode.h>

#include <cheri/cheric.h>

#include <compat/freebsd64/freebsd64.h>
#include <compat/freebsd64/freebsd64_signal.h>
#include <compat/freebsd64/freebsd64_util.h>
#include <compat/freebsd64/freebsd64_proto.h>

int
convert_sigevent64(const struct sigevent64 *sig64, struct sigevent *sig)
{

	CP(*sig64, *sig, sigev_notify);
	switch (sig->sigev_notify) {
	case SIGEV_NONE:
		break;
	case SIGEV_THREAD_ID:
		CP(*sig64, *sig, sigev_notify_thread_id);
		/* FALLTHROUGH */
	case SIGEV_SIGNAL:
		CP(*sig64, *sig, sigev_signo);
		memset(&sig->sigev_value, 0, sizeof(sig->sigev_value));
		sig->sigev_value.sival_ptr =
		    cheri_fromint(sig64->sigev_value.sival_ptr);
		break;
	case SIGEV_KEVENT:
		CP(*sig64, *sig, sigev_notify_kqueue);
		CP(*sig64, *sig, sigev_notify_kevent_flags);
		memset(&sig->sigev_value, 0, sizeof(sig->sigev_value));
		sig->sigev_value.sival_ptr =
		    cheri_fromint(sig64->sigev_value.sival_ptr);
		break;
	default:
		return (EINVAL);
	}
	return (0);
}

int
freebsd64_sigaction(struct thread *td, struct freebsd64_sigaction_args *uap)
{
	struct sigaction act, oact;
	struct sigaction64 act64, oact64;
	struct sigaction *actp, *oactp;
	int error;

	actp = (uap->act != NULL) ? &act : NULL;
	oactp = (uap->oact != NULL) ? &oact : NULL;
	if (actp) {
		error = copyin(uap->act, &act64, sizeof(act64));
		if (error)
			return (error);
		if (is_magic_sighandler_constant(act64.sa_u))
			actp->sa_handler = cheri_fromint(act64.sa_u);
		else
			actp->sa_handler = __USER_CODE_CAP((void *)act64.sa_u);
		actp->sa_flags = act64.sa_flags;
		actp->sa_mask = act64.sa_mask;
	}
	error = kern_sigaction(td, uap->sig, actp, oactp, 0);
	if (oactp && !error) {
		memset(&oact64, 0, sizeof(oact64));
		oact64.sa_u = (__cheri_addr vaddr_t)oactp->sa_handler;
		oact64.sa_flags = oactp->sa_flags;
		oact64.sa_mask = oactp->sa_mask;
		error = copyout(&oact64, uap->oact, sizeof(oact64));
	}
	return (error);
}

int
freebsd64_sigprocmask(struct thread *td, struct freebsd64_sigprocmask_args *uap)
{
	return (user_sigprocmask(td, uap->how, __USER_CAP_OBJ(uap->set),
	    __USER_CAP_OBJ(uap->oset)));
}

int
freebsd64_sigwait(struct thread *td, struct freebsd64_sigwait_args *uap)
{

	return (user_sigwait(td, __USER_CAP_OBJ(uap->set),
	    __USER_CAP_OBJ(uap->sig)));
}

void
siginfo_to_siginfo64(const siginfo_t *si, struct siginfo64 *si64)
{
	memset(si64, 0, sizeof(*si64));
	si64->si_signo = si->si_signo;
	si64->si_errno = si->si_errno;
	si64->si_code = si->si_code;
	si64->si_pid = si->si_pid;
	si64->si_uid = si->si_uid;
	si64->si_status = si->si_status;
	si64->si_addr = (__cheri_addr uint64_t)si->si_addr;
	si64->si_value.sival_ptr = (__cheri_addr uint64_t)si->si_value.sival_ptr;
}

static int
freebsd64_copyout_siginfo(const siginfo_t *si, void * __capability info)
{
	struct siginfo64 si64;
	
	siginfo_to_siginfo64(si, &si64);
	return (copyout_c(&si64, info, sizeof(struct siginfo64)));
}

int
freebsd64_sigtimedwait(struct thread *td,
    struct freebsd64_sigtimedwait_args *uap)
{

	return (user_sigtimedwait(td, __USER_CAP_OBJ(uap->set),
	    __USER_CAP_OBJ(uap->info), __USER_CAP_OBJ(uap->timeout),
	    (copyout_siginfo_t *)freebsd64_copyout_siginfo));
}

int
freebsd64_sigwaitinfo(struct thread *td, struct freebsd64_sigwaitinfo_args *uap)
{

	return (user_sigwaitinfo(td, __USER_CAP_OBJ(uap->set),
	    __USER_CAP_OBJ(uap->info),
	    (copyout_siginfo_t *)freebsd64_copyout_siginfo));
}

int
freebsd64_sigpending(struct thread *td, struct freebsd64_sigpending_args *uap)
{

	return (kern_sigpending(td, __USER_CAP_OBJ(uap->set)));
}

int
freebsd64_sigsuspend(struct thread *td, struct freebsd64_sigsuspend_args *uap)
{

	return (user_sigsuspend(td, __USER_CAP_OBJ(uap->sigmask)));
}

int
freebsd64_sigaltstack(struct thread *td,
    struct freebsd64_sigaltstack_args *uap)
{
	struct sigaltstack ss, oss;
	struct sigaltstack64 ss64;
	int error;

	if (uap->ss != NULL) {
		error = copyin(uap->ss, &ss64, sizeof(ss64));
		if (error != 0)
			return (error);
		ss.ss_sp = __USER_CAP_UNBOUND(ss64.ss_sp);
		ss.ss_size = ss64.ss_size;
		ss.ss_flags = ss64.ss_flags;
	}
	error = kern_sigaltstack(td, (uap->ss != NULL) ? &ss : NULL,
	    (uap->oss != NULL) ? &oss : NULL);
	if (error != 0)
		return (error);
	if (uap->oss != NULL) {
		memset(&ss64, 0, sizeof(ss64));
		ss64.ss_sp = (__cheri_fromcap void *)oss.ss_sp;
		ss64.ss_size = oss.ss_size;
		ss64.ss_flags = oss.ss_flags;
		error = copyout(&ss64, uap->oss, sizeof(ss64));
	}
	return (error);
}

int
freebsd64_sigqueue(struct thread *td, struct freebsd64_sigqueue_args *uap)
{
	union sigval sv;

	/*
	 * Store the 64-bit value (either int or address) in the
	 * capability's address.
	 */
	memset(&sv, 0, sizeof(sv));
	sv.sival_ptr = cheri_fromint((uintptr_t)uap->value);

	return (kern_sigqueue(td, uap->pid, uap->signum, &sv));
}
