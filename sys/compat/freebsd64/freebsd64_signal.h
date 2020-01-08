/*-
 * Copyright (c) 2015-2019 SRI International
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

#ifndef _COMPAT_FREEBSD64_FREEBSD64_SIGNAL_H_
#define _COMPAT_FREEBSD64_FREEBSD64_SIGNAL_H_

struct sigaction64 {
	union {
		void    (*__sa_handler)(int);
		void    (*__sa_sigaction)(int, struct __siginfo *, void *);
	} __sigaction_u;		/* signal handler */
	int	sa_flags;		/* see signal options below */
	sigset_t sa_mask;		/* signal mask to apply */
};

struct sigaltstack64 {
	void		*ss_sp;		/* signal stack base */
	size_t		ss_size;	/* signal stack length */
	int		ss_flags;	/* SS_DISABLE and/or SS_ONSTACK */
};
typedef struct sigaltstack64 freebsd64_stack_t;

struct sigevent64 {
	int	sigev_notify;
	int	sigev_signo;
	union sigval64 sigev_value;
	union {
		__lwpid_t	_threadid;
		struct {
			void (*_function)(union sigval64);
			struct pthread_attr **_attribute;
		} _sigev_thread;
		unsigned short _kevent_flags;
		long __spare__[8];
	} _sigev_un;
};

void	siginfo_to_siginfo64(const _siginfo_t *si, struct siginfo64 *si64);
int	convert_sigevent64(const struct sigevent64 *sig64, ksigevent_t *sig);

#endif /* _COMPAT_FREEBSD64_FREEBSD64_SIGNAL_H_ */
