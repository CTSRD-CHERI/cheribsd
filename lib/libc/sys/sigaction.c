/*
 * Copyright (c) 2014 The FreeBSD Foundation.
 *
 * Portions of this software were developed by Konstantin Belousov
 * under sponsorship from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice(s), this list of conditions and the following disclaimer as
 *    the first lines of this file unmodified other than the possible
 *    addition of one or more copyright notices.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice(s), this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER(S) ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <signal.h>
#include "libc_private.h"

__weak_reference(__sys_sigaction, __sigaction);
__weak_reference(sigaction, __libc_sigaction);
#if defined(__CHERI_PURE_CAPABILITY__) && defined(RTLD_SANDBOX)
/*
 * These weak symbols will always be resolved at runtime.
 */
/*
 * XXX: Explicit function pointer used so that RTLD can wrap it in trampoline.
 */
extern void (*_rtld_sighandler)(int, siginfo_t *, void *);

#pragma weak _rtld_sigaction_begin
void *_rtld_sigaction_begin(int, struct sigaction *);

#pragma weak _rtld_sigaction_end
void _rtld_sigaction_end(int, void *, const struct sigaction *,
    struct sigaction *);

int
sigaction_c18n(int sig, const struct sigaction *act, struct sigaction *oact)
{
	int ret;
	void *context = 0;
	struct sigaction newact;
	const struct sigaction *newactp = act;

	if (act &&
	    act->sa_handler != SIG_DFL && act->sa_handler != SIG_IGN) {
		newact = *act;
		newactp = &newact;

		context = _rtld_sigaction_begin(sig, &newact);
		newact.sa_sigaction = _rtld_sighandler;
	}

	ret = __sys_sigaction(sig, newactp, oact);

	if (ret == 0)
		_rtld_sigaction_end(sig, context, act, oact);

	return (ret);
}
#endif

#pragma weak sigaction
int
sigaction(int sig, const struct sigaction *act, struct sigaction *oact)
{

	return (((int (*)(int, const struct sigaction *, struct sigaction *))
	    __libc_interposing[INTERPOS_sigaction])(sig, act, oact));
}
