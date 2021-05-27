/*-
 * Copyright (c) 2020 Edward Tomasz Napierala <trasz@FreeBSD.org>
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "namespace.h"
#include <sys/param.h>
#include <sys/uio.h>
#include <sys/ktrace.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "cheri_private.h"
#include "libc_private.h"
#include "un-namespace.h"

struct utrace_cocall {
	char	sig[6];	/* 'COCALL' */
	ptraddr_t target;
	size_t	outlen;
	size_t	inlen;
};

_Thread_local void * __capability _cocall_code;
_Thread_local void * __capability _cocall_data;
_Thread_local void * __capability _coaccept_code;
_Thread_local void * __capability _coaccept_data;

_Thread_local void * __capability _cogetpid2_code;
_Thread_local void * __capability _cogetpid2_data;
_Thread_local void * __capability _cogettid_code;
_Thread_local void * __capability _cogettid_data;

static bool trace_cocalls;
static pthread_once_t once_control = PTHREAD_ONCE_INIT;

static void
check_trace_cocalls(void)
{
	trace_cocalls = (getenv("COCALL_UTRACE") != NULL);
}

void
_trace_cocall(ptraddr_t target, size_t outlen, size_t inlen)
{
	struct utrace_cocall uc;

	_once(&once_control, check_trace_cocalls);

	if (!trace_cocalls)
		return;
	memcpy(uc.sig, "COCALL", sizeof(uc.sig));
	uc.target = target;
	uc.outlen = outlen;
	uc.inlen = inlen;
	utrace(&uc, sizeof(uc));
}

int
cosetup(int what)
{
	switch (what) {
	case COSETUP_COACCEPT:
		return (_cosetup(what, &_coaccept_code, &_coaccept_data));
	case COSETUP_COCALL:
		return (_cosetup(what, &_cocall_code, &_cocall_data));
	case COSETUP_COGETPID:
		return (_cosetup(what, &_cogetpid2_code, &_cogetpid2_data));
	case COSETUP_COGETTID:
		return (_cosetup(what, &_cogettid_code, &_cogettid_data));
	default:
		return (EINVAL);
	}
}
