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
#include <errno.h>
#include <unistd.h>
#include "cheri_private.h"
#include "un-namespace.h"

int __usleep(useconds_t);	// XXX

int
cocall(void * __capability target,
    const void * __capability outbuf, size_t outlen,
    void * __capability inbuf, size_t inlen)
{
	int error;

	_trace_cocall((ptraddr_t)target, outlen, inlen);

	/* XXX This loop is like this for no particular reason. */
	for (;;) {
		error = _cocall(_cocall_code, _cocall_data, target,
		    outbuf, outlen, inbuf, inlen);

		if (__predict_true(error == 0))
			return (error);

		switch (errno) {
		case EAGAIN:
			/*
			 * So, originally this part looked like this:
			 */
#if 0
			/*
			 * EAGAIN means the caller hasn't entered coaccept(2)
			 * yet.  We will need to enter anyhow, if only to wait,
			 * so why not just retry the whole thing.
			 */
			error = cocall_slow(target, outbuf, outlen, inbuf, inlen);
			break;
#endif
			/*
			 * BUT: Suppose we got EAGAIN from _cocall(2);
			 * if we fall back to cocall_slow(2) we will block
			 * there, and if the callee calls _coaccept(2),
			 * there is no code path to wake us up.  If the callee
			 * chooses cocall_slow(2) instead, then we will receive
			 * an EPROTOTYPE, handled below.
			 */
			__usleep(1000);
			continue;

		case EPROTOTYPE:
			/*
			 * EPROTOTYPE means the callee is waiting on
			 * coaccept_slow(2), not _coaccept(2).  It's a syscall,
			 * so it's slow anyway; this whole switch is the slow
			 * path.
			 */
			return (cocall_slow(target, outbuf, outlen, inbuf, inlen));

		default:
			return (error);
		}
	}

}
