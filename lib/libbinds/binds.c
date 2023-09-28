/*-
 * Copyright (c) 2022 Edward Tomasz Napierala <trasz@FreeBSD.org>
 * All rights reserved.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory as part of the CHERI for Hypervisors and Operating Systems
 * (CHaOS) project, funded by EPSRC grant EP/V000292/1.
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

#include <sys/param.h>
#include <sys/syscall.h>
#include <capv.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

__thread static void * __capability target = NULL;

/*
 * We could turn this into a constructor, but then we would lose
 * the advantage of this code never being run unless the thread
 * actually makes an attempt to call clock_gettime().
 */
static inline int
init_maybe(void)
{
	void * __capability *capv;
	int capc, error;

	if (__predict_true(target != NULL))
		return (0);

	capvfetch(&capc, &capv);
	if (capc <= CAPV_BINDS || capv[CAPV_BINDS] == NULL) {
		warn("%s: null capability %d", __func__, CAPV_BINDS);
		errno = ENOLINK;
		return (-1);
	}
	error = cosetup(COSETUP_COCALL);
	if (error != 0) {
		warn("%s: cosetup", __func__);
		return (-1);
	}
	target = capv[CAPV_BINDS];

	return (0);
}

int
bind(int s, const struct sockaddr *addr, socklen_t addrlen)
{
	capv_binds_return_t in;
	capv_binds_t out;
	void * __capability fdcap;
	ssize_t received;
	int error;

	error = init_maybe();
	if (error != 0)
		return (error);

	error = capfromfd(&fdcap, s);
	if (error != 0)
		err(1, "capfromfd");

	/*
	 * Send our request.
	 */
	memset(&out, 0, sizeof(out));
	out.len = sizeof(out);
	out.op = SYS_bind;
	out.s = fdcap;
	memcpy(&out.addr, addr, addrlen);
	out.addrlen = addrlen;

	received = cocall(target, &out, out.len, &in, sizeof(in));
	if (received < 0) {
		warn("%s: cocall", __func__);
		return (error);
	}

	/*
	 * Handle the response.
	 */
	if ((size_t)received != sizeof(in)) {
		warnx("%s: size mismatch: received %zd, expected %zd; returning ENOMSG",
		    __func__, (size_t)received, sizeof(in));
		errno = ENOMSG;
		return (error);
	}

	fprintf(stderr, "%s: <- op %d returned error %d, errno %d\n", __func__, in.op, in.error, in.errno_);
	error = in.error;
	errno = in.errno_;
	return (error);
}

int
connect(int s, const struct sockaddr *addr, socklen_t addrlen)
{
	capv_binds_return_t in;
	capv_binds_t out;
	void * __capability fdcap;
	ssize_t received;
	int error;

	error = init_maybe();
	if (error != 0)
		return (error);

	error = capfromfd(&fdcap, s);
	if (error != 0)
		err(1, "capfromfd");

	/*
	 * Send our request.
	 */
	memset(&out, 0, sizeof(out));
	out.len = sizeof(out);
	out.op = SYS_connect;
	out.s = fdcap;
	memcpy(&out.addr, addr, addrlen);
	out.addrlen = addrlen;

	received = cocall(target, &out, out.len, &in, sizeof(in));
	if (received < 0) {
		warn("%s: cocall", __func__);
		return (error);
	}

	/*
	 * Handle the response.
	 */
	if ((size_t)received != sizeof(in)) {
		warnx("%s: size mismatch: received %zd, expected %zd; returning ENOMSG",
		    __func__, (size_t)received, sizeof(in));
		errno = ENOMSG;
		return (error);
	}

	error = in.error;
	errno = in.errno_;
	return (error);
}
