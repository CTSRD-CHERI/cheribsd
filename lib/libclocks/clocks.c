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

#include <sys/auxv.h>
#include <sys/param.h>
#include <assert.h>
#include <capv.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

int
clock_gettime(clockid_t clock_id, struct timespec *tp)
{
	__thread static void * __capability target = NULL;
	capv_clocks_t in;
	capv_t out;
	void * __capability *capv;
	int capc, error;

	/*
	 * We could turn this into a constructor, but then we would lose
	 * the advantage of this code never being run unless the process
	 * actually makes an attempt to call clock_gettime().
	 */
	if (__predict_false(target == NULL)) {
		errno = elf_aux_info(AT_CAPC, &capc, sizeof(capc));
		if (errno != 0) {
			warn("AT_CAPC");
			return (-1);
		}
		errno = elf_aux_info(AT_CAPV, &capv, sizeof(capv));
		if (errno != 0) {
			warn("AT_CAPV");
			return (-1);
		}
		if (capc <= CAPV_CLOCKS || capv[CAPV_CLOCKS] == NULL) {
			warn("null capability %d", CAPV_CLOCKS);
			errno = ENOLINK;
			return (-1);
		}
		error = cosetup(COSETUP_COCALL);
		if (error != 0) {
			warn("cosetup");
			return (-1);
		}
		target = capv[CAPV_CLOCKS];
	}

	/*
	 * Send our request.
	 */
	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	out.len = sizeof(out);
	out.op = clock_id + CAPV_CLOCKS; /* I'm sorry, but CLOCK_REALTIME == 0 */

	//fprintf(stderr, "%s: -> calling target %lp, in %lp, inlen %zd, out %lp, outlen %zd\n", __func__, target, &in, sizeof(in), &out, sizeof(out));
	error = cocall(target, &out, out.len, &in, sizeof(in));
	if (error != 0) {
		warn("cocall");
		return (error);
	}

	/*
	 * Handle the response.
	 */
	if (in.len != sizeof(in)) {
		warnx("in.len %zd != sizeof %zd", in.len, sizeof(in));
		errno = ENOMSG;
		return (error);
	}

	//fprintf(stderr, "%s: <- returned error %d, errno %d\n", __func__, in.error, in._errno);
	error = in.error;
	if (error != 0)
		errno = in._errno;
	else
		memcpy(tp, &in.ts, sizeof(*tp));
	return (error);
}
