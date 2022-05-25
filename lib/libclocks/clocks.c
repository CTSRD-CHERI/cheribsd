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
#include <sys/nv.h>
#include <sys/param.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

// XXX
static __inline int imin(int a, int b) { return (a < b ? a : b); }

int
clock_gettime(clockid_t clock_id, struct timespec *tp)
{
	__thread static void * __capability target = NULL;
	__thread static volatile bool in_progress = false;
	static bool go_slow = false;
	char in[BUFSIZ];
	void * __capability *capv;
	const struct timespec *returned_tp;
	nvlist_t *nvl;
	char *libclocks_slow = NULL;
	void *out;
	size_t outlen, returned_tplen;
	int capc, error, returned_error, returned_errno;

	/*
	 * XXX: This is no longer necessary - was supposed to detect situations
	 * 	like nvlist_create(3) calling malloc(3) calling back
	 * 	into clock_gettime(3), but jemalloc got hacked into compliance.
	 * 	Not even sure if this chunk works; it will be removed next anyway.
	 */
	if (in_progress) {
		warnx("%s recursing, returning EDEADLK", __func__);
		errno = EDEADLK;
		return (-1);
	}
	in_progress = true;

	/*
	 * We could turn this into a constructor, but then we would lose
	 * the advantage of this code never being run unless the process
	 * actually makes an attempt to call clock_gettime().
	 */
	if (__predict_false(target == NULL)) {
		errno = elf_aux_info(AT_CAPC, &capc, sizeof(capc));
		if (errno != 0) {
			warn("AT_CAPC");
			error = -1;
			goto out;
		}
		errno = elf_aux_info(AT_CAPV, &capv, sizeof(capv));
		if (errno != 0) {
			warn("AT_CAPV");
			error = -1;
			goto out;
		}
		if (capc <= CAPV_CLOCKS || capv[CAPV_CLOCKS] == NULL) {
			warn("null capability");
			errno = ENOLINK;
			error = -1;
			goto out;
		}
		error = cosetup(COSETUP_COACCEPT);
		if (error != 0) {
			warn("cosetup");
			goto out;
		}
		target = capv[CAPV_CLOCKS];

		libclocks_slow = getenv("LIBCLOCKS_SLOW");
		if (libclocks_slow != NULL && libclocks_slow[0] == '1')
			go_slow = true;
	}

	/*
	 * Send our request.
	 */
	nvl = nvlist_create(NV_FLAG_MEMALIGN);
	nvlist_add_number(nvl, "op", clock_id + CAPV_CLOCKS /* I'm sorry, but CLOCK_REALTIME == 0 */);
	out = nvlist_pack(nvl, &outlen);
	assert(out != NULL);
	outlen = roundup2(outlen, 16);
	nvlist_destroy(nvl);

	//fprintf(stderr, "%s: -> calling target %lp%s\n", __func__, target, go_slow ? " (slow)" : "");
	if (go_slow)
		error = cocall_slow(target, out, outlen, in, sizeof(in));
	else
		error = cocall(target, out, outlen, in, sizeof(in));
	free(out);
	//fprintf(stderr, "%s: <- returned error %d, errno %d%s\n", __func__, error, errno, go_slow ? " (slow)" : "");
	if (error != 0) {
		warn("%s", go_slow ? "cocall_slow" : "cocall");
		goto out;
	}

	/*
	 * Handle the response.
	 */
	nvl = nvlist_unpack(in, sizeof(in), NV_FLAG_MEMALIGN);
	if (nvl == NULL) {
		warnx("nvlist_unpack(3) failed");
		in_progress = false;
		return (error);
	}
	returned_error = nvlist_get_number(nvl, "error");
	if (returned_error != 0) {
		returned_errno = nvlist_get_number(nvl, "errno");
		errno = returned_errno;
	} else {
		returned_tp = nvlist_get_binary(nvl, "tp", &returned_tplen);
		memcpy(tp, returned_tp, imin(sizeof(*tp), returned_tplen));
	}
	nvlist_destroy(nvl);
	error = returned_error;
out:
	in_progress = false;
	return (error);
}
