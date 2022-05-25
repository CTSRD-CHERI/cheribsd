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
#include <sys/types.h>
#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void
usage(void)
{

	fprintf(stderr, "usage: clocks [-kv] command [args ...]\n");
	exit(0);
}

static void
sigchld_handler(int dummy __unused)
{

	exit(0);
}

/*
 * XXX: Move to libc?
 */
static void
capvset(int *capcp, void * __capability **capvp, int new_index, void * __capability new_value)
{
	void * __capability *capv;
	void * __capability *old_capv;
	int capc;

	capc = *capcp;
	capv = *capvp;

	if (capc <= new_index) {
		/*
		 * XXX: We can't free old_capv, we don't know how it's been allocated.
		 */
		old_capv = capv;
		capv = calloc(new_index + 1, sizeof(void * __capability));
		if (capv == NULL)
			err(1, "calloc");
		if (capc > 0)
			memcpy(capv, old_capv, capc * sizeof(void * __capability));
#ifdef notyet
		capc = (new_index < 16 ? 8 : new_index) * 2;
#else
		capc = new_index + 1;
#endif
	}

	capv[new_index] = new_value;

	*capcp = capc;
	*capvp = capv;
}

int
main(int argc, char **argv)
{
	char in[BUFSIZ];
	struct timespec tp;
	clockid_t clock_id;
	nvlist_t *nvl;
	void * __capability dummy; // XXX
	void * __capability public;
	void * __capability *capv = NULL;
	void *out;
	pid_t pid;
	size_t outlen;
	bool kflag = false, vflag = false;
	int capc, ch, error, op;

	while ((ch = getopt(argc, argv, "ks:v")) != -1) {
		switch (ch) {
		case 'k':
			kflag = true;
			break;
		case 'v':
			vflag = true;
			break;
		case '?':
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;
	if (argc < 1)
		usage();

	struct sigaction sa;
	sa.sa_handler = sigchld_handler;
	sigfillset(&sa.sa_mask);

	error = sigaction(SIGCHLD, &sa, NULL);
	if (error != 0)
		err(1, "sigaction");

	error = cosetup(COSETUP_COACCEPT);
	if (error != 0)
		err(1, "cosetup");

	error = coregister(NULL, &public);
	if (error != 0)
		err(1, "coregister");

	error = elf_aux_info(AT_CAPC, &capc, sizeof(capc));
	if (error != 0)
		errc(1, error, "AT_CAPC");
	error = elf_aux_info(AT_CAPV, &capv, sizeof(capv));
	if (error != 0 && error != ENOENT)
		errc(1, error, "AT_CAPV");

	capvset(&capc, &capv, CAPV_CLOCKS, public);

	pid = vfork();
	if (pid < 0)
		err(1, "vfork");

	if (pid == 0) {
		/*
		 * Child, will coexecvec(2) the new command.
		 *
		 * This whole mess with environment variables is to preload
		 * libclocks.so, which provides clock_gettime(3) replacement,
		 * which then shadows the system call.  This makes unmodified
		 * purecap binaries transparently call clocks(1) instead
		 * of kernel.  A bit ugly, but convenient for now.
		 */
		char *ld_preload;
		char *tmp = NULL;

		ld_preload = getenv("LD_PRELOAD");
		if (ld_preload != NULL) {
			asprintf(&tmp, "%s:%s", ld_preload, "/usr/lib/libclocks.so");
		} else {
			asprintf(&tmp, "%s", "/usr/lib/libclocks.so");
		}
		error = setenv("LD_PRELOAD", tmp, 1);
		if (error != 0)
			err(1, "setenv");

		if (kflag) {
			error = setenv("LIBCLOCKS_SLOW", "1", 1);
			if (error != 0)
				err(1, "setenv");
		} else {
			warnx("XXX consider using -k");
		}

		/*
		 * This doesn't return.
		 */
		coexecvpc(getppid(), argv[0], argv, capv, capc);
		err(1, "coexecvpc");
	}

	/*
	 * Parent, will loop on coaccept(2) until SIGCHLD.
	 */
	out = NULL;
	outlen = 0;

	for (;;) {
		if (kflag)
			error = coaccept_slow(&dummy, out, outlen, in, sizeof(in));
		else
			error = coaccept(&dummy, out, outlen, in, sizeof(in));

		free(out);
		out = NULL;
		outlen = 0;

		if (error != 0) {
			warn("%s", kflag ? "cocall_slow" : "cocall");
			continue;
		}

		/*
		 * Answered, unmarshall the input buffer.
		 */
		if (vflag) {
			error = cogetpid(&pid);
			if (error != 0)
				warn("cogetpid");
			printf("%s: call from pid %d -> pid %d%s\n",
			    getprogname(), pid, getpid(), kflag ? " (slow)" : "");
		}

		nvl = nvlist_unpack(in, sizeof(in), NV_FLAG_MEMALIGN);
		if (nvl == NULL) {
			warnx("nvlist_unpack(3) failed");
			continue;
		}

		op = nvlist_get_number(nvl, "op");
		nvlist_destroy(nvl);

		nvl = nvlist_create(NV_FLAG_MEMALIGN);
		switch (op) {
		case 0:
			nvlist_add_stringf(nvl, "answerback", "pid %d (%s), uid %d",
			    getpid(), getprogname(), getuid());
			clock_id = error = errno = 0;
			break;
		default:
			/*
			 * Check time.
			 */
			clock_id = op - CAPV_CLOCKS; /* iksde */
			error = clock_gettime(clock_id, &tp);
			if (error != 0)
				warn("clock_gettime(%d)", clock_id);
			nvlist_add_binary(nvl, "tp", &tp, sizeof(tp));
			nvlist_add_number(nvl, "error", error);
			nvlist_add_number(nvl, "errno", errno);
			break;
		}

		/*
		 * Send the response back and loop.
		 */
		out = nvlist_pack(nvl, &outlen);
		assert(out != NULL);
		nvlist_destroy(nvl);

		if (vflag) {
			printf("%s: returning to pid %d <- pid %d: op %d, clock_id %d, error %d, errno %d%s\n",
			    getprogname(), pid, getpid(), op, clock_id, error, errno, kflag ? " (slow)" : "");
		}
	}
}
