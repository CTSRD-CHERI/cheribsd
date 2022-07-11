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

/*
 * This is the callee (coaccepting) part of the clock service,
 * with the client (cocalling) part in lib/libclocks/clocks.c.
 * The fact that clock_gettime() gets called all over the place
 * makes it easier to exercise underlying mechanisms.  It's also
 * a good starting point for implementing a new service.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/auxv.h>
#include <sys/capsicum.h>
#include <sys/param.h>
#include <sys/types.h>
#include <assert.h>
#include <capv.h>
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

static bool Cflag = false, kflag = false, vflag = false;

static void
usage(void)
{

	fprintf(stderr, "usage: clocks [-Ckv] command [args ...]\n");
	exit(0);
}

static void
sigchld_handler(int dummy __unused)
{

	exit(0);
}

static void
answerback(capv_answerback_t *out)
{
	int error, mode;

	mode = 0;
	error = cap_getmode(&mode);
	if (error != 0)
		err(1, "cap_getmode");

	memset(out, 0, sizeof(*out));
	out->len = sizeof(*out);
	out->op = 0;
	snprintf(out->answerback, sizeof(out->answerback),
	    "clocks(1), pid %d, %s%s responding to clock_gettime(), running as uid %d",
	    getpid(), kflag ? "halfheartedly" : "merrily",
	    mode ? "" : ", yet unsettlingly,", getuid());
}

int
main(int argc, char **argv)
{
	capv_t in;
	union {
		capv_answerback_t answerback;
		capv_clocks_t clocks;
	} outbuf;
	capv_clocks_t *out = &outbuf.clocks;
	struct sigaction sa;
	void * __capability public;
	void * __capability cookie;
	void * __capability *capv = NULL;
	char *ld_preload;
	char *tmp = NULL;
	ssize_t received;
	clockid_t clock_id;
	pid_t pid;
	int capc, ch, error;

	while ((ch = getopt(argc, argv, "Ckv")) != -1) {
		switch (ch) {
		case 'C':
			Cflag = true;
			break;
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

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigchld_handler;
	sa.sa_flags = SA_NOCLDSTOP;
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

	capvfetch(&capc, &capv);
	error = capvset(&capc, &capv, CAPV_CLOCKS, public);
	if (error != 0)
		err(1, "capvset");

	/*
	 * This whole mess with environment variables is to preload
	 * libclocks.so, which provides clock_gettime(3) replacement,
	 * which then shadows the system call.  This makes unmodified
	 * purecap binaries transparently call clocks(1) instead
	 * of kernel.  A bit ugly, but convenient for now.
	 */
	ld_preload = getenv("LD_PRELOAD");
	if (ld_preload != NULL) {
		asprintf(&tmp, "%s:%s", ld_preload, "/usr/lib/libclocks.so");
	} else {
		asprintf(&tmp, "%s", "/usr/lib/libclocks.so");
	}
	error = setenv("LD_PRELOAD", tmp, 1);
	if (error != 0)
		err(1, "setenv");

	/*
	 * We can't explicitely pass capv into another address space,
	 * so we need vfork(2) here, not fork(2).
	 */
	pid = vfork();
	if (pid < 0)
		err(1, "vfork");

	if (pid == 0) {
		/*
		 * Child, will coexecvec(2) the new command.
		 */
		coexecvpc(getppid(), argv[0], argv, capv, capc);

		/*
		 * Shouldn't have returned.
		 */
		err(1, "coexecvpc");
	}

	/*
	 * Parent, will loop on coaccept(2) until SIGCHLD.
	 */

	if (!Cflag) {
		error = cap_enter();
		if (error != 0)
			err(1, "cap_enter");
	}

	memset(out, 0, sizeof(*out));
	//out->len = 0; /* Nothing to send at this point. */
	out->len = 16; /* XXX */

	for (;;) {
		if (kflag)
			received = coaccept_slow(&cookie, out, out->len, &in, sizeof(in));
		else
			received = coaccept(&cookie, out, out->len, &in, sizeof(in));
		if (received < 0) {
			warn("%s", kflag ? "coaccept_slow" : "coaccept");
			out->len = 0;
			continue;
		}

		/*
		 * Answered, unmarshall the input buffer.
		 */
		if (vflag) {
			error = cocachedpid(&pid, cookie);
			if (error != 0)
				warn("cogetpid");
			printf("%s: op %d, len %zd from pid %d -> pid %d%s\n",
			    getprogname(), in.op, in.len, pid, getpid(), kflag ? " (slow)" : "");
		}

		clock_id = error = errno = 0;
		switch (in.op) {
		case 0:
			answerback(&outbuf.answerback);
			break;
		default:
			/*
			 * Is this a proper packet?
			 */
			if ((size_t)received != in.len || in.len != sizeof(in)) {
				warnx("size mismatch: received %zd, in.len %zd, expected %zd",
				    (size_t)received, in.len, sizeof(in));
				memset(out, 0, sizeof(*out));
				out->len = sizeof(*out);
				out->op = 0;
				out->error = error;
				out->errno_ = ENOMSG;
				break;
			}

			/*
			 * Check time.
			 */
			memset(out, 0, sizeof(*out));
			clock_id = in.op - CAPV_CLOCKS; /* iksde */
			/*
			 * XXX: Insert code to talk to USB GPS dongle.
			 */
			error = clock_gettime(clock_id, &out->ts);
			out->len = sizeof(*out);
			out->op = -CAPV_CLOCKS;
			out->error = error;
			out->errno_ = errno;
			if (error != 0)
				warn("clock_gettime(%d)", clock_id);
			break;
		}

		/*
		 * Send the response back and loop.
		 */
		if (vflag) {
			printf("%s: returning to pid %d <- pid %d: op %d, len %zd, error %d, errno %d%s\n",
			    getprogname(), pid, getpid(), out->op, out->len, out->error, out->errno_, kflag ? " (slow)" : "");
		}
	}
}
