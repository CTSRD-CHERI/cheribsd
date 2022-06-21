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
 * This is the callee (coaccepting) part of the bind(2) service.
 * with the client (cocalling) part in lib/libbinds/binds.c.
 * The point is to demonstrate file descriptor passing using
 * capfromfd(2) and captofd(2).
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/auxv.h>
#include <sys/capsicum.h>
#include <sys/param.h>
#include <sys/types.h>
#include <netinet/in.h>
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
static int allowed_port = -1;

static void
usage(void)
{

	fprintf(stderr, "usage: binds [-Ckv] [-p port] command [args ...]\n");
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
	    "binds(1), allowed port %d, running as pid %d, uid %d%s%s",
	    allowed_port, getpid(), getuid(), kflag ? " (slow)" : "",
	    mode ? "" : " (capsicum disabled)");
}

static void
capvreturn(capv_binds_return_t *out, int op, int error, int errno_)
{
	memset(out, 0, sizeof(*out));
	out->len = sizeof(*out);
	out->op = op;
	out->error = error;
	out->errno_ = errno_;
}

static int
sockaddr_denied(const struct sockaddr_storage *ss, size_t sslen, pid_t pid)
{
	const struct sockaddr_in *sin;

	if (allowed_port < 0)
		return (0);

	if (ss->ss_family != AF_INET) {
		if (vflag) {
			printf("%s: pid %d: ss_family %d != AF_INET %d; allowing\n",
			    getprogname(), pid, ss->ss_family, AF_INET);
		}
		return (0);
	}

	if (sslen < sizeof(*sin)) {
		if (vflag) {
			printf("%s: pid %d: sslen %zd < %zd; returning EACCES\n",
			    getprogname(), pid, sslen, sizeof(*sin));
		}
		return (EACCES);
	}

	sin = (const struct sockaddr_in *)ss;
	if (ntohs(sin->sin_port) != allowed_port) {
		if (vflag) {
			printf("%s: pid %d: disallowed port %d; returning EACCES\n",
			    getprogname(), pid, ntohs(sin->sin_port));
		}
		return (EACCES);

	}

	if (vflag) {
		printf("%s: pid %d: allowing port %d\n",
		    getprogname(), pid, sin->sin_port);
	}

	return (0);
}

int
main(int argc, char **argv)
{
	capv_binds_t in;
	union {
		capv_answerback_t answerback;
		capv_binds_return_t binds;
	} outbuf;
	struct sigaction sa;
	capv_binds_return_t *out = &outbuf.binds;
	void * __capability public;
	void * __capability cookie;
	void * __capability *capv = NULL;
	char *ld_preload;
	char *tmp = NULL;
	ssize_t received;
	pid_t pid;
	int capc, ch, error, fd;

	while ((ch = getopt(argc, argv, "Ckp:v")) != -1) {
		switch (ch) {
		case 'C':
			Cflag = true;
			break;
		case 'k':
			kflag = true;
			break;
		case 'p':
			allowed_port = strtol(optarg, &tmp, 10);
			if (*tmp != '\0')
				errx(1, "argument to -p must be a number");
			if (allowed_port < 0)
				usage();
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
	error = capvset(&capc, &capv, CAPV_BINDS, public);
	if (error != 0)
		err(1, "capvset");

	/*
	 * This whole mess with environment variables is to preload
	 * libbinds.so, which provides bind(2) replacement,
	 * which then shadows the system call.  This makes unmodified
	 * purecap binaries transparently call binds(1) instead
	 * of kernel.  A bit ugly, but convenient for now.
	 */
	ld_preload = getenv("LD_PRELOAD");
	if (ld_preload != NULL) {
		asprintf(&tmp, "%s:%s", ld_preload, "/usr/lib/libbinds.so");
	} else {
		asprintf(&tmp, "%s", "/usr/lib/libbinds.so");
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

#if 0
	/*
	 * We need to bind(2), so Capsicum looks out of question.
	 */
	if (!Cflag) {
		error = cap_enter();
		if (error != 0)
			err(1, "cap_enter");
	}
#endif

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

		error = errno = 0;
		switch (in.op) {
		case 0:
			answerback(&outbuf.answerback);
			break;
		case CAPV_BINDS:
			/*
			 * Is this a proper packet?
			 */
			if ((size_t)received != in.len || in.len != sizeof(in)) {
				warnx("size mismatch: received %zd, in.len %zd, expected %zd",
				    (size_t)received, in.len, sizeof(in));
				capvreturn(out, -CAPV_BINDS, error, ENOMSG);
				break;
			}

			/*
			 * Do the thing.
			 */
			error = captofd(in.s, &fd);
			if (error != 0) {
				warnx("captofd(%#lp, &%d)", in.s, fd);
				capvreturn(out, -CAPV_BINDS, error, ENOMSG);
				break;
			}
			error = sockaddr_denied(&in.addr, in.addrlen, pid);
			if (error != 0) {
				capvreturn(out, -CAPV_BINDS, -1, error);
				break;
			}
			error = bind(fd, (const struct sockaddr *)&in.addr, in.addrlen);
			if (error != 0)
				warn("bind(%d, ..., %u)", fd, in.addrlen);

			capvreturn(out, -CAPV_BINDS, error, ENOMSG);

			error = close(fd);
			if (error != 0)
				warn("close(%d)", fd);
			break;
		default:
			warnx("unknown op %d", in.op);
			capvreturn(out, -CAPV_BINDS, -1, ENOMSG);
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
