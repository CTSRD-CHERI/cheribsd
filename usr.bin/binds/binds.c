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
#include <sys/syscall.h>
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
	    "binds(1), pid %d, allowed port %d%s%s",
	    getpid(), allowed_port, kflag ? " (slow)" : "",
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
check_if_denied(const struct sockaddr_storage *ss, size_t sslen, pid_t pid)
{
	const struct sockaddr_in *sin;

	/*
	 * XXX: Add filtering by something else than just a port.
	 */

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
	sa.sa_flags = SA_NOCLDSTOP;
	sigfillset(&sa.sa_mask);

	/*
	 * We are spawning child processes, so we'll need to handle SIGCHLD.
	 */
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
	 * We can't explicitly pass capv into another address space,
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
		err(1, "%s", argv[0]);
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

	for (;;) {
		/*
		 * Send back a response, if any, and wait for the next call.
		 */
		if (kflag)
			received = coaccept_slow(&cookie, out, out->len, &in, sizeof(in));
		else
			received = coaccept(&cookie, out, out->len, &in, sizeof(in));
		if (received < 0) {
			warn("%s", kflag ? "coaccept_slow" : "coaccept");
			memset(out, 0, sizeof(*out));
			continue;
		}

		/*
		 * Answered.
		 */
		if (vflag) {
			error = cocachedpid(&pid, cookie);
			if (error != 0)
				warn("cogetpid");
			printf("%s: op %d, len %zd from pid %d -> pid %d%s\n",
			    getprogname(), in.op, in.len, pid, getpid(), kflag ? " (slow)" : "");
		}

		/*
		 * Many syscalls are similar to one another; handle the similarities
		 * here.
		 */
		error = errno = 0;

		switch (in.op) {
		case 0:
			/*
			 * Is this a proper packet?  Op 0 is answerback request, so the size
			 * obviously won't match; just make sure that we've received the op field.
			 */
			if ((size_t)received < sizeof(capv_t)) {
				warnx("size mismatch: received %zd, expected %zd",
				    (size_t)received, sizeof(capv_t));
				capvreturn(out, 0, -1, ENOMSG);
				goto respond;
			}

			answerback(&outbuf.answerback);
			goto respond;
		case SYS_bind:
		case SYS_connect:
			/*
			 * Is this a proper packet?
			 */
			if ((size_t)received != sizeof(in)) {
				warnx("size mismatch: received %zd, expected %zd",
				    (size_t)received, sizeof(in));
				capvreturn(out, 0, -1, ENOMSG);
				goto respond;
			}

			/*
			 * Receive the socket descriptor.
			 */
			error = captofd(in.s, &fd);
			if (error != 0) {
				warn("captofd: %#lp", in.s);
				capvreturn(out, -in.op, error, ENOMSG);
				goto respond;
			}
			error = check_if_denied(&in.addr, in.addrlen, pid);
			if (error != 0) {
				capvreturn(out, -in.op, -1, error);
				goto respond;
			}
			break;
		default:
			warnx("unknown op %d", in.op);
			capvreturn(out, -in.op, -1, ENOMSG);
			goto respond;
		}

		/*
		 * Do the thing.
		 */
		switch (in.op) {
		case SYS_bind:
			error = bind(fd, (const struct sockaddr *)&in.addr, in.addrlen);
			if (error != 0)
				warn("bind(%d, ..., %u)", fd, in.addrlen);
			break;
		case SYS_connect:
			error = connect(fd, (const struct sockaddr *)&in.addr, in.addrlen);
			if (error != 0)
				warn("connect(%d, ..., %u)", fd, in.addrlen);
			break;
		}

		/*
		 * Cleanup, again supposed to be shared between multiple syscalls.
		 */
		switch (in.op) {
		case SYS_bind:
		case SYS_connect:
			capvreturn(out, -in.op, error, errno);

			error = close(fd);
			if (error != 0)
				warn("close(%d)", fd);
			break;
		}

respond:
		/*
		 * Send the response back and loop.
		 */
		if (vflag) {
			printf("%s: returning to pid %d <- pid %d: op %d, len %zd, error %d, errno %d%s\n",
			    getprogname(), pid, getpid(), out->op, out->len, out->error, out->errno_, kflag ? " (slow)" : "");
		}
	}
}
