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
 * This is the callee (coaccepting) part of the syscall remoting service.
 * with the client (cocalling) counterpart in lib/libcs/cs.c.
 *
 * At this point it just directly executes the syscalls it receives.
 * Implementing an actual policy (or telling the client processes apart)
 * is left as an exercise for the reader.
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
#include <sysdecode.h>
#include <unistd.h>

static bool kflag = false, vflag = false;

static void
usage(void)
{

	fprintf(stderr, "usage: cs [-kv] command [args ...]\n");
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

	memset(out, 0, sizeof(*out));
	out->len = sizeof(*out);
	out->op = 0;
	snprintf(out->answerback, sizeof(out->answerback),
	    "cs(1), pid %d%s",
	    getpid(), kflag ? " (slow)" : "");
}

static void
capvreturn(capv_syscall_return_t *out, int op, int error, int errno_, uintcap_t fdcap)
{
	memset(out, 0, sizeof(*out));
	out->len = sizeof(*out);
	out->op = op;
	out->error = error;
	out->errno_ = errno_;
	out->fdcap = fdcap;
}

int
main(int argc, char **argv)
{
	capv_syscall_t in;
	union {
		capv_answerback_t answerback;
		capv_syscall_return_t syscall;
	} outbuf;
	struct sigaction sa;
	capv_syscall_return_t *out = &outbuf.syscall;
	void * __capability public;
	void * __capability cookie;
	void * __capability *capv = NULL;
	char *ld_preload;
	char *tmp = NULL;
	uintcap_t fdcap;
	ssize_t received;
	pid_t pid;
	int capc, ch, error, _error;

	while ((ch = getopt(argc, argv, "kv")) != -1) {
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
	error = capvset(&capc, &capv, CAPV_SYSCALL, public);
	if (error != 0)
		err(1, "capvset");

	/*
	 * This whole mess with environment variables is to preload
	 * libcs.so, which provides replacement stubs to shadow
	 * the system calls.  This makes unmodified purecap binaries
	 * transparently call cs(1) instead of kernel.  A bit ugly,
	 * but convenient for now.
	 */
	ld_preload = getenv("LD_PRELOAD");
	if (ld_preload != NULL) {
		asprintf(&tmp, "%s:%s", ld_preload, "/usr/lib/libcs.so");
	} else {
		asprintf(&tmp, "%s", "/usr/lib/libcs.so");
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
			printf("%s: op %d<%s>, len %zd from pid %d -> pid %d%s\n",
			    getprogname(), in.op, sysdecode_syscallname(SYSDECODE_ABI_FREEBSD, in.op),
			    in.len, pid, getpid(), kflag ? " (slow)" : "");
		}

		/*
		 * Many syscalls are similar to one another; handle the similarities
		 * here.
		 */
		error = errno = fdcap = 0;

		switch (in.op) {
		case 0:
			/*
			 * Is this a proper packet?  Op 0 is answerback request, so the size
			 * obviously won't match; just make sure that we've received the op field.
			 */
			if ((size_t)received < sizeof(capv_t)) {
				warnx("size mismatch: received %zd, expected %zd",
				    (size_t)received, sizeof(capv_t));
				capvreturn(out, 0, -1, ENOMSG, 0);
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
				capvreturn(out, 0, -1, ENOMSG, 0);
				goto respond;
			}

			/*
			 * Receive the socket descriptor.
			 */
			error = captofd((void *)in.arg[0], (int *)&in.arg[0]);
			if (error != 0) {
				warn("captofd: %#lp", (void *)in.arg[0]);
				capvreturn(out, -in.op, error, ENOMSG, 0);
				goto respond;
			}
			break;
		case SYS_fstatat:
		case SYS_fchmodat:
		case SYS_fchownat:
		case SYS_utimensat:
		case SYS_openat:
		case SYS_fchdir:
			if (in.arg[0] != (uintcap_t)AT_FDCWD) {
				error = captofd((void *)in.arg[0], (int *)&in.arg[0]);
				if (error != 0) {
					warn("captofd: %#lp", (void *)in.arg[0]);
					capvreturn(out, -in.op, error, ENOMSG, 0);
					goto respond;
				}
			}
			break;
		case SYS_mkdir:
		case SYS_rmdir:
		case SYS_pathconf:
		case SYS_lpathconf:
		case SYS___getcwd:
			// nothing special to do here.
			break;
		default:
			warnx("unknown op %d<%s>", in.op, sysdecode_syscallname(SYSDECODE_ABI_FREEBSD, in.op));
			capvreturn(out, -in.op, -1, ENOMSG, 0);
			goto respond;
		}

		/*
		 * Do the thing.
		 */
		error = syscall(in.op, in.arg[0], in.arg[1], in.arg[2], in.arg[3], in.arg[4], in.arg[5], in.arg[6]);
		if (vflag && error != 0 && errno != 0) /* Check errno to not display this warning on every openat(2) */
			warn("syscall(%d<%s>, ...)", in.op, sysdecode_syscallname(SYSDECODE_ABI_FREEBSD, in.op));

		/*
		 * Any file descriptors to return?
		 */
		switch (in.op) {
		case SYS_openat:
			/*
			 * NB: It's actually a file descriptor number, not an error.
			 */
			if (error > 0) {
				_error = capfromfd((void *)&fdcap, error);
				if (_error != 0) {
					warn("capfromfd");
					capvreturn(out, -in.op, error, ENOMSG, 0);
					goto respond;
				}
			}
			break;
		}

		/*
		 * Cleanup, again supposed to be shared between multiple syscalls.
		 */
		switch (in.op) {
		case SYS_bind:
		case SYS_connect:
			_error = close((int)in.arg[0]);
			if (_error != 0)
				warn("close(%d)", (int)in.arg[0]);
			break;
		case SYS_fstatat:
		case SYS_fchmodat:
		case SYS_fchownat:
		case SYS_utimensat:
		case SYS_openat:
		case SYS_fchdir:
			if (in.arg[0] != (uintcap_t)AT_FDCWD) {
				_error = close((int)in.arg[0]);
				if (_error != 0)
					warn("close(%d)", (int)in.arg[0]);
			}
			break;
		}

		/*
		 * XXX: So when do we close the descriptor returned by openat?
		 */

		capvreturn(out, -in.op, error, errno, fdcap);

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
