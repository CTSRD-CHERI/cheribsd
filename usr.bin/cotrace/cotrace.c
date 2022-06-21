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
 * XXX: Make -i optional; would probably need pthreads.
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
static int chosen = -1;

static void
usage(void)
{

	fprintf(stderr, "usage: cotrace [-Ckv] -i entry command [args ...]\n");
	exit(0);
}

static void
sigchld_handler(int dummy __unused)
{

	exit(0);
}

static void
answerback(capv_answerback_t *out, void * __capability target)
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
	    "this is %s, pid %d, tracing service %d (%#lp), running as uid %d%s%s",
	    getprogname(), getpid(), chosen, target, getuid(),
	    kflag ? " (slow)" : "", mode ? "" : ", (capsicum disabled)");
}

int
main(int argc, char **argv)
{
	union {
		capv_t		cap;
		capv_answerback_t answerback;
		char		buf[MAXBSIZE]; // XXX
	} inbuf, outbuf;
	capv_t *in = &inbuf.cap;
	capv_t *out = &outbuf.cap;
	struct sigaction sa;
	void * __capability target = NULL;
	void * __capability public;
	void * __capability cookie;
	void * __capability *capv;
	char *tmp = NULL;
	ssize_t received;
	pid_t pid;
	int capc, ch, error;

	while ((ch = getopt(argc, argv, "Ci:kv")) != -1) {
		switch (ch) {
		case 'C':
			Cflag = true;
			break;
		case 'i':
			if (chosen >= 0)
				errx(-1, "-i specified more than once");
			chosen = strtol(optarg, &tmp, 10);
			if (*tmp != '\0')
				errx(1, "argument to -i must be a number");
			if (chosen < 0)
				usage();
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
	if (argc < 1 || chosen < 0)
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

	error = cosetup(COSETUP_COCALL);
	if (error != 0)
		err(1, "2nd cosetup");

	error = coregister(NULL, &public);
	if (error != 0)
		err(1, "coregister");

	capvfetch(&capc, &capv);
	if (chosen >= capc || capv[chosen] == NULL)
		errx(1, "capv[%d] is NULL", chosen);
	target = capv[chosen];

	error = capvset(&capc, &capv, chosen, public);
	if (error != 0)
		err(1, "capvset");
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
		/*
		 * Receive cocalls from the child process.
		 */
		if (kflag)
			received = coaccept_slow(&cookie, out, out->len, in, sizeof(inbuf));
		else
			received = coaccept(&cookie, out, out->len, in, sizeof(inbuf));
		if (received < 0) {
			warn("%s", kflag ? "coaccept_slow" : "coaccept");
			out->len = 0;
			continue;
		}

		/*
		 * Answered, print out a line and cocall into the service
		 * we are interposing.
		 */
		if (vflag) {
			error = cocachedpid(&pid, cookie);
			if (error != 0)
				warn("cogetpid");
			printf("%s: cocall op %d, len %zd from pid %d -> pid %d%s\n",
			    getprogname(), in->op, in->len, pid, getpid(), kflag ? " (slow)" : "");
		} else {
			printf("%s: -> op %d, len %zd%s\n",
			    getprogname(), in->op, in->len, kflag ? " (slow)" : "");
		}

		if (in->op == 0 && vflag) {
			answerback(&outbuf.answerback, capv[chosen]);
			printf("%s: returning answerback to pid %d <- pid %d%s\n",
			    getprogname(), pid, getpid(), kflag ? " (slow)" : "");
			continue;
		}

		/*
		 * Is this a proper packet?
		 */
		if ((size_t)received != in->len || in->len != sizeof(*in)) {
			warnx("size mismatch: received %zd, in.len %zd, expected %zd",
			    (size_t)received, in->len, sizeof(*in));
#ifdef inconvenient
			memset(out, 0, sizeof(outbuf);
			out->len = sizeof(outbuf);
			out->op = 0;
			out->error = error;
			out->_errno = ENOMSG;
			continue;
#endif
		}

		/*
		 * Forward the call.  Note the reversed directions.
		 */
		if (kflag)
			received = cocall_slow(target, in, received, out, sizeof(outbuf));
		else
			received = cocall(target, in, received, out, sizeof(outbuf));
		if (received < 0) {
			warn("%s", kflag ? "coaccept_slow" : "coaccept");
			out->len = 0;
			continue;
		}

		// XXX verify received vs out.len

		/*
		 * Send the response back and loop.
		 */
		if (vflag) {
			printf("%s: returning op %d, len %zd to pid %d <- pid %d%s\n",
			    getprogname(), out->op, out->len, pid, getpid(), kflag ? " (slow)" : "");
		} else {
			printf("%s: <- op %d, len %zd%s\n",
			    getprogname(), out->op, out->len, kflag ? " (slow)" : "");
		}
	}
}
