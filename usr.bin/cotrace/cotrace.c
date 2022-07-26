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
#include <unistd.h>
#include <vis.h>

static bool Cflag = false, kflag = false, vflag = false;

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
	char *tmp;

	mode = 0;
	error = cap_getmode(&mode);
	if (error != 0)
		err(1, "cap_getmode");

	/*
	 * There's already a response in 'out'; we need to modify it a bit.
	 */
	tmp = strndup(out->answerback, sizeof(out->answerback) - 1);

	memset(out, 0, sizeof(*out));
	out->len = sizeof(*out);
	out->op = 0;
	snprintf(out->answerback, sizeof(out->answerback),
	    "%s -- via cotrace(1), pid %d, tracing %#lp%s%s",
	    tmp, getpid(), target, kflag ? " (slow)" : "",
	    mode ? "" : " (capsicum disabled)");
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
	char dumpbuf[MAXBSIZE * 4 + 1];
	ssize_t received;
	pid_t pid;
	int chosen = -1;
	int capc, ch, error, len;

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
	sa.sa_flags = SA_NOCLDSTOP;
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
		err(1, "%s", argv[0]);
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
	received = 0; /* Nothing to send back at this point. */

	for (;;) {
		/*
		 * Receive cocalls from the child process.
		 */
		if (kflag)
			received = coaccept_slow(&cookie, out, received, in, sizeof(inbuf));
		else
			received = coaccept(&cookie, out, received, in, sizeof(inbuf));
		if (received < 0) {
			warn("%s", kflag ? "coaccept_slow" : "coaccept");
			/*
			 * Don't really have a cocall to respond to; just go around.
			 */
			out->len = received = 0;
			continue;
		}

		/*
		 * Answered; log it and cocall into the service we are interposing.
		 */
		len = strvisx(dumpbuf, (const char *)in, received,
		    VIS_DQ | VIS_NL | VIS_CSTYLE | VIS_OCTAL);
		if (len < 0)
			err(1, "strvisx");

		if (vflag) {
			error = cocachedpid(&pid, cookie);
			if (error != 0)
				warn("cogetpid");
			printf("%s: cocall len %zd, op %d, received %zd, from pid %d -> pid %d%s: \"%s\"\n",
			    getprogname(), in->len, in->op, received, pid, getpid(), kflag ? " (slow)" : "",
			    dumpbuf);
		} else {
			dumpbuf[56] = '.';
			dumpbuf[57] = '.';
			dumpbuf[58] = '.';
			dumpbuf[59] = '\0';

			printf("len %4zd, op %2d%s -> \"%s\"\n",
			    in->len, in->op, kflag ? " (slow)" : "", dumpbuf);
		}

		if ((size_t)received != in->len) {
			warnx("size mismatch: received %zd, in.len %zd, buflen %zd",
			    (size_t)received, in->len, sizeof(*in));
#ifdef inconvenient
			memset(out, 0, sizeof(outbuf);
			out->len = received = sizeof(outbuf);
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
			out->len = received = 0;
			// XXX we should send back error response
		}

		/*
		 * Got response from the service; log it.
		 */
		len = strvisx(dumpbuf, (const char *)out, received, VIS_DQ | VIS_NL | VIS_CSTYLE | VIS_OCTAL);
		if (len < 0)
			err(1, "strvisx");

		if (vflag) {
			printf("%s: returning len %zd, op %d to pid %d <- pid %d%s: \"%s\"\n",
			    getprogname(), out->len, out->op, pid, getpid(), kflag ? " (slow)" : "",
			    dumpbuf);
		} else {
			dumpbuf[56] = '.';
			dumpbuf[57] = '.';
			dumpbuf[58] = '.';
			dumpbuf[59] = '\0';

			printf("len %4zd, op %2d%s <- \"%s\"\n",
			    out->len, out->op, kflag ? " (slow)" : "", dumpbuf);
		}

		/*
		 * If this was an answerback request, modify the answer to add our own info.
		 */
		if ((size_t)received >= sizeof(*in) && in->op == 0) {
			answerback(&outbuf.answerback, target);
			received = out->len;
			if (vflag) {
				printf("%s: returning answerback to pid %d <- pid %d%s\n",
				    getprogname(), pid, getpid(), kflag ? " (slow)" : "");
			}
		}

		/*
		 * Now loop; coaccept(2) will send the response back and then wait for the next one.
		 */
	}
}
