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
static const char *authorise_cmd = NULL;

static void
usage(void)
{

	fprintf(stderr, "usage: clearances [-1OXCkv] -i entry command [args ...]\n");
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
	    "%s%sclearances(1), pid %d, wrapping %#lp%s%s",
	    tmp, tmp[0] != '\0' ? " -- via " : "", getpid(), target,
	    kflag ? " (slow)" : "", mode ? "" : " (capsicum disabled)");
}

static int
authorise_one_process(void * __capability cookie)
{
	static pid_t one = -1;
	pid_t pid;
	int error;

	error = cocachedpid(&pid, cookie);
	if (error != 0) {
		warn("cocachedpid");
		return (ECANCELED);
	}

	if (one == pid)
		return (0);

	if (one == -1) {
		one = pid;
		return (0);
	}

	return (ECANCELED);
}

static int
authorise_exec(void * __capability cookie)
{
	pid_t pid;
	char buf[32];
	FILE *p;
	int error, ret;

	error = cocachedpid(&pid, cookie);
	if (error != 0) {
		warn("cocachedpid");
		return (ECANCELED);
	}

	ret = snprintf(buf, sizeof(buf), "%s %d", authorise_cmd, pid);
	if (ret < 0)
		err(1, "snprintf");
	p = popen(buf, "r");
	fprintf(stderr, "%s: popen '%s' ret %p\n", __func__, authorise_cmd, p);
	if (p == NULL) {
		warn("popen: %s", authorise_cmd);
		return (ECANCELED);
	}
	// XXX: For some reason crashes here.
	ret = pclose(p);
	fprintf(stderr, "%s: pclose '%s' ret %d\n", __func__, authorise_cmd, ret);
	if (ret != 0) {
		if (vflag)
			printf("%s: \"%s\" returned %d\n", __func__, authorise_cmd, ret);
		return (ECANCELED);
	}

	return (0);
}

static int
authorise_odd_minutes(void * __capability cookie __unused)
{
	int error;
	struct timespec tv;
	time_t minutes;

	error = clock_gettime(CLOCK_REALTIME_FAST, &tv);
	if (error != 0) {
		warn("clock_gettime");
		return (error);
	}

	/*
	 * XXX: This assumes reasonable timezones.
	 */
	minutes = tv.tv_sec / 60;
	if ((minutes % 2) != 0)
		return (ECANCELED);

	return (0);
}

int
main(int argc, char **argv)
{
	union {
		capv_t		cap;
		capv_answerback_t answerback;
		capv_clearances_return_t capreturn;
		char		buf[MAXBSIZE]; // XXX
	} inbuf, outbuf;
	capv_t *in = &inbuf.cap;
	capv_clearances_return_t *out = &outbuf.capreturn;
	struct sigaction sa;
	void * __capability target = NULL;
	void * __capability public;
	void * __capability cookie;
	void * __capability *capv;
	char *tmp = NULL;
	ssize_t received;
	pid_t pid;
	int chosen = -1;
	int capc, ch, error;
	int (*authorise)(void * __capability cookie) = NULL;

	while ((ch = getopt(argc, argv, "1E:GOXCi:kv")) != -1) {
		switch (ch) {
		case '1':
			if (authorise != NULL)
				errx(-1, "-1 conflicts with another policy");
			authorise = authorise_one_process;
			break;
		case 'E':
			if (authorise != NULL)
				errx(-1, "-E conflicts with another policy");
			authorise_cmd = strdup(optarg);
			if (authorise_cmd == NULL)
				err(1, "strdup");
			authorise = authorise_exec;
			break;
#if 0
		case 'G':
			/*
			 * Use libprocstat(3) I guess; we can assume the PID
			 * indicated by getcachedpid(3) won't be reused, because
			 * that very process it's blocked on the cocall.
			 */
			if (authorise != NULL)
				errx(-1, "-G conflicts with another policy");
			authorise = authorise_G;
			break;
#endif
		case 'O':
			if (authorise != NULL)
				errx(-1, "-O conflicts with another policy");
			authorise = authorise_odd_minutes;
			break;
#if 0
		case 'X':
			if (authorise != NULL)
				errx(-1, "-X conflicts with another policy");
			authorise = authorise_O;
			break;
#endif
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
	if (argc < 1 || chosen < 0 || authorise == NULL)
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

		if ((size_t)received != in->len) {
			warnx("size mismatch: received %zd, in.len %zd, buflen %zd",
			    (size_t)received, in->len, sizeof(*in));
#ifdef inconvenient
			memset(out, 0, sizeof(*out));
			out->len = received = sizeof(*out);
			out->op = 0;
			out->error = error;
			out->errno_ = ENOMSG;
			goto respond;
#endif
		}

		/*
		 * XXX: Authorise.  XXX: do we need to access 'in' at all?
		 */
		error = authorise(cookie);
		if (error == 0) {
			/*
			 * Forward the call.  Note the reversed directions.
			 */
			if (kflag)
				received = cocall_slow(target, in, received, out, sizeof(outbuf));
			else
				received = cocall(target, in, received, out, sizeof(outbuf));
			if (received < 0) {
				warn("%s", kflag ? "cocall_slow" : "cocall");
				out->len = received = 0;
				// XXX we should send back error response
			}

			/*
			 * If this was an answerback request, modify the answer to add our own info.
			 */
			if (in->len >= sizeof(*in) && in->op == 0) {
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
			continue;
		}

		if (vflag) {
			error = cocachedpid(&pid, cookie);
			if (error != 0)
				warn("cogetpid");
			printf("%s: pid %d failed authorization; canceled\n",
			    getprogname(), pid);
		}

		memset(out, 0, sizeof(*out));

		if (in->len >= sizeof(*in) && in->op == 0) {
			answerback(&outbuf.answerback, target);
			received = out->len;
			if (vflag) {
				printf("%s: returning answerback to pid %d <- pid %d%s\n",
				    getprogname(), pid, getpid(), kflag ? " (slow)" : "");
			}
		} else {
			out->len = received = sizeof(*out);
			out->op = -in->op;
			out->error = -1;
			out->errno_ = ECANCELED;
		}

		/*
		 * Loop after the failed attempt.
		 */
	}
}
