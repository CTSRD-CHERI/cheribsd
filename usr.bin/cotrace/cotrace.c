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
#include <sys/capsicum.h>
#include <sys/param.h>
#include <sys/types.h>
#include <assert.h>
#include <capv.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <pthread_np.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vis.h>

struct interposer {
	int			i_index;
	void * __capability	i_target;
	void * __capability	i_public;
	pthread_t		i_pthread;
};

static bool Cflag = false, kflag = false, vflag = false;
static pthread_mutex_t mtx;
static pthread_cond_t donecv;
static int pending;

static void
usage(void)
{

	fprintf(stderr, "usage: cotrace [-Ckv] command [args ...]\n");
	exit(0);
}

static void
sigchld_handler(int dummy __unused)
{

	exit(0);
}

static void
answerback(capv_answerback_t *out, const void * __capability target)
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
	    "%s -- via cotrace(1), pid %d, threadid %d, tracing %#lp%s%s",
	    tmp, getpid(), pthread_getthreadid_np(), target, kflag ? " (slow)" : "",
	    mode ? "" : " (capsicum disabled)");
}

static void *
interpose(void *tmp)
{
	union {
		capv_t		cap;
		capv_answerback_t answerback;
		char		buf[MAXBSIZE]; // XXX
	} inbuf, outbuf;
	capv_t *in = &inbuf.cap;
	capv_t *out = &outbuf.cap;
	void * __capability cookie;
	char dumpbuf[MAXBSIZE * 4 + 1];
	ssize_t received;
	pid_t pid;
	int error, len;
	struct interposer *interposer;

	interposer = (struct interposer *)tmp;
	error = cosetup(COSETUP_COACCEPT);
	if (error != 0)
		err(1, "cosetup");

	error = cosetup(COSETUP_COCALL);
	if (error != 0)
		err(1, "2nd cosetup");

	error = coregister(NULL, &interposer->i_public);
	if (error != 0)
		err(1, "coregister");

	memset(out, 0, sizeof(*out));
	received = 0; /* Nothing to send back at this point. */

	pthread_mutex_lock(&mtx);
	pending--;
	if (pending == 0)
		pthread_cond_signal(&donecv);
	pthread_mutex_unlock(&mtx);

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
			pthread_mutex_lock(&mtx);
			error = cocachedpid(&pid, cookie);
			pthread_mutex_unlock(&mtx);
			if (error != 0)
				warn("cocachedpid");
			printf("%s: cocall from pid %d[%d] -> pid %d, received %zd, len %zd, op %d%s: \"%s\"\n",
			    getprogname(), pid, interposer->i_index, getpid(), received, in->len, in->op,
			    kflag ? " (slow)" : "", dumpbuf);
		} else {
			dumpbuf[66] = '.';
			dumpbuf[67] = '.';
			dumpbuf[68] = '.';
			dumpbuf[69] = '\0';

			printf("-> %d: \"%s\"%s\n", interposer->i_index, dumpbuf, kflag ? " (slow)" : "");
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
			received = cocall_slow(interposer->i_target, in, received, out, sizeof(outbuf));
		else
			received = cocall(interposer->i_target, in, received, out, sizeof(outbuf));
		if (received < 0) {
			warn("%s", kflag ? "cocall_slow" : "cocall");
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
			printf("%s: returning to pid %d[%d] <- pid %d, len %zd, op %d: \"%s\"%s\n",
			    getprogname(), pid, interposer->i_index, getpid(), out->len, out->op,
			    dumpbuf, kflag ? " (slow)" : "");
		} else {
			dumpbuf[66] = '.';
			dumpbuf[67] = '.';
			dumpbuf[68] = '.';
			dumpbuf[69] = '\0';

			printf("<- %d: \"%s\"%s\n", interposer->i_index, dumpbuf, kflag ? " (slow)" : "");
		}

		/*
		 * If this was an answerback request, modify the answer to add our own info.
		 */
		if ((size_t)received >= sizeof(*in) && in->op == 0) {
			answerback(&outbuf.answerback, interposer->i_target);
			received = out->len;
			if (vflag) {
				printf("%s: returning answerback to pid[%d] %d <- pid %d%s\n",
				    getprogname(), pid, interposer->i_index, getpid(), kflag ? " (slow)" : "");
			}
		}

		/*
		 * Now loop; coaccept(2) will send the response back and then wait for the next one.
		 */
	}
}

int
main(int argc, char **argv)
{
	struct sigaction sa;
	void * __capability *capv;
	struct interposer *interposers;
	pid_t pid;
	int capc, ch, error, i;

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

	capvfetch(&capc, &capv);

	interposers = calloc(capc, sizeof(*interposers));
	if (interposers == NULL)
		err(1, "calloc");

	error = pthread_mutex_init(&mtx, NULL);
	if (error != 0)
		err(1, "pthread_mutex_init");
	error = pthread_cond_init(&donecv, NULL);
	if (error != 0)
		err(1, "pthread_cond_init");

	/*
	 * Start the threads, one for each service found in capv.
	 *
	 * XXX: I wonder if we should be using processes here instead.  Threads
	 *      within a single process are bit of a security risk, and I'm not
	 *      sure they are really more efficient here.
	 */
	for (i = 0; i < capc; i++) {
		if (capv[i] == NULL)
			continue;
		pthread_mutex_lock(&mtx);
		pending++;
		pthread_mutex_unlock(&mtx);

		interposers[i].i_index = i;
		interposers[i].i_target = capv[i];
		error = pthread_create(&interposers[i].i_pthread, NULL, interpose, (void *)&interposers[i]);
		if (error != 0)
			err(1, "pthread_create");
	}

	/*
	 * Wait until the threads are ready.
	 *
	 * XXX: There's still a slight race there, in that we're still signalling
	 *      we're ready before calling coaccept(2).
	 */
	pthread_mutex_lock(&mtx);
	while (pending > 0)
		pthread_cond_wait(&donecv, &mtx);
	pthread_mutex_unlock(&mtx);

	for (i = 0; i < capc; i++) {
		if (capv[i] == NULL)
			continue;
		capv[i] = interposers[i].i_public;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigchld_handler;
	sa.sa_flags = SA_NOCLDSTOP;
	sigfillset(&sa.sa_mask);
	error = sigaction(SIGCHLD, &sa, NULL);
	if (error != 0)
		err(1, "sigaction");

	/*
	 * We can't explicitely pass capv into another address space,
	 * so we need vfork(2) here, not fork(2).
	 *
	 * XXX: vforking a threaded process #yolo
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
	 * XXX: There's another race here: another thread could have already started
	 *      making cocalls before we call cap_enter(2).
	 */
	if (!Cflag) {
		error = cap_enter();
		if (error != 0)
			err(1, "cap_enter");
	}

	/*
	 * Parent.  Nothing to do until SIGCHLD.  Can't use wait(2), because Capsicum,
	 * and we don't have pdvfork(2), so lets wait for ourselves instead.
	 */
	for (i = 0; i < capc; i++) {
		if (capv[i] == NULL)
			continue;
		error = pthread_join(interposers[i].i_pthread, NULL);
		if (error != 0)
			err(1, "pthread_join");
	}

	/*
	 * XXX: We're not passing pass child's exit code here.
	 */
	return (0);
}
