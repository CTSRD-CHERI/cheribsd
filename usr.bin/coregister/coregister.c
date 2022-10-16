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
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
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

static void
usage(void)
{

	fprintf(stderr, "usage: coregister [-Ckv] -i entry -f path\n"
			"       coregister [-Ckv] -i entry -n new-name\n");
	exit(0);
}

static void
sigchld_handler(int dummy __unused)
{

	exit(0);
}

static void
answerback(capv_answerback_t *out, void * __capability target, const char *registered)
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
	    "%s -- via coregister(1), pid %d, sharing %#lp as %s%s%s",
	    tmp, getpid(), target, registered, kflag ? " (slow)" : "",
	    mode ? "" : " (capsicum disabled)");
}

/*
 * Loop on coaccept(2) until SIGCHLD.
 *
 * The whole reason for doing this is that we can't coregister(2)
 * a capability that's not our own.  Which is silly and should be
 * fixed by removing colookup(2).
 */
static void
coaccept_loop(char *registered, void * __capability target)
{
	union {
		capv_t		cap;
		capv_answerback_t answerback;
		char		buf[MAXBSIZE]; // XXX
	} inbuf, outbuf;
	capv_t *in = &inbuf.cap;
	capv_t *out = &outbuf.cap;
	void * __capability public;
	void * __capability cookie;
	ssize_t received;
	pid_t pid;
	int error;

	error = cosetup(COSETUP_COACCEPT);
	if (error != 0)
		err(1, "cosetup");

	error = cosetup(COSETUP_COCALL);
	if (error != 0)
		err(1, "2nd cosetup");

	error = coregister(registered, &public);
	if (error != 0)
		err(1, "failed to coregister \"%s\"", registered);

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
		 * Answered, print out a line and cocall into the service
		 * we are interposing.
		 */
		if (vflag) {
			error = cocachedpid(&pid, cookie);
			if (error != 0)
				warn("cogetpid");
			printf("%s: cocall op %d, len %zd, received %zd, from pid %d -> pid %d%s\n",
			    getprogname(), in->op, in->len, received, pid, getpid(), kflag ? " (slow)" : "");
		}

		/*
		 * Is this a proper packet?
		 */
		if ((size_t)received != in->len || in->len != sizeof(*in)) {
			warnx("size mismatch: received %zd, in.len %zd, expected %zd",
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
			warn("%s", kflag ? "cocall_slow" : "cocall");
			out->len = received = 0;
			// XXX we should send back error response
		}

		/*
		 * If this was an answerback request, modify the answer to add our own info.
		 */
		if ((size_t)received >= sizeof(*in) && in->op == 0) {
			answerback(&outbuf.answerback, target, registered);
			received = out->len;
			if (vflag) {
				printf("%s: returning answerback to pid %d <- pid %d%s\n",
				    getprogname(), pid, getpid(), kflag ? " (slow)" : "");
			}
			continue;
		}

		/*
		 * Loop; coaccept(2) will send the response back and then wait for the next one.
		 */
		if (vflag) {
			printf("%s: returning op %d, len %zd to pid %d <- pid %d%s\n",
			    getprogname(), out->op, out->len, pid, getpid(), kflag ? " (slow)" : "");
		}
	}
}

/*
 * Loop on a unix domain socket of choice, accepting connections from colookup(1)
 * and sending back the target capability.
 */
static void
socket_loop(char *filename, void * __capability target)
{
	struct msghdr msg;
	union {
		struct cmsghdr	hdr;
		unsigned char	buf[CMSG_SPACE(sizeof(target))];
	} cmsgbuf;
	struct cmsghdr *cmsg;
	struct sockaddr_un sun;
	ssize_t sent;
	int clientfd, fd, error;

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		err(1, "socket");

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, filename, sizeof(sun.sun_path));
	sun.sun_len = SUN_LEN(&sun);

	error = bind(fd, (struct sockaddr *)&sun, sizeof(sun));
	if (error != 0) {
		if (errno == EADDRINUSE)
			warnx("cannot bind to existing socket; remove %s and try again", filename);
		err(1, "%s", filename);
	}
	error = listen(fd, SOMAXCONN);
	if (error != 0)
		err(1, "listen");

	for (;;) {
		clientfd = accept(fd, NULL, NULL);
		if (clientfd < 0)
			err(1, "accept");

		if (vflag)
			printf("%s: accepted; will send back %#lp\n", getprogname(), target);

		memset(&msg, 0, sizeof(msg));
		msg.msg_control = &cmsgbuf.buf;
		msg.msg_controllen = sizeof(cmsgbuf.buf);
		msg.msg_iov = NULL;
		msg.msg_iovlen = 0;

		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_len = CMSG_LEN(sizeof(target));
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_CAPS;
#if 0 // XXX increases alignment
		*(void * __capability *)CMSG_DATA(cmsg) = target;
#else
		memcpy(CMSG_DATA(cmsg), &target, sizeof(target));
#endif

		sent = sendmsg(clientfd, &msg, MSG_NOSIGNAL);
		if (sent < 0)
			warn("sendmsg");
		error = close(clientfd);
		if (error != 0)
			err(1, "close");
		if (vflag)
			printf("%s: sent; waiting for another client\n", getprogname());
	}
}

int
main(int argc, char **argv)
{
	struct sigaction sa;
	void * __capability *capv;
	void * __capability target = NULL;
	char *tmp = NULL, *registered = NULL, *filename = NULL;
	int capc, ch, chosen = -1, error;

	while ((ch = getopt(argc, argv, "Cf:i:kn:v")) != -1) {
		switch (ch) {
		case 'C':
			Cflag = true;
			break;
		case 'f':
			if (filename != NULL)
				errx(-1, "-f specified more than once");
			if (registered != NULL)
				errx(-1, "-f and -n are mutually exclusive");
			filename = optarg;
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
		case 'n':
			if (registered != NULL)
				errx(-1, "-n specified more than once");
			if (filename != NULL)
				errx(-1, "-n and -f are mutually exclusive");
			registered = optarg;
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
	if (argc != 0 || chosen < 0 || (registered == NULL && filename == NULL))
		usage();

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigchld_handler;
	sa.sa_flags = SA_NOCLDSTOP;
	sigfillset(&sa.sa_mask);

	error = sigaction(SIGCHLD, &sa, NULL);
	if (error != 0)
		err(1, "sigaction");

	capvfetch(&capc, &capv);
	if (chosen >= capc || capv[chosen] == NULL)
		errx(1, "capv[%d] is NULL", chosen);
	target = capv[chosen];

	if (registered != NULL)
		coaccept_loop(registered, target);
	else
		socket_loop(filename, target);
	/* NOTREACHED */
}
