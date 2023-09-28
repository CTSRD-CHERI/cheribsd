/*-
 * Copyright (c) 2023 Edward Tomasz Napierala <trasz@FreeBSD.org>
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
 * This is the callee (coaccepting) part of the path translation service.
 * with the client (cocalling) counterpart in lib/libpaths/paths.c.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/auxv.h>
#include <sys/capsicum.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/sbuf.h>
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

struct pathname {
	LIST_ENTRY(pathname)	p_link;
	int			p_fd;
	char			*p_path;
};

LIST_HEAD(, pathname) pathnames = LIST_HEAD_INITIALIZER(pathnames);
static bool kflag = false, qflag = false, vflag = false;

static void
usage(void)
{

	fprintf(stderr, "usage: paths [-kqv] [-r path] [-w path] command [args ...]\n");
	exit(0);
}

static void
sigchld_handler(int dummy __unused)
{

	exit(0);
}

static void
answerback(capv_paths_return_t *pathsp)
{
	struct sbuf sb;
	const struct pathname *r;
	capv_answerback_t *out = (capv_answerback_t *)pathsp;
	int error, mode;

	mode = 0;
	error = cap_getmode(&mode);
	if (error != 0)
		err(1, "cap_getmode");

	memset(out, 0, sizeof(*out));
	out->len = sizeof(*out);
	out->op = 0;
	sbuf_new(&sb, out->answerback, sizeof(out->answerback), SBUF_FIXEDLEN);

	sbuf_printf(&sb, "paths");
	LIST_FOREACH(r, &pathnames, p_link)
		sbuf_printf(&sb, " -r %s", r->p_path);
	sbuf_printf(&sb, ", pid %d", getpid());
	if (kflag)
		sbuf_printf(&sb, " (slow)");
	if (mode == 0)
		sbuf_printf(&sb, " (capsicum disabled)");

	error = sbuf_finish(&sb);
	if (error != 0)
		err(1, "sbuf_finish");
}

static void
prepare(capv_paths_return_t *outp, const char *path, uintcap_t fdcap)
{

	memset(outp, 0, sizeof(*outp));
	outp->len = sizeof(*outp);
	outp->op = -CAPV_PATHS;
	strlcpy(outp->path, path, sizeof(outp->path));
	outp->fdcap = fdcap;
}

static void
add_pathname(const char *path)
{
	struct pathname *r;

	if (path[0] != '/')
		errx(1, "\"%s\" is not an absolute path", path);

	r = calloc(1, sizeof(*r));
	if (r == NULL)
		err(1, "calloc");
	r->p_path = strdup(path);
	if (r->p_path == NULL)
		err(1, "strdup %s", path);
	r->p_fd = open(r->p_path, O_RDONLY);
	if (r->p_fd < 0)
		err(1, "%s", r->p_path);
	LIST_INSERT_HEAD(&pathnames, r, p_link);
}

static const struct pathname *
find_pathname(const char *path)
{
	const struct pathname *r;

	/*
	 * XXX: Suboptimal.
	 */
	LIST_FOREACH(r, &pathnames, p_link) {
		if (strncmp(path, r->p_path, strlen(r->p_path)) == 0)
			return (r);
	}

	return (NULL);
}

static void
respond(capv_paths_t *inp, ssize_t received, capv_paths_return_t *outp)
{
	uintcap_t fdcap;
	const struct pathname *pathname;
	int error;

	if (inp->op == 0) {
		/*
		 * Is this a proper packet?  Op 0 is answerback request, so the size
		 * obviously won't match; just make sure that we've received the op field.
		 */
		if ((size_t)received < sizeof(capv_t)) {
			warnx("size mismatch: received %zd, expected %zd",
			    (size_t)received, sizeof(capv_t));
			prepare(outp, "", -ENOMSG);
			return;
		}

		answerback(outp);
		return;
	}

	if ((size_t)received != sizeof(*inp)) {
		warnx("size mismatch: received %zd, expected %zd",
		    (size_t)received, sizeof(*inp));
		prepare(outp, "", -ENOMSG);
		return;
	}

#if 0
	/*
	 * Did we get a file descriptor?
	 */
	if ((void * __capability)in.fdcap != NULL) {
		error = captofd((void * __capability)in.fdcap, &in.error);
		if (error != 0)
			err(1, "captofd");
	}
#endif

	pathname = find_pathname(inp->path);
	if (pathname == NULL) {
		if (!qflag)
			warnx("refusing %s", inp->path);
		prepare(outp, "", -EPERM);
		return;
	}

	/*
	 * Return the file descriptor.
	 */
	error = capfromfd((void *)&fdcap, pathname->p_fd);
	if (error != 0) {
		warn("capfromfd");
		prepare(outp, "", -ENOMSG);
		return;
	}

	prepare(outp, pathname->p_path, fdcap);
}

int
main(int argc, char **argv)
{
	capv_paths_t in;
	capv_paths_return_t out;
	struct sigaction sa;
	void * __capability public;
	void * __capability cookie;
	void * __capability *capv;
	char *ld_preload;
	char *tmp = NULL;
	ssize_t received;
	pid_t pid;
	int capc, ch, error;

	LIST_INIT(&pathnames);

	while ((ch = getopt(argc, argv, "kqr:w:v")) != -1) {
		switch (ch) {
		case 'k':
			kflag = true;
			break;
		case 'q':
			qflag = true;
			break;
		case 'r':
			add_pathname(optarg);
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
	error = capvset(&capc, &capv, CAPV_PATHS, public);
	if (error != 0)
		err(1, "capvset");

	/*
	 * This whole mess with environment variables is to preload
	 * libpaths.so, which provides replacement stubs to shadow
	 * the system calls.  This makes unmodified purecap binaries
	 * transparently call paths(1) instead of kernel.  A bit ugly,
	 * but convenient for now.
	 */
	ld_preload = getenv("LD_PRELOAD");
	if (ld_preload != NULL) {
		asprintf(&tmp, "%s:%s", ld_preload, "/usr/lib/libpaths.so");
	} else {
		asprintf(&tmp, "%s", "/usr/lib/libpaths.so");
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

	error = cap_enter();
	if (error != 0)
		err(1, "cap_enter");

	memset(&out, 0, sizeof(out));

	for (;;) {
		/*
		 * Send back a response, if any, and wait for the next call.
		 */
		if (kflag)
			received = coaccept_slow(&cookie, &out, out.len, &in, sizeof(in));
		else
			received = coaccept(&cookie, &out, out.len, &in, sizeof(in));
		if (received < 0) {
			warn("%s", kflag ? "coaccept_slow" : "coaccept");
			memset(&out, 0, sizeof(out));
			continue;
		}

		/*
		 * Answered.
		 */
		if (vflag) {
			error = cocachedpid(&pid, cookie);
			if (error != 0)
				warn("cogetpid");
			printf("%s: len %zd from pid %d -> pid %d%s\n",
			    getprogname(),
			    in.len, pid, getpid(), kflag ? " (slow)" : "");
		}

		respond(&in, received, &out);

		/*
		 * Send the response back and loop.
		 */
		if (vflag) {
			printf("%s: returning to pid %d <- pid %d: len %zd%s\n",
			    getprogname(), pid, getpid(), out.len, kflag ? " (slow)" : "");
		}
	}
}
