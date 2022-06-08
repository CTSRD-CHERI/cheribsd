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

#include <sys/capsicum.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <err.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern ssize_t	switcher_cocall(void * __capability, void * __capability,
    const void * __capability,
    const void * __capability, size_t, void * __capability, size_t);
extern ssize_t	switcher_coaccept(void * __capability, void * __capability,
    void * __capability * __capability,
    const void * __capability, size_t, void * __capability, size_t);

static void
usage(void)
{

	fprintf(stderr, "usage: dispatch [-Cv] command [args ...]\n");
	exit(0);
}

static void
sigchld_handler(int dummy __unused)
{

	exit(0);
}

int
main(int argc, char **argv)
{
	void * __capability capv[] = { NULL };
	void * __capability _cocall_code;
	void * __capability _coaccept_code;
	pid_t pid;
	int ch, error, status;
	bool Cflag = false, vflag = false;

	while ((ch = getopt(argc, argv, "Cv")) != -1) {
		switch (ch) {
		case 'C':
			Cflag = true;
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

	struct sigaction sa;
	sa.sa_handler = sigchld_handler;
	sigfillset(&sa.sa_mask);

	error = sigaction(SIGCHLD, &sa, NULL);
	if (error != 0)
		err(1, "sigaction");

	/*
	 * Do not mess up an existing address space - fork(2) to get
	 * a fresh new one, and use setsid(2) to make sure the kernel
	 * won't opportunistically colocate us back.
	 */
	pid = fork();
	if (pid < 0)
		err(1, "fork");
	if (pid > 0) {
		error = waitpid(pid, &status, WEXITED);
		if (error < 0)
			err(1, "waitpid");
		return (WEXITSTATUS(status));
	}

	/*
	 * XXX: Makes sh(1) unhappy:
	 *
	 * # dispatch sh
	 * sh: can't access tty; job control turned off
	 */
	pid = setsid();
	if (pid < 0)
		err(1, "setsid");

	_cocall_code = switcher_cocall;
	_coaccept_code = switcher_coaccept;
	error = _cosetup(COSETUP_TAKEOVER, &_cocall_code, &_coaccept_code);
	if (error != 0)
		err(1, "COSETUP_TAKEOVER");

	/*
	 * At this point we are running in a new address space.
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
		coexecvpc(getppid(), argv[0], argv, capv, nitems(capv));

		/*
		 * Shouldn't have returned.
		 */
		err(1, "coexecvpc");
	}

	if (!Cflag) {
		/*
		 * For mostly metaphysical reasons.
		 */
		error = cap_enter();
		if (error != 0)
			err(1, "cap_enter");
	}

	/*
	 * This thread has literally nothing more to do - cocalls carry
	 * their own CPU context, and switcher doesn't use the stack.
	 * The only reason for this thread's continued existence is to make
	 * sure the code segment doesn't get unmapped.  And perhaps also
	 * to make sure there is an easy way to forcibly make it unmapped.
	 *
	 * XXX mine bitcoin or sth
	 */
	pause();
	err(vflag, "pause");
}
