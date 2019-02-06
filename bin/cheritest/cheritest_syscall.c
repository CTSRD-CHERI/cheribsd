/*-
 * Copyright (c) 2013-2016 Robert N. M. Watson
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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

#if !__has_feature(capabilities)
#error "This code requires a CHERI-aware compiler"
#endif

#include <sys/types.h>
#include <sys/signal.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/ptrace.h>

#include <machine/cpuregs.h>
#include <machine/sysarch.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#ifdef CHERI_LIBCHERI_TESTS
#include <cheri/libcheri_enter.h>
#include <cheri/libcheri_fd.h>
#include <cheri/libcheri_sandbox.h>

#include <cheritest-helper.h>
#endif

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "cheritest.h"

#ifdef CHERI_LIBCHERI_TESTS
void
test_sandbox_syscall(const struct cheri_test *ctp __unused)
{
	size_t len;
	int old, new;

	/*
	 * Track whether or not the number of system-call violations increases
	 * as a result of triggering a system call in a sandbox.  Note that
	 * this isn't really authoritative (nor in the strictest sense
	 * correct), as we can race with other threads that trigger
	 * violations, but it's still a useful test case.
	 */
	len = sizeof(old);
	if (sysctlbyname("security.cheri.syscall_violations", &old, &len,
	    NULL, 0) < 0)
		cheritest_failure_errx(
		    "security.cheri.syscall_violations sysctl read (%d)",
		    errno);
	invoke_syscall();
	len = sizeof(new);
	if (sysctlbyname("security.cheri.syscall_violations", &new, &len,
	    NULL, 0) < 0)
		cheritest_failure_errx(
		    "security.cheri.syscall_violations sysctl read (%d)",
		    errno);
	if (new <= old)
		cheritest_failure_errx(
		    "security.cheri.syscall_violations unchanged");
	cheritest_success();
}
#endif

void
test_sig_dfl_neq_ign(const struct cheri_test *ctp __unused)
{
	void * __capability sic = (__cheri_tocap void * __capability)SIG_IGN;

	/*
	 * This may appear redundant, but it tickles some of the optimizers
	 * differently than the condition below, which, apparently, can get
	 * constant-folded and DCE'd, while this does not.
	 */
	int eq = (SIG_IGN == SIG_DFL);

	CHERI_FPRINT_PTR(stderr, sic);
	fprintf(stderr, "IGN=%d(%p) DFL=%d(%p) EQ=%d(%d)\n",
		(int)SIG_IGN, SIG_IGN,
		(int)SIG_DFL, SIG_DFL, SIG_IGN == SIG_DFL, eq);

	if (SIG_IGN == SIG_DFL)
		cheritest_failure_errx("SIG_{IGN,DFL} conflated");
	else if (eq)
		cheritest_failure_errx("SIG_{IGN,DFL} somewhat conflated?");
	else
		cheritest_success();
}

static void
test_sig_dfl_ign_handler(int x)
{
	(void)x;
}

void
test_sig_dfl_ign(const struct cheri_test *ctp __unused)
{
	int cpid;
	int res;
	struct sigaction sa;
	sigset_t ss, oss;

	bzero(&sa, sizeof sa);

	/* Block SIGEMT and SIGURG */
	res = sigprocmask(0, NULL, &ss);
	assert(res == 0);
	res = sigaddset(&ss, SIGEMT);
	assert(res == 0);
	res = sigaddset(&ss, SIGURG);
	assert(res == 0);
	res = sigprocmask(SIG_BLOCK, &ss, &oss);
	assert(res == 0);

	/* Install IGN as behavior for SIGEMT */
	sa.sa_handler = SIG_IGN;
	res = sigaction(SIGEMT, &sa, NULL);
	assert(res == 0);

	/* Make SIGURG a no-op */
	sa.sa_handler = test_sig_dfl_ign_handler;
	res = sigaction(SIGURG, &sa, NULL);
	assert(res == 0);

	cpid = fork();
	if (cpid != 0) {
		int status;
		kill(cpid, SIGEMT); /* Ignored */
		kill(cpid, SIGURG); /* wake from suspend */
		res = waitpid(cpid, &status, 0);
		assert(res == cpid);
		assert(WIFEXITED(status) == 1);
		assert(WEXITSTATUS(status) == 42);
	} else {
		sigsuspend(&oss);
		exit(42);
	}

	/* Use SIG_DFL for SIGEMT */
	sa.sa_handler = SIG_DFL;
	res = sigaction(SIGEMT, &sa, NULL);
	assert(res == 0);

	cpid = fork();
	if (cpid != 0) {
		int status;
		kill(cpid, SIGEMT); /* Fatal */
		res = waitpid(cpid, &status, 0);
		assert(res == cpid);
		assert(WIFSIGNALED(status) == 1);
		assert(WTERMSIG(status) == SIGEMT);
	} else {
		sigsuspend(&oss);
		exit(42);
	}

	cheritest_success();
}

void
test_ptrace_basic(const struct cheri_test *ctp __unused)
{
	int cpid, res;

	cpid = fork();
	if (cpid != 0) {
		int status;

		/* Attach to process */
		res = ptrace(PT_ATTACH, cpid, NULL, 0);
		assert(res == 0);

		/* Stop it */
		kill(cpid, SIGURG);
		res = waitpid(cpid, &status, WTRAPPED);
		assert(res == cpid);

		/* Kill it */
		res = ptrace(PT_KILL, cpid, NULL, 0);
		assert(res == 0);

		/* Reap it */
		res = waitpid(cpid, &status, 0);
		assert (res == cpid);

		cheritest_success();
	} else {
		sigset_t ss;
		sigemptyset(&ss);
		sigsuspend(&ss);
		exit(23);
	}
}
