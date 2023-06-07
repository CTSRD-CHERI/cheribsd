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
#include <sys/aio.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/ptrace.h>

#include <machine/sysarch.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

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

#include "cheribsdtest.h"

CHERIBSDTEST(sig_dfl_neq_ign, "Test SIG_DFL != SIG_IGN")
{
	void * __capability sic = (__cheri_tocap void * __capability)SIG_IGN;

	/*
	 * This may appear redundant, but it tickles some of the optimizers
	 * differently than the condition below, which, apparently, can get
	 * constant-folded and DCE'd, while this does not.
	 */
	int eq = (SIG_IGN == SIG_DFL);

	fprintf(stderr, "sic %#lp\n", sic);
	fprintf(stderr, "IGN=%ld(%p) DFL=%ld(%p) EQ=%d(%d)\n",
		(long)SIG_IGN, SIG_IGN,
		(long)SIG_DFL, SIG_DFL, SIG_IGN == SIG_DFL, eq);

	if (SIG_IGN == SIG_DFL)
		cheribsdtest_failure_errx("SIG_{IGN,DFL} conflated");
	else if (eq)
		cheribsdtest_failure_errx("SIG_{IGN,DFL} somewhat conflated?");
	else
		cheribsdtest_success();
}

static void
test_sig_dfl_ign_handler(int x)
{
	(void)x;
}

CHERIBSDTEST(sig_dfl_ign, "Test proper handling of SIG_DFL and SIG_IGN")
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

	cheribsdtest_success();
}

CHERIBSDTEST(ptrace_basic, "Test basic handling of ptrace functionality")
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

		cheribsdtest_success();
	} else {
		sigset_t ss;
		sigemptyset(&ss);
		sigsuspend(&ss);
		exit(23);
	}
}

static int test_aio_sival_signal = 0;
static siginfo_t test_aio_sival_info = { 0 };

static void
test_aio_sival_handler(int sig, siginfo_t *si, void *uc __unused)
{
	test_aio_sival_signal = sig;
	test_aio_sival_info = *si;
}

CHERIBSDTEST(aio_sival, "Test pointer passing through AIO signals")
{
	char buf[128];
	int pfd[2];
	int res;
	sigset_t sigset, osigset;
	struct aiocb aiocb;
	struct sigaction sa;

	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = &test_aio_sival_handler;
	res = sigaction(SIGUSR1, &sa, NULL);
	CHERIBSDTEST_VERIFY2(res == 0, "Could not install AIO handler; errno=%d", errno);

	res = sigaction(SIGALRM, &sa, NULL);
	CHERIBSDTEST_VERIFY2(res == 0, "Could not install ALRM handler; errno=%d", errno);

	res = socketpair(AF_UNIX, SOCK_STREAM, 0, pfd);
	CHERIBSDTEST_VERIFY2(res == 0, "Could not create socketpair; errno=%d", errno);

	bzero(&aiocb, sizeof(aiocb));
	aiocb.aio_fildes = pfd[0];
	aiocb.aio_buf = buf;
	aiocb.aio_nbytes = sizeof(buf);
	aiocb.aio_lio_opcode = LIO_READ;

	aiocb.aio_sigevent.sigev_notify = SIGEV_SIGNAL;
	aiocb.aio_sigevent.sigev_signo = SIGUSR1;
	aiocb.aio_sigevent.sigev_value.sival_ptr = test_aio_sival_handler;

	res = aio_read(&aiocb);
	CHERIBSDTEST_VERIFY2(res == 0, "Could not register aio; errno=%d", errno);

	CHERIBSDTEST_VERIFY(sigemptyset(&sigset) == 0);
	CHERIBSDTEST_VERIFY(sigaddset(&sigset, SIGUSR1) == 0);
	CHERIBSDTEST_VERIFY(sigaddset(&sigset, SIGALRM) == 0);
	CHERIBSDTEST_VERIFY(sigprocmask(SIG_BLOCK, &sigset, &osigset) == 0);
	close(pfd[1]);
	alarm(2);
	CHERIBSDTEST_VERIFY(sigsuspend(&osigset) == -1 && errno == EINTR);
	close(pfd[0]);

	switch (test_aio_sival_signal) {
	case SIGALRM:
		cheribsdtest_failure_errx("Test timeout!");
		break;
	case 0:
		cheribsdtest_failure_errx("No signal received?");
		break;
	default:
		cheribsdtest_failure_errx("Bad signal %d",
					test_aio_sival_signal);
		break;
	case SIGUSR1:
		CHERIBSDTEST_VERIFY2(test_aio_sival_info.si_code == SI_ASYNCIO,
			"Signal not asyncio?  code=%d",
			test_aio_sival_info.si_code);
		CHERIBSDTEST_VERIFY2(test_aio_sival_info.si_value.sival_ptr ==
				  test_aio_sival_handler,
			"Bad si_value; expected=%p got=%p",
			test_aio_sival_handler,
			test_aio_sival_info.si_value.sival_ptr);
		cheribsdtest_success();
	}
}
