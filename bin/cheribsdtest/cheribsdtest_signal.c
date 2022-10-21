/*-
 * Copyright (c) 2017, 2019 Jessica Clarke
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

#include <cheri/cheri.h>

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cheribsdtest.h"

static int handler_signum;

static void
handler_func(int signum)
{
	handler_signum = signum;
}

CHERIBSDTEST(test_signal_handler_usr1,
    "Install a signal handler (sa_handler) for SIGUSR1 and check it works")
{
	struct sigaction sa;
	sa.sa_handler = handler_func;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGUSR1, &sa, NULL) != 0)
		cheribsdtest_failure_errx("sigaction failed: %s", strerror(errno));

	handler_signum = 0;
	if (kill(getpid(), SIGUSR1) != 0)
		cheribsdtest_failure_errx("kill(getpid(), SIGUSR1) failed: %s",
		                       strerror(errno));

	if (handler_signum != SIGUSR1)
		cheribsdtest_failure_errx("handler_signum (%d) != SIGUSR1 (%d)",
		                       handler_signum, SIGUSR1);

	cheribsdtest_success();
}

static int sigaction_signum;
static int sigaction_info_si_signo;
static int sigaction_info_si_code;

static void
sigaction_func(int signum, siginfo_t *siginfo, void *context __unused)
{
	sigaction_signum = signum;
	sigaction_info_si_signo = siginfo->si_signo;
	sigaction_info_si_code = siginfo->si_code;
}

CHERIBSDTEST(test_signal_sigaction_usr1,
    "Install a signal handler (sa_sigaction) for SIGUSR1 and check it works")
{
	struct sigaction sa;
	sa.sa_sigaction = sigaction_func;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	if (sigaction(SIGUSR1, &sa, NULL) != 0)
		cheribsdtest_failure_errx("sigaction failed: %s", strerror(errno));

	sigaction_signum = 0;
	if (kill(getpid(), SIGUSR1) != 0)
		cheribsdtest_failure_errx("kill(getpid(), SIGUSR1) failed: %s",
		                       strerror(errno));

	if (sigaction_signum != SIGUSR1)
		cheribsdtest_failure_errx("signum (%d) != SIGUSR1 (%d)",
		                       sigaction_signum, SIGUSR1);

	if (sigaction_info_si_signo != SIGUSR1)
		cheribsdtest_failure_errx("si_signo (%d) != SIGUSR1 (%d)",
		                       sigaction_info_si_signo, SIGUSR1);

	if (sigaction_info_si_code != SI_USER)
		cheribsdtest_failure_errx("si_code (%d) != SI_USER (%d)",
		                       sigaction_info_si_code, SI_USER);

	cheribsdtest_success();
}

static size_t sigaltstack_local_addr;

static void
sigaltstack_func(int signum __unused)
{
	int x;
	sigaltstack_local_addr = (__cheri_addr size_t)&x;
}

CHERIBSDTEST(test_signal_sigaltstack,
    "Check signal handlers use the alternate stack when enabled",
    .ct_xfail_reason = XFAIL_C18N_SIGALTSTACK)
{
	stack_t sigstk;
	struct sigaction sa;
	size_t altstack_addr;

	if ((sigstk.ss_sp = malloc(SIGSTKSZ)) == NULL)
		cheribsdtest_failure_errx("malloc(SIGSTKSZ) failed: %s",
		                       strerror(errno));

	altstack_addr = (__cheri_addr size_t)sigstk.ss_sp;
	sigstk.ss_size = SIGSTKSZ;
	sigstk.ss_flags = 0;
	if (sigaltstack(&sigstk, NULL) != 0)
		cheribsdtest_failure_errx("sigaltstack failed: %s",
		                       strerror(errno));

	sa.sa_handler = sigaltstack_func;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_ONSTACK;
	if (sigaction(SIGUSR1, &sa, NULL) != 0)
		cheribsdtest_failure_errx("sigaction failed: %s",
		                       strerror(errno));

	sigaltstack_local_addr = 0;
	if (kill(getpid(), SIGUSR1) != 0)
		cheribsdtest_failure_errx("kill(getpid(), SIGUSR1) failed: %s",
		                       strerror(errno));

	if (sigaltstack_local_addr < altstack_addr)
		cheribsdtest_failure_errx(
		    "stack local (0x%zx) < sigstk.ss_sp (0x%zx)",
		    sigaltstack_local_addr, altstack_addr);

	if (sigaltstack_local_addr >= altstack_addr + SIGSTKSZ)
		cheribsdtest_failure_errx(
		    "stack local (0x%zx) >= sigstk.ss_sp+SIGSTKSZ (0x%zx)",
		    sigaltstack_local_addr, altstack_addr + SIGSTKSZ);

	cheribsdtest_success();
}

static size_t sigaltstack_disable_local_addr;

static void
sigaltstack_disable_func(int signum __unused)
{
	int x;
	sigaltstack_disable_local_addr = (__cheri_addr size_t)&x;
}

CHERIBSDTEST(test_signal_sigaltstack_disable,
    "Check signal handlers don't use a given alternate stack when re-disabled")
{
	stack_t sigstk;
	struct sigaction sa;
	size_t altstack_addr;

	if ((sigstk.ss_sp = malloc(SIGSTKSZ)) == NULL)
		cheribsdtest_failure_errx("malloc(SIGSTKSZ) failed: %s",
		                       strerror(errno));

	altstack_addr = (__cheri_addr size_t)sigstk.ss_sp;
	sigstk.ss_size = SIGSTKSZ;
	sigstk.ss_flags = 0;
	if (sigaltstack(&sigstk, NULL) != 0)
		cheribsdtest_failure_errx("sigaltstack failed: %s",
		                       strerror(errno));

	sigstk.ss_flags = SS_DISABLE;
	if (sigaltstack(&sigstk, NULL) != 0)
		cheribsdtest_failure_errx("sigaltstack (disable) failed: %s",
		                       strerror(errno));

	sa.sa_handler = sigaltstack_disable_func;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_ONSTACK;
	if (sigaction(SIGUSR1, &sa, NULL) != 0)
		cheribsdtest_failure_errx("sigaction failed: %s", strerror(errno));

	sigaltstack_disable_local_addr = 0;
	if (kill(getpid(), SIGUSR1) != 0)
		cheribsdtest_failure_errx("kill(getpid(), SIGUSR1) failed: %s",
		                       strerror(errno));

	if (sigaltstack_disable_local_addr >= altstack_addr &&
	    sigaltstack_disable_local_addr < altstack_addr + SIGSTKSZ)
		cheribsdtest_failure_errx(
		    "stack local (0x%zx) in range of sigstk.ss_sp (0x%zx-0x%zx)",
		    sigaltstack_disable_local_addr, altstack_addr,
		    altstack_addr+SIGSTKSZ);

	cheribsdtest_success();
}

#ifdef __CHERI_PURE_CAPABILITY__
extern int __sys_sigaction(int, const struct sigaction *, struct sigaction *);

static void *handler_returncap;

static void
returncap_func(int signum __unused)
{
	handler_returncap = __builtin_return_address(0);
}

CHERIBSDTEST(test_signal_returncap,
    "Test value of signal handler return capability")
{
	struct sigaction sa;
	uintmax_t v;

	sa.sa_handler = returncap_func;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	/*
	 * Note: we call __sys_sigaction directly here to avoid any interposing by
	 * libthr and ensure that our handler is called directly by the kernel,
	 * since we want to capture the return capability for sigcode it gives to
	 * userspace.
	 */
	if (__sys_sigaction(SIGUSR1, &sa, NULL) != 0)
		cheribsdtest_failure_errx("sigaction failed: %s",
		                       strerror(errno));

	handler_returncap = NULL;
	if (kill(getpid(), SIGUSR1) != 0)
		cheribsdtest_failure_errx("kill(getpid(), SIGUSR1) failed: %s",
		                       strerror(errno));

	/* Length -- 256 bytes should be more than enough to cover sigcode. */
	v = cheri_getlen(handler_returncap);
	CHERIBSDTEST_VERIFY2(v <= 0x100, "length 0x%jx (expected <= 0x100)", v);

	/* Type -- should be a sentry capability. */
	v = cheri_gettype(handler_returncap);
	CHERIBSDTEST_VERIFY2(v == (uintmax_t)CHERI_OTYPE_SENTRY,
	    "otype %jx (expected %jx)", v, (uintmax_t)CHERI_OTYPE_SENTRY);

	/* Sealed bit. */
	CHERIBSDTEST_VERIFY(cheri_getsealed(handler_returncap));

	/* Tag bit. */
	CHERIBSDTEST_VERIFY(cheri_gettag(handler_returncap));

	/* Permissions -- should have execute but no store permissions. */
	v = cheri_getperm(handler_returncap);
	CHERIBSDTEST_VERIFY2((v & CHERI_PERM_EXECUTE) == CHERI_PERM_EXECUTE,
	    "perms %jx (execute missing)", v);
	CHERIBSDTEST_VERIFY2((v & CHERI_PERM_STORE) == 0,
	    "perms %jx (store present)", v);
	CHERIBSDTEST_VERIFY2((v & CHERI_PERM_STORE_CAP) == 0,
	    "perms %jx (storecap present)", v);
	CHERIBSDTEST_VERIFY2((v & CHERI_PERM_STORE_LOCAL_CAP) == 0,
	    "perms %jx (store_local_cap present)", v);

	cheribsdtest_success();
}
#endif
