/*-
 * Copyright (c) 2017 Robert N. M. Watson
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
#include <sys/time.h>

#include <machine/cpuregs.h>
#include <machine/sysarch.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>
#include <cheri/cheri_enter.h>
#include <cheri/cheri_errno.h>
#include <cheri/cheri_fd.h>
#include <cheri/sandbox.h>

#include <cheritest-helper.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "cheritest.h"

/*
 * Run several libcheri-related tests in a second thread.
 */
static void *
test_sandbox_pthread_abort_fn(void *arg __unused)
{
	register_t v;

	v = invoke_abort();
	if (v == -2)
		cheritest_success();
	else
		cheritest_failure_errx("Sandbox did not abort()");
}

void
test_sandbox_pthread_abort(const struct cheri_test *ctp __unused)
{
	pthread_t thread;

	if (pthread_create(&thread, NULL, test_sandbox_pthread_abort_fn, NULL)
	    < 0)
		cheritest_failure_err("pthread_create");
	if (pthread_join(thread, NULL) < 0)
		cheritest_failure_err("pthread_join");
	cheritest_success();
}

static void *
test_sandbox_pthread_cs_helloworld_fn(void *arg __unused)
{
	register_t v;

	v = invoke_cheri_system_helloworld();
	if (v < 0)
		cheritest_failure_errx("Sandbox returned %jd", (intmax_t)v);
	else
		cheritest_success();
}

void
test_sandbox_pthread_cs_helloworld(const struct cheri_test *ctp __unused)
{
	pthread_t thread;

	if (pthread_create(&thread, NULL,
	    test_sandbox_pthread_cs_helloworld_fn, NULL) < 0)
		cheritest_failure_err("pthread_create");
	if (pthread_join(thread, NULL) < 0)
		cheritest_failure_err("pthread_join");
	cheritest_success();
}
