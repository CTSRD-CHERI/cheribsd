/*-
 * Copyright (c) 2017 James Clarke
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
#include <cheri/cheric.h>

#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include "cheritest.h"

#define	CAP(x)	((__capability void*)(x))

static int thread_global;

static void *
access_globals(void *arg __unused)
{
	thread_global = 0x910b41;
	return NULL;
}

void
test_thread_access_globals(const struct cheri_test *ctp __unused)
{
	pthread_t thread;

	thread_global = 0xdead;
	if (pthread_create(&thread, NULL, access_globals, NULL) != 0)
		cheritest_failure_errx("pthread_create failed: %s", strerror(errno));

	if (pthread_join(thread, NULL) != 0)
		cheritest_failure_errx("pthread_join failed: %s", strerror(errno));

	if (thread_global != 0x910b41)
		cheritest_failure_errx("thread_global (0x%x) != 0x910b41", thread_global);

	cheritest_success();
}

static void *
arg_write(void *arg)
{
	*(int *)arg = 0x900d;
	return NULL;
}

void
test_thread_arg_write(const struct cheri_test *ctp __unused)
{
	pthread_t thread;
	int arg = 0xbad;

	if (pthread_create(&thread, NULL, arg_write, &arg) != 0)
		cheritest_failure_errx("pthread_create failed: %s", strerror(errno));

	if (pthread_join(thread, NULL) != 0)
		cheritest_failure_errx("pthread_join failed: %s", strerror(errno));

	if (arg != 0x900d)
		cheritest_failure_errx("arg (0x%x) != 0x900d", arg);

	cheritest_success();
}

static void *
return_value(void *arg __unused)
{
	return (void *)(uintptr_t)0x900d;
}

void
test_thread_return_value(const struct cheri_test *ctp __unused)
{
	pthread_t thread;
	void *retval = (void *)(uintptr_t)0xbad;

	if (pthread_create(&thread, NULL, return_value, NULL) != 0)
		cheritest_failure_errx("pthread_create failed: %s", strerror(errno));

	if (pthread_join(thread, &retval) != 0)
		cheritest_failure_errx("pthread_join failed: %s", strerror(errno));

	if ((size_t)retval != 0x900d)
		cheritest_failure_errx("retval (0x%zx) != 0x900d", (size_t)retval);

	cheritest_success();
}
