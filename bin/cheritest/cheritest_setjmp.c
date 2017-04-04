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

#include <setjmp.h>

#include "cheritest.h"

#define	CAP(x)	((__capability void*)(x))

__attribute__((noinline))
static void
do_longjmp(jmp_buf env, int val)
{
	longjmp(env, val);
}

void
test_setjmp(const struct cheri_test *ctp __unused)
{
	jmp_buf env;

	/* No need to check global data accesses work; by calling longjmp after a
	 * longjmp we check that we can still get function capabilities from the
	 * MCT. The load for do_longjmp's entry point could have been hoisted to
	 * before the setjmp, but since it isn't inlined, its own load of a
	 * capability for longjmp will have to come after setjmp has returned. */

	/* Must be volatile; reading non-volatile stack-local variables which have
	 * been modified between the setjmp and longjmp calls is undefined
	 * behaviour (if they happen to be stored in registers, they will be
	 * restored to that register's value at the first call to setjmp). */
	volatile int saw_zero = 0;
	volatile int saw_one = 0;
	volatile int saw_two = 0;

	int val = setjmp(env);
	switch (val) {
	case 0:
		if (saw_zero)
			cheritest_failure_errx("setjmp returned 0 after returning 0");
		if (saw_one)
			cheritest_failure_errx("setjmp returned 0 after returning 1");
		if (saw_two)
			cheritest_failure_errx("setjmp returned 0 after returning 2");
		saw_zero = 1;
		do_longjmp(env, 1);
		cheritest_failure_errx("longjmp(env, 1) returned");
	case 1:
		if (!saw_zero)
			cheritest_failure_errx("setjmp returned 1 before returning 0");
		if (saw_one)
			cheritest_failure_errx("setjmp returned 1 after returning 1");
		if (saw_two)
			cheritest_failure_errx("setjmp returned 1 after returning 2");
		saw_one = 1;
		do_longjmp(env, 2);
		cheritest_failure_errx("longjmp(env, 2) returned");
	case 2:
		if (!saw_zero)
			cheritest_failure_errx("setjmp returned 2 before returning 0");
		if (!saw_one)
			cheritest_failure_errx("setjmp returned 2 before returning 1");
		if (saw_two)
			cheritest_failure_errx("setjmp returned 2 after returning 2");
		break;
	default:
		cheritest_failure_errx("setjmp returned unexpected value %d", val);
	}

	cheritest_success();
}
