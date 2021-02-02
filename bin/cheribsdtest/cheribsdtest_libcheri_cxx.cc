/*-
 * Copyright (c) 2012-2016 Robert N. M. Watson
 * Copyright (c) 2014 SRI International
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

#include <cheribsdtest-helper.h>

extern "C" {
#include "cheribsdtest.h"
}

CHERIBSDTEST(test_sandbox_cxx_exception,
    "Test that failed sandbox invocations become exceptions in C++",
    .ct_flags = CT_FLAG_SANDBOX)
{
#ifdef CHERIERRNO_LINKS
	try
	{
		invoke_clock_gettime();
	}
	catch (cheri::sandbox_invoke_failure &e)
	{
		cheribsdtest_success();
		return;
	}
	catch (...)
	{
		cheribsdtest_failure_errx("Sandbox failure threw the wrong kind of exception\n");
		return;
	}
	cheribsdtest_failure_errx("Sandbox failure didn't throw an exception\n");
#else
	cheribsdtest_success();
#endif
}

CHERIBSDTEST(test_sandbox_cxx_no_exception,
    "Test that successful sandbox invocations don't exceptions in C++",
    .ct_flags = CT_FLAG_SANDBOX)
{
#ifdef CHERIERRNO_LINKS
	try
	{
		invoke_cheri_system_putchar();
	}
	catch (cheri::sandbox_invoke_failure &e)
	{
		cheribsdtest_failure_errx("Sandbox success threw a cheri exception\n");
		return;
	}
	catch (...)
	{
		cheribsdtest_failure_errx("Sandbox success threw an exception\n");
		return;
	}
	cheribsdtest_success();
#else
	cheribsdtest_success();
#endif
}
