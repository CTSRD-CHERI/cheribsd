/*-
 * Copyright (c) 2020 Robert N. M. Watson
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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
#include <sys/types.h>
#include <sys/signal.h>
#include <sys/sysctl.h>
#include <sys/time.h>

#include <machine/frame.h>
#include <machine/trap.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <err.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>

#include "cheribsdtest.h"

/*
 * Perform a few tests relating to varargs processing to ensure that the
 * underlying ABI and code generation enforce bounds on their use.  We expect
 * bounds checking only in pure-capability code, currently.
 */

/*
 * Directly overflow the varargs array by accessing off the end using
 * va_arg() one too many times.
 */
static __noinline void
varargs_test_onearg(const char *fmt, ...)
{
	volatile int i;
	va_list ap;

	va_start(ap, fmt);

	/* Ignore valid first pointer argument. */
	(void)va_arg(ap, void *);

	/* Improperly access invalid second argument. */
	i = va_arg(ap, int);

	cheribsdtest_failure_errx("va_arg() overran bounds without fault");
}

CHERIBSDTEST(bounds_varargs_vaarg_overflow,
    "check that va_arg() triggers a fault on overrun",
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO,
    .ct_signum = SIGPROT,
    .ct_si_code = PROT_CHERI_BOUNDS,
    .ct_si_trapno = TRAPNO_LOAD_STORE,
    .ct_xfail_reason = XFAIL_VARARG_BOUNDS)
{

	varargs_test_onearg("%p", NULL);
}

/*
 * Perform end-to-end tests using printf(3).
 */

/*
 * Check that accessing the varargs array when there have been no variable
 * arguments leads to a tag violation.  If it is left uninitialized in the
 * ABI, then this could allow accesses via a shadowed value.  In principle a
 * zero-length pointer would also be fine -- if one arises in one of our ABIs,
 * the acceptable conditions may need to be updated.
 */
CHERIBSDTEST(bounds_varargs_empty_pointer_null,
    "check that empty varargs gives a tag violation on load",
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO,
    .ct_signum = SIGPROT,
    .ct_si_code = PROT_CHERI_TAG,
    .ct_si_trapno = TRAPNO_LOAD_STORE,
    .ct_xfail_reason = XFAIL_VARARG_BOUNDS)
{

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat"
	printf("%p");
#pragma clang diagnostic pop

	cheribsdtest_failure_errx("printf(\"%%p\") did not fault");
}

/*
 * Check that if we overflow the varargs array with a load, we get a bounds
 * violation.
 */
CHERIBSDTEST(bounds_varargs_printf_load,
    "check that load via printf varargs overflow faults",
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO,
    .ct_signum = SIGPROT,
    .ct_si_code = PROT_CHERI_BOUNDS,
    .ct_si_trapno = TRAPNO_LOAD_STORE,
    .ct_xfail_reason = XFAIL_VARARG_BOUNDS)
{

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat"
	printf("%c%p", 1);
#pragma clang diagnostic pop

	cheribsdtest_failure_errx("printf(\"%%c%%p\", 1) did not fault");
}

/*
 * Check that if we overflow the varargs array to load a pointer we will
 * store via (%n), we get a bounds violation -- rather than, say, a tag
 * violation as a result of dereferencing that pointer.
 */
CHERIBSDTEST(bounds_varargs_printf_store,
    "check that store via printf varargs overflow faults",
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO,
    .ct_signum = SIGPROT,
    .ct_si_code = PROT_CHERI_BOUNDS,
    .ct_si_trapno = TRAPNO_LOAD_STORE,
    .ct_xfail_reason = XFAIL_VARARG_BOUNDS)
{

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat"
	printf("%c%n", 0);
#pragma clang diagnostic pop

	cheribsdtest_failure_errx("printf(\"%%c%%n\", 0) did not fault");
}
