/*-
 * Copyright (c) 2012-2017 Robert N. M. Watson
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

/*
 * libcheri + cheri_fd tests.
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
#include <cheri/libcheri_enter.h>
#include <cheri/libcheri_fd.h>
#include <cheri/libcheri_sandbox.h>

#include <cheribsdtest-helper.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "cheribsdtest.h"

#define	CHERIBSDTEST_FD_READ_STR	"read123"
#define	CHERIBSDTEST_FD_WRITE_STR	"write123"

/*
 * XXXRW: Where are these initialised?
 */
int zero_fd = -1;
struct sandbox_object *sbop_stdin, *sbop_stdout, *sbop_zero;

static char read_string[128];

CHERIBSDTEST(test_sandbox_fd_fstat,
    "Exercise fstat() on a cheri_fd in a libcheri sandbox",
    .ct_flags = CT_FLAG_SANDBOX)
{
	register_t v;

	v = invoke_fd_fstat_c(sandbox_object_getobject(sbop_zero));
	if (v != 0)
		cheribsdtest_failure_errx("invoke returned %ld (expected 0)", v);
	cheribsdtest_success();
}

CHERIBSDTEST(test_sandbox_fd_lseek,
    "Exercise lseek() on a cheri_fd in a libcheri sandbox",
    .ct_flags = CT_FLAG_SANDBOX)
{
	register_t v;

	v = invoke_fd_lseek_c(sandbox_object_getobject(sbop_zero));
	if (v != 0)
		cheribsdtest_failure_errx("invoke returned %ld (expected 0)", v);
	cheribsdtest_success();
}

CHERIBSDTEST(test_sandbox_fd_read,
    "Exercise read() on a cheri_fd in a libcheri sandbox",
    .ct_flags = CT_FLAG_STDIN_STRING | CT_FLAG_SANDBOX,
    .ct_stdin_string = CHERIBSDTEST_FD_READ_STR)
{
	char * __capability stringc;
	register_t v;
	size_t len;

	len = sizeof(read_string);
	stringc = cheri_ptrperm(read_string, len, CHERI_PERM_STORE);
	v = invoke_fd_read_c(sandbox_object_getobject(sbop_stdin), stringc,
	    len);
	if (v != (register_t)strlen(ctp->ct_stdin_string))
		cheribsdtest_failure_errx("invoke returned %ld (expected %ld)",
		    v, strlen(ctp->ct_stdin_string));
	read_string[sizeof(read_string)-1] = '\0';
	if (strcmp(read_string, ctp->ct_stdin_string) != 0)
		cheribsdtest_failure_errx("invoke returned mismatched string "
		    "'%s' (expected '%s')", read_string, ctp->ct_stdin_string);
	cheribsdtest_success();
}

CHERIBSDTEST(test_sandbox_fd_read_revoke,
    "Exercise revoke() before read() on a cheri_fd",
    .ct_flags = CT_FLAG_STDIN_STRING | CT_FLAG_SANDBOX,
    .ct_stdin_string = CHERIBSDTEST_FD_READ_STR)
{
	char * __capability stringc;
	register_t v;
	size_t len;

	/*
	 * Essentially the same test as test_sandbox_fd_read() except that we
	 * expect not to receive input.
	 */
	libcheri_fd_revoke(sbop_stdin);
	len = sizeof(read_string);
	stringc = cheri_ptrperm(read_string, len, CHERI_PERM_STORE);
	v = invoke_fd_read_c(sandbox_object_getobject(sbop_stdin), stringc,
	    len);
	if (v != -1)
		cheribsdtest_failure_errx("invoke returned %lu; expected %d\n",
		    v, -1);
	cheribsdtest_success();
}

CHERIBSDTEST(test_sandbox_fd_write,
    "Exercise write() on a cheri_fd in a libcheri sandbox",
    .ct_flags = CT_FLAG_STDOUT_STRING | CT_FLAG_SANDBOX,
    .ct_stdout_string = CHERIBSDTEST_FD_WRITE_STR)
{
	char * __capability stringc;
	register_t v;
	size_t len;

	len = strlen(ctp->ct_stdout_string);
	stringc = cheri_ptrperm(ctp->ct_stdout_string, len, CHERI_PERM_LOAD);
	v = invoke_fd_write_c(sandbox_object_getobject(sbop_stdout), stringc,
	    len);
	if (v != (ssize_t)len)
		cheribsdtest_failure_errx("invoke returned %lu; expected %zd\n",
		    v, strlen(ctp->ct_stdout_string));
	cheribsdtest_success();
}

CHERIBSDTEST(test_sandbox_fd_write_revoke,
    "Exercise revoke() before write() on a cheri_fd",
    /* NB: String defined but flag not set: shouldn't print. */
    .ct_stdout_string = CHERIBSDTEST_FD_WRITE_STR,
    .ct_flags = CT_FLAG_SANDBOX)
{
	char * __capability stringc;
	register_t v;
	size_t len;

	/*
	 * Essentially the same test as test_sandbox_fd_write() except that we
	 * expect to see no output.
	 */
	libcheri_fd_revoke(sbop_stdout);
	len = strlen(ctp->ct_stdout_string);
	stringc = cheri_ptrperm(ctp->ct_stdout_string, len, CHERI_PERM_LOAD);
	v = invoke_fd_write_c(sandbox_object_getobject(sbop_stdout), stringc,
	    len);
	if (v != -1)
		cheribsdtest_failure_errx("invoke returned %lu; expected %d\n",
		    v, -1);
	cheribsdtest_success();
}
