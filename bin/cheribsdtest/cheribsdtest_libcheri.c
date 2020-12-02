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

#include <sys/cdefs.h>

#if !__has_feature(capabilities)
#error "This code requires a CHERI-aware compiler"
#endif

#include <sys/types.h>
#include <sys/signal.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/time.h>

#include <machine/cpuregs.h>
#include <machine/sysarch.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>
#include <cheri/libcheri_enter.h>
#include <cheri/libcheri_errno.h>
#include <cheri/libcheri_system.h>
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

struct sandbox_class	*cheribsdtest_classp;
struct sandbox_object	*cheribsdtest_objectp;

struct cheri_object cheribsdtest, cheribsdtest2;

static int	allow_syscall(int *retp __unused,
		    int * __capability errno_val __unused);

void
test_sandbox_abort(const struct cheri_test *ctp __unused)
{
	register_t v;

	v = invoke_abort();
	if (v == -2)
		cheribsdtest_success();
	else
		cheribsdtest_failure_errx("Sandbox did not abort()");
}

void
test_sandbox_cs_calloc(const struct cheri_test *ctp __unused)
{
	register_t v;

	v = invoke_system_calloc();
	if (v < 0)
		cheribsdtest_failure_errx("Sandbox returned %jd", (intmax_t)v);
	else
		cheribsdtest_success();
}

static int
allow_syscall(int *retp __unused, int * __capability errno_val __unused)
{

	return (0);
}

static int
deny_syscall(int *retp, int * __capability stub_errno)
{

	*retp = -1;
	*stub_errno = ENOSYS;

	return (-1);
}

void
test_sandbox_cs_clock_gettime(const struct cheri_test *ctp __unused)
{
	register_t v;

	libcheri_syscall_checks[SYS_clock_gettime] =
	    (libcheri_syscall_check_t)allow_syscall;

	v = invoke_clock_gettime();
	if (v < 0)
		cheribsdtest_failure_errx("Sandbox returned %jd", (intmax_t)v);
	else
		cheribsdtest_success();
}

void
test_sandbox_cs_clock_gettime_default(const struct cheri_test *ctp __unused)
{
	register_t v;

	libcheri_errno = 0;
	v = invoke_clock_gettime();
	if (v != -1)
		cheribsdtest_failure_errx("Sandbox returned %jd", (intmax_t)v);
	else if (libcheri_errno != 0)
		cheribsdtest_failure_errx(
		    "Sandbox returned -1, but set libcheri_errno to %d",
		    libcheri_errno);
	else
		cheribsdtest_success();
}

void
test_sandbox_cs_clock_gettime_deny(const struct cheri_test *ctp __unused)
{
	register_t v;

	libcheri_syscall_checks[SYS_clock_gettime] =
	    (libcheri_syscall_check_t)deny_syscall;

	libcheri_errno = 0;
	v = invoke_clock_gettime();
	if (v != -1)
		cheribsdtest_failure_errx("Sandbox returned %jd", (intmax_t)v);
	else if (libcheri_errno != 0)
		cheribsdtest_failure_errx(
		    "Sandbox returned -1, but set libcheri_errno to %d",
		    libcheri_errno);
	else
		cheribsdtest_success();
}

void
test_sandbox_cs_helloworld(const struct cheri_test *ctp __unused)
{
	register_t v;

	v = invoke_cheri_system_helloworld();
	if (v < 0)
		cheribsdtest_failure_errx("Sandbox returned %jd", (intmax_t)v);
	else
		cheribsdtest_success();
}

void
test_sandbox_cs_putchar(const struct cheri_test *ctp __unused)
{
	register_t v;

	v = invoke_cheri_system_putchar();
	if (v < 0)
		cheribsdtest_failure_errx("Sandbox returned %jd", (intmax_t)v);
	else
		cheribsdtest_success();
}

void
test_sandbox_cs_puts(const struct cheri_test *ctp __unused)
{
	register_t v;

	v = invoke_cheri_system_puts();
	if (v < 0)
		cheribsdtest_failure_errx("Sandbox returned %jd", (intmax_t)v);
	else
		cheribsdtest_success();
}

void
test_sandbox_printf(const struct cheri_test *ctp __unused)
{
	register_t v;

	v = invoke_cheri_system_printf();
	if (v < 0)
		cheribsdtest_failure_errx("Sandbox returned %jd", (intmax_t)v);
	else
		cheribsdtest_success();
}

void
test_sandbox_malloc(const struct cheri_test *ctp __unused)
{
	register_t v;

	v = invoke_malloc();
	if (v < 0)
		cheribsdtest_failure_errx("Sandbox returned %jd", (intmax_t)v);
	else
		cheribsdtest_success();
}

static char string_to_md5[] = "hello world";
static char string_md5[] = "5eb63bbbe01eeed093cb22bb8f5acdc3";

void
test_sandbox_md5_ccall(const struct cheri_test *ctp __unused, int class)
{
	void * __capability md5cap;
	void * __capability bufcap;
	char buf[33];

	md5cap = cheri_ptrperm(string_to_md5, sizeof(string_to_md5),
	    CHERI_PERM_LOAD);
	bufcap = cheri_ptrperm(buf, sizeof(buf), CHERI_PERM_STORE);

	switch (class) {
	case 1:
		invoke_md5(strlen(string_to_md5), md5cap, bufcap);
		break;
	case 2:
		call_invoke_md5(strlen(string_to_md5), md5cap, bufcap);
		break;
	default:
		cheribsdtest_failure_errx("invalid class %d", class);
		break;
	}

	buf[32] = '\0';
	if (strcmp(buf, string_md5) != 0)
		cheribsdtest_failure_errx(
		    "Incorrect MD5 checksum returned from sandbox ('%s')",
		    buf);
	cheribsdtest_success();
}

static register_t cheribsdtest_libcheri_userfn_handler(
    struct cheri_object system_object,
    register_t methodnum,
    register_t a0, register_t a1, register_t a2, register_t a3,
    register_t a4, register_t a5, register_t a6, register_t a7,
    void * __capability c3, void * __capability c4, void * __capability c5,
    void * __capability c6, void * __capability c7)
    __attribute__((cheri_ccall)); /* XXXRW: Will be ccheri_ccallee. */

void
test_sandbox_spin(const struct cheri_test *ctp __unused)
{
	register_t v;

	/*
	 * Test will never terminate on it's own.  We set an alarm to
	 * trigger a signal.
	 */
	alarm(10);

	v = invoke_spin();

	alarm(0);

	if (v != CHERIBSDTEST_SANDBOX_UNWOUND)
		cheribsdtest_failure_errx(
		    "Sandbox not unwound (returned 0x%jx instead of 0x%jx)",
		    (uintmax_t)v, (uintmax_t)CHERIBSDTEST_SANDBOX_UNWOUND);
	else
		cheribsdtest_success();
}

static register_t
cheribsdtest_libcheri_userfn_handler(struct cheri_object system_object __unused,
    register_t methodnum,
    register_t arg,
    register_t a1 __unused, register_t a2 __unused, register_t a3 __unused,
    register_t a4 __unused, register_t a5 __unused, register_t a6 __unused,
    register_t a7 __unused,
    void * __capability c3 __unused, void * __capability c4 __unused,
    void * __capability c5 __unused, void * __capability c6 __unused,
    void * __capability c7 __unused)
{

	switch (methodnum) {
	case CHERIBSDTEST_USERFN_RETURNARG:
		return (arg);

	case CHERIBSDTEST_USERFN_GETSTACK:
		return (cheribsdtest_libcheri_userfn_getstack());

	case CHERIBSDTEST_USERFN_SETSTACK:
		return (cheribsdtest_libcheri_userfn_setstack(arg));

	default:
		cheribsdtest_failure_errx("%s: unexpected method %ld", __func__,
		    methodnum);
	}
}

void
test_sandbox_userfn(const struct cheri_test *ctp __unused)
{
	register_t i, v;

	for (i = 0; i < 10; i++) {
		v = invoke_libcheri_userfn(CHERIBSDTEST_USERFN_RETURNARG, i);
		if (v != i)
			cheribsdtest_failure_errx("Incorrect return value "
			    "0x%lx (expected 0x%lx)\n", v, i);
	}
	cheribsdtest_success();
}

/*
 * Most tests run within a single object instantiated by
 * cheribsdtest_libcheri_setup().  These tests perform variations on the them of
 * "create a second object and optionally do stuff with it".
 */
void
test_2sandbox_newdestroy(const struct cheri_test *ctp __unused)
{

	struct sandbox_object *sbop;

	if (sandbox_object_new(cheribsdtest_classp, 2*1024*1024, &sbop) < 0)
		cheribsdtest_failure_errx("sandbox_object_new() failed");
	sandbox_object_destroy(sbop);
	cheribsdtest_success();
}

void
test_sandbox_ptrdiff(const struct cheri_test *ctp __unused)
{
	intmax_t ret;

	if ((ret = sandbox_test_ptrdiff()) != 0)
		cheribsdtest_failure_errx("sandbox_test_ptrdiff returned %jd\n",
		    ret);
	else
		cheribsdtest_success();
}

void
test_sandbox_varargs(const struct cheri_test *ctp __unused)
{
	intmax_t ret;

	if ((ret = sandbox_test_varargs()) != 0)
		cheribsdtest_failure_errx("sandbox_test_varargs returned %jd\n",
		    ret);
	else
		cheribsdtest_success();
}

void
test_sandbox_va_copy(const struct cheri_test *ctp __unused)
{
	intmax_t ret;

	if ((ret = sandbox_test_va_copy()) != 0)
		cheribsdtest_failure_errx("sandbox_test_va_copy returned %jd\n",
		    ret);
	else
		cheribsdtest_success();
}

int
cheribsdtest_libcheri_setup(void)
{

	/*
	 * Prepare CHERI objects representing stdin, stdout, and /dev/zero.
	 */
	if (libcheri_fd_new(STDIN_FILENO, &sbop_stdin) < 0)
		err(EX_OSFILE, "libcheri_fd_new: stdin");
	if (libcheri_fd_new(STDOUT_FILENO, &sbop_stdout) < 0)
		err(EX_OSFILE, "clibheri_fd_new: stdout");
	zero_fd = open("/dev/zero", O_RDWR);
	if (zero_fd < 0)
		err(EX_OSFILE, "open: /dev/zero");
	if (libcheri_fd_new(zero_fd, &sbop_zero) < 0)
		err(EX_OSFILE, "libcheri_fd_new: /dev/zero");

	if (sandbox_class_new("/usr/libexec/cheribsdtest-helper",
	    4*1024*1024, &cheribsdtest_classp) < 0)
		err(EX_OSERR, "sandbox_class_new: cheribsdtest-helper");
	if (sandbox_object_new(cheribsdtest_classp, 2*1024*1024, &cheribsdtest_objectp) < 0)
		err(EX_OSERR, "sandbox_object_new: cheribsdtest-helper");
	cheribsdtest = sandbox_object_getobject(cheribsdtest_objectp);
	cheribsdtest2 = sandbox_object_getobject(cheribsdtest_objectp);

	libcheri_system_user_register_fn(&cheribsdtest_libcheri_userfn_handler);

	return (0);
}

void
cheribsdtest_libcheri_destroy(void)
{

	sandbox_object_destroy(cheribsdtest_objectp);
	sandbox_class_destroy(cheribsdtest_classp);
	libcheri_fd_destroy(sbop_stdin);
	libcheri_fd_destroy(sbop_stdout);
	libcheri_fd_destroy(sbop_zero);
	close(zero_fd);
}
