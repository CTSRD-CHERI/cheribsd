/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 SRI International
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

#if !__has_feature(capabilities)
#error "This code requires a CHERI-aware compiler"
#endif

#include <sys/param.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>

#include <dlfcn.h>
#include <unistd.h>

#include "cheribsdtest.h"

static void
check_fptr(uintptr_t fptr)
{
	register_t perms;

	perms = cheri_getperm((void *)fptr);

	CHERIBSDTEST_VERIFY(cheri_gettag((void *)fptr));
	/* Check that execute is present and store permissions aren't */
	CHERIBSDTEST_VERIFY2((perms & CHERI_PERM_EXECUTE) == CHERI_PERM_EXECUTE,
	    "perms %jx (execute missing)", (uintmax_t)perms);
	CHERIBSDTEST_VERIFY2((perms & CHERI_PERM_STORE) == 0,
	    "perms %jx (store present)", (uintmax_t)perms);
	CHERIBSDTEST_VERIFY2((perms & CHERI_PERM_STORE_CAP) == 0,
	    "perms %jx (storecap present)", (uintmax_t)perms);
	CHERIBSDTEST_VERIFY2((perms & CHERI_PERM_STORE_LOCAL_CAP) == 0,
	    "perms %jx (store_local_cap present)", (uintmax_t)perms);

	CHERIBSDTEST_VERIFY2(cheri_gettype((void *)fptr) == CHERI_OTYPE_SENTRY,
	    "otype %jx (expected %jx)", cheri_gettype((void *)fptr),
	    (uintmax_t)CHERI_OTYPE_SENTRY);

	cheribsdtest_success();
}

#ifdef CHERIBSD_DYNAMIC_TESTS
CHERIBSDTEST(sentry_dlsym,
    "Check that a function pointer obtaine dfrom via dlsym is a sentry")
{
	unsigned int (*fptr)(unsigned int seconds);
	void *handle;
	const char *libm_so;

#if defined(COMPAT_CHERI)
	libm_so = "/usr/lib64c/" LIBM_SONAME;
#else
	libm_so = "/lib/" LIBM_SONAME;
#endif
	if ((handle = dlopen(libm_so, RTLD_LAZY)) == NULL)
		cheribsdtest_failure_errx("dlopen(%s) %s", libm_so, dlerror());
	if ((fptr = dlsym(handle, "acos")) == NULL)
		cheribsdtest_failure_err("dlsym(acos)");

	check_fptr((uintptr_t)fptr);
}
#endif

CHERIBSDTEST(sentry_libc,
    "Check that a function pointer from libc is a sentry")
{
	unsigned int (*fptr)(unsigned int seconds) = sleep;

	check_fptr((uintptr_t)fptr);
}

CHERIBSDTEST(sentry_static,
    "Check that a statically initialized function pointer is a sentry")
{

	check_fptr((uintptr_t)ctp->ct_func);
}
