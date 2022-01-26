/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2018 Alex Richadson <arichardson@FreeBSD.org>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
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
#include <sys/types.h>
#include <sys/sysctl.h>
#include <atf-c.h>
#include <dlfcn.h>
#include <libgen.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef const char* (exported_func_type)(void);

static char*
get_executable_dir(void)
{
	static char exe_buf[4096] = { '\0' };
	if (exe_buf[0] != '\0')
		return exe_buf;
	size_t len = sizeof(exe_buf);
	int name[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1 };
	ATF_REQUIRE_ERRNO(0, sysctl(name, 4, exe_buf, &len, NULL, 0) == 0);
	ATF_REQUIRE(len > 0);
	ATF_REQUIRE(exe_buf[0] != '\0');
	char *dir = dirname(exe_buf);
	ATF_REQUIRE(dir);
	if (dir != exe_buf)
		memmove(exe_buf, dir, strlen(dir) + 1);
	return exe_buf;
}

#define CHECK_DLERROR_NULL()	do { \
	const char* error = dlerror(); \
	ATF_CHECK_MSG(error == NULL, "Unexpected dlerror() = %s", error); \
} while (0)
#define CHECK_DLERROR_STREQ(msg)	do { \
	const char* error = dlerror(); \
	ATF_CHECK_STREQ(error, msg); \
} while (0)

static void*
test_dlopen_success(const char* lib, const char* expected_value, bool do_close)
{
	const char* exedir = get_executable_dir();
	char libpath[PATH_MAX];
	snprintf(libpath, sizeof(libpath), "%s/../%s", exedir, lib);
	printf("Loading library %s\n", libpath);
	ATF_REQUIRE_MSG(access(libpath, F_OK) == 0, "%s doesn't exist", libpath);

	// Check that noload doesn't pull it in
	void* handle = dlopen(libpath, RTLD_LAZY | RTLD_NOLOAD);
	ATF_CHECK_MSG(handle == NULL, "RTLD_NOLOAD loaded %s", libpath);
	CHECK_DLERROR_NULL();

	handle = dlopen(libpath, RTLD_LAZY);
	ATF_CHECK_MSG(handle != NULL, "Should be able to load hybrid lib");
	CHECK_DLERROR_NULL();

	exported_func_type* badfunc = (exported_func_type*)dlfunc(handle, "bad_function");
	CHECK_DLERROR_STREQ("Undefined symbol \"bad_function\"");
	ATF_CHECK_MSG(badfunc == NULL, "Unexpectedly found bad_function!");

	exported_func_type *exported_func = (exported_func_type*)dlfunc(handle, "exported_function");
	CHECK_DLERROR_NULL();
	ATF_REQUIRE(exported_func != NULL);
	const char* result = exported_func();
	printf("Got result '%s' from '%s'\n", result, lib);
	ATF_CHECK_STREQ(result, expected_value);

	if (do_close) {
		ATF_CHECK_EQ(dlclose(handle), 0);
		CHECK_DLERROR_NULL();
		return NULL;
	}
	return handle;
}

static void
test_dlopen_failure(const char* lib, const char* error_message)
{
	const char* exedir = get_executable_dir();
	char libpath[PATH_MAX];
	snprintf(libpath, sizeof(libpath), "%s/../%s", exedir, lib);
	printf("libpath = %s\n", libpath);
	ATF_REQUIRE_MSG(access(libpath, F_OK) == 0, "%s doesn't exist", libpath);

	// Check that noload doesn't pull it in (and doesn't give an error)
	void* handle = dlopen(libpath, RTLD_LAZY | RTLD_NOLOAD);
	ATF_CHECK_MSG(handle == NULL, "RTLD_NOLOAD loaded %s", libpath);
	CHECK_DLERROR_NULL();

	// Now check that we get an error on dlopen()
	handle = dlopen(libpath, RTLD_LAZY);
	CHECK_DLERROR_STREQ(error_message);
	ATF_REQUIRE_MSG(handle == NULL, "Should not be able to load wrong ABI lib");
}
