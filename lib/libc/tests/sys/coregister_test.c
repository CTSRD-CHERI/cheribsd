/*-
 * Copyright (c) 2020 Edward Tomasz Napierala <trasz@FreeBSD.org>
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

#include <atf-c.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/syslimits.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

extern char **environ;

/*
 * We are our own helper.  Each test case that requires a helper
 * has its '_h' counterpart.  These helper test cases do nothing
 * (skip) when executed normally.
 */
static void
get_exec_path(char *path)
{
	int sysctlname[4];
	size_t pathlen;
	int ret;

	sysctlname[0] = CTL_KERN;
	sysctlname[1] = KERN_PROC;
	sysctlname[2] = KERN_PROC_PATHNAME;
	sysctlname[3] = -1;

	pathlen = PATH_MAX;
	ret = sysctl(sysctlname, nitems(sysctlname), path, &pathlen, NULL, 0);
	if (ret == -1)
		atf_tc_fail("KERN_PROC_PATHNAME returned %d: %s", ret, strerror(errno));
}

static void
coexec_helper(pid_t pid, char *name, char *arg)
{
	char path[PATH_MAX];
	char *helper_argv[4];
	int error;

	get_exec_path(path);

	helper_argv[0] = path;
	helper_argv[1] = name;
	helper_argv[2] = NULL;

	error = setenv("COCALL_TEST_HELPER_ARG", arg, 1);
	ATF_REQUIRE_EQ(error, 0);

	error = coexecve(pid, path, helper_argv, environ);
	ATF_REQUIRE_EQ_MSG(error, 0, "failed to execute \"%s %s\": %s",
	    path, name, strerror(errno));
}

static char *
random_string(void)
{
	char *str = NULL;

	asprintf(&str, "cocall_test_%u", arc4random());
	return (str);
}

ATF_TC_WITHOUT_HEAD(coregister_colookup);
ATF_TC_BODY(coregister_colookup, tc)
{
	void * __capability registered;
	void * __capability lookedup;
	char *name;
	int error;

	name = random_string();
	error = coregister(name, &registered);
	ATF_REQUIRE_EQ(error, 0);
	error = colookup(name, &lookedup);
	ATF_REQUIRE_EQ(error, 0);
	ATF_REQUIRE_EQ(registered, lookedup);
}

ATF_TC_WITHOUT_HEAD(coregister_colookup_other_proc);
ATF_TC_BODY(coregister_colookup_other_proc, tc)
{
	char *name;
	pid_t pid, pid2;
	unsigned int remaining;
	int error;

	name = random_string();

	pid = atf_utils_fork();
	if (pid == 0) {
		error = coregister(name, NULL);
		ATF_REQUIRE_EQ(error, 0);
		do {
			remaining = sleep(1);
		} while (remaining == 0);
		exit(0);
	}

	pid2 = atf_utils_fork();
	if (pid2 == 0) {
		coexec_helper(pid, "coregister_colookup_other_proc_h", name);
		atf_tc_fail("You're not supposed to be here");
	}
	atf_utils_wait(pid2, 0, "passed\n", "save:/dev/null");

	error = kill(pid, SIGTERM);
	ATF_REQUIRE_EQ(error, 0);
}

ATF_TC_WITHOUT_HEAD(coregister_colookup_other_proc_h);
ATF_TC_BODY(coregister_colookup_other_proc_h, tc)
{
	void * __capability lookedup;
	char *arg;
	int error;

	arg = getenv("COCALL_TEST_HELPER_ARG");
	if (arg == NULL)
		atf_tc_skip("helper testcase, not supposed to be run directly");

	error = colookup(arg, &lookedup);
	ATF_REQUIRE_EQ(error, 0);
}

ATF_TC_WITHOUT_HEAD(coreregister_other_proc);
ATF_TC_BODY(coreregister_other_proc, tc)
{
	char *name;
	pid_t pid, pid2;
	unsigned int remaining;
	int error;

	name = random_string();

	pid = atf_utils_fork();
	if (pid == 0) {
		error = coregister(name, NULL);
		ATF_REQUIRE_EQ(error, 0);
		do {
			remaining = sleep(1);
		} while (remaining == 0);
		exit(0);
	}

	pid2 = atf_utils_fork();
	if (pid2 == 0) {
		coexec_helper(pid, "coreregister_other_proc_h", name);
		atf_tc_fail("You're not supposed to be here");
	}
	atf_utils_wait(pid2, 0, "passed\n", "save:/dev/null");

	error = kill(pid, SIGTERM);
	ATF_REQUIRE_EQ(error, 0);
}

ATF_TC_WITHOUT_HEAD(coreregister_other_proc_h);
ATF_TC_BODY(coreregister_other_proc_h, tc)
{
	char *arg;
	int error;

	arg = getenv("COCALL_TEST_HELPER_ARG");
	if (arg == NULL)
		atf_tc_skip("helper testcase, not supposed to be run directly");

	error = coregister(arg, NULL);
	ATF_REQUIRE_EQ(error, -1);
	ATF_REQUIRE_EQ(errno, EEXIST);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, coregister_colookup);
	ATF_TP_ADD_TC(tp, coregister_colookup_other_proc);
	ATF_TP_ADD_TC(tp, coregister_colookup_other_proc_h);
	ATF_TP_ADD_TC(tp, coreregister_other_proc);
	ATF_TP_ADD_TC(tp, coreregister_other_proc_h);

	return atf_no_error();
}
