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

#include <sys/auxv.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/syslimits.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

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

static int
coexecvec_helper(pid_t pid, char *name, void **capv, int capc)
{
	char path[PATH_MAX];
	char *helper_argv[4];
	int error;

	get_exec_path(path);

	helper_argv[0] = path;
	helper_argv[1] = name;
	helper_argv[2] = NULL;

	error = setenv("COCALL_TEST_HELPER_ARG", "1", 1);
	ATF_REQUIRE_EQ(error, 0);

	error = coexecvec(pid, path, helper_argv, environ, capv, capc);
	return (error);
}

ATF_TC_WITHOUT_HEAD(execve);
ATF_TC_BODY(execve, tc)
{
	char *new_argv[2], *new_env[1];
	pid_t pid;

	new_argv[0] = "/usr/bin/true";
	new_argv[1] = NULL;

	new_env[0] = NULL;

	pid = atf_utils_fork();
	if (pid == 0) {
		execve("/usr/bin/true", new_argv, new_env);
		atf_tc_fail("You're not supposed to be here");
	} else {
		atf_utils_wait(pid, 0, "", "");
	}
}

ATF_TC_WITHOUT_HEAD(coexecve_wrong_pid);
ATF_TC_BODY(coexecve_wrong_pid, tc)
{
	char *new_argv[2], *new_env[1];
	pid_t pid;
	int error;

	new_argv[0] = "/usr/bin/true";
	new_argv[1] = NULL;

	new_env[0] = NULL;

	pid = atf_utils_fork();
	if (pid == 0) {
		error = coexecve(99, "/usr/bin/true", new_argv, new_env);
		ATF_REQUIRE_EQ(error, -1);
		ATF_REQUIRE_EQ(errno, ESRCH);
		exit(0);
	} else {
		atf_utils_wait(pid, 0, "", "");
	}
}

ATF_TC_WITHOUT_HEAD(coexecve_right_pid);
ATF_TC_BODY(coexecve_right_pid, tc)
{
	char *new_argv[2], *new_env[1];
	pid_t pid;

	new_argv[0] = "/usr/bin/true";
	new_argv[1] = NULL;

	new_env[0] = NULL;

	pid = atf_utils_fork();
	if (pid == 0) {
		coexecve(getpid(), "/usr/bin/true", new_argv, new_env);
		atf_tc_fail("You're not supposed to be here");
	} else {
		atf_utils_wait(pid, 0, "", "");
	}
}

ATF_TC_WITHOUT_HEAD(vfork_coexecve_wrong_pid);
ATF_TC_BODY(vfork_coexecve_wrong_pid, tc)
{
	char *new_argv[2], *new_env[1];
	pid_t pid;
	int error, status;

	new_argv[0] = "/usr/bin/true";
	new_argv[1] = NULL;

	new_env[0] = NULL;

	pid = vfork();
	if (pid < 0) {
		atf_tc_fail("vfork returned %d: %s", pid, strerror(errno));
	} else if (pid == 0) {
		error = coexecve(99, "/usr/bin/true", new_argv, new_env);
		ATF_REQUIRE_EQ(error, -1);
		ATF_REQUIRE_EQ(errno, ESRCH);
		exit(0);
	} else {
		pid = waitpid(pid, &status, 0);
		if (pid <= 0)
			atf_tc_fail("waitpid returned %d: %s", pid, strerror(errno));
		ATF_REQUIRE_EQ(status, 0);
	}
}

ATF_TC_WITHOUT_HEAD(vfork_coexecve_right_pid);
ATF_TC_BODY(vfork_coexecve_right_pid, tc)
{
	char *new_argv[2], *new_env[1];
	pid_t pid;
	int status;

	new_argv[0] = "/usr/bin/true";
	new_argv[1] = NULL;

	new_env[0] = NULL;

	pid = vfork();
	if (pid < 0) {
		atf_tc_fail("vfork returned %d: %s", pid, strerror(errno));
	} else if (pid == 0) {
		coexecve(getppid(), "/usr/bin/true", new_argv, new_env);
		atf_tc_fail("You're not supposed to be here");
	} else {
		pid = waitpid(pid, &status, 0);
		if (pid <= 0)
			atf_tc_fail("waitpid returned %d: %s", pid, strerror(errno));
		ATF_REQUIRE_EQ(status, 0);
	}
}

ATF_TC_WITHOUT_HEAD(fork_coexecvec);
ATF_TC_BODY(fork_coexecvec, tc)
{
	void *new_capv[2];
	pid_t pid;
	int cookie, error;

	new_capv[0] = (void *)&cookie;

	cookie = 42;

	pid = atf_utils_fork();
	if (pid == 0) {
		error = coexecvec_helper(getppid(), "fork_coexecvec_h", new_capv, 1);
		ATF_REQUIRE_EQ(error, -1);
		ATF_REQUIRE_EQ(errno, EPROT);
	} else {
		atf_utils_wait(pid, 0, "", "");
	}
}

ATF_TC_WITHOUT_HEAD(fork_coexecvec_h);
ATF_TC_BODY(fork_coexecvec_h, tc)
{
	char *arg;

	arg = getenv("COCALL_TEST_HELPER_ARG");
	if (arg == NULL)
		atf_tc_skip("helper testcase, not supposed to be run directly");
	else
		atf_tc_fail("You're not supposed to be here");
}

ATF_TC_WITHOUT_HEAD(vfork_coexecvec);
ATF_TC_BODY(vfork_coexecvec, tc)
{
	void *new_capv[2];
	pid_t pid;
	int cookie, error, status;

	new_capv[0] = (void *)&cookie;

	cookie = 42;

	pid = vfork();
	if (pid < 0) {
		atf_tc_fail("vfork returned %d: %s", pid, strerror(errno));
	} else if (pid == 0) {
		error = coexecvec_helper(getppid(), "vfork_coexecvec_h", new_capv, 1);
		atf_tc_fail("coexecvec returned %d: %s", error, strerror(errno));
	} else {
		pid = waitpid(pid, &status, 0);
		if (pid <= 0)
			atf_tc_fail("waitpid returned %d: %s", pid, strerror(errno));
		ATF_REQUIRE_EQ(status, 0);
	}
}

ATF_TC_WITHOUT_HEAD(vfork_coexecvec_h);
ATF_TC_BODY(vfork_coexecvec_h, tc)
{
	void **capv;
	char *arg;
	int error, *intp;

	arg = getenv("COCALL_TEST_HELPER_ARG");
	if (arg == NULL)
		atf_tc_skip("helper testcase, not supposed to be run directly");

	error = elf_aux_info(AT_CAPV, &capv, sizeof(capv));
	ATF_REQUIRE_EQ(error, 0);

	ATF_REQUIRE(capv[0] != NULL);
	intp = (int *)capv[0];
	ATF_REQUIRE_EQ(*intp, 42);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, execve);
	ATF_TP_ADD_TC(tp, coexecve_wrong_pid);
	ATF_TP_ADD_TC(tp, coexecve_right_pid);
	ATF_TP_ADD_TC(tp, vfork_coexecve_wrong_pid);
	ATF_TP_ADD_TC(tp, vfork_coexecve_right_pid);
	ATF_TP_ADD_TC(tp, fork_coexecvec);
	ATF_TP_ADD_TC(tp, fork_coexecvec_h);
	ATF_TP_ADD_TC(tp, vfork_coexecvec);
	ATF_TP_ADD_TC(tp, vfork_coexecvec_h);

	return atf_no_error();
}
