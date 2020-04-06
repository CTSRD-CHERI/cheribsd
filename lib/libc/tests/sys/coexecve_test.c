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

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

ATF_TC_WITHOUT_HEAD(execve);
ATF_TC_BODY(execve, tc)
{
	char *new_argv[2], *new_env[1];
	pid_t pid;
	int error;

	new_argv[0] = "/usr/bin/true";
	new_argv[1] = NULL;

	new_env[0] = NULL;

	pid = atf_utils_fork();
	if (pid == 0) {
		error = execve("/usr/bin/true", new_argv, new_env);
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
	int error;

	new_argv[0] = "/usr/bin/true";
	new_argv[1] = NULL;

	new_env[0] = NULL;

	pid = atf_utils_fork();
	if (pid == 0) {
		error = coexecve(getpid(), "/usr/bin/true", new_argv, new_env);
		atf_tc_fail("You're not supposed to be here");
	} else {
		atf_utils_wait(pid, 0, "", "");
	}
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, execve);
	ATF_TP_ADD_TC(tp, coexecve_wrong_pid);
	ATF_TP_ADD_TC(tp, coexecve_right_pid);

	return atf_no_error();
}
