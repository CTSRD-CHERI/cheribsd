/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 SRI International
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency (DARPA) Contract No. HR001122S0003 ("MTSS").
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

#include <sys/wait.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "cheribsdtest.h"

static void
exec_child_cf(void)
{
	if (verbose)
		fprintf(stderr, "in child function\n");

	exit(0);
}

CHERIBSDTEST(internal_spawn_child_posix_spawn,
    "check that directly spawning a child process with posix_spawn runs properly",
    .ct_child_func = exec_child_cf)
{
	int res;
	pid_t pid;

	pid = cheribsdtest_spawn_child(SC_MODE_POSIX_SPAWN);

	CHERIBSDTEST_VERIFY2(pid > 0, "spawning child process failed");
	waitpid(pid, &res, 0);
	if (res != 0)
		cheribsdtest_failure_errx("Bad child process exit");

	cheribsdtest_success();
}

CHERIBSDTEST(internal_spawn_child_fork, "spawn a child process with fork",
    .ct_child_func = exec_child_cf)
{
	int res;
	pid_t pid;

	pid = cheribsdtest_spawn_child(SC_MODE_FORK);

	CHERIBSDTEST_VERIFY2(pid > 0, "spawning child process failed");
	waitpid(pid, &res, 0);
	if (res != 0)
		cheribsdtest_failure_errx("Bad child process exit");

	cheribsdtest_success();
}

CHERIBSDTEST(internal_spawn_child_rfork, "spawn a process with rfork",
    .ct_child_func = exec_child_cf)
{
	int res;
	pid_t pid;

	pid = cheribsdtest_spawn_child(SC_MODE_RFORK);

	CHERIBSDTEST_VERIFY2(pid > 0, "spawning child process failed");
	waitpid(pid, &res, 0);
	if (res != 0)
		cheribsdtest_failure_errx("Bad child process exit");

	cheribsdtest_success();
}

CHERIBSDTEST(internal_spawn_child_vfork, "spawn a process with vfork",
    .ct_child_func = exec_child_cf)
{
	int res;
	pid_t pid;

	pid = cheribsdtest_spawn_child(SC_MODE_VFORK);

	CHERIBSDTEST_VERIFY2(pid > 0, "spawning child process failed");
	waitpid(pid, &res, 0);
	if (res != 0)
		cheribsdtest_failure_errx("Bad child process exit");

	cheribsdtest_success();
}
