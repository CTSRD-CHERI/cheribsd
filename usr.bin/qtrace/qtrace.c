/*-
 * Copyright (c) 2016 SRI International
 * Copyright (c) 2016 Robert N. M. Watson
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

#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <machine/cheri.h>
#include <machine/sysarch.h>

#include <err.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <getopt.h>

#include <stdio.h>

extern char **environ;
static bool user_mode_only = false;

static void
usage(void)
{
	warnx("usage: qtrace [-u/--user-mode] (start|stop|exec)");
	exit (1);
}

static inline void
start_trace(void)
{
	if (user_mode_only)
		CHERI_START_USER_TRACE;
	else
		CHERI_START_TRACE;
}

static inline void
stop_trace(void)
{
	if (user_mode_only)
		CHERI_STOP_USER_TRACE;
	else
		CHERI_STOP_TRACE;
}

static inline void
set_thread_tracing(void)
{
	int error, intval;

	intval = 1;
	error = sysarch(QEMU_SET_QTRACE, &intval);
	if (error)
		err(EX_OSERR, "QEMU_SET_QTRACE");
	if (user_mode_only) {
		error = sysarch(QEMU_SET_QTRACE_USER, &intval);
		if (error)
			err(EX_OSERR, "QEMU_SET_QTRACE_USER");
	}
}

static inline void
set_buffered_tracing(void)
{
	uint intval;

	intval = 1;
	if (sysctlbyname("hw.qemu_trace_buffered", NULL, NULL,
	    &intval, sizeof(intval)) < 0)
		err(EX_OSERR, "sysctlbyname(\"hw.qemu_trace_buffered\")");
}

int
main(int argc, char **argv)
{
	size_t len;
	uint qemu_trace_perthread;
	int status;
	pid_t pid;
	int opt;
	int opt_index;

	while (1) {
		static struct option long_options[] = {
			{"user-mode", no_argument, 0, 'u'},
			{0, 0, 0, 0},
		};

		opt = getopt_long(argc, argv, "ub",
				  long_options, &opt_index);
		if (opt == -1)
			break;
		switch (opt) {
		case 'u':
			user_mode_only = true;
			break;
		case 'b':
			set_buffered_tracing();
			break;
		default:
			usage();
		}
	}

	len = sizeof(qemu_trace_perthread);
	if (sysctlbyname("hw.qemu_trace_perthread", &qemu_trace_perthread,
	    &len, NULL, 0) < 0)
		err(EX_OSERR, "sysctlbyname(\"hw.qemu_trace_perthread\")");

	if (qemu_trace_perthread &&
	    (strcmp(argv[optind], "start") == 0 ||
	    strcmp(argv[optind], "stop") == 0))
		errx(EX_OSERR, "start and stop unavailable when "
		    "hw.qemu_trace_perthread is set");

	if (strcmp("exec", argv[optind]) == 0) {
		pid = fork();
		if (pid < 0)
			err(EX_OSERR, "fork");
		if (pid == 0) {
			if (qemu_trace_perthread)
				set_thread_tracing();
			else
				start_trace();
			argv++;
			if (execvp(argv[optind], &argv[optind]) == -1)
				err(EX_OSERR, "execvp");
		}

		waitpid(pid, &status, 0);
		if (!qemu_trace_perthread)
			stop_trace();
		if (user_mode_only)
			CHERI_STOP_USER_TRACE;
		if (!WIFEXITED(status)) {
			warnx("child exited abnormally");
			exit(-1);
		}
		exit(WEXITSTATUS(status));
	}

	if (argc - optind > 1)
		usage();
	if (strcmp("start", argv[optind]) == 0) {
		start_trace();
		exit(0);
	} else if (strcmp("stop", argv[optind]) == 0) {
		stop_trace();
		exit(0);
	} else {
		warnx("Unknown command %s\n", argv[optind]);
		usage();
	}
}
