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

#include <err.h>
#include <libgen.h>
#include <spawn.h>
#include <statcounters.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sysexits.h>

extern char **environ;

static void
usage(int exitcode)
{
	warnx("usage: beri_count_stats [-v/--verbose] <command>");
	exit(exitcode);
}

int
main(int argc, char **argv)
{
	int status;
	pid_t pid;
	bool verbose = false;

	/* Adjust argc and argv as though we've used getopt. */
	argc--;
	argv++;

	if (argc == 0)
		usage(1);
	if (strcmp("--help", argv[0]) == 0 || strcmp("-h", argv[0]) == 0)
		usage(0);
	if (strcmp("-v", argv[0]) == 0 || strcmp("--verbose", argv[0]) == 0) {
		argc--;
		argv++;
		verbose = true;
	}

	statcounters_bank_t start_count;
	statcounters_sample(&start_count);
	status = posix_spawnp(&pid, argv[0], NULL, NULL, argv, environ);
	if (status != 0)
		errc(EX_OSERR, status, "posix_spawnp");

	waitpid(pid, &status, 0);
	if (!WIFEXITED(status)) {
		warnx("child exited abnormally");
	}
	statcounters_bank_t end_count;
	statcounters_bank_t diff_count;
	statcounters_sample(&end_count);
	statcounters_diff(&diff_count, &end_count, &start_count);
	/*
	 * Dump the stats and use the command basename as the name
	 * TODO: arch will be wrong since we are using the architecture of
	 * the beri_count_stats_binary!
	 */
	const char* prog_basename = basename(argv[0]);
	/* Also dump to stderr when -v was passed */
	if (verbose) {
		/* Ensure human readable output: */
		const char* original_fmt = getenv("STATCOUNTERS_FORMAT");
		unsetenv("STATCOUNTERS_FORMAT");
		statcounters_dump_with_args(&diff_count, prog_basename, NULL,
		    NULL, stderr, HUMAN_READABLE);
		setenv("STATCOUNTERS_FORMAT", original_fmt, 1);
	}
	statcounters_dump_with_args(&diff_count, prog_basename, NULL, NULL, NULL, HUMAN_READABLE);
	exit(WEXITSTATUS(status));
}
