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
#include <getopt.h>
#include <inttypes.h>
#include <libgen.h>
#include <spawn.h>
#include <statcounters.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sysexits.h>

extern char **environ;

static const struct option options[] = {
	{ "archname", required_argument, NULL, 'a' },
	{ "csv-noheader", no_argument, NULL, 'c' },
	{ "help", no_argument, NULL, 'h' },
	{ "format", required_argument, NULL, 'f' },
	{ "output", required_argument, NULL, 'o' },
	{ "progname", required_argument, NULL, 'p' },
	{ "quiet", no_argument, NULL, 'q' },
	{ "verbose", no_argument, NULL, 'v' },
	{ NULL, 0, NULL, 0 }
};

static void
usage(int exitcode)
{
	warnx("usage: beri_count_stats [-q/--quiet] [-v/--verbose] [-o file] <command>");
	fprintf(stderr, "options:\n");
	for (int i = 0; options[i].name != NULL; i++) {
		fprintf(stderr, "  --%s/-%c\n", options[i].name, options[i].val);
	}

	exit(exitcode);
}

int
main(int argc, char **argv)
{
	int status;
	pid_t pid;
	bool verbose = false;
	bool quiet = false;
	const char* output_filename = NULL;
	const char* progname = NULL;
	const char* architecture = "unknown";
	int opt;
	statcounters_fmt_flag_t statcounters_format = HUMAN_READABLE;

	/* Start option string with + to avoid parsing after first non-option */
	while ((opt = getopt_long(argc, argv, "+a:chf:o:p:qv", options, NULL)) != -1) {
		switch (opt) {
		case 'q':
			quiet = true;
			break;
		case 'v':
			verbose = true;
			break;
		case 'h':
			usage(0);
			break;
		case 'a':
			architecture = optarg;
			break;
		case 'o':
			output_filename = optarg;
			break;
		case 'p':
			progname = optarg;
			break;
		case 'c':
			/* Force the use of CSV format without the header: */
			unsetenv("STATCOUNTERS_FORMAT");
			statcounters_format = CSV_NOHEADER;
			break;
		case 'f':
			unsetenv("STATCOUNTERS_FORMAT");
			if (strcmp(optarg, "csv") == 0) {
				statcounters_format = CSV_HEADER;
			} else if (strcmp(optarg, "csv-noheader") == 0) {
				statcounters_format = CSV_NOHEADER;
			} else {
				errx(EX_DATAERR, "Invalid format %s", optarg);
			}
			break;
		default:
			usage(1);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 0)
		usage(1);
	if (strcmp("--help", argv[0]) == 0 || strcmp("-h", argv[0]) == 0)
		usage(0);
	if (strcmp("-q", argv[0]) == 0 || strcmp("--quiet", argv[0]) == 0) {
		argc--;
		argv++;
		quiet = true;
	}
	if (strcmp("-v", argv[0]) == 0 || strcmp("--verbose", argv[0]) == 0) {
		argc--;
		argv++;
		verbose = true;
	}

	statcounters_bank_t start_count;
	statcounters_sample(&start_count);
	status = posix_spawnp(&pid, argv[0], NULL, NULL, argv, environ);
	if (status != 0)
		errc(EX_OSERR, status, "posix_spawnp(%s)", argv[0]);

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
	if (!progname) {
		progname = basename(argv[0]);
	}
	if (quiet) {
		/* Only print cycles,instructions and TLB misses */
		printf("cyles:                 %12" PRId64 "\n", diff_count.cycle);
		printf("instructions:          %12" PRId64 "\n", diff_count.inst);
		printf("instructions (user):   %12" PRId64 "\n", diff_count.inst_user);
		printf("instructions (kernel): %12" PRId64 "\n", diff_count.inst_kernel);
		printf("tlb misses (data):     %12" PRId64 "\n", diff_count.dtlb_miss);
		printf("tlb misses (instr):    %12" PRId64 "\n", diff_count.itlb_miss);
		exit(WEXITSTATUS(status));
	}
	/* Also dump to stderr when -v was passed */
	if (verbose) {
		/* Ensure human readable output: */
		const char* original_fmt = getenv("STATCOUNTERS_FORMAT");
		unsetenv("STATCOUNTERS_FORMAT");
		statcounters_dump_with_args(&diff_count, progname, NULL,
		    architecture, stderr, HUMAN_READABLE);
		setenv("STATCOUNTERS_FORMAT", original_fmt, 1);
	}
	FILE* output_file = NULL;
	if (!output_filename || strcmp(output_filename, "-") == 0) {
		output_file = stdout;
	} else {
		output_file = fopen(output_filename, "a");
		/* If we are writing to a regular file and the offset is not
		 * zero omit the CSV header */
		if (statcounters_format == CSV_HEADER && ftello(output_file) > 0) {
			statcounters_format = CSV_NOHEADER;
		}
		if (!output_file) {
			err(EX_OSERR, "fopen(%s)", output_filename);
		}
	}
	// FIXME: find out architecture from executable header e_flags?
	statcounters_dump_with_args(&diff_count, progname, NULL,
	    architecture, output_file, statcounters_format);
	exit(WEXITSTATUS(status));
}
