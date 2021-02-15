/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2019-2020 Alex Richardson <arichardson@FreeBSD.org>
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * This work was supported by Innovate UK project 105694, "Digital Security by
 * Design (DSbD) Technology Platform Prototype".
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
#include <sys/time.h>
#include <sys/wait.h>

#include <assert.h>
#include <err.h>
#include <getopt.h>
#include <inttypes.h>
#include <libgen.h>
#include <spawn.h>
#include <statcounters.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern char **environ;

/* clang-format off */
static const struct option options[] = {
	{ "archname", required_argument, NULL, 'a' },
	{ "basic", no_argument, NULL, 'b' },
	{ "csv-noheader", no_argument, NULL, 'c' },
	{ "help", no_argument, NULL, 'h' },
	{ "format", required_argument, NULL, 'f' },
	{ "output", required_argument, NULL, 'o' },
	{ "progname", required_argument, NULL, 'p' },
	{ "quiet", no_argument, NULL, 'q' },
	{ "time-only", no_argument, NULL, 't' },
	{ "verbose", no_argument, NULL, 'v' },
	{ NULL, 0, NULL, 0 }
};
/* clang-format on */

static void
read_counters(statcounters_bank_t *c, bool basic_only, bool time_only)
{
	memset(c, 0, sizeof(*c));
	if (time_only)
		return;

	if (basic_only) {
		c->cycles = statcounters_read_cycles();
		c->instructions = statcounters_read_instructions();
	} else {
		statcounters_sample(c);
	}
}

static void
usage(int exitcode)
{
	warnx("usage: %s [-f format] [-o file] <command>", getprogname());
	fprintf(stderr, "options:\n");
	for (int i = 0; options[i].name != NULL; i++) {
		fprintf(stderr, "  --%s/-%c\n", options[i].name,
		    options[i].val);
	}

	exit(exitcode);
}

static void
print_basic_human_readable_diff(FILE *f, struct timespec *elapsed_time,
    statcounters_bank_t *diff)
{
	fprintf(f, "Elapsed time:          %jd.%09jds\n",
	    (intmax_t)elapsed_time->tv_sec, (intmax_t)elapsed_time->tv_nsec);
	fprintf(f, "cyles:                 %12" PRId64 "\n", diff->cycles);
	fprintf(f, "instructions:          %12" PRId64 "\n",
	    diff->instructions);
}

int
main(int argc, char **argv)
{
	int status;
	pid_t pid;
	bool verbose = false;
	bool quiet = false;
	bool basic_only = false;
	bool time_only = false;
	const char *output_filename = NULL;
	const char *progname = NULL;
	const char *architecture = NULL;
	int opt;
	statcounters_bank_t start_count;
	statcounters_bank_t end_count;
	statcounters_bank_t diff_count;
	struct timespec start_ts;
	struct timespec end_ts;
	struct timespec ts_diff;
	statcounters_fmt_flag_t statcounters_format =
	    (statcounters_fmt_flag_t)-1;

	/* Start option string with + to avoid parsing after first non-option */
	while ((opt = getopt_long(argc, argv, "+a:bchf:o:p:qtv", options,
	    NULL)) != -1) {
		switch (opt) {
		case 'b':
			basic_only = true;
			break;
		case 't':
			time_only = true;
			break;
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
			statcounters_format = CSV_NOHEADER;
			break;
		case 'f':
			if (strcmp(optarg, "csv") == 0) {
				statcounters_format = CSV_HEADER;
			} else if (strcmp(optarg, "csv-noheader") == 0) {
				statcounters_format = CSV_NOHEADER;
			} else {
				errx(1, "Invalid format %s", optarg);
			}
			break;
		default:
			usage(1);
		}
	}
	/* Infer default value for statcounters_format from the environment. */
	const char *original_fmt = getenv("STATCOUNTERS_FORMAT");
	if (statcounters_format == (statcounters_fmt_flag_t)-1) {
		if (original_fmt && strcmp(original_fmt, "csv") == 0) {
			/*
			 * If the file is non-empty, we will change this to
			 * CSV_NOHEADER later to avoid duplicate headers.
			 */
			statcounters_format = CSV_HEADER;
		} else {
			statcounters_format = HUMAN_READABLE;
		}
	}
	if (output_filename == NULL) {
		output_filename = getenv("STATCOUNTERS_OUTPUT");
	}
	if (architecture == NULL) {
		architecture = getenv("STATCOUNTERS_ARCHNAME");
		if (architecture == NULL) {
			architecture = "default";
		}
	}
	if (progname == NULL) {
		progname = getenv("STATCOUNTERS_PROGNAME");
	}

	argc -= optind;
	argv += optind;

	if (argc == 0)
		usage(1);
	if (!progname) {
		progname = basename(argv[0]);
	}

	/*
	 * Call clock_gettime first so that counters are read just before start
	 * and just after completion.
	 */
	if (clock_gettime(CLOCK_MONOTONIC_PRECISE, &start_ts) != 0)
		err(1, "clock_gettime");
	read_counters(&start_count, basic_only, time_only);
	status = posix_spawnp(&pid, argv[0], NULL, NULL, argv, environ);
	if (status != 0)
		errc(1, status, "posix_spawnp(%s)", argv[0]);

	waitpid(pid, &status, 0);
	if (!WIFEXITED(status)) {
		warnx("child exited abnormally");
	}
	read_counters(&end_count, basic_only, time_only);
	if (clock_gettime(CLOCK_MONOTONIC_PRECISE, &end_ts) != 0)
		err(1, "clock_gettime");

	timespecsub(&end_ts, &start_ts, &ts_diff);
	statcounters_diff(&diff_count, &end_count, &start_count);

	if (quiet) {
		/* Only print cycles,instructions and time elapsed */
		print_basic_human_readable_diff(stderr, &ts_diff, &diff_count);
		exit(WEXITSTATUS(status));
	}

	FILE *output_file = NULL;
	if (!output_filename || strcmp(output_filename, "-") == 0) {
		output_file = stdout;
	} else {
		output_file = fopen(output_filename, "a");
		/* Also dump basic stats to stderr when -v was passed. */
		if (verbose) {
			print_basic_human_readable_diff(stderr, &ts_diff,
			    &diff_count);
		}
		if (!output_file) {
			err(1, "fopen(%s)", output_filename);
		}
		/*
		 * If we are writing to a regular file and the offset is not
		 * zero omit the CSV header.
		 */
		if (statcounters_format == CSV_HEADER &&
		    ftello(output_file) > 0) {
			statcounters_format = CSV_NOHEADER;
		}
	}
	if (basic_only || time_only) {
		if (statcounters_format == HUMAN_READABLE) {
			print_basic_human_readable_diff(output_file, &ts_diff,
			    &diff_count);
		} else {
			/*
			 * CSV output requested: This should be compatible
			 * with existing libstatcounters analysis scripts.
			 */
			if (statcounters_format == CSV_HEADER) {
				fprintf(output_file,
				    "progname,archname,cycles,"
				    "instructions,clock-monotonic\n");
			} else {
				assert(statcounters_format == CSV_NOHEADER);
			}
			fprintf(output_file, "%s,%s,%jd,%jd,%jd.%09jd\n",
			    progname, architecture, (intmax_t)diff_count.cycles,
			    (intmax_t)diff_count.instructions,
			    (intmax_t)ts_diff.tv_sec,
			    (intmax_t)ts_diff.tv_nsec);
		}
	} else {
		statcounters_dump_with_args(&diff_count, progname, "",
		    architecture, output_file, statcounters_format);
	}
	return (status);
}
