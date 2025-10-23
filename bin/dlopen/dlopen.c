/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 SRI International
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency (DARPA) Contract No. FA8750-24-C-B047 ("DEC").
 */

#include <sys/cdefs.h>

#include <dlfcn.h>
#include <err.h>
#include <libutil.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static bool verbose = false;
static bool dump_comparts = false;
static int seconds = -1;
static int dlopen_mode = RTLD_NOW;
static int dlopen_local_global = 0; /* dlopen(3)'s default is RTLD_LOCAL */

static void _Noreturn
usage(void)
{
	printf("usage: dlopen [-L|N] [-g|l] [-s <seconds>] [-d <compname>] [-p <comppath> [-v] <lib> [...]\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	int ch;
	uint64_t num;
	char *disable = NULL, *path = NULL;

	while ((ch = getopt(argc, argv, "d:DgLlNp:s:v")) != -1) {
		switch (ch) {
		case 'd':
			disable = optarg;
			break;
		case 'D':
			dump_comparts = true;
			break;
		case 'g':
			dlopen_local_global = RTLD_GLOBAL;
			break;
		case 'l':
			dlopen_local_global = RTLD_LOCAL;
			break;
		case 'L':
			dlopen_mode = RTLD_LAZY;
			break;
		case 'N':
			dlopen_mode = RTLD_NOW;
			break;
		case 'p':
			path = optarg;
			break;
		case 's':
			if (expand_number(optarg, &num) != 0)
				err(1, "bad number '%s'", optarg);
			if (num > INT_MAX)
				seconds = INT_MAX;
			else
				seconds = num;
			break;
		case 'v':
			verbose = true;
			break;
		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	for (int i = 0; i < argc; i++) {
		if (dlopen(argv[i], dlopen_mode | dlopen_local_global) == NULL)
			errx(1, "dlopen(%s)", argv[i]);
		if (verbose)
			printf("loaded %s\n", argv[i]);
	}

	if (dump_comparts)
		if (!dl_c18n_control(NULL, NULL, C18N_CONTROL_DUMP, 0))
			errx(1, "dl_c18n_control(C18N_CONTROL_DUMP)");

	if (disable != NULL) {
		if (!dl_c18n_control(path, disable, C18N_CONTROL_DISABLE, 0))
			errx(1, "dl_c18n_control(\"%s\", \"%s\", "
			    "C18N_CONTROL_DISABLE)", path, disable);
	}

	if (seconds <= 0) {
		if (verbose)
			printf("waiting for input\n");
		(void)getchar();
	} else {
		if (verbose)
			printf("sleeping for %d seconds\n", seconds);
		sleep(seconds);
	}
	return (0);
}
