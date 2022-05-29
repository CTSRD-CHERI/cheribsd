/*-
 * Copyright (c) 2018 Edward Tomasz Napierala <trasz@FreeBSD.org>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
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
__FBSDID("$FreeBSD$");

#include <machine/sysarch.h>
#include <sys/auxv.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static bool aflag = false, kflag = false, vflag = false;

static void
usage(void)
{

	fprintf(stderr, "usage: coping [-c count] [-s time] [-kv] -a\n");
	fprintf(stderr, "usage: coping [-c count] [-s time] [-kv] -i index\n");
	fprintf(stderr, "usage: coping [-c count] [-s time] [-kv] service-name ...\n");
	exit(0);
}

static const char *
humanize(long x)
{
	static char *str = NULL;

	free(str);
	str = NULL;

	if (x > 1000000000)
		asprintf(&str, "%.3fs", x / 1000000000.0);
	else if (x > 1000000)
		asprintf(&str, "%.3fms", x / 1000000.0);
	else if (x > 1000)
		asprintf(&str, "%.3fus", x / 1000.0);
	else
		asprintf(&str, "%.3fns", x / 1.0);

	return (str);
}

static void
fetch_capv(void * __capability **capvp, int *capcp)
{
	int error;

	error = elf_aux_info(AT_CAPC, capcp, sizeof(*capcp));
	if (error != 0)
		errc(1, error, "AT_CAPC");

	error = elf_aux_info(AT_CAPV, capvp, sizeof(*capvp));
	if (error != 0) {
		if (error == ENOENT)
			errx(1, "no capability vector");
		errc(1, error, "AT_CAPV");
	}
}

static void
ping(void * __capability target, const char *target_name)
{
	struct timespec before, after, took;
	ssize_t received;
	int error;

	if (vflag || aflag) {
		if (!aflag)
			fprintf(stderr, "%s: cocalling \"%s\"...\n", getprogname(), target_name);
		error = clock_gettime(CLOCK_REALTIME, &before);
		if (error != 0)
			warn("clock_gettime");
	}

	if (kflag)
		received = cocall_slow(target, NULL, 0, NULL, 0);
	else
		received = cocall(target, NULL, 0, NULL, 0);
	if (received < 0)
		warn("cocall");

	/*
	 * We don't care about received data.  It's truncated anyway.
	 */

	if (vflag || aflag) {
		error = clock_gettime(CLOCK_REALTIME, &after);
		if (error != 0)
			warn("clock_gettime");

		timespecsub(&after, &before, &took);
		if (aflag && !vflag) {
			printf("%s: %s: %s\n",
			    getprogname(), target_name, humanize(took.tv_sec * 1000000000L + took.tv_nsec));
		} else {
			printf("%s: returned from \"%s\" after %s, pid %d\n",
			    getprogname(), target_name, humanize(took.tv_sec * 1000000000L + took.tv_nsec), getpid());
		}
	} else
		printf(".");
}

int
main(int argc, char **argv)
{
	void * __capability *capv;
	void * __capability *lookedup;
	void * __capability *target;
	char *target_name;
	char *tmp;
	float dt = 1.0;
	int capc, count = 0, ch, error, index = -1, i = 0, c = 0;

	while ((ch = getopt(argc, argv, "ac:i:ks:v")) != -1) {
		switch (ch) {
		case 'a':
			aflag = true;
			break;
		case 'c':
			count = atoi(optarg);
			if (count <= 0)
				usage();
			break;
		case 'i':
			index = strtol(optarg, &tmp, 10);
			if (*tmp != '\0')
				errx(1, "argument to -i must be a number");
			if (index < 0)
				usage();
			break;
		case 'k':
			kflag = true;
			break;
		case 's':
			dt = strtof(optarg, &tmp);
			if (*tmp != '\0')
				errx(1, "argument to -s must be a number");
			if (dt < 0)
				errx(1, "argument to -s must be >= 0.0");
			break;
		case 'v':
			vflag = true;
			break;
		case '?':
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (aflag) {
		/* coping -a */
		if (index >= 0)
			errx(1, "-a and -i are mutually exclusive");
		if (argc != 0)
			errx(1, "-a and target name are mutually exclusive");

		fetch_capv(&capv, &capc);

	} else if (index >= 0) {
		/* coping -i */
		if (argc != 0)
			errx(1, "-i and target name are mutually exclusive");

		fetch_capv(&capv, &capc);
		if (index >= capc)
			errx(1, "index %d must be lower than capc %d", index, capc);
		target = capv[index];
		asprintf(&target_name, "capv[%d]", index);
		if (target_name == NULL)
			err(1, "asprintf");

	} else {
		/* coping target-name */
		if (argc < 1)
			usage();

		lookedup = malloc(argc * sizeof(void * __capability));
		if (lookedup == NULL)
			err(1, "malloc");

		for (c = 0; c < argc; c++) {
			target_name = argv[c];
			error = colookup(target_name, &lookedup[c]);
			if (error != 0) {
				if (errno == ESRCH) {
					warnx("received ESRCH; this usually means there's nothing coregistered for \"%s\"", target_name);
					warnx("use coexec(1) to colocate; you might also find \"ps aux -o vmaddr\" useful");
				}
				err(1, "colookup");
			}
		}
	}

	error = cosetup(COSETUP_COCALL);
	if (error != 0)
		err(1, "cosetup");

	if (!vflag) {
		if (isatty(1))
			setvbuf(stdout, NULL, _IONBF, 0);
	}

	c = 0;
	for (;;) {
		if (aflag) {
			if (c == capc)
				break;
			target = capv[c];
			if (target == NULL) {
				c++;
				continue;
			}
			asprintf(&target_name, "capv[%d]", c);
			if (target_name == NULL)
				err(1, "asprintf");
			c++;

		} else if (index >= 0) {
			target = capv[index];
			asprintf(&target_name, "capv[%d]", index);
			if (target_name == NULL)
				err(1, "asprintf");
		} else {
			target = lookedup[c];
			target_name = argv[c];

			c++;
			if (c == argc)
				c = 0;
		}

		ping(target, target_name);

		i++;
		if (count != 0 && i >= count)
			break;

		if (dt > 0 && !aflag)
			usleep(dt * 1000000.0);
	}

	if (!vflag && !aflag)
		printf("\n");

	return (0);
}
