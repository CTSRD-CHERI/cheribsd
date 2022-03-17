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
#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void
usage(void)
{

	fprintf(stderr, "usage: coping [-c count] [-s time] [-kv] service-name ...\n");
	exit(0);
}

int
main(int argc, char **argv)
{
	void * __capability *lookedup;
	char *tmp;
	float dt = 1.0;
	bool kflag = false, vflag = false;
	int count = 0, ch, error, i = 0, c = 0;

	while ((ch = getopt(argc, argv, "c:ks:v")) != -1) {
		switch (ch) {
		case 'c':
			count = atoi(optarg);
			if (count <= 0)
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
	if (argc < 1)
		usage();

	if (vflag)
		fprintf(stderr, "%s: setting up...\n", getprogname());
	error = cosetup(COSETUP_COCALL);
	if (error != 0)
		err(1, "cosetup");

	lookedup = malloc(argc * sizeof(void * __capability));
	if (lookedup == NULL)
		err(1, "malloc");

	for (c = 0; c < argc; c++) {
		if (vflag)
			fprintf(stderr, "%s: colooking up \"%s\"...\n", getprogname(), argv[c]);
		error = colookup(argv[c], &lookedup[c]);
		if (error != 0) {
			if (errno == ESRCH) {
				warnx("received ESRCH; this usually means there's nothing coregistered for \"%s\"", argv[c]);
				warnx("use coexec(1) to colocate; you might also find \"ps aux -o vmaddr\" useful");
			}
			err(1, "colookup");
		}
	}

	if (!vflag) {
		if (isatty(1))
			setvbuf(stdout, NULL, _IONBF, 0);
	}

	c = 0;

	for (;;) {
		if (vflag)
			fprintf(stderr, "%s: cocalling \"%s\"...\n", getprogname(), argv[c]);

		if (kflag)
			error = cocall_slow(lookedup[c], NULL, 0, NULL, 0);
		else
			error = cocall(lookedup[c], NULL, 0, NULL, 0);
		if (error != 0)
			warn("cocall");

		if (vflag)
			printf("%s: returned from \"%s\", pid %d\n", getprogname(), argv[c], getpid());
		else
			printf(".");

		c++;
		if (c == argc)
			c = 0;

		i++;
		if (count != 0 && i >= count)
			break;

		if (dt > 0)
			usleep(dt * 1000000);
	}

	if (!vflag)
		printf("\n");

	return (0);
}
