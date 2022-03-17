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

	fprintf(stderr, "usage: copong [-s time] [-kxv] service-name [target-name ...]\n");
	exit(0);
}

int
main(int argc, char **argv)
{
	char inout[BUFSIZ];
	void * __capability cookie;
	void * __capability *lookedup;
	char *registered, *tmp;
	uint64_t *halfcookie;
	pid_t pid;
	float dt = 0.0;
	bool kflag = false, vflag = false, xflag = false;
	int c, ch, error;

	while ((ch = getopt(argc, argv, "ks:xv")) != -1) {
		switch (ch) {
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
		case 'x':
			xflag = true;
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

	registered = argv[0];

	if (vflag)
		fprintf(stderr, "%s: %s: setting up...\n",
		    getprogname(), registered);
	error = cosetup(COSETUP_COACCEPT);
	if (error != 0)
		err(1, "cosetup");

	argc--;
	argv++;

	if (argc > 0) {
		if (vflag)
			fprintf(stderr, "%s: %s: setting up the caller side...\n",
			    getprogname(), registered);
		error = cosetup(COSETUP_COCALL);
		if (error != 0)
			err(1, "cosetup");

		lookedup = malloc(argc * sizeof(void * __capability));
		if (lookedup == NULL)
			err(1, "malloc");

		for (c = 0; c < argc; c++) {
			if (vflag)
				fprintf(stderr, "%s: %s: colooking up \"%s\"...\n",
				    getprogname(), registered, argv[c]);
			error = colookup(argv[c], &lookedup[c]);
			if (error != 0) {
				if (errno == ESRCH) {
					warnx("received ESRCH; this usually means there's nothing coregistered for \"%s\"", argv[c]);
					warnx("use coexec(1) to colocate; you might also find \"ps aux -o vmaddr\" useful");
				}
				err(1, "colookup");
			}
		}
	}

	if (vflag)
		fprintf(stderr, "%s: %s: coregistering...\n", getprogname(), registered);
	error = coregister(registered, NULL);
	if (error != 0)
		err(1, "coregister");

	if (vflag)
		fprintf(stderr, "%s: %s: coaccepting...\n", getprogname(), registered);

	for (;;) {
		if (kflag)
			error = coaccept_slow(&cookie, inout, sizeof(inout), inout, sizeof(inout));
		else
			error = coaccept(&cookie, inout, sizeof(inout), inout, sizeof(inout));
		if (error != 0)
			warn("coaccept");
		if (vflag) {
			halfcookie = (uint64_t *)&cookie;
			error = cogetpid(&pid);
			if (error != 0)
				warn("cogetpid");
			printf("%s: %s: coaccepted, pid %d, caller pid %d, cookie %#lx%lx\n",
			    getprogname(), registered, getpid(), pid, halfcookie[0], halfcookie[1]);
		}

		for (c = 0; c < argc; c++) {
			if (vflag)
				fprintf(stderr, "%s: %s: cocalling \"%s\"...\n",
				    getprogname(), registered, argv[c]);
			if (kflag)
				error = cocall_slow(lookedup[c], inout, sizeof(inout), inout, sizeof(inout));
			else
				error = cocall(lookedup[c], inout, sizeof(inout), inout, sizeof(inout));
			if (error != 0)
				warn("cocall");
			if (vflag)
				printf("%s: %s: returned from \"%s\", pid %d\n",
				    getprogname(), registered, argv[c], getpid());
		}

		if (dt > 0)
			usleep(dt * 1000000);

		if (xflag)
			abort();
	}
}
