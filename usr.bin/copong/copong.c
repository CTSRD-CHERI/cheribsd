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

#include <machine/param.h>
#include <machine/sysarch.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static long long buf[1000000];

static void
usage(void)
{

	fprintf(stderr, "usage: copong [-xv] service-name\n");
	exit(0);
}

int
main(int argc, char **argv)
{
	void * __capability switcher_code;
	void * __capability switcher_data;
	void * __capability cookie;
	uint64_t *halfcookie;
	bool vflag = false, xflag = false;
	int ch, error;

	while ((ch = getopt(argc, argv, "xv")) != -1) {
		switch (ch) {
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
	if (argc != 1)
		usage();

	if (vflag)
		fprintf(stderr, "%s: setting up...\n", getprogname());
	error = cosetup(COSETUP_COACCEPT, &switcher_code, &switcher_data);
	if (error != 0)
		err(1, "cosetup");

	if (vflag)
		fprintf(stderr, "%s: coregistering as \"%s\"...\n", getprogname(), argv[0]);
	error = coregister(argv[0], NULL);
	if (error != 0)
		err(1, "coregister");

	if (vflag)
		fprintf(stderr, "%s: coaccepting...\n", getprogname());

	for (;;) {
		error = coaccept(switcher_code, switcher_data, &cookie, buf, sizeof(buf));
		if (error != 0)
			warn("coaccept");
		if (vflag) {
			halfcookie = (uint64_t *)&cookie;
			printf("pong, pid %d, cookie %#lx%lx, buf[0] is %lld\n",
			    getpid(), halfcookie[0], halfcookie[1], buf[0]);
		}
		buf[0]++;
		if (xflag)
			abort();
	}
}
