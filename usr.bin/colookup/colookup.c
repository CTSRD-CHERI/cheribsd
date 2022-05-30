/*-
 * Copyright (c) 2022 Edward Tomasz Napierala <trasz@FreeBSD.org>
 * All rights reserved.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory as part of the CHERI for Hypervisors and Operating Systems
 * (CHaOS) project, funded by EPSRC grant EP/V000292/1.
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

#include <sys/auxv.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
usage(void)
{

	fprintf(stderr,
	    "usage: colookups -i index name [-i index name ...] command [args ...]\n");
	exit(0);
}

int
main(int argc, char **argv)
{
	void * __capability *capv;
	void * __capability lookedup;
	char *tmp;
	int capc, ch, entry, error;

	capvfetch(&capc, &capv);
	if (capc <= 0) {
		//warnx("no capability vector");
	}

	while ((ch = getopt(argc, argv, "i:")) != -1) {
		switch (ch) {
		case 'i':
			entry = strtol(optarg, &tmp, 10);
			if (*tmp != '\0')
				errx(1, "argument to -i must be a number");
			if (entry < 0)
				usage();

			if (argv[optind] == NULL)
				errx(1, "missing name for colookup(2)");
			error = colookup(argv[optind], &lookedup);
			if (error != 0) {
				if (errno == ESRCH) {
					warnx("received ESRCH; this usually means there's nothing coregistered for \"%s\"", argv[optind]);
					warnx("use coexec(1) to colocate; you might also find \"ps aux -o vmaddr\" useful");
				}
				err(1, "colookup");
			}
			optind++;

			error = capvset(&capc, &capv, entry, lookedup);
			if (error != 0)
				err(1, "capvset");
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

	coexecvpc(getppid(), argv[0], argv, capv, capc);
	err(1, "%s", argv[0]);

	return (EDOOFUS);
}
