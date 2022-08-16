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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
usage(void)
{

	fprintf(stderr,
	    "usage: colookup -c name\n"
	    "       colookup -i index -n name [-i index -n name ...] command [args ...]\n"
	    "       colookup -s\n");
	exit(0);
}

static void
maybe_add(int *capcp, void * __capability **capvp, int *chosenp, char **registeredp)
{
	void * __capability lookedup;
	int error;

	if (*chosenp < 0 || *registeredp == NULL)
		return;

	error = colookup(*registeredp, &lookedup);
	if (error != 0)
		err(1, "%s", *registeredp);
	error = capvset(capcp, capvp, *chosenp, lookedup);
	if (error != 0)
		err(1, "capvset");

	*chosenp = -1;
	*registeredp = NULL;
}

int
main(int argc, char **argv)
{
	void * __capability *capv;
	void * __capability lookedup;
	void * __capability code;
	void * __capability data;
	char *tmp = NULL, *registered = NULL;
	int capc, ch, chosen = -1, error;

	capvfetch(&capc, &capv);

	while ((ch = getopt(argc, argv, "c:i:n:s")) != -1) {
		switch (ch) {
		case 'c':
			error = colookup(optarg, &lookedup);
			if (error != 0)
				err(1, "%s", optarg);
			printf("%s: %#lp\n", optarg, lookedup);
			return (0);
		case 'i':
			if (chosen >= 0)
				errx(-1, "-i specified more than once");
			chosen = strtol(optarg, &tmp, 10);
			if (*tmp != '\0')
				errx(1, "argument to -i must be a number");
			if (chosen < 0)
				usage();
			maybe_add(&capc, &capv, &chosen, &registered);
			break;
		case 'n':
			if (registered != NULL)
				errx(-1, "-n specified more than once");
			registered = optarg;
			maybe_add(&capc, &capv, &chosen, &registered);
			break;
		case 's':
			error = _cosetup(COSETUP_COCALL, &code, &data);
			if (error != 0)
				err(1, "cosetup");
			printf("cocall %#lp, %#lp\n", code, data);
			error = _cosetup(COSETUP_COACCEPT, &code, &data);
			if (error != 0)
				err(1, "cosetup");
			printf("coaccept %#lp, %#lp\n", code, data);
			return (0);
		case '?':
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1 || chosen >= 0 || registered != NULL)
		usage();

	coexecvpc(getppid(), argv[0], argv, capv, capc);
	err(1, "%s", argv[0]);
}
