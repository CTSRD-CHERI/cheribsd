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

#include <sys/param.h>
#include <sys/auxv.h>
#include <assert.h>
#include <capv.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
usage(void)
{

	fprintf(stderr,
	    "usage: capv [-ckn]\n"
	    "       capv [-k] -i entry [-i entry ...] command [args ...]\n");
	exit(0);
}

static int
interrogate(void * __capability target, char **bufp, bool kflag, bool vflag)
{
	capv_answerback_t in;
	capv_t out;
	int error;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	out.len = sizeof(out);
	out.op = 0;

	//fprintf(stderr, "%s: out %#lp, outlen %zd, in %#lp, inlen %zd\n", __func__, &out, out.len, &in, sizeof(in));

	if (kflag)
		error = cocall_slow(target, &out, out.len, &in, sizeof(in));
	else
		error = cocall(target, &out, out.len, &in, sizeof(in));
	if (error != 0)
		return (errno);

	if (in.len != sizeof(in)) {
		warnx("received in.len %zd >= %zd", in.len, sizeof(in));
		return (ENOMSG);
	}

	if (!vflag) {
		/*
		 * Try doing this with libxo :->
		 */
		in.answerback[66] = '.';
		in.answerback[67] = '.';
		in.answerback[68] = '.';
		in.answerback[69] = '\0';
	}

	*bufp = strndup(in.answerback, sizeof(in.answerback));
	return (0);
}

int
main(int argc, char **argv)
{
	void * __capability *capv, * __capability *new_capv;
	char *tmpstr;
	char *tmp;
	int capc, ch, entry, error, i;
	bool cflag = false, iflag = false, kflag = false, nflag = false, vflag = false;

	error = elf_aux_info(AT_CAPC, &capc, sizeof(capc));
	if (error != 0)
		errc(1, error, "AT_CAPC");
	if (capc <= 0)
		errx(1, "no capability vector");

	error = elf_aux_info(AT_CAPV, &capv, sizeof(capv));
	if (error != 0)
		errc(1, error, "AT_CAPV");

	assert(capv != NULL);

	new_capv = calloc(capc, sizeof(new_capv));
	if (new_capv == NULL)
		err(1, "calloc");
	memset(new_capv, 0, capc * sizeof(new_capv));

	while ((ch = getopt(argc, argv, "ci:knv")) != -1) {
		switch (ch) {
		case 'c':
			cflag = true;
			break;
		case 'i':
			entry = strtol(optarg, &tmp, 10);
			if (*tmp != '\0')
				errx(1, "argument to -i must be a number");
			if (entry < 0)
				usage();
			iflag = true;
			if (entry >= capc) {
				// Silently ignore for convenience.
				break;
			}
			new_capv[entry] = capv[entry];
			break;
		case 'k':
			kflag = true;
			break;
		case 'n':
			nflag = true;
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

	if (iflag) {
		if (argc < 1)
			usage();
	} else {
		if (argc != 0)
			usage();
	}

	if (iflag) {
		coexecvpc(getppid(), argv[0], argv, new_capv, capc);
		err(1, "%s", argv[0]);
	}

	if (!nflag) {
		error = cosetup(COSETUP_COCALL);
		if (error != 0)
			err(1, "cosetup");
	}

	for (i = 0; i < capc; i++) {
		if (capv[i] == NULL)
			continue;

		printf("%d", i);
		if (cflag)
			printf(":\t%#lp", capv[i]);
		if (!nflag) {
			error = interrogate(capv[i], &tmpstr, kflag, vflag);
			if (error != 0) {
				printf(":\t%s", strerror(error));
			} else {
				/* XXX Double quotes to hint that this string came from the service itself? */
				printf(":\t\"%s\"", tmpstr);
				free(tmpstr);
			}
		}
		printf("\n");
	}

	return (0);
}
