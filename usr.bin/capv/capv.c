/*-
 * Copyright (c) 2018 Edward Tomasz Napierala <trasz@FreeBSD.org>
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
#include <sys/nv.h>
#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void
usage(void)
{

	fprintf(stderr, "usage: capv [-kv]\n");
	exit(0);
}

static void
interrogate(void * __capability target, char **bufp, bool kflag)
{
	char in[BUFSIZ];
	nvlist_t *nvl;
	void *out;
	size_t outlen;
	int error;

	nvl = nvlist_create(NV_FLAG_MEMALIGN);
	nvlist_add_number(nvl, "op", 42 /* XXX */);
	out = nvlist_pack(nvl, &outlen);
	assert(out != NULL);
	nvlist_destroy(nvl);

	if (kflag)
		error = cocall_slow(target, out, outlen, in, sizeof(in));
	else
		error = cocall(target, out, outlen, in, sizeof(in));
	free(out);
	if (error != 0) {
		warn("cocall");
		return;
	}

	nvl = nvlist_unpack(in, sizeof(in), NV_FLAG_MEMALIGN);
	if (nvl == NULL) {
		warnx("nvlist_unpack(3) failed");
		return;
	}

	asprintf(bufp, "%s", nvlist_get_string(nvl, "answerback" /* XXX */));
	nvlist_destroy(nvl);
}

int
main(int argc, char **argv)
{
	void * __capability *capv;
	char *buf = NULL;
	int capc, ch, error, i;
	bool kflag = false, vflag = false;

	while ((ch = getopt(argc, argv, "kv")) != -1) {
		switch (ch) {
		case 'k':
			kflag = true;
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
	if (argc != 0)
		usage();

	error = elf_aux_info(AT_CAPC, &capc, sizeof(capc));
	if (error != 0)
		errc(1, error, "AT_CAPC");

	error = elf_aux_info(AT_CAPV, &capv, sizeof(capv));
	if (error != 0) {
		if (error == ENOENT)
			errx(1, "no capability vector");
		errc(1, error, "AT_CAPV");
	}

	if (vflag) {
		error = cosetup(COSETUP_COCALL);
		if (error != 0)
			err(1, "cosetup");
	}

	if (capc == 0)
		assert(capv == NULL);
	else
		assert(capv != NULL);

	for (i = 0; i < capc; i++) {
		if (capv[i] == NULL)
			continue;

		if (vflag) {
			interrogate(capv[i], &buf, kflag);
			printf("%i:\t%#lp: %s\n", i, capv[i], buf);
		} else {
			printf("%i:\t%#lp\n", i, capv[i]);
		}
	}

	return (0);
}
