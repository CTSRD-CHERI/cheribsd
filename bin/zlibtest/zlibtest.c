/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2014 The NetBSD Foundation, Inc.
 * All rights reserved.
 * Copyright (c) 2022 Konrad Witaszczyk
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) under Office of
 * Naval Research (ONR) Contract No. N00014-22-1-2463 ("SoftWare Integrated
 * with Secure Hardware (SWISH)").
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include <crypto/cryptodev.h>

#include <err.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <zlib.h>

static void
usage(void)
{

	fprintf(stderr,
"usage:\n"
"    zlibtest [options]\n"
"\n"
"options:\n"
"    -p  -- Pause the test after interacting with the zlib kernel module\n"
	     );
	exit(EX_USAGE);
}

static void
do_test(bool pause)
{
	int fd, res;
	struct session2_op cs;
	struct crypt_op co1;
	unsigned char buf1[10000], buf2[10000];
	char text[10000] = {0};
	z_stream z;

	fd = open("/dev/crypto", O_RDWR, 0);
	if (fd < 0)
		err(1, "open");
	memset(&cs, 0, sizeof(cs));
	cs.cipher = CRYPTO_DEFLATE_COMP;
	res = ioctl(fd, CIOCGSESSION2, &cs);
	if (res < 0)
		err(1, "CIOCGSESSION2");

	memset(&co1, 0, sizeof(co1));
	co1.ses = cs.ses;
	co1.op = COP_ENCRYPT;
	co1.src = text;
	co1.dst = (char *)&buf1;
	co1.len = sizeof(buf1);
	co1.flags = COP_F_BATCH;
	res = ioctl(fd, CIOCCRYPT, &co1);
	if (res < 0)
		err(1, "CIOCCRYPT");

	if (pause) {
		warnx("pausing the process");
		if (kill(getpid(), SIGSTOP) == -1) {
			err(1, "kill");
		}
		warnx("resuming the process");
	}

	memset(&z, 0, sizeof(z));
	z.next_in = buf1;
	z.avail_in = co1.len;
	z.zalloc = Z_NULL;
	z.zfree = Z_NULL;
	z.opaque = 0;
	z.next_out = buf2;
	z.avail_out = sizeof(buf2);
	res = inflateInit2(&z, -15);
	if (res != Z_OK)
		errx(1, "inflateInit: %d", res);
	do {
		res = inflate(&z, Z_SYNC_FLUSH);
	} while (res == Z_OK);
	if (res != Z_STREAM_END)
		errx(1, "inflate: %d msg %s", res, z.msg);
	if (z.total_out != sizeof(text))
		errx(1, "decomp len %lu", z.total_out);
	if (memcmp(buf2, text, sizeof(text)))
		errx(1, "decomp data mismatch");

	warnx("success");
}

int
main(int argc, char *argv[])
{
	int ch;
	bool pause;

	pause = false;
	while ((ch = getopt(argc, argv, "ph")) != -1) {
		switch (ch) {
		case 'p':
			pause = true;
			break;
		case 'h':
		default:
			usage();
		}
	}

	do_test(pause);

	return (0);
}
