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

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <crypto/cryptodev.h>

#include <stdlib.h>
#include <err.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

#include <zlib.h>

void
usage(void)
{

	errx(1, "usage: zlib -l length");
}

int
main(int argc, char **argv)
{
	struct crypt_op operation;
	struct session2_op session;
	z_stream zstream;
	char *input, *outbuf, *revbuf;
	int ch, error, fd;
	long length;

	length = 0;

	while ((ch = getopt(argc, argv, "l:")) != -1) {
		switch (ch) {
		case 'l':
			length = strtol(optarg, NULL, 10);
			if (length < 0 || length == LONG_MAX) {
				usage();
			}
			break;
		default:
			usage();
		}
	}

	if (length == 0) {
		usage();
	}

	input = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
	if (input == NULL) {
		err(1, "Failed to allocate memory for input");
	}

	outbuf = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
	if (outbuf == NULL) {
		err(1, "Failed to allocate memory for outbuf");
	}

	revbuf = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
	if (revbuf == NULL) {
		err(1, "Failed to allocate memory for revbuf");
	}

	fd = open("/dev/crypto", O_RDWR, 0);
	if (fd < 0) {
		err(1, "Failed to open /dev/crypto");
	}

	memset(&session, 0, sizeof(session));
	session.cipher = CRYPTO_DEFLATE_COMP;
	error = ioctl(fd, CIOCGSESSION2, &session);
	if (error == -1) {
		err(1, "Failed to create a crypto session");
	}
	memset(&operation, 0, sizeof(operation));
	operation.ses = session.ses;
	operation.op = COP_ENCRYPT;
	operation.src = input;
	operation.dst = outbuf;
	operation.len = length;
	operation.flags = COP_F_BATCH;
	error = ioctl(fd, CIOCCRYPT, &operation);
	if (error == -1) {
		err(1, "Failed to compress data using crypto");
	}

	memset(&zstream, 0, sizeof(zstream));
	zstream.next_in = (Bytef *)outbuf;
	zstream.avail_in = operation.len;
	zstream.zalloc = Z_NULL;
	zstream.zfree = Z_NULL;
	zstream.opaque = 0;
	zstream.next_out = (Bytef *)revbuf;
	zstream.avail_out = length;
	error = inflateInit2(&zstream, -15);
	if (error != Z_OK) {
		errx(1, "Failed to initialize zlib: code %u.", error);
	}
	do {
		error = inflate(&zstream, Z_SYNC_FLUSH);
	} while (error == Z_OK);
	if (error != Z_STREAM_END) {
		errx(1, "Failed to decompress data using zlib: code %d message '%s'.",
		    error, zstream.msg);
	}
	if (zstream.total_out != length) {
		errx(1, "Decompressed data length (%lu) does not match expected length (%lu).",
		    zstream.total_out, length);
	}

	if (memcmp(revbuf, input, length) != 0) {
		errx(1, "Decompressed data do not match input.");
	}

	return (0);
}
