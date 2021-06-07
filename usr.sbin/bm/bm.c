/*-
 * Copyright (c) 2018 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
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
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>  
#include <langinfo.h>
#include <limits.h>
#include <locale.h>
#include <paths.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <timeconv.h>
#include <unistd.h>
#include <utmpx.h>

struct beri_cmd {
	int test;
};

#define	BM_RESET	_IOWR('X', 1, struct beri_cmd)
#define	BM_RELEASE	_IOWR('X', 2, struct beri_cmd)
#define	BUFSIZE		32

static void
usage(void)
{

	fprintf(stderr, "usage: bm [-rR] [-l filename]\n");

	exit(1);
}

static int
write_file(int fd, char *filename)
{
	char buffer[BUFSIZE];
	ssize_t bytes;
	int fd1;

	printf("%s: %s\n", __func__, filename);

	if (filename == NULL)
		return (-1);

	fd1 = open(filename, O_RDONLY);
	if (fd1 == -1) {
		printf("Failed to open %s\n", filename);
		return (-2);
	}

	do {
		bytes = read(fd1, buffer, BUFSIZE);
		write(fd, buffer, bytes);
	} while (bytes > 0);

	return (0);
}

int
main(int argc, char *argv[])
{
	struct beri_cmd cmd;
	char *filename;
	int fd;
	int ch;
	int reset_flag;
	int load_flag;
	int release_flag;
	int error;

	fd = open("/dev/beri0", O_RDWR);
	if (fd == -1) {
		warn("Unable to open beri manager device");
	}

	reset_flag = 0;
	load_flag = 0;
	release_flag = 0;
	filename = NULL;

	while ((ch = getopt(argc, argv, "rl:R")) != -1) {
		switch (ch) {
		case 'r':		/* Reset */
			reset_flag = 1;
			break;
		case 'l':		/* Load file */
			load_flag = 1;
			filename = optarg;
			break;
		case 'R':		/* Release */
			release_flag = 1;
			break;
		default:
			usage();

			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (reset_flag) {
		if (ioctl(fd, BM_RESET, &cmd) != 0) {
			printf("Failed to reset.\n");
			return (1);
		}
	}

	if (load_flag) {
		error = write_file(fd, filename);
		if (error != 0)
			return (2);
	}

	if (release_flag) {
		if (ioctl(fd, BM_RELEASE, &cmd) != 0) {
			printf("Failed to release CPU1.\n");
			return (3);
		}
	}

	return (0);
}
