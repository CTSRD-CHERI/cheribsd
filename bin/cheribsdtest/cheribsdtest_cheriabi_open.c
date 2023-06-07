/*-
 * Copyright (c) 2017 Edward Tomasz Napierala
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

#if !__has_feature(capabilities)
#error "This code requires a CHERI-aware compiler"
#endif

#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/time.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "cheribsdtest.h"

CHERIBSDTEST(cheriabi_open_ordinary, "Smoke test for open(2)")
{
	char path[] = "/dev/null";
	int error, fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		cheribsdtest_failure_err("open");

	error = close(fd);
	if (error != 0)
		cheribsdtest_failure_err("close");

	cheribsdtest_success();
}

CHERIBSDTEST(cheriabi_open_offset, "Path with non-zero offset")
{
	char pathbuf[] = "xxxx/dev/null";;
	char *path;
	int error, fd;

	path = pathbuf;
	path += 4;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		cheribsdtest_failure_err("open");

	error = close(fd);
	if (error != 0)
		cheribsdtest_failure_err("close");

	cheribsdtest_success();
}

CHERIBSDTEST(cheriabi_open_shortened,
    "Path shorter than its capability bounds")
{
	char path[] = "/dev/null/xxxx";
	int error, fd;

	path[9] = '\0';

	fd = open(path, O_RDONLY);
	if (fd < 0)
		cheribsdtest_failure_err("open");

	error = close(fd);
	if (error != 0)
		cheribsdtest_failure_err("close");

	cheribsdtest_success();
}

CHERIBSDTEST(cheriabi_open_bad_addr, "Path with nonsensical address")
{
	char *path;
	int fd;

	path = (char *)(intptr_t)90210;

	fd = open(path, O_RDONLY);
	if (fd > 0)
		cheribsdtest_failure_errx("open succeeded");

	if (errno != EFAULT)
		cheribsdtest_failure_err("EFAULT expected");

	cheribsdtest_success();
}

CHERIBSDTEST(cheriabi_open_bad_addr_2,
    "Path with nonsensical address in kernel range")
{
	char *path;
	int fd;

	path = (char *)(intptr_t)-90210;

	fd = open(path, O_RDONLY);
	if (fd > 0)
		cheribsdtest_failure_errx("open succeeded");

	if (errno != EFAULT)
		cheribsdtest_failure_err("EFAULT expected");

	cheribsdtest_success();
}

CHERIBSDTEST(cheriabi_open_bad_len,
    "Path too long for the capaility bounds")
{
	char pathbuf[] = "/dev/null";
	char *path;
	int fd;

	path = cheri_setbounds(pathbuf, strlen(pathbuf));

	fd = open(path, O_RDONLY);
	if (fd > 0)
		cheribsdtest_failure_errx("open succeeded");

	if (errno != EFAULT)
		cheribsdtest_failure_err("EFAULT expected");

	cheribsdtest_success();
}

CHERIBSDTEST(cheriabi_open_bad_len_2, "Path with offset past its bounds")
{
	char pathbuf[] = "xxxx/dev/null";;
	char *path;
	int fd;

	path = cheri_setbounds(pathbuf, 3);
	path += 4;

	fd = open(path, O_RDONLY);
	if (fd > 0)
		cheribsdtest_failure_errx("open succeeded");

	if (errno != EFAULT)
		cheribsdtest_failure_err("EFAULT expected");

	cheribsdtest_success();
}

CHERIBSDTEST(cheriabi_open_bad_tag, "Path with tag bit missing")
{
	char pathbuf[] = "/dev/null";
	char *path;
	int fd;

	path = cheri_cleartag(pathbuf);

	fd = open(path, O_RDONLY);
	if (fd > 0)
		cheribsdtest_failure_errx("open succeeded");

	if (errno != EFAULT)
		cheribsdtest_failure_err("EFAULT expected");

	cheribsdtest_success();
}

CHERIBSDTEST(cheriabi_open_bad_perm,
    "Path with CHERI_PERM_LOAD permission missing")
{
	char pathbuf[] = "/dev/null";
	char *path;
	int fd;

	path = cheri_andperm(pathbuf, ~CHERI_PERM_LOAD);

	fd = open(path, O_RDONLY);
	if (fd > 0)
		cheribsdtest_failure_errx("open succeeded");

	if (errno != EFAULT)
		cheribsdtest_failure_err("EFAULT expected");

	cheribsdtest_success();
}

CHERIBSDTEST(cheriabi_open_sealed, "Sealed path")
{
	char *path, *sealed_path;
	void *sealer;
	size_t sealer_size;
	int fd;

	sealer_size = sizeof(sealer);
	if (sysctlbyname("security.cheri.sealcap", &sealer, &sealer_size,
	    NULL, 0) < 0)
		cheribsdtest_failure_err("sysctlbyname(security.cheri.sealcap)");

	/* Allocate enough space that it's sealable for 128-bit */
	path = calloc(1, 1<<12);
	if (path == NULL)
		cheribsdtest_failure_err("calloc");
	strcpy(path, "/dev/null");
	sealed_path = cheri_seal(path, sealer);

	fd = open(sealed_path, O_RDONLY);
	free(path);
	if (fd > 0)
		cheribsdtest_failure_errx("open succeeded");

	if (errno != EFAULT)
		cheribsdtest_failure_err("EFAULT expected");

	cheribsdtest_success();
}
