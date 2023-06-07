/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2022 SRI International
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency (DARPA) Contract No. HR001122C0110 ("ETC").
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

#include <sys/param.h>
#include <sys/mount.h>

#include <err.h>
#include <stdlib.h>
#include <unistd.h>

#include <cheri/cheric.h>

#include "cheribsdtest.h"

static const char *
skip_non_tmpfs_tmp(const char *name __unused)
{
	struct statfs sb;

	if (statfs("/tmp", &sb) != 0) {
		warn("%s: statfs(\"/tmp\")", __func__);
		return ("unable to query statfs for /tmp");
	}

	if (strcmp(sb.f_fstypename, "tmpfs") == 0)
		return (NULL);
	else
		return ("/tmp is not using tmpfs");
}

static int
create_tempfile(void)
{
	char template[] = "/tmp/cheribsdtest.XXXXXXXX";
	int fd = CHERIBSDTEST_CHECK_SYSCALL2(mkstemp(template),
	    "mkstemp %s", template);
	CHERIBSDTEST_CHECK_SYSCALL(unlink(template));
	CHERIBSDTEST_CHECK_SYSCALL(ftruncate(fd, getpagesize()));
	return (fd);
}

CHERIBSDTEST(tmpfs_rw_nocaps,
    "check that read(2) and write(2) of tmpfs files do not return tags",
    .ct_check_skip = skip_non_tmpfs_tmp)
{
	void * __capability c;
	void * __capability d;
	size_t rv;
	int fd;

	fd = create_tempfile();

	/* Just some pointer */
	c = &fd;
	CHERIBSDTEST_VERIFY2(cheri_gettag(c) != 0, "tag set on source");

	rv = CHERIBSDTEST_CHECK_SYSCALL(pwrite(fd, &c, sizeof(c), 0));
	CHERIBSDTEST_CHECK_EQ_SIZE(rv, sizeof(c));

	rv = CHERIBSDTEST_CHECK_SYSCALL(pread(fd, &d, sizeof(d), 0));
	CHERIBSDTEST_CHECK_EQ_SIZE(rv, sizeof(d));

	CHERIBSDTEST_VERIFY2(cheri_gettag(d) == 0, "tag read");
	CHERIBSDTEST_VERIFY2(cheri_equal_exact(cheri_cleartag(c), d),
	    "untagged value not read");

	CHERIBSDTEST_CHECK_SYSCALL(close(fd));
	cheribsdtest_success();
}
