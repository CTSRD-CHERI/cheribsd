/*-
 * Copyright (c) 2025 John Baldwin <john@araratriver.co>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency (DARPA) Contract No. FA8750-24-C-B047 ("DEC").
 */

#include <sys/linker.h>
#include <sys/sysctl.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

static u_long
symbol_address(const char *name)
{
	struct kld_sym_lookup ksl;

	memset(&ksl, 0, sizeof(ksl));
	ksl.version = sizeof(ksl);
	ksl.symname = __DECONST(char *, name);

	/* XXX: Assumes the kernel is file 1. */
	if (kldsym(1, KLDSYM_LOOKUP, &ksl) == -1)
		ATF_REQUIRE_MSG(false, "kldsym(%s): %s", name, strerror(errno));

	return (ksl.symvalue);
}

/*
 * Read the contents of the `version` symbol via sysctl(3) as well as
 * /dev/ace2-ace-data and verify both return the same string.
 */
ATF_TC_WITHOUT_HEAD(read_version);
ATF_TC_BODY(read_version, tc)
{
	char *buf1, *buf2;
	size_t len;
	ssize_t nread;
	int fd;

	fd = open("/dev/ace2-ace-data", O_RDONLY);
	ATF_REQUIRE_MSG(fd != -1, "/dev/ace2-ace-data: %s", strerror(errno));

	ATF_REQUIRE_MSG(sysctlbyname("kern.version", NULL, &len, NULL, 0) == 0,
	    "sysctl(kern.version): %s", strerror(errno));

	buf1 = malloc(len);
	ATF_REQUIRE_MSG(sysctlbyname("kern.version", buf1, &len, NULL, 0) == 0,
	    "sysctl(kern.version): %s", strerror(errno));

	buf2 = malloc(len);
	nread = pread(fd, buf2, len, symbol_address("version"));
	ATF_REQUIRE_MSG(nread != -1, "pread: %s", strerror(errno));
	ATF_REQUIRE_INTEQ(len, nread);
	ATF_REQUIRE_INTEQ(0, memcmp(buf1, buf2, len));
}

/*
 * Use /dev/ace2-ace-data to toggle the value of bootverbose querying
 * the value via sysctl(3) before and after to validate the change.
 */
ATF_TC_WITHOUT_HEAD(toggle_bootverbose);
ATF_TC_BODY(toggle_bootverbose, tc)
{
	size_t len;
	ssize_t nwritten;
	int fd, new, old;

	fd = open("/dev/ace2-ace-data", O_WRONLY);
	ATF_REQUIRE_MSG(fd != -1, "/dev/ace2-ace-data: %s", strerror(errno));

	len = sizeof(old);
	ATF_REQUIRE_MSG(sysctlbyname("debug.bootverbose", &old, &len, NULL,
	    0) == 0, "sysctl(debug.bootverbose): %s", strerror(errno));
	ATF_REQUIRE_INTEQ(sizeof(old), len);

	new = old ^ 1;
	nwritten = pwrite(fd, &new, sizeof(new), symbol_address("bootverbose"));
	ATF_REQUIRE_MSG(nwritten != -1, "pwrite: %s", strerror(errno));
	ATF_REQUIRE_INTEQ(sizeof(new), nwritten);

	len = sizeof(old);
	ATF_REQUIRE_MSG(sysctlbyname("debug.bootverbose", &old, &len, NULL,
	    0) == 0, "sysctl(debug.bootverbose): %s", strerror(errno));
	ATF_REQUIRE_INTEQ(sizeof(old), len);

	ATF_REQUIRE_INTEQ(new, old);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, read_version);
	ATF_TP_ADD_TC(tp, toggle_bootverbose);
	return (atf_no_error());
}
