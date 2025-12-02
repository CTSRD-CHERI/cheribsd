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
#include <sys/malloc.h>
#include <sys/sysctl.h>
#include <errno.h>
#include <fcntl.h>
#include <memstat.h>
#include <stdio.h>
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

static struct memory_type_list *
fetch_malloc_stats(void)
{
	struct memory_type_list *mtlp;

	mtlp = memstat_mtl_alloc();
	ATF_REQUIRE(mtlp != NULL);
	ATF_REQUIRE_MSG(memstat_sysctl_malloc(mtlp, 0) == 0,
	    "memstat_sysctl_malloc: %s",
	    memstat_strerror(memstat_mtl_geterror(mtlp)));
	return (mtlp);
}

/*
 * Temporarily adjust the address of the M_LINKER.ks_shortdesc pointer
 * by one byte.  Fetch the malloc stats before and after the change to
 * ensure that the reported description of M_LINKER changes from
 * "linker" to "inker".
 */
ATF_TC_WITHOUT_HEAD(adjust_malloc_description);
ATF_TC_BODY(adjust_malloc_description, tc)
{
	const char descr[] = "linker";
	struct memory_type_list *mtlp;
	ptraddr_t cap_addr, desc_addr;
	char *data_descr;
	size_t len;
	ssize_t rv;
	int fd[2];

	fd[0] = open("/dev/ace2-ace-data", O_RDONLY);
	ATF_REQUIRE_MSG(fd[0] != -1, "/dev/ace2-ace-data: %s", strerror(errno));
	fd[1] = open("/dev/ace2-ace-capability", O_RDWR);
	ATF_REQUIRE_MSG(fd[1] != -1, "/dev/ace2-ace-capability: %s",
	    strerror(errno));

	/* cap_addr holds the address of M_LINKER.ks_shortdesc */
	cap_addr = symbol_address("M_LINKER");
	cap_addr += offsetof(struct malloc_type, ks_shortdesc);

	/* Ensure M_LINKER exists with the normal description. */
	mtlp = fetch_malloc_stats();
	ATF_REQUIRE_MSG(memstat_mtl_find(mtlp, ALLOCATOR_MALLOC, descr) !=
	    NULL, "No malloc stat named \"%s\" exists", descr);
	ATF_REQUIRE_MSG(memstat_mtl_find(mtlp, ALLOCATOR_MALLOC, descr + 1) ==
	    NULL, "Malloc stat named \"%s\" exists", descr + 1);
	memstat_mtl_free(mtlp);

	/* Read the current address of ks_shortdesc. */
	rv = pread(fd[1], &desc_addr, sizeof(desc_addr), cap_addr);
	ATF_REQUIRE_MSG(rv != -1, "cap pread: %s", strerror(errno));
	ATF_REQUIRE_INTEQ(sizeof(desc_addr), rv);
	printf("Original address: %p\n", (void *)(uintptr_t)desc_addr);

	/*
	 * Read the string at desc_addr and check that it matches the
	 * sysctl description.
	 */
	len = strlen(descr) + 1;
	data_descr = malloc(len);
	rv = pread(fd[0], data_descr, len, desc_addr);
	ATF_REQUIRE_MSG(rv != -1, "data pread: %s", strerror(errno));
	ATF_REQUIRE_INTEQ(len, rv);

	printf("Description read from address: %.*s\n", (int)len, data_descr);
	ATF_REQUIRE(memcmp(descr, data_descr, len) == 0);

	/* Move the ks_shortdesc address one byte forward. */
	desc_addr++;
	rv = pwrite(fd[1], &desc_addr, sizeof(desc_addr), cap_addr);
	ATF_REQUIRE_MSG(rv != -1, "cap pwrite: %s", strerror(errno));
	ATF_REQUIRE_INTEQ(sizeof(desc_addr), rv);

	/* Ensure M_LINKER now uses the adjusted description. */
	mtlp = fetch_malloc_stats();
	ATF_REQUIRE_MSG(memstat_mtl_find(mtlp, ALLOCATOR_MALLOC, descr + 1) !=
	    NULL, "No malloc stat named \"%s\" exists", descr + 1);
	ATF_REQUIRE_MSG(memstat_mtl_find(mtlp, ALLOCATOR_MALLOC, descr) ==
	    NULL, "Malloc stat named \"%s\" exists", descr);
	memstat_mtl_free(mtlp);

	/* Restore the ks_shortdesc address. */
	desc_addr--;
	rv = pwrite(fd[1], &desc_addr, sizeof(desc_addr), cap_addr);
	ATF_REQUIRE_MSG(rv != -1, "cap pwrite: %s", strerror(errno));
	ATF_REQUIRE_INTEQ(sizeof(desc_addr), rv);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, read_version);
	ATF_TP_ADD_TC(tp, toggle_bootverbose);
	ATF_TP_ADD_TC(tp, adjust_malloc_description);
	return (atf_no_error());
}
