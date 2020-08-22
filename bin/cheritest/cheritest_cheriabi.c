/*-
 * Copyright (c) 2016 SRI International
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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/signal.h>
#include <sys/sysctl.h>
#include <sys/time.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <machine/sysarch.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "cheritest.h"

#define	PERM_READ	(CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP)
#define	PERM_WRITE	(CHERI_PERM_STORE | CHERI_PERM_STORE_CAP | \
			    CHERI_PERM_STORE_LOCAL_CAP)
#define	PERM_EXEC	CHERI_PERM_EXECUTE
#define	PERM_RWX	(PERM_READ|PERM_WRITE|PERM_EXEC)

#ifdef CHERI_MMAP_SETBOUNDS
void
test_cheriabi_mmap_nospace(const struct cheri_test *ctp __unused)
{
	size_t len;
	void *cap;

	/* Remove all space from the default mmap capability. */
	len = 0;
	if (sysarch(CHERI_MMAP_SETBOUNDS, &len) != 0)
		cheritest_failure_err(
		    "sysarch(CHERI_MMAP_SETBOUNDS, 0) failed");
	if ((cap = mmap(0, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_ANON, -1, 0)) != MAP_FAILED)
		cheritest_failure_err(
		    "mmap() returned a a pointer when it should have failed");

	cheritest_success();
}
#endif

#ifdef CHERI_MMAP_GETPERM
void
test_cheriabi_mmap_perms(const struct cheri_test *ctp __unused)
{
	uint64_t perms, operms;
	void *cap, *tmpcap;

	if (sysarch(CHERI_MMAP_GETPERM, &perms) != 0)
		cheritest_failure_err("sysarch(CHERI_MMAP_GETPERM) failed");

	/*
	 * Make sure perms we are going to try removing are there...
	 */
	if (!(perms & CHERI_PERM_SW0))
		cheritest_failure_errx(
		    "no CHERI_PERM_SW0 in default perms (0x%lx)", perms);
	if (!(perms & CHERI_PERM_SW2))
		cheritest_failure_errx(
		    "no CHERI_PERM_SW2 in default perms (0x%lx)", perms);

	if ((cap = mmap(0, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_ANON, -1, 0)) == MAP_FAILED)
		cheritest_failure_err("mmap() failed");

	if (cheri_getperm(cap) != perms)
		cheritest_failure_errx("mmap() returned with perms 0x%lx "
		    "instead of expected 0x%lx", cheri_getperm(cap), perms);

	if (munmap(cap, PAGE_SIZE) != 0)
		cheritest_failure_err("munmap() failed");

	operms = perms;
	perms = ~CHERI_PERM_SW2;
	if (sysarch(CHERI_MMAP_ANDPERM, &perms) != 0)
		cheritest_failure_err("sysarch(CHERI_MMAP_ANDPERM) failed");
	if (perms != (operms & ~CHERI_PERM_SW2))
		cheritest_failure_errx("sysarch(CHERI_MMAP_ANDPERM) did not "
		    "just remove CHERI_PERM_SW2.  Got 0x%lx but "
		    "expected 0x%lx", perms,
		    operms & ~CHERI_PERM_SW2);
	if (sysarch(CHERI_MMAP_GETPERM, &perms) != 0)
		cheritest_failure_err("sysarch(CHERI_MMAP_GETPERM) failed");
	if (perms & CHERI_PERM_SW2)
		cheritest_failure_errx("sysarch(CHERI_MMAP_ANDPERM) failed "
		    "to remove CHERI_PERM_SW2.  Got 0x%lx.", perms);

	if ((cap = mmap(0, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_ANON, -1, 0)) == MAP_FAILED)
		cheritest_failure_err("mmap() failed");

	if (cheri_getperm(cap) & CHERI_PERM_SW2)
		cheritest_failure_errx("mmap() returned with "
		    "CHERI_PERM_SW2 after restriction (0x%lx)",
		    cheri_getperm(cap));

	cap = cheri_andperm(cap, ~CHERI_PERM_SW0);
	if ((cap = mmap(cap, PAGE_SIZE, PROT_READ,
	    MAP_ANON|MAP_FIXED, -1, 0)) == MAP_FAILED)
		cheritest_failure_err("mmap(MAP_FIXED) failed");
	if (cheri_getperm(cap) & CHERI_PERM_SW0)
		cheritest_failure_errx(
		    "mmap(MAP_FIXED) returned with CHERI_PERM_SW0 in perms "
		    "without it in addr (perms 0x%lx)", cheri_getperm(cap));

	if (munmap(cap, PAGE_SIZE) != 0)
		cheritest_failure_err("munmap() failed");

	if ((cap = mmap(0, PAGE_SIZE, PROT_NONE, MAP_ANON, -1, 0)) ==
	    MAP_FAILED)
		cheritest_failure_err("mmap() failed");
	if (cheri_getperm(cap) & PERM_RWX)
		cheritest_failure_errx("mmap(PROT_NONE) returned unrequested "
		    "permissions (0x%lx)", cheri_getperm(cap));

	if (munmap(cap, PAGE_SIZE) != 0)
		cheritest_failure_err("munmap() failed");

	/* Attempt to unmap without CHERI_PERM_CHERIABI_VMMAP */
	if ((cap = mmap(0, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_ANON, -1, 0)) == MAP_FAILED)
		cheritest_failure_err("mmap() failed");
	tmpcap = cheri_andperm(cap, ~CHERI_PERM_CHERIABI_VMMAP);
	if (munmap(tmpcap, PAGE_SIZE) == 0)
		cheritest_failure_errx(
		    "munmap() unmapped without CHERI_PERM_CHERIABI_VMMAP");

	/*
	 * Try to map over the previous mapping to check that it is still
	 * there.
	 */
	if ((tmpcap = mmap(cap, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_ANON|MAP_FIXED|MAP_EXCL, -1, 0)) != MAP_FAILED)
		cheritest_failure_err("mmap(%#p, MAP_FIXED|MAP_EXCL) "
		    "succeeded when page should have been mapped", cap);

	if (munmap(cap, PAGE_SIZE) != 0)
		cheritest_failure_err("munmap() failed after overlap check");

	/*
	 * Attempt to MAP_FIXED though a valid capability without
	 * CHERI_PERM_CHERIABI_VMMAP.
	 */
	if ((cap = mmap(0, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_ANON, -1, 0)) == MAP_FAILED)
		cheritest_failure_err("mmap() failed");
	tmpcap = cheri_andperm(cap, ~CHERI_PERM_CHERIABI_VMMAP);

	if ((tmpcap = mmap(tmpcap, PAGE_SIZE, PROT_NONE, MAP_ANON|MAP_FIXED, -1, 0)) !=
	    MAP_FAILED)
		cheritest_failure_errx(
		    "mmap(MAP_FIXED) succeeded through a cap without"
		    " CHERI_PERM_CHERIABI_VMMAP (original %#p, new %#p)",
		    cap, tmpcap);

	if (munmap(cap, PAGE_SIZE) != 0)
		cheritest_failure_err("munmap() failed after MAP_FIXED "
		    "without permission");

	/* Disallow executable pages */
	perms = ~PERM_EXEC;
	if (sysarch(CHERI_MMAP_ANDPERM, &perms) != 0)
		cheritest_failure_err("sysarch(CHERI_MMAP_ANDPERM) failed");
	if ((cap = mmap(0, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_ANON, -1, 0)) != MAP_FAILED)
		cheritest_failure_err("mmap(PROT_READ|PROT_WRITE|PROT_EXEC) "
		    "succeeded after removing PROT_EXEC from default cap");

	cheritest_success();
}
#endif	/* CHERI_MMAP_GETPERM */

#ifdef CHERI_BASELEN_BITS
void
test_cheriabi_mmap_unrepresentable(const struct cheri_test *ctp __unused)
{
	size_t len = ((size_t)PAGE_SIZE << CHERI_BASELEN_BITS) + 1;
	size_t expected_len;
	void *cap;

	expected_len = __builtin_cheri_round_representable_length(len);
	if ((cap = mmap(0, len, PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_ANON, -1, 0)) == MAP_FAILED)

		cheritest_failure_errx("mmap() failed to return a pointer "
		   "when given an unrepresentable length (%zu)", len);
	if (cheri_getlen(cap) != expected_len)
		cheritest_failure_errx("mmap() returned a pointer with "
		    "an unexpected length (%zu vs %zu) when given an "
		    "unrepresentable length (%zu): %#p", cheri_getlen(cap),
		    expected_len, len, cap);

	cheritest_success();
}
#endif

void
test_cheriabi_malloc_zero_size(const struct cheri_test *ctp __unused)
{
	void *cap;

	cap = malloc(0);
	if (cap != NULL && cheri_getlength(cap) != 0)
		cheritest_failure_errx("malloc(0) returned a non-NULL capability with "
		    "non-zero length (%zu)", cheri_getlength(cap));
	cheritest_success();
}

static void
test_cheriabi_printf_cap_one(void *p, int expected_tokens, const char *descr)
{
	char perms[16], *permsp;
	char attr[32];
	char *str;
	unsigned long addr, base, top;
	int tokens;

	assert(expected_tokens == 1 || expected_tokens == 4 ||
	    expected_tokens == 5);

	asprintf(&str, "%#p", p);
	tokens = sscanf(str, "%lx [%15[^,],%lx-%lx] %31s", &addr, perms, &base,
	    &top, attr);
	free(str);
	if (tokens != expected_tokens)
		cheritest_failure_errx("Mismatched tokens for %s, "
		    "expected %d got %d", descr, expected_tokens, tokens);

	if (addr != cheri_getaddress(p))
		cheritest_failure_errx("Mismatched address for %s", descr);

	if (tokens == 1)
		return;

	permsp = perms;
	if ((cheri_getperm(p) & CHERI_PERM_LOAD) != 0) {
		if (*permsp != 'r')
			cheritest_failure_errx("Missing 'r' permission for %s",
			    descr);
		permsp++;
	}
	if ((cheri_getperm(p) & CHERI_PERM_STORE) != 0) {
		if (*permsp != 'w')
			cheritest_failure_errx("Missing 'w' permission for %s",
			    descr);
		permsp++;
	}
	if ((cheri_getperm(p) & CHERI_PERM_EXECUTE) != 0) {
		if (*permsp != 'x')
			cheritest_failure_errx("Missing 'x' permission for %s",
			    descr);
		permsp++;
	}
	if ((cheri_getperm(p) & CHERI_PERM_LOAD) != 0) {
		if (*permsp != 'R')
			cheritest_failure_errx("Missing 'R' permission for %s",
			    descr);
		permsp++;
	}
	if ((cheri_getperm(p) & CHERI_PERM_STORE) != 0) {
		if (*permsp != 'W')
			cheritest_failure_errx("Missing 'W' permission for %s",
			    descr);
		permsp++;
	}
	if (*permsp != '\0')
		cheritest_failure_errx("Extra permissions '%s' for %s", permsp,
		    descr);

	if (base != cheri_getbase(p))
		cheritest_failure_errx("Mismatched base for %s", descr);
	if (top != cheri_getbase(p) + cheri_getlength(p))
		cheritest_failure_errx("Mismatched top for %s", descr);

	if (tokens == 4)
		return;

	if (cheri_gettag(p)) {
		if (strstr(attr, "invalid") != NULL)
			cheritest_failure_errx("Tagged cap marked invalid "
			    "for %s", descr);
	} else {
		if (strstr(attr, "invalid") == NULL)
			cheritest_failure_errx("Untagged cap not marked "
			    "invalid for %s", descr);
	}

	switch (cheri_gettype(p)) {
	case CHERI_OTYPE_UNSEALED:
		if (strstr(attr, "sealed") != NULL)
			cheritest_failure_errx("Unsealed cap marked as "
			    "sealed for %s", descr);
		if (strstr(attr, "sentry") != NULL)
			cheritest_failure_errx("Unsealed cap marked as "
			    "sentry for %s", descr);
		break;
	case CHERI_OTYPE_SENTRY:
		if (strstr(attr, "sealed") != NULL)
			cheritest_failure_errx("Sentry cap marked as "
			    "sealed for %s", descr);
		if (strstr(attr, "sentry") == NULL)
			cheritest_failure_errx("Sentry cap not marked as "
			    "sentry for %s", descr);
		break;
	default:
		if (strstr(attr, "sealed") == NULL)
			cheritest_failure_errx("Sealed cap not marked as "
			    "sealed for %s", descr);
		if (strstr(attr, "sentry") != NULL)
			cheritest_failure_errx("Sealed cap marked as "
			    "sentry for %s", descr);
		break;
	}
}

void
test_cheriabi_printf_cap(const struct cheri_test *ctp __unused)
{
	char data[64];

	snprintf(data, sizeof(data), "%#p", (void *)(uintcap_t)4);
	if (strcmp(data, "0x4") != 0)
		cheritest_failure_errx("Wrong output for simple scalar");

	snprintf(data, sizeof(data), "%#.4p", (void *)(uintcap_t)4);
	if (strcmp(data, "0x0004") != 0)
		cheritest_failure_errx("Wrong output for simple scalar "
		    "with precision");

	snprintf(data, sizeof(data), "%#8p", (void *)(uintcap_t)4);
	if (strcmp(data, "     0x4") != 0)
		cheritest_failure_errx("Wrong output for simple scalar "
		    "with padding");

	snprintf(data, sizeof(data), "%#-8p", (void *)(uintcap_t)4);
	if (strcmp(data, "0x4     ") != 0)
		cheritest_failure_errx("Wrong output for simple scalar "
		    "with left adjust padding");

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat"
	snprintf(data, sizeof(data), "%#08p", (void *)(uintcap_t)4);
	if (strcmp(data, "     0x4") != 0)
		cheritest_failure_errx("Wrong output for simple scalar "
		    "with zero (ignored) padding");
#pragma clang diagnostic pop

	snprintf(data, sizeof(data), "%#8.4p", (void *)(uintcap_t)4);
	if (strcmp(data, "  0x0004") != 0)
		cheritest_failure_errx("Wrong output for simple scalar "
		    "with precision and padding");

	test_cheriabi_printf_cap_one(__builtin_return_address(0), 5,
	    "return address");

	test_cheriabi_printf_cap_one((void *)(uintcap_t)4, 1,
	    "null-derived capability");

	test_cheriabi_printf_cap_one(data, 4, "stack array");

	test_cheriabi_printf_cap_one(cheri_cleartag(data), 5,
	    "untagged stack array");

	cheritest_success();
}
