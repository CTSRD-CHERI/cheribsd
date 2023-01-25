/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 SRI International
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cheribsdtest.h"

static void
test_printf_cap_one(void * __capability p, int expected_tokens,
    const char *descr)
{
	char perms[16], *permsp;
	char attr[32];
	char *str;
	unsigned long addr, base, top;
	int tokens;

	assert(expected_tokens == 1 || expected_tokens == 4 ||
	    expected_tokens == 5);

	asprintf(&str, "%#lp", p);
	tokens = sscanf(str, "%lx [%15[^,],%lx-%lx] %31s", &addr, perms, &base,
	    &top, attr);
	free(str);
	if (tokens != expected_tokens)
		cheribsdtest_failure_errx("Mismatched tokens for %s, "
		    "expected %d got %d", descr, expected_tokens, tokens);

	if (addr != cheri_getaddress(p))
		cheribsdtest_failure_errx("Mismatched address for %s", descr);

	if (tokens == 1)
		return;

	permsp = perms;
	if ((cheri_getperm(p) & CHERI_PERM_LOAD) != 0) {
		if (*permsp != 'r')
			cheribsdtest_failure_errx("Missing 'r' permission for %s",
			    descr);
		permsp++;
	}
	if ((cheri_getperm(p) & CHERI_PERM_STORE) != 0) {
		if (*permsp != 'w')
			cheribsdtest_failure_errx("Missing 'w' permission for %s",
			    descr);
		permsp++;
	}
	if ((cheri_getperm(p) & CHERI_PERM_EXECUTE) != 0) {
		if (*permsp != 'x')
			cheribsdtest_failure_errx("Missing 'x' permission for %s",
			    descr);
		permsp++;
	}
	if ((cheri_getperm(p) & CHERI_PERM_LOAD) != 0) {
		if (*permsp != 'R')
			cheribsdtest_failure_errx("Missing 'R' permission for %s",
			    descr);
		permsp++;
	}
	if ((cheri_getperm(p) & CHERI_PERM_STORE) != 0) {
		if (*permsp != 'W')
			cheribsdtest_failure_errx("Missing 'W' permission for %s",
			    descr);
		permsp++;
	}
	if (*permsp != '\0')
		cheribsdtest_failure_errx("Extra permissions '%s' for %s", permsp,
		    descr);

	if (base != cheri_getbase(p))
		cheribsdtest_failure_errx("Mismatched base for %s", descr);
	if (top != cheri_getbase(p) + cheri_getlength(p))
		cheribsdtest_failure_errx("Mismatched top for %s", descr);

	if (tokens == 4)
		return;

	if (cheri_gettag(p)) {
		if (strstr(attr, "invalid") != NULL)
			cheribsdtest_failure_errx("Tagged cap marked invalid "
			    "for %s", descr);
	} else {
		if (strstr(attr, "invalid") == NULL)
			cheribsdtest_failure_errx("Untagged cap not marked "
			    "invalid for %s", descr);
	}

	switch (cheri_gettype(p)) {
	case CHERI_OTYPE_UNSEALED:
		if (strstr(attr, "sealed") != NULL)
			cheribsdtest_failure_errx("Unsealed cap marked as "
			    "sealed for %s", descr);
		if (strstr(attr, "sentry") != NULL)
			cheribsdtest_failure_errx("Unsealed cap marked as "
			    "sentry for %s", descr);
		break;
	case CHERI_OTYPE_SENTRY:
		if (strstr(attr, "sealed") != NULL)
			cheribsdtest_failure_errx("Sentry cap marked as "
			    "sealed for %s", descr);
		if (strstr(attr, "sentry") == NULL)
			cheribsdtest_failure_errx("Sentry cap not marked as "
			    "sentry for %s", descr);
		break;
	default:
		if (strstr(attr, "sealed") == NULL)
			cheribsdtest_failure_errx("Sealed cap not marked as "
			    "sealed for %s", descr);
		if (strstr(attr, "sentry") != NULL)
			cheribsdtest_failure_errx("Sealed cap marked as "
			    "sentry for %s", descr);
		break;
	}
}

CHERIBSDTEST(printf_cap, "Various checks of %#p")
{
	char data[64];
	void * __capability scalar = (void * __capability)(uintcap_t)4;
	char * __capability datap = data;

	snprintf(data, sizeof(data), "%#lp", scalar);
	if (strcmp(data, "0x4") != 0)
		cheribsdtest_failure_errx("Wrong output for simple scalar");

	snprintf(data, sizeof(data), "%#.4lp", scalar);
	if (strcmp(data, "0x0004") != 0)
		cheribsdtest_failure_errx("Wrong output for simple scalar "
		    "with precision");

	snprintf(data, sizeof(data), "%#8lp", scalar);
	if (strcmp(data, "     0x4") != 0)
		cheribsdtest_failure_errx("Wrong output for simple scalar "
		    "with padding");

	snprintf(data, sizeof(data), "%#-8lp", scalar);
	if (strcmp(data, "0x4     ") != 0)
		cheribsdtest_failure_errx("Wrong output for simple scalar "
		    "with left adjust padding");

	snprintf(data, sizeof(data), "%#8.4lp", scalar);
	if (strcmp(data, "  0x0004") != 0)
		cheribsdtest_failure_errx("Wrong output for simple scalar "
		    "with precision and padding");

#ifndef __CHERI_PURE_CAPABILITY__
	snprintf(data, sizeof(data) / 2, "%lp", datap);
	snprintf(data + sizeof(data) / 2, sizeof(data) / 2, "%p", data);
	if (strcmp(data, data + sizeof(data) / 2) != 0)
		cheribsdtest_failure_errx("Mismatched output for %%p (%s) and "
		    "%%lp (%s)", data + sizeof(data) / 2, data);
#endif

#ifdef __CHERI_PURE_CAPABILITY__
	test_printf_cap_one(__builtin_return_address(0), 5, "return address");
#endif

	test_printf_cap_one(datap, 4, "stack array");

	test_printf_cap_one(cheri_cleartag(datap), 5, "untagged stack array");

	cheribsdtest_success();
}
