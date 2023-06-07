/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020,2021 SRI International
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

#include <sys/param.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cheribsdtest.h"

static void
test_strfcap_C_cap_one(void * __capability p, int expected_tokens,
    const char *descr)
{
	char perms[16], *permsp;
	char attr[32];
	char str[128];
	unsigned long addr, base, top;
	int tokens;

	assert(expected_tokens == 1 || expected_tokens == 4 ||
	    expected_tokens == 5);

	strfcap(str, sizeof(str), "%C", (uintcap_t)p);
	tokens = sscanf(str, "%lx [%15[^,],%lx-%lx] %31s", &addr, perms, &base,
	    &top, attr);
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
#ifdef __aarch64__
	if ((cheri_getperm(p) & CHERI_PERM_EXECUTIVE) != 0) {
		if (*permsp != 'E')
			cheribsdtest_failure_errx("Missing 'E' permission for %s",
			    descr);
		permsp++;
	}
#endif
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

static void
test_strfcap_number_one_cap(uintcap_t cap, const char *cap_desc)
{
	char *cap_bytes, *format, str_s[33], str_p[33];
	const char spec_chars[] = "ablopstv";
	struct {
		const char *strfcap_format;
		const char *printf_format;
		const char *desc;
	} formats[] = {
		{"%S", "%ld", "plain number"},
		{"%.4S", "%.4ld", "precision"},
		{"%16S", "%16ld", "padding"},
		{"%-16S", "%-16ld", "right align padding"},
		{"%16.4S", "%16.4ld", "padding and precision"},

		{"%xS", "%lx", "plain number"},
		{"%#xS", "%#lx", "0x prefix"},
		{"%#.4xS", "%#.4lx", "precision"},
		{"%#16xS", "%#16lx", "padding"},
		{"%#16xS", "%#16lx", "right align padding"},
		{"%#16.4xS", "%#16.4lx", "padding and precision"},

		{"%XS", "%lX", "uppercase, plain number"},
		{"%#XS", "%#lX", "uppercase, 0x prefix"},
		{"%#.4XS", "%#.4lX", "uppercase, precision"},
		{"%#16XS", "%#16lX", "uppercase, padding"},
		{"%#16XS", "%#16lX", "uppercase, right align padding"},
		{"%#16.4XS", "%#16.4lX", "uppercase, padding and precision"},
	};
	ssize_t ret_s, ret_p;
	size_t value;

	for (size_t s = 0; s < nitems(formats); s++) {
		for (const char *scp = spec_chars; *scp != '\0'; scp++) {
			format = strdup(formats[s].strfcap_format);
			*strchr(format, 'S') = *scp;
			ret_s = strfcap(str_s, sizeof(str_s), format, cap);

			switch (*scp) {
			case 'a':	value = cheri_getaddress(cap); break;
			case 'b':	value = cheri_getbase(cap); break;
			case 'l':	value = cheri_getlength(cap); break;
			case 'o':	value = cheri_getoffset(cap); break;
			case 'p':	value = cheri_getperm(cap); break;
			case 's':	value = cheri_gettype(cap); break;
			case 'S':	value = cheri_gettype(cap); break;
			case 't':	value = cheri_gettop(cap); break;
			case 'v':	value = cheri_gettag(cap); break;
			default:
				cheribsdtest_failure_errx("Internal error: "
				    "unknown specifier %c", *scp);
			}
			if (*scp == 'S' &&
			    value == (size_t)CHERI_OTYPE_UNSEALED)
				strcpy(str_p, "<unsealed>");
			else if (*scp == 'S' &&
			    value == (size_t)CHERI_OTYPE_SENTRY)
				strcpy(str_p, "<sentry>");
			else
				ret_p = snprintf(str_p, sizeof(str_p),
				    formats[s].printf_format, value);
			if (strcmp(str_s, str_p) != 0) {
				cheribsdtest_failure_errx("strfcap (%s) and "
				    "printf (%s) don't match when formatting "
				    "%s with %s (%s)",
				    str_s, str_p, cap_desc, formats[s].desc,
				    format);
			}
			free(format);
		}
	}

	ret_s = strfcap(str_s, sizeof(str_s), "%B", cap);
	if (ret_s != sizeof(void * __capability) * 2)
		cheribsdtest_failure_errx("wrong size (%zu) returned from "
		    "%%B format should be (%zu) string: (%s)",
		    ret_s, sizeof(void * __capability) * 2, str_s);
	cap_bytes = (char *)&cap;
	snprintf(str_p, sizeof(str_p), "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
	    cap_bytes[0], cap_bytes[1], cap_bytes[2], cap_bytes[3],
	    cap_bytes[4], cap_bytes[5], cap_bytes[6], cap_bytes[7],
	    cap_bytes[8], cap_bytes[9], cap_bytes[10], cap_bytes[11],
	    cap_bytes[12], cap_bytes[13], cap_bytes[14], cap_bytes[15]);
	if (strcmp(str_s, str_p) != 0)
		cheribsdtest_failure_errx("strfcap output (%s) does not "
		    "match byte-wise printf (%s) when formatting %s with "
		    "%%B (raw hex)", str_s, str_p, cap_desc);

}

CHERIBSDTEST(strfcap_numbers, "Checks of formats of a single number")
{
	char foo[4];
	char * __capability foop = foo;

	test_strfcap_number_one_cap((uintcap_t)4, "scaler (4)");

	test_strfcap_number_one_cap((uintcap_t)foop, "stack array");

	test_strfcap_number_one_cap((uintcap_t)cheri_cleartag(foop),
	    "stack array");

	test_strfcap_number_one_cap(
	    (uintcap_t)__builtin_cheri_global_data_get(), "DDC");

	test_strfcap_number_one_cap(
	    (uintcap_t)__builtin_cheri_program_counter_get(), "PCC");

	cheribsdtest_success();
}

CHERIBSDTEST(strfcap_T, "Check of tag in format")
{
	char str_t[128], str_u[128];
	char * __capability cap = (__cheri_tocap char * __capability)str_t;

	strfcap(str_t, sizeof(str_t), "%C", (uintcap_t)cap);
	strfcap(str_u, sizeof(str_u), "%C", (uintcap_t)cheri_cleartag(cap));
	if (strcmp(str_t, str_u) == 0)
		cheribsdtest_failure_errx("Tagged (%s) and untagged (%s) %%C "
		    "formatted output is identical", str_t, str_u);

	strfcap(str_u, sizeof(str_u), "%T%C", (uintcap_t)cheri_cleartag(cap));
	if (strcmp(str_t, str_u) != 0)
		cheribsdtest_failure_errx("Tagged (%s) and untagged (%s) "
		    "differs when untagged formatted with %%T%%C",
		    str_t, str_u);

	cheribsdtest_success();
}

CHERIBSDTEST(strfcap_textual, "Checks of %? and %%")
{
	char str[128];
	char * __capability cap = str;
	const char *fmt;

	fmt = "%%";
	strfcap(str, sizeof(str), fmt, 0);
	if (strcmp(str, "%") != 0)
		cheribsdtest_failure_errx("(%s) produced (%s)", fmt, str);

	fmt = "%?12345%a";
	strfcap(str, sizeof(str), fmt, (uintcap_t)cap);
	if (strncmp(str, "12345", 5) != 0)
		cheribsdtest_failure_errx("(%s) did not include 12345 (%s)",
		    fmt, str);

	fmt = "%?12345%A";
	strfcap(str, sizeof(str), fmt, (uintcap_t)cap);
	if (strcmp(str, "") != 0)
		cheribsdtest_failure_errx("(%s) of valid cap is not empty (%s)",
		    fmt, str);

	fmt = "%?12345%A";
	strfcap(str, sizeof(str), fmt, (uintcap_t)cheri_cleartag(cap));
	if (strncmp(str, "12345", 5) != 0)
		cheribsdtest_failure_errx("(%s) of untagged cap did not "
		    "include 12345 (%s)", fmt, str);

	cheribsdtest_success();
}

CHERIBSDTEST(strfcap_C, "Various checks of %C (%A and %P indirectly)")
{
	char data[64];
	uintcap_t scalar = (uintcap_t)4;
	char * __capability datap = data;

	strfcap(data, sizeof(data), "%#C", scalar);
	if (strcmp(data, "0x4") != 0)
		cheribsdtest_failure_errx("Wrong output for simple scalar '%s'",
		    data);

	strfcap(data, sizeof(data), "%#.4C", scalar);
	if (strcmp(data, "0x0004") != 0)
		cheribsdtest_failure_errx("Wrong output for simple scalar "
		    "with precision '%s'", data);

	strfcap(data, sizeof(data), "%#8C", scalar);
	if (strcmp(data, "     0x4") != 0)
		cheribsdtest_failure_errx("Wrong output for simple scalar "
		    "with padding '%s'", data);

	strfcap(data, sizeof(data), "%#-8C", scalar);
	if (strcmp(data, "0x4     ") != 0)
		cheribsdtest_failure_errx("Wrong output for simple scalar "
		    "with left adjust padding '%s'", data);

	strfcap(data, sizeof(data), "%#8.4C", scalar);
	if (strcmp(data, "  0x0004") != 0)
		cheribsdtest_failure_errx("Wrong output for simple scalar "
		    "with precision and padding '%s'", data);

#ifdef __CHERI_PURE_CAPABILITY__
	test_strfcap_C_cap_one(__builtin_return_address(0), 5, "return address");
#endif

	test_strfcap_C_cap_one(datap, 4, "stack array");

	test_strfcap_C_cap_one(cheri_cleartag(datap), 5, "untagged stack array");

	cheribsdtest_success();
}
