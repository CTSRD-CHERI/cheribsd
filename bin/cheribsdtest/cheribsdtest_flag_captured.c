/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 SRI International
 * All rights reserved.
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
#include <sys/syscall.h>
#include <sys/sysctl.h>

#include <unistd.h>

#include "cheribsdtest.h"

#define	CORRECT_KEY	0xfe77c0de
#define	INCORRECT_KEY	0

static void
call_flag_captured(const char *message, uint32_t key)
{
	int error;
	uint64_t fc_old, fc_new;
	uint64_t fck_old, fck_new;
	size_t fc_size = sizeof(uint64_t);

	if (sysctlbyname("security.flags_captured", &fc_old, &fc_size,
	    NULL, 0) != 0)
		cheribsdtest_failure_err("sysctl(security.flags_captured)");
	if (sysctlbyname("security.flags_captured_key", &fck_old, &fc_size,
	    NULL, 0) != 0)
		cheribsdtest_failure_err("sysctl(security.flags_captured_key)");

	error = syscall(SYS_flag_captured, message, key);
	if (error)
		cheribsdtest_failure_err("call failed");

	if (sysctlbyname("security.flags_captured", &fc_new, &fc_size,
	    NULL, 0) != 0)
		cheribsdtest_failure_err("sysctl(security.flags_captured)");
	if (fc_new != fc_old + 1) {
		cheribsdtest_failure_errx(
		    "security.flags_captured not incremented");
	}
	if (sysctlbyname("security.flags_captured_key", &fck_new, &fc_size,
	    NULL, 0) != 0)
		cheribsdtest_failure_err("sysctl(security.flags_captured_key)");
	if (key == CORRECT_KEY) {
		if (fck_new != fck_old + 1) {
			cheribsdtest_failure_errx("security.flags_captured_key "
			    "not incremented with correct key");
		}
	} else {
		if (fck_new != fck_old) {
			cheribsdtest_failure_errx("security.flags_captured_key "
			    "incremented with incorrect key");
		}
	}

	cheribsdtest_success();
}

void
test_flag_captured(const struct cheri_test *ctp __unused)
{

	call_flag_captured(__func__, CORRECT_KEY);
}

void
test_flag_captured_incorrect_key(const struct cheri_test *ctp __unused)
{

	call_flag_captured(__func__, INCORRECT_KEY);
}

void
test_flag_captured_null(const struct cheri_test *ctp __unused)
{

	call_flag_captured(NULL, CORRECT_KEY);
}

#ifdef __CHERI_PURE_CAPABILITY__
void
test_flag_captured_empty(const struct cheri_test *ctp __unused)
{
	char buf[] = "";

	call_flag_captured(cheri_setbounds(buf, 0), CORRECT_KEY);
}
#endif
