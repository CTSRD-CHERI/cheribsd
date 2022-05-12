/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2021 SRI International
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

#define	STR_VAL	"123"

CHERIBSDTEST(test_store_local_allowed,
    "Checks local capabilities can be stored via default capabilities")
{
	char str[] = STR_VAL;
	char * __capability cap = str;
	char * __capability target;
	char * __capability * __capability targetp = &target;

	CHERIBSDTEST_VERIFY(strcmp(STR_VAL, str) == 0);
	*targetp = cap;
	CHERIBSDTEST_VERIFY(
	    strcmp(STR_VAL, (__cheri_fromcap char *)target) == 0);

	/* Make cap local */
	cap = cheri_andperm(cap, ~CHERI_PERM_GLOBAL);

	/* Store local cap through cap with store-local permission */
	*targetp = cap;
	CHERIBSDTEST_VERIFY(
	    strcmp(STR_VAL, (__cheri_fromcap char *)target) == 0);

	cheribsdtest_success();
}

CHERIBSDTEST(test_store_local_disallowed,
    "Checks local capabilities can not be stored via non-store-local capabilities",
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO,
    .ct_signum = SIGPROT,
    .ct_si_code = SI_CODE_STORELOCAL,
    .ct_si_trapno = TRAPNO_LOAD_STORE)
{
	char str[] = STR_VAL;
	char * __capability cap = str;
	char * __capability target;
	char * __capability * __capability targetp = &target;

	CHERIBSDTEST_VERIFY(strcmp(STR_VAL, str) == 0);
	*targetp = cap;
	CHERIBSDTEST_VERIFY(
	    strcmp(STR_VAL, (__cheri_fromcap char *)target) == 0);

	/* Make cap local */
	cap = cheri_andperm(cap, ~CHERI_PERM_GLOBAL);

	/* Store local cap through cap without store-local permission */
	targetp = cheri_andperm(targetp, ~CHERI_PERM_STORE_LOCAL_CAP);
	/* This should fault */
	*targetp = cap;

	cheribsdtest_failure_errx(
	    "No fault after storing local cap via non-store-local cap");
}
