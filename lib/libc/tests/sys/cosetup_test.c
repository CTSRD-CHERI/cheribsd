/*-
 * Copyright (c) 2020 Edward Tomasz Napierala <trasz@FreeBSD.org>
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

#include <atf-c.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/syslimits.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

ATF_TC_WITHOUT_HEAD(cosetup_cocall);
ATF_TC_BODY(cosetup_cocall, tc)
{
	void * __capability switcher_code;
	void * __capability switcher_data;
	pid_t pid;
	int error;

	pid = atf_utils_fork();
	if (pid == 0) {
		error = cosetup(COSETUP_COCALL, &switcher_code, &switcher_data);
		ATF_REQUIRE_EQ(error, 0);
		exit(error);
	} else {
		atf_utils_wait(pid, 0, "", "");
	}
}

ATF_TC_WITHOUT_HEAD(cosetup_coaccept);
ATF_TC_BODY(cosetup_coaccept, tc)
{
	void * __capability switcher_code;
	void * __capability switcher_data;
	pid_t pid;
	int error;

	pid = atf_utils_fork();
	if (pid == 0) {
		error = cosetup(COSETUP_COACCEPT, &switcher_code, &switcher_data);
		ATF_REQUIRE_EQ(error, 0);
		exit(error);
	} else {
		atf_utils_wait(pid, 0, "", "");
	}
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, cosetup_cocall);
	ATF_TP_ADD_TC(tp, cosetup_coaccept);

	return atf_no_error();
}
