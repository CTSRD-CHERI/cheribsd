/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2018 Alex Richadson <arichardson@FreeBSD.org>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
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
#include "../utils.h"

#ifdef __CHERI_PURE_CAPABILITY__
#error "This should be a hybrid binary"
#endif
#if !__has_feature(capabilities)
#error "This should be a hybrid binary"
#endif

ATF_TC(dlopen_purecap_fail);
ATF_TC_HEAD(dlopen_purecap_fail, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Check that opening a purecap library from a hybrid binary fails");
}
ATF_TC_BODY(dlopen_purecap_fail, tc)
{
	char error_msg[PATH_MAX];
	const char* exedir = get_executable_dir();
	snprintf(error_msg, sizeof(error_msg),
	    "%s/%s: cannot load %s/../%s since it is CheriABI",
	    exedir, "dlopen-hybrid", exedir, "libbasic_purecap.so.0");
	test_dlopen_failure("libbasic_purecap.so.0", error_msg);
}

ATF_TC(dlopen_hybrid);
ATF_TC_HEAD(dlopen_hybrid, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Check that we can dlopen() a hybrid library from a hybrid binary");
}
ATF_TC_BODY(dlopen_hybrid, tc)
{
	// TODO: test that we can get a capability back
	test_dlopen_success("libbasic_hybrid.so.0", "hybrid", true);
}

ATF_TC(dlopen_nocheri);
ATF_TC_HEAD(dlopen_nocheri, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Check that we can dlopen() a non-CHERI library from a hybrid binary");
}
ATF_TC_BODY(dlopen_nocheri, tc)
{
	test_dlopen_success("libbasic_nocheri.so.0", "not CHERI", true);
}


ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, dlopen_purecap_fail);
	ATF_TP_ADD_TC(tp, dlopen_hybrid);
	ATF_TP_ADD_TC(tp, dlopen_nocheri);
	return atf_no_error();
}
