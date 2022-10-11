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

#ifndef __CHERI_PURE_CAPABILITY__
#error "This should be a purecap binary"
#endif


ATF_TC(dlopen_purecap);
ATF_TC_HEAD(dlopen_purecap, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Check that we can dlopen() a purecap library from a purecap binary");
}
ATF_TC_BODY(dlopen_purecap, tc)
{
	test_dlopen_success("libbasic_purecap.so.0", "purecap", true);
}

ATF_TC(dlopen_hybrid_fail);
ATF_TC_HEAD(dlopen_hybrid_fail, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Check that dlopen() of a hybrid library from a purecap binary fails");
}
ATF_TC_BODY(dlopen_hybrid_fail, tc)
{
	char error_msg[PATH_MAX];
	const char* exedir = get_executable_dir();
#if defined(__riscv) || defined(__aarch64__)
	snprintf(error_msg, sizeof(error_msg),
	    "%s/%s: cannot load %s/../%s since it is not CheriABI",
	    exedir, "dlopen-purecap", exedir, "libbasic_hybrid.so.0");
#else
#error "Unknown architecture"
#endif
	test_dlopen_failure("libbasic_hybrid.so.0", error_msg);
}

ATF_TC(dlopen_nocheri_fail);
ATF_TC_HEAD(dlopen_nocheri_fail, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Check that dlopen() of a non-CHERI library from a purecap binary fails");
}
ATF_TC_BODY(dlopen_nocheri_fail, tc)
{
	char error_msg[PATH_MAX];
	const char* exedir = get_executable_dir();

#if defined(__riscv) || (__aarch64__)
	/*
	 * RISC-V has no CHERI vs non-CHERI distinction in its flags (just like all
	 * extensions other than C, which influences linker relaxation). We
	 * therefore fall back on it not being purecap.
	 */
	snprintf(error_msg, sizeof(error_msg),
	    "%s/%s: cannot load %s/../%s since it is not CheriABI",
	    exedir, "dlopen-purecap", exedir, "libbasic_nocheri.so.0");
#else
#error "Unknown architecture"
#endif
	test_dlopen_failure("libbasic_nocheri.so.0", error_msg);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, dlopen_purecap);
	ATF_TP_ADD_TC(tp, dlopen_hybrid_fail);
	ATF_TP_ADD_TC(tp, dlopen_nocheri_fail);
	return atf_no_error();
}
