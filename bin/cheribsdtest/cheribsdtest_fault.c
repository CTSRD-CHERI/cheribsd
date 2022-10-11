/*-
 * Copyright (c) 2012-2018 Robert N. M. Watson
 * Copyright (c) 2014 SRI International
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

#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/time.h>

#include <machine/frame.h>
#include <machine/trap.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <err.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "cheribsdtest.h"

/*
 * Exercises CHERI faults outside of sandboxes.
 */

#if CHERI_SEAL_VIOLATION_EXCEPTION
#define	CT_SEAL_VIOLATION_EXCEPTION					\
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO,	\
    .ct_signum = SIGPROT,						\
    .ct_si_code = PROT_CHERI_PERM,					\
    .ct_si_trapno = TRAPNO_CHERI
#else
#define	CT_SEAL_VIOLATION_EXCEPTION
#endif

#define	ARRAY_LEN	2
static char array[ARRAY_LEN];
static char sink;

CHERIBSDTEST(test_fault_bounds, "Exercise capability bounds check failure",
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO,
    .ct_signum = SIGPROT,
    .ct_si_code = PROT_CHERI_BOUNDS,
    .ct_si_trapno = TRAPNO_LOAD_STORE)
{
	char * __capability arrayp = cheri_ptr(array, sizeof(array));
	int i;

	for (i = 0; i < ARRAY_LEN; i++)
		arrayp[i] = 0;
	arrayp[i] = 0;

	cheribsdtest_failure_errx("out of bounds access did not fault");
}

CHERIBSDTEST(test_fault_perm_load,
    "Exercise capability load permission failure",
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO,
    .ct_signum = SIGPROT,
    .ct_si_code = PROT_CHERI_PERM,
    .ct_si_trapno = TRAPNO_LOAD_STORE)
{
	char * __capability arrayp = cheri_ptrperm(array, sizeof(array), 0);

	sink = arrayp[0];

	cheribsdtest_failure_errx("access without required permissions did not fault");
}

CHERIBSDTEST(test_nofault_perm_load,
    "Exercise capability load permission success")
{
	char * __capability arrayp = cheri_ptrperm(array, sizeof(array),
	    CHERI_PERM_LOAD);

	sink = arrayp[0];
	cheribsdtest_success();
}

CHERIBSDTEST(test_illegal_perm_seal,
    "Exercise capability seal permission failure",
    CT_SEAL_VIOLATION_EXCEPTION)
{
	int i;
	void * __capability ip = &i;
	void * __capability sealcap;
	void * __capability sealed;
	size_t sealcap_size;

	sealcap_size = sizeof(sealcap);
	if (sysctlbyname("security.cheri.sealcap", &sealcap, &sealcap_size,
	    NULL, 0) < 0)
		cheribsdtest_failure_err("sysctlbyname(security.cheri.sealcap)");
	sealcap = cheri_andperm(sealcap, ~CHERI_PERM_SEAL);
	sealed = cheri_seal(ip, sealcap);
#if !CHERI_SEAL_VIOLATION_EXCEPTION
	if (!cheri_gettag(sealed))
		cheribsdtest_success();
#endif
	cheribsdtest_failure_errx("cheri_seal() performed successfully "
	    "%#lp with bad sealcap %#lp", sealed, sealcap);
}

CHERIBSDTEST(test_fault_perm_store,
    "Exercise capability store permission failure",
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO,
    .ct_signum = SIGPROT,
    .ct_si_code = PROT_CHERI_PERM,
    .ct_si_trapno = TRAPNO_LOAD_STORE)
{
	char * __capability arrayp = cheri_ptrperm(array, sizeof(array), 0);

	arrayp[0] = sink;
}

CHERIBSDTEST(test_nofault_perm_store,
    "Exercise capability store permission success")
{
	char * __capability arrayp = cheri_ptrperm(array, sizeof(array),
	    CHERI_PERM_STORE);

	arrayp[0] = sink;
	cheribsdtest_success();
}

CHERIBSDTEST(test_illegal_perm_unseal,
    "Exercise capability unseal permission failure",
    CT_SEAL_VIOLATION_EXCEPTION)
{
	int i;
	void * __capability ip = &i;
	void * __capability sealcap;
	void * __capability sealed;
	void * __capability unsealed;
	size_t sealcap_size;

	sealcap_size = sizeof(sealcap);
	if (sysctlbyname("security.cheri.sealcap", &sealcap, &sealcap_size,
	    NULL, 0) < 0)
		cheribsdtest_failure_err("sysctlbyname(security.cheri.sealcap)");
	if ((cheri_getperm(sealcap) & CHERI_PERM_SEAL) == 0)
		cheribsdtest_failure_errx("unexpected !seal perm on sealcap");
	sealed = cheri_seal(ip, sealcap);
	sealcap = cheri_andperm(sealcap, ~CHERI_PERM_UNSEAL);
	unsealed = cheri_unseal(sealed, sealcap);
#if !CHERI_SEAL_VIOLATION_EXCEPTION
	if (!cheri_gettag(unsealed))
		cheribsdtest_success();
#endif
	cheribsdtest_failure_errx("cheri_unseal() performed successfully "
	    "%#lp with bad unsealcap %#lp", unsealed, sealcap);
}

CHERIBSDTEST(test_fault_tag, "Store via untagged capability",
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO,
    .ct_signum = SIGPROT,
    .ct_si_code = PROT_CHERI_TAG,
    .ct_si_trapno = TRAPNO_LOAD_STORE)
{
	char ch;
	char * __capability chp = cheri_ptr(&ch, sizeof(ch));

	chp = cheri_cleartag(chp);
	*chp = '\0';
}

CHERIBSDTEST(test_nofault_cfromptr, "Exercise CFromPtr success")
{
	char buf[256];
	void * __capability cb; /* derived from here */
	char * __capability cd; /* stored into here */

	cb = cheri_ptr(buf, 256);
#if defined(__aarch64__)
	/*
	 * morello-llvm emits cvtz for this intrinsic, which has an
	 * address interpretation by default (unlike CFromPtr, which
	 * has an offset interpretation).
	 * https://git.morello-project.org/morello/llvm-project/-/issues/16
	 */
	cd = __builtin_cheri_cap_from_pointer(cb, (ptraddr_t)buf + 10);
#else
	/*
	 * This pragma is require to allow compiling this file both with and
	 * without overloaded CHERI builtins.
	 *
	 * FIXME: remove once everyone has updated to overloaded builtins.
	 */
#pragma clang diagnostic ignored "-Wint-conversion"
	cd = __builtin_cheri_cap_from_pointer(cb, 10);
#endif
	*cd = '\0';
	cheribsdtest_success();
}
