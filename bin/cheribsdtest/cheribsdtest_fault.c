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
#include <sys/mman.h>

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

/* 
 * Test data for cap version tests. A capability is handy because it is one
 * version granule.
 */
static void * __capability vp;

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

CHERIBSDTEST(test_fault_setversion, "Attempt to set version twice.",
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO,
    .ct_signum = SIGPROT,
    .ct_si_code = PROT_CHERI_VERSION,
    .ct_si_trapno = TRAPNO_CHERI)
{
	char ch;
	char * __capability chp = cheri_ptr(&ch, sizeof(ch));
	chp = cheri_setversion(chp, 3);
	/* Attempt to set version again on versioned cap: */
	chp = cheri_setversion(chp, 0); /* fault */
}

CHERIBSDTEST(test_fault_wrong_version, "Store to unversioned memory via versioned cap",
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO | CT_FLAG_SI_ADDR,
    .ct_signum = SIGPROT,
    .ct_si_code = PROT_CHERI_VERSION,
    .ct_si_trapno = TRAPNO_VERSION)
{
	cheribsdtest_set_expected_si_addr(NULL_DERIVED_VOIDP(&vp));
	void * __capability * __capability cvpp = cheri_ptr(&vp, sizeof(vp));
	cvpp = cheri_setversion(cvpp, 3);
	*cvpp = NULL; /* should fault due to incorrect version */
}

CHERIBSDTEST(test_fault_storeversion, "Attempt to store version on memory without CWV",
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO | CT_FLAG_SI_ADDR,
    .ct_signum = SIGPROT,
    .ct_si_code = PROT_CHERI_VERSION,
    .ct_si_trapno = TRAPNO_VERSION)
{
	cheribsdtest_set_expected_si_addr(NULL_DERIVED_VOIDP(&vp));
	void * __capability * __capability cvpp = cheri_ptr(&vp, sizeof(vp));
	int v = cheri_loadversion(cvpp);
	if (v != 0)
		cheribsdtest_failure_errx("Unexpected initial version: %d", v);
	cheri_storeversion(cvpp, 3); /* fault due to absent PTE bit */
}

CHERIBSDTEST(test_fault_storeversion_mmap, "Attempt to store version on MAP_ANON memory without CWV",
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO | CT_FLAG_SI_ADDR,
    .ct_signum = SIGPROT,
    .ct_si_code = PROT_CHERI_VERSION,
    .ct_si_trapno = TRAPNO_VERSION)
{
	int *p = CHERIBSDTEST_CHECK_SYSCALL(
		mmap(NULL, getpagesize(), PROT_READ|PROT_WRITE,	MAP_ANON, -1, 0)
	);
	cheribsdtest_set_expected_si_addr(NULL_DERIVED_VOIDP(p));
	void * __capability cp = cheri_ptr(p, getpagesize());
	int v = cheri_loadversion(cp);
	if (v != 0)
		cheribsdtest_failure_errx("Unexpected initial version: %d", v);
	cheri_storeversion(cp, 3); /* fault due to absent PTE bit */

	/* *p leaked here! */
}

CHERIBSDTEST(test_storeversion_mmap, "Attempt to store version on MAP_ANON PROT_MTE memory")
{
	int  page_sz = getpagesize(); 
	int *p = CHERIBSDTEST_CHECK_SYSCALL(
		mmap(NULL, page_sz, PROT_READ|PROT_WRITE|PROT_MTE, MAP_ANON, -1, 0)
	);
	int * __capability cp = cheri_ptr(p, page_sz);
	int v = cheri_loadversion(cp);
	if (v != 0)
		cheribsdtest_failure_errx("Unexpected initial version: %d", v);
	cheri_storeversion(cp, 3);
	v = cheri_loadversion(cp);
	if (v != 3)
		cheribsdtest_failure_errx("Unexpected version after storeversion: %d", v);
	cp = cheri_setversion(cp, 3);
	/* Cast to volatile so that store / load do not get optimised away. */
	volatile int * __capability vcp = cp;
	*vcp = 1;
	if (*vcp != 1)
		cheribsdtest_failure_errx("Failed to store to versioned memory.");
	CHERIBSDTEST_CHECK_SYSCALL(munmap(p, page_sz));
	cheribsdtest_success();
}

#ifdef __mips__
CHERIBSDTEST(test_fault_ccheck_user_fail,
    "Exercise CCheckPerm failure",
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO,
    .ct_signum = SIGPROT,
    .ct_si_code = PROT_CHERI_PERM,
    .ct_si_trapno = TRAPNO_CHERI)
{
	void * __capability cp;
	char ch;

	cp = cheri_ptrperm(&ch, sizeof(ch), 0);
	cheri_ccheckperm(cp, CHERI_PERM_SW0);
}

CHERIBSDTEST(test_nofault_ccheck_user_pass,
    "Exercise CCheckPerm success")
{
	void * __capability cp;
	char ch;

	cp = cheri_ptrperm(&ch, sizeof(ch), CHERI_PERM_SW0);
	cheri_ccheckperm(cp, CHERI_PERM_SW0);
	cheribsdtest_success();
}

CHERIBSDTEST(test_fault_cgetcause,
    "Ensure CGetCause is unavailable in userspace",
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO,
    .ct_signum = SIGPROT,
    .ct_si_code = PROT_CHERI_SYSREG,
    .ct_si_trapno = TRAPNO_CHERI)
{
	register_t cause;

	cause = cheri_getcause();
	printf("CP2 cause register: %ju\n", (uintmax_t)cause);
}
#endif

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
	cd = __builtin_cheri_cap_from_pointer(cb, (vaddr_t)buf + 10);
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

#ifdef __mips__
CHERIBSDTEST(test_fault_read_kr1c,
    "Ensure KR1C is unavailable in userspace",
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO,
    .ct_signum = SIGPROT,
    .ct_si_code = PROT_CHERI_SYSREG,
    .ct_si_trapno = TRAPNO_CHERI)
{

	CHERI_CAP_PRINT(cheri_getkr1c());
}

CHERIBSDTEST(test_fault_read_kr2c,
    "Ensure KR2C is unavailable in userspace",
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO,
    .ct_signum = SIGPROT,
    .ct_si_code = PROT_CHERI_SYSREG,
    .ct_si_trapno = TRAPNO_CHERI)
{

	CHERI_CAP_PRINT(cheri_getkr2c());
}

CHERIBSDTEST(test_fault_read_kcc,
    "Ensure KCC is unavailable in userspace",
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO,
    .ct_signum = SIGPROT,
    .ct_si_code = PROT_CHERI_SYSREG,
    .ct_si_trapno = TRAPNO_CHERI)
{

	CHERI_CAP_PRINT(cheri_getkcc());
}

CHERIBSDTEST(test_fault_read_kdc,
    "Ensure KDC is unavailable in userspace",
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO,
    .ct_signum = SIGPROT,
    .ct_si_code = PROT_CHERI_SYSREG,
    .ct_si_trapno = TRAPNO_CHERI)
{

	CHERI_CAP_PRINT(cheri_getkdc());
}

CHERIBSDTEST(test_fault_read_epcc,
    "Ensure EPCC is unavailable in userspace",
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO,
    .ct_signum = SIGPROT,
    .ct_si_code = PROT_CHERI_SYSREG,
    .ct_si_trapno = TRAPNO_CHERI)
{

	CHERI_CAP_PRINT(cheri_getepcc());
}
#endif	/* __mips__ */
