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

#include <machine/cpuregs.h>
#include <machine/sysarch.h>

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

#include "cheritest.h"

/*
 * Exercises CHERI faults outside of sandboxes.
 */
#define	ARRAY_LEN	2
static char array[ARRAY_LEN];
static char sink;

void
test_fault_bounds(const struct cheri_test *ctp __unused)
{
	char * __capability arrayp = cheri_ptr(array, sizeof(array));
	int i;

	for (i = 0; i < ARRAY_LEN; i++)
		arrayp[i] = 0;
	arrayp[i] = 0;

	cheritest_failure_errx("out of bounds access did not fault");
}

void
test_fault_perm_load(const struct cheri_test *ctp __unused)
{
	char * __capability arrayp = cheri_ptrperm(array, sizeof(array), 0);

	sink = arrayp[0];

	cheritest_failure_errx("access without required permissions did not fault");
}

void
test_nofault_perm_load(const struct cheri_test *ctp __unused)
{
	char * __capability arrayp = cheri_ptrperm(array, sizeof(array),
	    CHERI_PERM_LOAD);

	sink = arrayp[0];
	cheritest_success();
}

void
test_fault_perm_seal(const struct cheri_test *ctp __unused)
{
	int i;
	void * __capability ip = &i;
	void * __capability sealcap;
	void * __capability sealed;

	if (sysarch(CHERI_GET_SEALCAP, &sealcap) < 0)
		cheritest_failure_err("sysarch(CHERI_GET_SEALCAP)");
	sealcap = cheri_andperm(sealcap, ~CHERI_PERM_SEAL);
	sealed = cheri_seal(ip, sealcap);
	/*
	 * Ensure that sealed is actually use, otherwise the faulting
	 * instruction can be optimized away since it is dead.
	 */
	cheritest_failure_errx("cheri_seal() performed successfully "
	    _CHERI_PRINTF_CAP_FMT " with bad sealcap" _CHERI_PRINTF_CAP_FMT,
	    _CHERI_PRINTF_CAP_ARG(sealed), _CHERI_PRINTF_CAP_ARG(sealcap));
}

void
test_fault_perm_store(const struct cheri_test *ctp __unused)
{
	char * __capability arrayp = cheri_ptrperm(array, sizeof(array), 0);

	arrayp[0] = sink;
}

void
test_nofault_perm_store(const struct cheri_test *ctp __unused)
{
	char * __capability arrayp = cheri_ptrperm(array, sizeof(array),
	    CHERI_PERM_STORE);

	arrayp[0] = sink;
	cheritest_success();
}

void
test_fault_perm_unseal(const struct cheri_test *ctp __unused)
{
	int i;
	void * __capability ip = &i;
	void * __capability sealcap;
	void * __capability sealed;
	void * __capability unsealed;

	if (sysarch(CHERI_GET_SEALCAP, &sealcap) < 0)
		cheritest_failure_err("sysarch(CHERI_GET_SEALCAP)");
	if ((cheri_getperm(sealcap) & CHERI_PERM_SEAL) == 0)
		cheritest_failure_errx("unexpected !seal perm on sealcap");
	sealed = cheri_seal(ip, sealcap);
	sealcap = cheri_andperm(sealcap, ~CHERI_PERM_UNSEAL);
	unsealed = cheri_unseal(sealed, sealcap);
	/*
	 * Ensure that unsealed is actually use, otherwise the faulting
	 * instruction can be optimized away since it is dead.
	 */
	cheritest_failure_errx("cheri_unseal() performed successfully "
	    _CHERI_PRINTF_CAP_FMT " with bad unsealcap" _CHERI_PRINTF_CAP_FMT,
	    _CHERI_PRINTF_CAP_ARG(unsealed), _CHERI_PRINTF_CAP_ARG(sealcap));
}

void
test_fault_tag(const struct cheri_test *ctp __unused)
{
	char ch;
	char * __capability chp = cheri_ptr(&ch, sizeof(ch));

	chp = cheri_cleartag(chp);
	*chp = '\0';
}

void
test_fault_ccheck_user_fail(const struct cheri_test *ctp __unused)
{
	void * __capability cp;
	char ch;

	cp = cheri_ptrperm(&ch, sizeof(ch), 0);
	cheri_ccheckperm(cp, CHERI_PERM_SW0);
}

void
test_nofault_ccheck_user_pass(const struct cheri_test *ctp __unused)
{
	void * __capability cp;
	char ch;

	cp = cheri_ptrperm(&ch, sizeof(ch), CHERI_PERM_SW0);
	cheri_ccheckperm(cp, CHERI_PERM_SW0);
	cheritest_success();
}

void
test_fault_cgetcause(const struct cheri_test *ctp __unused)
{
	register_t cause;

	cause = cheri_getcause();
	printf("CP2 cause register: %ju\n", (uintmax_t)cause);
}

void
test_nofault_cfromptr(const struct cheri_test *ctp __unused)
{
	char buf[256];
	void * __capability cd; /* stored into here */
	void * __capability cb; /* derived from here */
	int rt;

	/*
	 * XXX: Could we be using cheri_cap_from_pointer() here to
	 * avoid explicit inline assembly?
	 */
	cb = cheri_ptr(buf, 256);
	rt = 10;
	__asm__ __volatile__ ("cfromptr %0, %1, %2" : "=r"(cd) : "r"(cb),
	    "r"(rt) : "memory");
	cheritest_success();
}

void
test_fault_read_kr1c(const struct cheri_test *ctp __unused)
{

	CHERI_CAP_PRINT(cheri_getkr1c());
}

void
test_fault_read_kr2c(const struct cheri_test *ctp __unused)
{

	CHERI_CAP_PRINT(cheri_getkr2c());
}

void
test_fault_read_kcc(const struct cheri_test *ctp __unused)
{

	CHERI_CAP_PRINT(cheri_getkcc());
}

void
test_fault_read_kdc(const struct cheri_test *ctp __unused)
{

	CHERI_CAP_PRINT(cheri_getkdc());
}

void
test_fault_read_epcc(const struct cheri_test *ctp __unused)
{

	CHERI_CAP_PRINT(cheri_getepcc());
}
