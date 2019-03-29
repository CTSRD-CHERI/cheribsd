/*-
 * Copyright (c) 2018 Robert N. M. Watson
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

#include <machine/cherireg.h>
#include <machine/cpuregs.h>
#include <machine/sysarch.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <err.h>

#include "cheritest.h"

void
test_sealcap_sysarch(const struct cheri_test *ctp __unused)
{
	void * __capability sealcap;
	u_register_t v;

	if (sysarch(CHERI_GET_SEALCAP, &sealcap) < 0)
		cheritest_failure_err("sysarch(CHERI_GET_SEALCAP)");

	/* Base. */
	v = cheri_getbase(sealcap);
	if (v != CHERI_SEALCAP_USERSPACE_BASE)
		cheritest_failure_errx("base %jx (expected %jx)", v,
		    (uintmax_t)CHERI_SEALCAP_USERSPACE_BASE);

	/* Length. */
	v = cheri_getlen(sealcap);
	if (v != CHERI_SEALCAP_USERSPACE_LENGTH)
		cheritest_failure_errx("length 0x%jx (expected 0x%jx)", v,
		    (uintmax_t)CHERI_SEALCAP_USERSPACE_LENGTH);

	/* Offset. */
	v = cheri_getoffset(sealcap);
	if (v != CHERI_SEALCAP_USERSPACE_OFFSET)
		cheritest_failure_errx("offset %jx (expected %jx)", v,
		    (uintmax_t)CHERI_SEALCAP_USERSPACE_OFFSET);

	/* Type -- should be (-1) for an unsealed capability. */
	v = cheri_gettype(sealcap);
	if (v != 0xffffffffffffffff)
		cheritest_failure_errx("otype %jx (expected %jx)", v,
		    (uintmax_t)0xffffffffffffffff);

	/* Permissions. */
	v = cheri_getperm(sealcap);
	if (v != CHERI_SEALCAP_USERSPACE_PERMS)
		cheritest_failure_errx("perms %jx (expected %jx)", v,
		    (uintmax_t)CHERI_SEALCAP_USERSPACE_PERMS);

	/*
	 * More overt tests for permissions that should -- or should not -- be
	 * there, regardless of consistency with the kernel headers.
	 */
	if ((v & CHERI_PERM_GLOBAL) == 0)
		cheritest_failure_errx("perms %jx (global missing)", v);

	if ((v & CHERI_PERM_EXECUTE) != 0)
		cheritest_failure_errx("perms %jx (execute present)", v);

	if ((v & CHERI_PERM_LOAD) != 0)
		cheritest_failure_errx("perms %jx (load present)", v);

	if ((v & CHERI_PERM_STORE) != 0)
		cheritest_failure_errx("perms %jx (store present)", v);

	if ((v & CHERI_PERM_LOAD_CAP) != 0)
		cheritest_failure_errx("perms %jx (loadcap present)", v);

	if ((v & CHERI_PERM_STORE_CAP) != 0)
		cheritest_failure_errx("perms %jx (storecap present)", v);

	if ((v & CHERI_PERM_STORE_LOCAL_CAP) != 0)
		cheritest_failure_errx("perms %jx (store_local_cap present)",
		    v);

	if ((v & CHERI_PERM_SEAL) == 0)
		cheritest_failure_errx("perms %jx (seal missing)", v);

	if ((v & CHERI_PERM_CCALL) != 0)
		cheritest_failure_errx("perms %jx (ccall present)", v);

	if ((v & CHERI_PERM_UNSEAL) == 0)
		cheritest_failure_errx("perms %jx (unseal missing)", v);

	if ((v & CHERI_PERM_SYSTEM_REGS) != 0)
		cheritest_failure_errx("perms %jx (system_regs present)", v);

	if ((v & CHERI_PERMS_SWALL) != 0)
		cheritest_failure_errx("perms %jx (swperms present)", v);

	/* Sealed bit. */
	v = cheri_getsealed(sealcap);
	if (v != 0)
		cheritest_failure_errx("sealed %jx (expected 0)", v);

	/* Tag bit. */
	v = cheri_gettag(sealcap);
	if (v != 1)
		cheritest_failure_errx("tag %jx (expected 1)", v);
	cheritest_success();
}

static uint8_t sealdata[4096] __attribute__ ((aligned(4096)));

void
test_sealcap_seal(const struct cheri_test *ctp __unused)
{
	void * __capability sealdatap;
	void * __capability sealcap;
	void * __capability sealed;
	u_register_t v;

	if (sysarch(CHERI_GET_SEALCAP, &sealcap) < 0)
		cheritest_failure_err("sysarch(CHERI_GET_SEALCAP)");

	sealdatap = &sealdata;
	sealed = cheri_seal(sealdatap, sealcap);

	/* Base. */
	v = cheri_getbase(sealed);
	if (v != cheri_getbase(sealdatap))
		cheritest_failure_errx("base %jx (expected %jx)", v,
		    (uintmax_t)cheri_getbase(sealdatap));

	/* Length. */
	v = cheri_getlen(sealed);
	if (v != cheri_getlen(sealdatap))
		cheritest_failure_errx("length 0x%jx (expected 0x%jx)", v,
		    (uintmax_t)cheri_getlen(sealdatap));

	/* Offset. */
	v = cheri_getoffset(sealed);
	if (v != cheri_getoffset(sealdatap))
		cheritest_failure_errx("offset %jx (expected %jx)", v,
		    (uintmax_t)cheri_getoffset(sealdatap));

	/* Type. */
	v = cheri_gettype(sealed);
	if (v != cheri_getaddress(sealcap))
		cheritest_failure_errx("otype %jx (expected %jx)", v,
		    (uintmax_t)cheri_getaddress(sealcap));

	/* Sealed bit. */
	v = cheri_getsealed(sealed);
	if (v != 1)
		cheritest_failure_errx("sealed %jx (expected 0)", v);

	/* Tag bit. */
	v = cheri_gettag(sealed);
	if (v != 1)
		cheritest_failure_errx("tag %jx (expected 1)", v);

	/* Permissions. */
	v = cheri_getperm(sealed);
	if (v != cheri_getperm(sealdatap))
		cheritest_failure_errx("perms %jx (expected %jx)", v,
		    cheri_getperm(sealdatap));

	cheritest_success();
}

void
test_sealcap_seal_unseal(const struct cheri_test *ctp __unused)
{
	void * __capability sealdatap;
	void * __capability sealcap;
	void * __capability sealed;
	void * __capability unsealed;
	u_register_t v;

	if (sysarch(CHERI_GET_SEALCAP, &sealcap) < 0)
		cheritest_failure_err("sysarch(CHERI_GET_SEALCAP)");

	sealdatap = &sealdata;
	sealed = cheri_seal(sealdatap, sealcap);
	unsealed = cheri_unseal(sealed, sealcap);

	/* Base. */
	v = cheri_getbase(unsealed);
	if (v != cheri_getbase(sealdatap))
		cheritest_failure_errx("base %jx (expected %jx)", v,
		    (uintmax_t)cheri_getbase(sealdatap));

	/* Length. */
	v = cheri_getlen(unsealed);
	if (v != cheri_getlen(sealdatap))
		cheritest_failure_errx("length 0x%jx (expected 0x%jx)", v,
		    (uintmax_t)cheri_getlen(sealdatap));

	/* Offset. */
	v = cheri_getoffset(unsealed);
	if (v != cheri_getoffset(sealdatap))
		cheritest_failure_errx("offset %jx (expected %jx)", v,
		    (uintmax_t)cheri_getoffset(sealdatap));

	/* Type -- should be (-1) for an unsealed capability. */
	v = cheri_gettype(unsealed);
	if (v != 0xffffffffffffffff)
		cheritest_failure_errx("otype %jx (expected %jx)", v,
		    (uintmax_t)0xffffffffffffffff);

	/* Sealed bit. */
	v = cheri_getsealed(unsealed);
	if (v != 0)
		cheritest_failure_errx("sealed %jx (expected 0)", v);

	/* Tag bit. */
	v = cheri_gettag(unsealed);
	if (v != 1)
		cheritest_failure_errx("tag %jx (expected 1)", v);

	/* Permissions. */
	v = cheri_getperm(unsealed);
	if (v != cheri_getperm(sealdatap))
		cheritest_failure_errx("perms %jx (expected %jx)", v,
		    cheri_getperm(sealdatap));

	cheritest_success();
}
