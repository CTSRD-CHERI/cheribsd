/*-
 * Copyright (c) 2016 SRI International
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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/signal.h>
#include <sys/sysctl.h>
#include <sys/time.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <machine/cpuregs.h>
#include <machine/sysarch.h>

#include <cheri/libcheri_enter.h>
#include <cheri/libcheri_fd.h>
#include <cheri/libcheri_sandbox.h>

#include <cheritest-helper.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "cheritest.h"

#define	PERM_READ	(CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP)
#define	PERM_WRITE	(CHERI_PERM_STORE | CHERI_PERM_STORE_CAP | \
			    CHERI_PERM_STORE_LOCAL_CAP)
#define	PERM_EXEC	CHERI_PERM_EXECUTE
#define	PERM_RWX	(PERM_READ|PERM_WRITE|PERM_EXEC)

void
test_cheriabi_mmap_nospace(const struct cheri_test *ctp __unused)
{
	size_t len;
	void *cap;

	/* Remove all space from the default mmap capability. */
	len = 0;
	if (sysarch(CHERI_MMAP_SETBOUNDS, &len) != 0)
		cheritest_failure_err(
		    "sysarch(CHERI_MMAP_SETBOUNDS, 0) failed");
	if ((cap = mmap(0, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_ANON, -1, 0)) != MAP_FAILED)
		cheritest_failure_err(
		    "mmap() returned a a pointer when it should have failed");

	cheritest_success();
}

void
test_cheriabi_mmap_perms(const struct cheri_test *ctp __unused)
{
	uint64_t perms, operms;
	void *cap, *tmpcap;

	if (sysarch(CHERI_MMAP_GETPERM, &perms) != 0)
		cheritest_failure_err("sysarch(CHERI_MMAP_GETPERM) failed");

	/*
	 * Make sure perms we are going to try removing are there...
	 */
	if (!(perms & CHERI_PERM_SW0))
		cheritest_failure_errx(
		    "no CHERI_PERM_SW0 in default perms (0x%lx)", perms);
	if (!(perms & CHERI_PERM_SW2))
		cheritest_failure_errx(
		    "no CHERI_PERM_SW2 in default perms (0x%lx)", perms);

	if ((cap = mmap(0, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_ANON, -1, 0)) == MAP_FAILED)
		cheritest_failure_err("mmap() failed");

	if (cheri_getperm(cap) != perms)
		cheritest_failure_errx("mmap() returned with perms 0x%lx "
		    "instead of expected 0x%lx", cheri_getperm(cap), perms);

	if (munmap(cap, PAGE_SIZE) != 0)
		cheritest_failure_err("munmap() failed");

	operms = perms;
	perms = ~CHERI_PERM_SW2;
	if (sysarch(CHERI_MMAP_ANDPERM, &perms) != 0)
		cheritest_failure_err("sysarch(CHERI_MMAP_ANDPERM) failed");
	if (perms != (operms & ~CHERI_PERM_SW2))
		cheritest_failure_errx("sysarch(CHERI_MMAP_ANDPERM) did not "
		    "just remove CHERI_PERM_SW2.  Got 0x%lx but "
		    "expected 0x%lx", perms,
		    operms & ~CHERI_PERM_SW2);
	if (sysarch(CHERI_MMAP_GETPERM, &perms) != 0)
		cheritest_failure_err("sysarch(CHERI_MMAP_GETPERM) failed");
	if (perms & CHERI_PERM_SW2)
		cheritest_failure_errx("sysarch(CHERI_MMAP_ANDPERM) failed "
		    "to remove CHERI_PERM_SW2.  Got 0x%lx.", perms);

	if ((cap = mmap(0, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_ANON, -1, 0)) == MAP_FAILED)
		cheritest_failure_err("mmap() failed");

	if (cheri_getperm(cap) & CHERI_PERM_SW2)
		cheritest_failure_errx("mmap() returned with "
		    "CHERI_PERM_SW2 after restriction (0x%lx)",
		    cheri_getperm(cap));

	cap = cheri_andperm(cap, ~CHERI_PERM_SW0);
	if ((cap = mmap(cap, PAGE_SIZE, PROT_READ,
	    MAP_ANON|MAP_FIXED, -1, 0)) == MAP_FAILED)
		cheritest_failure_err("mmap(MAP_FIXED) failed");
	if (cheri_getperm(cap) & CHERI_PERM_SW0)
		cheritest_failure_errx(
		    "mmap(MAP_FIXED) returned with CHERI_PERM_SW0 in perms "
		    "without it in addr (perms 0x%lx)", cheri_getperm(cap));

	if (munmap(cap, PAGE_SIZE) != 0)
		cheritest_failure_err("munmap() failed");

	if ((cap = mmap(0, PAGE_SIZE, PROT_NONE, MAP_ANON, -1, 0)) ==
	    MAP_FAILED)
		cheritest_failure_err("mmap() failed");
	if (cheri_getperm(cap) & PERM_RWX)
		cheritest_failure_errx("mmap(PROT_NONE) returned unrequested "
		    "permissions (0x%lx)", cheri_getperm(cap));

	/* Remove VMMAP permission from cap */
	tmpcap = cheri_andperm(cap, ~CHERI_PERM_CHERIABI_VMMAP);
	if (munmap(tmpcap, PAGE_SIZE) == 0)
		cheritest_failure_errx(
		    "munmap() unmapped without CHERI_PERM_CHERIABI_VMMAP");

	if (munmap(cap, PAGE_SIZE) != 0)
		cheritest_failure_err("munmap() failed");

	if ((cap = mmap(tmpcap, PAGE_SIZE, PROT_NONE, MAP_ANON|MAP_FIXED,
	    -1, 0)) != MAP_FAILED)
		cheritest_failure_errx(
		    "mmap(MAP_FIXED) succeeded through a cap without"
		    " CHERI_PERM_CHERIABI_VMMAP");

	/* Disallow executable pages */
	perms = ~PERM_EXEC;
	if (sysarch(CHERI_MMAP_ANDPERM, &perms) != 0)
		cheritest_failure_err("sysarch(CHERI_MMAP_ANDPERM) failed");
	if ((cap = mmap(0, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_ANON, -1, 0)) != MAP_FAILED)
		cheritest_failure_err("mmap(PROT_READ|PROT_WRITE|PROT_EXEC) "
		    "succeeded after removing PROT_EXEC from default cap");

	cheritest_success();
}

void
test_cheriabi_mmap_unrepresentable(const struct cheri_test *ctp __unused)
{
#ifdef CHERI_BASELEN_BITS
	size_t len = ((size_t)PAGE_SIZE << CHERI_BASELEN_BITS) + 1;
	void *cap;

	if ((cap = mmap(0, len, PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_ANON, -1, 0)) != MAP_FAILED)
		cheritest_failure_errx("mmap() returned a pointer when "
		    "given an unrepresentable length (%zu): %#p", len, cap);
	cheritest_success();
#endif

	cheritest_success();
}

void
test_cheriabi_mmap_ddc(const struct cheri_test *ctp __unused)
{
	void *cap, *ddc;
	size_t length;

	ddc = cheri_getdefault();
	if ((cheri_getperm(ddc) & CHERI_PERM_CHERIABI_VMMAP) ==
	    CHERI_PERM_CHERIABI_VMMAP) {
		if ((cap = mmap(0, PAGE_SIZE, PROT_READ|PROT_WRITE,
		    MAP_ANON|MAP_CHERI_DDC, -1, 0)) == MAP_FAILED)
			cheritest_failure_err("mmap(MAP_CHERI_DDC) failed");

		if (cheri_getbase(cap) < cheri_getbase(ddc) ||
		    cheri_getbase(cap) > cheri_getbase(ddc) + cheri_getlen(ddc))
			cheritest_failure_errx(
			    "cap (%#p) base outside ddc (%#p)", cap, ddc);
		if (cheri_getbase(cap) + cheri_getlen(cap) >
		    cheri_getbase(ddc) + cheri_getlen(ddc))
			cheritest_failure_errx(
			    "cap (%#p) extends beyond ddc (%#p)", cap, ddc);
	}

	cheritest_success();
}
