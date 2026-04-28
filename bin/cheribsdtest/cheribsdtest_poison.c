/*-
 * Copyright (c) 2026 Alfredo Mazzinghi
 * All rights reserved.
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

/*
 * Test poison capability functionality and integration across allocator
 * and kernel.
 */

#include <sys/cdefs.h>

#if !__has_feature(capabilities)
#error "This code requires a CHERI-aware compiler"
#endif

#include <sys/mman.h>
#include <sys/signal.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#include <cheri/revoke.h>
#include <cheri/cheric.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "cheribsdtest.h"

static const char *
skip_need_poison(const struct cheri_test *ctp __unused)
{
	if (!feature_present("cheri_caprevoke_poison"))
		return ("Kernel does not support poison revocation");
	return (NULL);
}

static void
poison_region(void *base, size_t length)
{
	uintcap_t *region = base;
	unsigned long i;

	CHERIBSDTEST_VERIFY2(cheri_can_access(base,
		CHERI_PERM_STORE | CHERI_PERM_STORE_CAP, (ptraddr_t)base, length),
	    "invalid poison region bounds");
	CHERIBSDTEST_VERIFY2(__builtin_is_aligned(base, sizeof(uintcap_t)) &&
	    __builtin_is_aligned(length, sizeof(uintcap_t)),
	    "invalid poison region alignment");
	for (i = 0; i < length / sizeof(uintcap_t); i++) {
		cheri_poison_set(region + i);
	}
}

CHERIBSDTEST(cheri_poison_mmap,
    "check that mmap returns a capability that permits poisoning",
    .ct_check_skip = skip_need_poison)
{
	void *mem = CHERIBSDTEST_CHECK_SYSCALL(
	    mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0));
	CHERIBSDTEST_VERIFY2((cheri_getperm(mem) & CHERI_PERM_POISON) != 0,
	    "missing PERM_POISON");

	/* Attempt to poison the memory */
	cheri_poison_set(mem);
	CHERIBSDTEST_VERIFY2(cheri_poison_get(mem) == 1, "invalid poison");
	cheri_poison_clear(mem);
	CHERIBSDTEST_VERIFY2(cheri_poison_get(mem) == 0, "did not clear poison");

	CHERIBSDTEST_CHECK_SYSCALL(munmap(mem, 0x1000));
	cheribsdtest_success();
}

CHERIBSDTEST(cheri_poison_fault_read,
    "check that reading a poisoned region causes a fault",
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO,
#ifdef notyet
    .ct_signum = SIGSEGV,
    .ct_si_code = SEGV_POISON,
    .ct_si_trapno = TRAPNO_POISON_ACCESS,
#else
    .ct_signum = SIGPROT,
    .ct_si_code = PROT_CHERI_SEALED,
    .ct_si_trapno = TRAPNO_CHERI,
#endif
    .ct_check_skip = skip_need_poison)
{
	void *mem = CHERIBSDTEST_CHECK_SYSCALL(
	    mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0));
	CHERIBSDTEST_VERIFY2((cheri_getperm(mem) & CHERI_PERM_POISON) != 0,
	    "missing PERM_POISON");

	char *usermem = cheri_clearperm(mem, CHERI_PERM_POISON);
	*usermem = 'A';
	CHERIBSDTEST_VERIFY2(*usermem == 'A', "invalid memory content");

	cheri_poison_set(mem);
	volatile char c __unused = *usermem;
	cheribsdtest_failure_errx("poison read succeded");
}

#ifdef notyet
CHERIBSDTEST(cheri_poison_fault_write,
    "check that writing to a poisoned region causes a fault",
    .ct_check_skip = skip_need_poison)
{
	void *mem = CHERIBSDTEST_CHECK_SYSCALL(
	    mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0));
	CHERIBSDTEST_VERIFY2((cheri_getperm(mem) & CHERI_PERM_POISON) != 0,
	    "missing PERM_POISON");

	cheribsdtest_failure_errx("poison write succeded");
}
#endif

/* CHERIBSDTEST(cheri_double_poison, "try to poison twice") {} */

CHERIBSDTEST(cheri_poison_revoke,
    "check revocation of poisoned allocation",
    .ct_check_skip = skip_need_poison)
{
	struct cheri_revoke_syscall_info crsi;

	void *mem = CHERIBSDTEST_CHECK_SYSCALL(
	    mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0));
	CHERIBSDTEST_VERIFY2((cheri_getperm(mem) & CHERI_PERM_POISON) != 0,
	    "missing PERM_POISON");

	void **stash = &((void **)mem)[0xf0];

	void *cap = cheri_clearperm(mem, CHERI_PERM_POISON | CHERI_PERM_SW_VMEM);
	cap = cheri_setboundsexact(cap, 0x100);

	/* Stash the capability */
	*stash = cap;

	/* Poison cap range */
	poison_region(mem, 0x100);

	/* Trigger sync revocation */
	crsi.epochs.enqueue = 0xC0FFEE;
	crsi.epochs.dequeue = 0xB00;

	CHERIBSDTEST_CHECK_SYSCALL(
	    cheri_revoke(CHERI_REVOKE_LAST_PASS | CHERI_REVOKE_IGNORE_START |
	    CHERI_REVOKE_TAKE_STATS , 0, &crsi));

	/* Check that we revoked the capabilities */
	CHERIBSDTEST_VERIFY2(cheri_gettag(*stash) == 0, "unrevoked capability");
	cheribsdtest_success();
}

CHERIBSDTEST(cheri_poison_revoke_bounds,
    "check revocation of poisoned allocation with poison bounds",
    .ct_check_skip = skip_need_poison)
{
	struct cheri_revoke_syscall_info crsi;

	void *mem = CHERIBSDTEST_CHECK_SYSCALL(
	    mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0));
	CHERIBSDTEST_VERIFY2((cheri_getperm(mem) & CHERI_PERM_POISON) != 0,
	    "missing PERM_POISON");
	char **test_stash = &((char **)mem)[0xf0];
	char **nested_stash = &((char **)mem)[0xf1];

	/* Parent cap does not have SW_VMEM, but can poison */
	char *test_cap = cheri_clearperm(mem, CHERI_PERM_SW_VMEM);
	test_cap = cheri_setboundsexact(test_cap, 0x100);

	/* Nested cap can't poison */
	char *nested_cap = cheri_clearperm(test_cap, CHERI_PERM_POISON);
	nested_cap = cheri_setboundsexact(nested_cap, 0x50);

	/* Note: both parent and nested cap share the same base */
	CHERIBSDTEST_VERIFY2(cheri_getbase(test_cap) == cheri_getbase(nested_cap),
	    "unexpected test capability base mismatch");

	/* Stash both capabilities */
	*test_stash = test_cap;
	*nested_stash = nested_cap;

	/* Poison nested "allocation" */
	void *poison_authority = cheri_setboundsexact(mem, 0x50);
	poison_region(poison_authority, 0x50);

	/* Trigger revocation */
	crsi.epochs.enqueue = 0xC0FFEE;
	crsi.epochs.dequeue = 0xB00;

	CHERIBSDTEST_CHECK_SYSCALL(
	    cheri_revoke(CHERI_REVOKE_LAST_PASS | CHERI_REVOKE_IGNORE_START |
	    CHERI_REVOKE_TAKE_STATS , 0, &crsi));

	/* Check that we revoked the capabilities */
	CHERIBSDTEST_VERIFY2(cheri_gettag(mem) != 0,
	    "revoked PERM_SW_VMEM root cap");
	CHERIBSDTEST_VERIFY2(cheri_gettag(test_stash) != 0,
	    "revoked test stash cap");
	CHERIBSDTEST_VERIFY2(cheri_gettag(nested_stash) != 0,
	    "revoked nested stash cap");
	CHERIBSDTEST_VERIFY2(cheri_gettag(*nested_stash) == 0,
	    "unrevoked capability");
	CHERIBSDTEST_VERIFY2(cheri_gettag(*test_stash) != 0,
	    "revoked parent capability");
	cheribsdtest_success();
}
