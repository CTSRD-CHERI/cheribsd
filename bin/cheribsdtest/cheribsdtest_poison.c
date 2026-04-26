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

/* CHERIBSDTEST(cheri_poison_strip, "strip PERM_POISON") {} */
/* CHERIBSDTEST(cheri_double_poison, "try to poison twice") {} */

CHERIBSDTEST(cheri_poison_revoke,
    "check revocation of poisoned allocation",
    .ct_check_skip = skip_need_poison)
{
	struct cheri_revoke_syscall_info crsi;
	unsigned long i;

	void *mem = CHERIBSDTEST_CHECK_SYSCALL(
	    mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0));
	CHERIBSDTEST_VERIFY2((cheri_getperm(mem) & CHERI_PERM_POISON) != 0,
	    "missing PERM_POISON");

	void *cap = cheri_clearperm(mem, CHERI_PERM_POISON);
	cap = cheri_setboundsexact(cap, 0x100);

	/* Stash the capability */
	void **mb = mem;
	mb[0x20] = cap;

	/* Trigger sync revocation */
	for (i = 0; i < 0x100 / sizeof(void *); i++) {
		cheri_poison_set((uintptr_t)mem + i * sizeof(void *));
	}
	crsi.epochs.enqueue = 0xC0FFEE;
	crsi.epochs.dequeue = 0xB00;

	CHERIBSDTEST_CHECK_SYSCALL(
	    cheri_revoke(CHERI_REVOKE_LAST_PASS | CHERI_REVOKE_IGNORE_START |
	    CHERI_REVOKE_TAKE_STATS , 0, &crsi));

	/* Check that we revoked the capabilities */
	CHERIBSDTEST_VERIFY2(cheri_gettag(mb[0x20]) == 0, "unrevoked capability");
	cheribsdtest_success();
}
