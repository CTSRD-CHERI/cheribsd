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
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/signal.h>
#include <sys/sysctl.h>
#include <sys/time.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <machine/sysarch.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "cheribsdtest.h"

#define	PERM_READ	(CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP)
#define	PERM_WRITE	(CHERI_PERM_STORE | CHERI_PERM_STORE_CAP | \
			    CHERI_PERM_STORE_LOCAL_CAP)
#define	PERM_EXEC	CHERI_PERM_EXECUTE
#define	PERM_RWX	(PERM_READ|PERM_WRITE|PERM_EXEC)

#ifdef CHERI_MMAP_SETBOUNDS
void
test_cheriabi_mmap_nospace(const struct cheri_test *ctp __unused)
{
	size_t len;
	void *cap;

	/* Remove all space from the default mmap capability. */
	len = 0;
	if (sysarch(CHERI_MMAP_SETBOUNDS, &len) != 0)
		cheribsdtest_failure_err(
		    "sysarch(CHERI_MMAP_SETBOUNDS, 0) failed");
	if ((cap = mmap(0, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_ANON, -1, 0)) != MAP_FAILED)
		cheribsdtest_failure_err(
		    "mmap() returned a a pointer when it should have failed");

	cheribsdtest_success();
}
#endif

#ifdef CHERI_MMAP_GETPERM
void
test_cheriabi_mmap_perms(const struct cheri_test *ctp __unused)
{
	uint64_t perms, operms;
	void *cap, *tmpcap;

	if (sysarch(CHERI_MMAP_GETPERM, &perms) != 0)
		cheribsdtest_failure_err("sysarch(CHERI_MMAP_GETPERM) failed");

	/*
	 * Make sure perms we are going to try removing are there...
	 */
	if (!(perms & CHERI_PERM_SW0))
		cheribsdtest_failure_errx(
		    "no CHERI_PERM_SW0 in default perms (0x%lx)", perms);
	if (!(perms & CHERI_PERM_SW2))
		cheribsdtest_failure_errx(
		    "no CHERI_PERM_SW2 in default perms (0x%lx)", perms);

	if ((cap = mmap(0, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_ANON, -1, 0)) == MAP_FAILED)
		cheribsdtest_failure_err("mmap() failed");

	if (cheri_getperm(cap) != perms)
		cheribsdtest_failure_errx("mmap() returned with perms 0x%lx "
		    "instead of expected 0x%lx", cheri_getperm(cap), perms);

	if (munmap(cap, PAGE_SIZE) != 0)
		cheribsdtest_failure_err("munmap() failed");

	operms = perms;
	perms = ~CHERI_PERM_SW2;
	if (sysarch(CHERI_MMAP_ANDPERM, &perms) != 0)
		cheribsdtest_failure_err("sysarch(CHERI_MMAP_ANDPERM) failed");
	if (perms != (operms & ~CHERI_PERM_SW2))
		cheribsdtest_failure_errx("sysarch(CHERI_MMAP_ANDPERM) did not "
		    "just remove CHERI_PERM_SW2.  Got 0x%lx but "
		    "expected 0x%lx", perms,
		    operms & ~CHERI_PERM_SW2);
	if (sysarch(CHERI_MMAP_GETPERM, &perms) != 0)
		cheribsdtest_failure_err("sysarch(CHERI_MMAP_GETPERM) failed");
	if (perms & CHERI_PERM_SW2)
		cheribsdtest_failure_errx("sysarch(CHERI_MMAP_ANDPERM) failed "
		    "to remove CHERI_PERM_SW2.  Got 0x%lx.", perms);

	if ((cap = mmap(0, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_ANON, -1, 0)) == MAP_FAILED)
		cheribsdtest_failure_err("mmap() failed");

	if (cheri_getperm(cap) & CHERI_PERM_SW2)
		cheribsdtest_failure_errx("mmap() returned with "
		    "CHERI_PERM_SW2 after restriction (0x%lx)",
		    cheri_getperm(cap));

	cap = cheri_andperm(cap, ~CHERI_PERM_SW0);
	if ((cap = mmap(cap, PAGE_SIZE, PROT_READ,
	    MAP_ANON|MAP_FIXED, -1, 0)) == MAP_FAILED)
		cheribsdtest_failure_err("mmap(MAP_FIXED) failed");
	if (cheri_getperm(cap) & CHERI_PERM_SW0)
		cheribsdtest_failure_errx(
		    "mmap(MAP_FIXED) returned with CHERI_PERM_SW0 in perms "
		    "without it in addr (perms 0x%lx)", cheri_getperm(cap));

	if (munmap(cap, PAGE_SIZE) != 0)
		cheribsdtest_failure_err("munmap() failed");

	if ((cap = mmap(0, PAGE_SIZE, PROT_NONE, MAP_ANON, -1, 0)) ==
	    MAP_FAILED)
		cheribsdtest_failure_err("mmap() failed");
	if (cheri_getperm(cap) & PERM_RWX)
		cheribsdtest_failure_errx("mmap(PROT_NONE) returned unrequested "
		    "permissions (0x%lx)", cheri_getperm(cap));

	if (munmap(cap, PAGE_SIZE) != 0)
		cheribsdtest_failure_err("munmap() failed");

	/* Attempt to unmap without CHERI_PERM_CHERIABI_VMMAP */
	if ((cap = mmap(0, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_ANON, -1, 0)) == MAP_FAILED)
		cheribsdtest_failure_err("mmap() failed");
	tmpcap = cheri_andperm(cap, ~CHERI_PERM_CHERIABI_VMMAP);
	if (munmap(tmpcap, PAGE_SIZE) == 0)
		cheribsdtest_failure_errx(
		    "munmap() unmapped without CHERI_PERM_CHERIABI_VMMAP");

	/*
	 * Try to map over the previous mapping to check that it is still
	 * there.
	 */
	if ((tmpcap = mmap(cap, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_ANON|MAP_FIXED|MAP_EXCL, -1, 0)) != MAP_FAILED)
		cheribsdtest_failure_err("mmap(%#p, MAP_FIXED|MAP_EXCL) "
		    "succeeded when page should have been mapped", cap);

	if (munmap(cap, PAGE_SIZE) != 0)
		cheribsdtest_failure_err("munmap() failed after overlap check");

	/*
	 * Attempt to MAP_FIXED though a valid capability without
	 * CHERI_PERM_CHERIABI_VMMAP.
	 */
	if ((cap = mmap(0, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_ANON, -1, 0)) == MAP_FAILED)
		cheribsdtest_failure_err("mmap() failed");
	tmpcap = cheri_andperm(cap, ~CHERI_PERM_CHERIABI_VMMAP);

	if ((tmpcap = mmap(tmpcap, PAGE_SIZE, PROT_NONE, MAP_ANON|MAP_FIXED, -1, 0)) !=
	    MAP_FAILED)
		cheribsdtest_failure_errx(
		    "mmap(MAP_FIXED) succeeded through a cap without"
		    " CHERI_PERM_CHERIABI_VMMAP (original %#p, new %#p)",
		    cap, tmpcap);

	if (munmap(cap, PAGE_SIZE) != 0)
		cheribsdtest_failure_err("munmap() failed after MAP_FIXED "
		    "without permission");

	/* Disallow executable pages */
	perms = ~PERM_EXEC;
	if (sysarch(CHERI_MMAP_ANDPERM, &perms) != 0)
		cheribsdtest_failure_err("sysarch(CHERI_MMAP_ANDPERM) failed");
	if ((cap = mmap(0, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_ANON, -1, 0)) != MAP_FAILED)
		cheribsdtest_failure_err("mmap(PROT_READ|PROT_WRITE|PROT_EXEC) "
		    "succeeded after removing PROT_EXEC from default cap");

	cheribsdtest_success();
}
#endif	/* CHERI_MMAP_GETPERM */

#ifdef CHERI_BASELEN_BITS
void
test_cheriabi_mmap_unrepresentable(const struct cheri_test *ctp __unused)
{
	size_t len = ((size_t)PAGE_SIZE << CHERI_BASELEN_BITS) + 1;
	size_t expected_len;
	void *cap;

	expected_len = __builtin_cheri_round_representable_length(len);
	if ((cap = mmap(0, len, PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_ANON, -1, 0)) == MAP_FAILED)

		cheribsdtest_failure_errx("mmap() failed to return a pointer "
		   "when given an unrepresentable length (%zu)", len);
	if (cheri_getlen(cap) != expected_len)
		cheribsdtest_failure_errx("mmap() returned a pointer with "
		    "an unexpected length (%zu vs %zu) when given an "
		    "unrepresentable length (%zu): %#p", cheri_getlen(cap),
		    expected_len, len, cap);

	cheribsdtest_success();
}
#endif

void
test_cheriabi_malloc_zero_size(const struct cheri_test *ctp __unused)
{
	void *cap;

	cap = malloc(0);
	if (cap != NULL && cheri_getlength(cap) != 0)
		cheribsdtest_failure_errx("malloc(0) returned a non-NULL capability with "
		    "non-zero length (%zu)", cheri_getlength(cap));
	cheribsdtest_success();
}

struct adjacent_mappings {
	char *first;
	char *middle;
	char *last;
	size_t maplen;
};

/*
 * Create three adjacent memory mappings that be used to check that the memory
 * mapping system calls reject out-of-bounds capabilities that have the address
 * of a valid mapping.
 */
static void
create_adjacent_mappings(struct adjacent_mappings *mappings)
{
	void *requested_addr;
	size_t len;

	len = getpagesize() * 2;
	mappings->first = CHERIBSDTEST_CHECK_SYSCALL(
	    mmap(0, len, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0));
	CHERIBSDTEST_VERIFY(cheri_gettag(mappings->first));
	/* Try to create a mapping immediately following the latest one. */
	requested_addr =
	    (void *)(uintcap_t)(cheri_getaddress(mappings->first) + len);
	mappings->middle = CHERIBSDTEST_CHECK_SYSCALL2(mmap(requested_addr, len,
	    PROT_READ | PROT_WRITE, MAP_ANON | MAP_FIXED, -1, 0),
	    "Failed to create mapping at address %p", requested_addr);
	CHERIBSDTEST_CHECK_EQ_LONG((vaddr_t)mappings->middle,
	    (vaddr_t)mappings->first + len);
	requested_addr =
	    (void *)(uintcap_t)(cheri_getaddress(mappings->middle) + len);
	CHERIBSDTEST_VERIFY(cheri_gettag(mappings->middle));
	mappings->last = CHERIBSDTEST_CHECK_SYSCALL2(mmap(requested_addr, len,
	    PROT_READ | PROT_WRITE, MAP_ANON | MAP_FIXED, -1, 0),
	    "Failed to create mapping at address %p", requested_addr);
	CHERIBSDTEST_CHECK_EQ_LONG((vaddr_t)mappings->last,
	    (vaddr_t)mappings->middle + len);
	CHERIBSDTEST_VERIFY(cheri_gettag(mappings->last));
	mappings->maplen = len;
}

static void
free_adjacent_mappings(struct adjacent_mappings *mappings)
{
	CHERIBSDTEST_CHECK_SYSCALL(munmap(mappings->first, mappings->maplen));
	CHERIBSDTEST_CHECK_SYSCALL(munmap(mappings->middle, mappings->maplen));
	CHERIBSDTEST_CHECK_SYSCALL(munmap(mappings->last, mappings->maplen));
}

void
test_cheriabi_munmap_invalid_ptr(const struct cheri_test *ctp __unused)
{
	struct adjacent_mappings mappings;

	create_adjacent_mappings(&mappings);

	/* munmap() with an out-of-bounds length should fail. */
	CHERIBSDTEST_CHECK_CALL_ERROR(
	    munmap(mappings.middle, mappings.maplen * 2), EPROT);
	mappings.middle[0] = 'a'; /* Check that it still has PROT_WRITE */
	CHERIBSDTEST_CHECK_CALL_ERROR(
	    munmap(mappings.middle, mappings.maplen + 1), EPROT);
	mappings.middle[0] = 'a'; /* Check that it still has PROT_WRITE */

	/* munmap() with an in-bounds but untagged capability should fail. */
	CHERIBSDTEST_CHECK_CALL_ERROR(
	    munmap(cheri_cleartag(mappings.middle), mappings.maplen), EPROT);
	mappings.middle[0] = 'a'; /* Check that the mapping is still valid */

	/* munmap() with an out-of-bounds capability should fail. */
	CHERIBSDTEST_CHECK_CALL_ERROR(
	    munmap(mappings.middle - mappings.maplen, mappings.maplen), EPROT);
	mappings.first[0] = 'a'; /* Check that the mapping is still valid */
	CHERIBSDTEST_CHECK_CALL_ERROR(
	    munmap(mappings.middle + mappings.maplen, mappings.maplen), EPROT);
	mappings.last[0] = 'a'; /* Check that the mapping is still valid */

	/* Unmapping the original capabilities should succeed. */
	free_adjacent_mappings(&mappings);
	cheribsdtest_success();
}

void
test_cheriabi_mprotect_invalid_ptr(const struct cheri_test *ctp __unused)
{
	struct adjacent_mappings mappings;

	create_adjacent_mappings(&mappings);

	/* mprotect() with an out-of-bounds length should fail. */
	CHERIBSDTEST_CHECK_CALL_ERROR(
	    mprotect(mappings.middle, mappings.maplen * 2, PROT_NONE), EPROT);
	mappings.middle[0] = 'a'; /* Check that it still has PROT_WRITE */
	CHERIBSDTEST_CHECK_CALL_ERROR(
	    mprotect(mappings.middle, mappings.maplen + 1, PROT_NONE), EPROT);
	mappings.middle[0] = 'a'; /* Check that it still has PROT_WRITE */

	/* mprotect() with an in-bounds but untagged capability should fail. */
	CHERIBSDTEST_CHECK_CALL_ERROR(mprotect(cheri_cleartag(mappings.middle),
	    mappings.maplen, PROT_NONE), EPROT);
	mappings.middle[0] = 'a'; /* Check that it still has PROT_WRITE */

	/* mprotect() with an out-of-bounds capability should fail. */
	CHERIBSDTEST_CHECK_CALL_ERROR(mprotect(mappings.middle - mappings.maplen,
	    mappings.maplen, PROT_NONE), EPROT);
	mappings.first[0] = 'a'; /* Check that it still has PROT_WRITE */
	CHERIBSDTEST_CHECK_CALL_ERROR(mprotect(mappings.middle + mappings.maplen,
	    mappings.maplen, PROT_NONE), EPROT);
	mappings.last[0] = 'a'; /* Check that it still has PROT_WRITE */

	/* Sanity check: mprotect() on a valid capability should succeed. */
	CHERIBSDTEST_CHECK_SYSCALL(mprotect(mappings.middle, mappings.maplen,
	    PROT_NONE));
	CHERIBSDTEST_CHECK_SYSCALL(mprotect(mappings.middle, mappings.maplen,
	    PROT_READ));

	/* Unmapping the original capabilities should succeed. */
	free_adjacent_mappings(&mappings);
	cheribsdtest_success();
}

void
test_cheriabi_minherit_invalid_ptr(const struct cheri_test *ctp __unused)
{
	struct adjacent_mappings mappings;

	create_adjacent_mappings(&mappings);

	/* minherit() with an out-of-bounds length should fail. */
	CHERIBSDTEST_CHECK_CALL_ERROR(minherit(mappings.middle,
	    mappings.maplen * 2, INHERIT_NONE), EPROT);
	CHERIBSDTEST_CHECK_CALL_ERROR(minherit(mappings.middle,
	    mappings.maplen + 1, INHERIT_NONE), EPROT);

	/* minherit() with an in-bounds but untagged capability should fail. */
	CHERIBSDTEST_CHECK_CALL_ERROR(minherit(cheri_cleartag(mappings.middle),
	    mappings.maplen, INHERIT_NONE), EPROT);

	/* minherit() with an out-of-bounds capability should fail. */
	CHERIBSDTEST_CHECK_CALL_ERROR(minherit(mappings.middle - mappings.maplen,
	    mappings.maplen, INHERIT_NONE), EPROT);
	CHERIBSDTEST_CHECK_CALL_ERROR(minherit(mappings.middle + mappings.maplen,
	    mappings.maplen, INHERIT_NONE), EPROT);

	/* Sanity check: minherit() on a valid capability should succeed. */
	CHERIBSDTEST_CHECK_SYSCALL(minherit(mappings.middle, mappings.maplen,
	    INHERIT_NONE));
	CHERIBSDTEST_CHECK_SYSCALL(minherit(mappings.middle, mappings.maplen,
	    INHERIT_SHARE));

	/* Unmapping the original capabilities should succeed. */
	free_adjacent_mappings(&mappings);
	cheribsdtest_success();
}

/*
 * Create three adjacent memory mappings that be used to check that the memory
 * mapping system calls reject out-of-bounds capabilities that have the address
 * of a valid mapping.
 */
static void
create_adjacent_mappings_shm(struct adjacent_mappings *mappings)
{
	void *requested_addr;
	size_t len;
	int shmid;

	len = getpagesize() * 2;
	shmid = CHERIBSDTEST_CHECK_SYSCALL(shmget(IPC_PRIVATE, len, 0600));
	mappings->first = CHERIBSDTEST_CHECK_SYSCALL(shmat(shmid, NULL, 0));
	CHERIBSDTEST_VERIFY(cheri_gettag(mappings->first));
	/* Try to create a mapping immediately following the latest one. */
	requested_addr =
	    (void *)(uintcap_t)(cheri_getaddress(mappings->first) + len);
	mappings->middle = CHERIBSDTEST_CHECK_SYSCALL2(
	    shmat(shmid, requested_addr, 0),
	    "Failed to create mapping at address %p", requested_addr);
	CHERIBSDTEST_CHECK_EQ_LONG((vaddr_t)mappings->middle,
	    (vaddr_t)requested_addr);
	CHERIBSDTEST_VERIFY(cheri_gettag(mappings->middle));
	requested_addr =
	    (void *)(uintcap_t)(cheri_getaddress(mappings->middle) + len);
	mappings->last = CHERIBSDTEST_CHECK_SYSCALL2(
	    shmat(shmid, requested_addr, 0),
	    "Failed to create mapping at address %p", requested_addr);
	CHERIBSDTEST_CHECK_EQ_LONG((vaddr_t)mappings->last,
	    (vaddr_t)requested_addr);
	CHERIBSDTEST_VERIFY(cheri_gettag(mappings->last));
	mappings->maplen = len;
}

static void
free_adjacent_mappings_shm(struct adjacent_mappings *mappings)
{
	CHERIBSDTEST_CHECK_SYSCALL(shmdt(mappings->first));
	CHERIBSDTEST_CHECK_SYSCALL(shmdt(mappings->middle));
	CHERIBSDTEST_CHECK_SYSCALL(shmdt(mappings->last));
}

void
test_cheriabi_shmdt_invalid_ptr(const struct cheri_test *ctp __unused)
{
	struct adjacent_mappings mappings;

	create_adjacent_mappings_shm(&mappings);

	/* shmdt() with an in-bounds but untagged capability should fail. */
	CHERIBSDTEST_CHECK_CALL_ERROR(
	    shmdt(cheri_cleartag(mappings.middle)), EPROT);
	mappings.middle[0] = 'a'; /* Check that the mapping is still valid */

	/* shmdt() with an out-of-bounds capability should fail. */
	CHERIBSDTEST_CHECK_CALL_ERROR(
	    shmdt(mappings.middle - mappings.maplen), EPROT);
	mappings.first[0] = 'a'; /* Check that the mapping is still valid */
	CHERIBSDTEST_CHECK_CALL_ERROR(
	    shmdt(mappings.middle + mappings.maplen), EPROT);
	mappings.last[0] = 'a'; /* Check that the mapping is still valid */

	/* Unmapping the original capabilities should succeed. */
	free_adjacent_mappings_shm(&mappings);
	cheribsdtest_success();
}
