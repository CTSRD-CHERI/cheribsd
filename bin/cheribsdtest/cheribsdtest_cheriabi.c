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

CHERIBSDTEST(cheriabi_mmap_unrepresentable,
    "Test CheriABI mmap() with unrepresentable lengths")
{
	int shift = 0;
	size_t len;
	size_t expected_len;
	void *cap;

	/*
	 * Generate the shortest unrepresentable length, for which rounding
	 * up to PAGE_SIZE is still unrepresentable.
	 */
	do {
		len = (1 << (PAGE_SHIFT + shift)) + 1;
		shift++;
	} while (round_page(len) ==
	    __builtin_cheri_round_representable_length(round_page(len)));

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

CHERIBSDTEST(cheriabi_mmap_fixed,
    "Verify that we can MAP_FIXED over multiple vm map entries")
{
	void *p1, *p2;

	/* Create a large mapping */
	p1 = mmap(0, 0x200000, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANON | MAP_ALIGNED(21), -1, 0);
	CHERIBSDTEST_VERIFY(p1 != MAP_FAILED);

	/*
	 * Map over part of the mapping.  This (currently) results
	 * in there being two vm map entries, one of length 0x20000
	 * and another of 0x200000 - 0x20000.
	 */
	p2 = mmap(p1, 0x20000, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_FIXED | MAP_ANON, -1, 0);
	CHERIBSDTEST_VERIFY(p1 == p2);

	/*
	 * Map over a larger part of the origional mapping spanning
	 * two vm map entries.
	 */
	p2 = mmap(p1, 0x40000, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_FIXED | MAP_ANON, -1, 0);
	CHERIBSDTEST_VERIFY(p1 == p2);

	cheribsdtest_success();
}

CHERIBSDTEST(cheriabi_malloc_zero_size,
    "Check that zero-sized mallocs are properly bounded")
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
	memset(mappings, 0, sizeof(*mappings));
	requested_addr = (void *)(uintcap_t)find_address_space_gap(len * 3, 0);
	mappings->first = CHERIBSDTEST_CHECK_SYSCALL(mmap(requested_addr, len,
	    PROT_READ | PROT_WRITE, MAP_ANON | MAP_FIXED, -1, 0));
	CHERIBSDTEST_VERIFY(cheri_gettag(mappings->first));
	/* Try to create a mapping immediately following the latest one. */
	requested_addr =
	    (void *)(uintcap_t)(cheri_getaddress(mappings->first) + len);
	mappings->middle = CHERIBSDTEST_CHECK_SYSCALL2(mmap(requested_addr, len,
	    PROT_READ | PROT_WRITE, MAP_ANON | MAP_FIXED, -1, 0),
	    "Failed to create mapping at address %p", requested_addr);
	CHERIBSDTEST_CHECK_EQ_LONG((ptraddr_t)mappings->middle,
	    (ptraddr_t)mappings->first + len);
	requested_addr =
	    (void *)(uintcap_t)(cheri_getaddress(mappings->middle) + len);
	CHERIBSDTEST_VERIFY(cheri_gettag(mappings->middle));
	mappings->last = CHERIBSDTEST_CHECK_SYSCALL2(mmap(requested_addr, len,
	    PROT_READ | PROT_WRITE, MAP_ANON | MAP_FIXED, -1, 0),
	    "Failed to create mapping at address %p", requested_addr);
	CHERIBSDTEST_CHECK_EQ_LONG((ptraddr_t)mappings->last,
	    (ptraddr_t)mappings->middle + len);
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

CHERIBSDTEST(cheriabi_munmap_invalid_ptr,
    "Check that munmap() rejects invalid pointer arguments")
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

CHERIBSDTEST(cheriabi_mprotect_invalid_ptr,
    "Check that mprotect() rejects invalid pointer arguments")
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

CHERIBSDTEST(cheriabi_minherit_invalid_ptr,
    "Check that minherit() rejects invalid pointer arguments")
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
	memset(mappings, 0, sizeof(*mappings));
	shmid = CHERIBSDTEST_CHECK_SYSCALL(shmget(IPC_PRIVATE, len, 0600));
	requested_addr = (void *)(uintcap_t)find_address_space_gap(len * 3, 0);
	mappings->first = CHERIBSDTEST_CHECK_SYSCALL(shmat(shmid,
	    requested_addr, 0));
	CHERIBSDTEST_VERIFY(cheri_gettag(mappings->first));
	/* Try to create a mapping immediately following the latest one. */
	requested_addr =
	    (void *)(uintcap_t)(cheri_getaddress(mappings->first) + len);
	mappings->middle = CHERIBSDTEST_CHECK_SYSCALL2(
	    shmat(shmid, requested_addr, 0),
	    "Failed to create mapping at address %p", requested_addr);
	CHERIBSDTEST_CHECK_EQ_LONG((ptraddr_t)mappings->middle,
	    (ptraddr_t)requested_addr);
	CHERIBSDTEST_VERIFY(cheri_gettag(mappings->middle));
	requested_addr =
	    (void *)(uintcap_t)(cheri_getaddress(mappings->middle) + len);
	mappings->last = CHERIBSDTEST_CHECK_SYSCALL2(
	    shmat(shmid, requested_addr, 0),
	    "Failed to create mapping at address %p", requested_addr);
	CHERIBSDTEST_CHECK_EQ_LONG((ptraddr_t)mappings->last,
	    (ptraddr_t)requested_addr);
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

CHERIBSDTEST(cheriabi_shmdt_invalid_ptr,
    "Check that shmdt() rejects invalid pointer arguments")
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
