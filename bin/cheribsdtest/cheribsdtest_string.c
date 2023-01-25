/*-
 * Copyright (c) 2012-2014 David T. Chisnall
 * Copyright (c) 2015 SRI International
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

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <string.h>

#include "cheribsdtest.h"

#ifdef KERNEL_MEMCPY_TESTS
void * __capability
    kern_memcpy_c(void * __capability, const void * __capability, size_t);
void * __capability
    kern_memmove_c(void * __capability, const void * __capability, size_t);
#endif

/* XXXAR: extra cast to void* to work around CTSRD-CHERI/clang#178 */
#define	CAP(x)	((__cheri_tocap void *__capability)(void*)(x))

/*
 * Test structure which will be memcpy'd.  Contains data and a capability in
 * the middle.  The capability must be aligned, but memcpy should work for any
 * partial copy of this structure that includes the capability, as long as both
 * have the correct alignment.
 */
struct Test
{
	char pad0[32];
	void * __capability y;
	char pad1[32];
};

static void * __capability expected_y;

/*
 * Check that the copy has the data that we expect it to contain.  The start
 * and end parameters describe the range in the padding to check.  For partial
 * copies, the uncopied range will contain nonsense.
 */
static void
check(struct Test *t1, int start, int end)
{
	int i;

	for (i = start; i < 32; i++)
		if (t1->pad0[i] != i)
			cheribsdtest_failure_errx(
			    "(start = %d, end %d) t1->pad0[%d] != %d", start,
			    end, i, i);
	if (t1->y != expected_y)
		cheribsdtest_failure_errx("(start = %d, end %d) t1->y != t1",
		    start, end);
	if (!cheri_gettag(t1->y))
		cheribsdtest_failure_errx("(start = %d, end %d) t1->y is untagged",
		     start, end);
	for (i = 0 ; i < end ; i++)
		if (t1->pad1[i] != i)
			cheribsdtest_failure_errx(
			    "(start = %d, end %d) t1->pad1[%d] != %d",
			    start, end, i, i);
}

/*
 * Write an obviously invalid byte pattern over the output structure.
 */
static void
invalidate(struct Test *t1)
{
	size_t i;
	unsigned char *x = (unsigned char*)t1;

	for (i = 0; i < sizeof(*t1); i++)
		*x = 0xa5;
}

CHERIBSDTEST(string_memcpy_c, "Test explicit capability memcpy")
{
	int i;
	void * __capability cpy;
	struct Test t1, t2;

	invalidate(&t1);
	for (i = 0; i < 32; i++) {
		t1.pad0[i] = i;
		t1.pad1[i] = i;
	}
	expected_y = t1.y = CAP(&t2);

	/* Simple case: aligned start and end */
	invalidate(&t2);
	cpy = memcpy_c(CAP(&t2), CAP(&t1), sizeof(t1));
	if ((__cheri_fromcap void *)cpy != &t2)
		cheribsdtest_failure_errx("memcpy_c did not return dst (&t2)");
	check(&t2, 0, 32);

	/* Test that it still works with an unaligned start... */
	invalidate(&t2);
	cpy = memcpy_c(CAP(&t2.pad0[3]), CAP(&t1.pad0[3]), sizeof(t1) - 3);
	if ((__cheri_fromcap void*)cpy != &t2.pad0[3])
		cheribsdtest_failure_errx("memcpy_c did not return dst "
		    "(&t2.pad0[3])");
	check(&t2, 3, 32);

	/* ...or and unaligned end... */
	invalidate(&t2);
	cpy = memcpy_c(CAP(&t2), CAP(&t1), sizeof(t1) - 3);
	if ((__cheri_fromcap void *)cpy != &t2)
		cheribsdtest_failure_errx("memcpy_c did not return dst (&t2)");
	check(&t2, 0, 29);

	/* ...or both... */
	invalidate(&t2);
	cpy = memcpy_c(CAP(&t2.pad0[3]), CAP(&t1.pad0[3]), sizeof(t1) - 6);
	if ((__cheri_fromcap void*)cpy != &t2.pad0[3])
		cheribsdtest_failure_errx("memcpy_c did not return dst "
		    "(&t2.pad0[3])");
	check(&t2, 3, 29);

	/* ...and case where the alignment is different for both... */
	invalidate(&t2);
	cpy = memcpy_c(CAP(&t2), CAP(&t1.pad0[1]), sizeof(t1) - 1);
	if ((__cheri_fromcap void*)cpy != &t2)
		cheribsdtest_failure_errx("memcpy_c did not return dst (&t2)");
	/* This should have invalidated the capability */
	if (cheri_gettag(t2.y) != 0)
		cheribsdtest_failure_errx("dst has capability after unaligned "
		    "write");
	for (i = 0; i < 31; i++) {
		if (t2.pad0[i] != i+1)
			cheribsdtest_failure_errx("t2.pad0[%d] != %d", i, i+1);
		if (t2.pad1[i] != i+1)
			cheribsdtest_failure_errx("t2.pad1[%d] != %d", i, i+1);
	}

	/*
	 * ...and finally finally tests that offsets are taken into
	 * account when checking alignment.  These are regression tests
	 * for a bug in memcpy_c.
	 */
	/* aligned base, unaligned offset + base */
	invalidate(&t2);
	cpy = memcpy_c(
	    __builtin_cheri_offset_increment(CAP(&t2), 3),
	    __builtin_cheri_offset_increment(CAP(&t1), 3),
	    sizeof(t1)-6);
	if ((__cheri_fromcap void*)cpy != &t2.pad0[3])
		cheribsdtest_failure_errx("memcpy_c did not return dst "
		    "(&t2.pad0[3])");
	check(&t2, 3, 29);

	/* unaligned base, aligned offset + base */
	// FIXME: This currently gives an aligned base.  We should make the CAP
	// macro take a base and length so that it can do CIncBase / CSetLen on
	// CHERI256, CFromPtr / CSetBounds on CHERI128
	invalidate(&t2);
	cpy = memcpy_c(
	    __builtin_cheri_offset_increment(CAP(t2.pad0-1), 1),
	    __builtin_cheri_offset_increment(CAP(t1.pad0-1), 1),
	    sizeof(t1));
	if ((__cheri_fromcap void*)cpy != &t2.pad0)
		cheribsdtest_failure_errx("(void*)cpy != &t2.pad0");
	check(&t2, 0, 32);

	/* Unaligned, but offset=32 */
	invalidate(&t2);
	cpy = memmove_c(
	    __builtin_cheri_offset_increment(CAP(t2.pad0-1), 32),
	    __builtin_cheri_offset_increment(CAP(t1.pad0-1), 32),
	    sizeof(t1) - 31);
	if ((__cheri_fromcap void*)cpy != t2.pad0+31)
		cheribsdtest_failure_errx("(void*)cpy != t2.pad0+31");
	check(&t2, 31, 32);

	cheribsdtest_success();
}

CHERIBSDTEST(string_memcpy, "Test implicit capability memcpy")
{
	int i;
	void *copy;
	struct Test t1, t2;

	invalidate(&t1);
	for (i = 0; i < 32; i++) {
		t1.pad0[i] = i;
		t1.pad1[i] = i;
	}
	expected_y = t1.y = CAP(&t2);

	/* Simple case: aligned start and end */
	invalidate(&t2);
	copy = memcpy(&t2, &t1, sizeof(t1));
	if (copy != &t2)
		cheribsdtest_failure_errx("copy != &t2");
	check(&t2, 0, 32);

	/* Test that it still works with an unaligned start... */
	invalidate(&t2);
	copy = memcpy(&t2.pad0[3], &t1.pad0[3], sizeof(t1) - 3);
	if ((void*)copy != &t2.pad0[3])
		cheribsdtest_failure_errx("memcpy_c did not return dst "
		    "(&t2.pad0[3])");
	check(&t2, 3, 32);

	/* ...or an unaligned end... */
	invalidate(&t2);
	copy = memcpy(&t2, &t1, sizeof(t1) - 3);
	if (copy != &t2)
		cheribsdtest_failure_errx("copy != &t2");
	check(&t2, 0, 29);

	/* ...or both... */
	invalidate(&t2);
	copy = memcpy(&t2.pad0[3], &t1.pad0[3], sizeof(t1) - 6);
	if ((void*)copy != &t2.pad0[3])
		cheribsdtest_failure_errx("memcpy_c did not return dst "
		    "(&t2.pad0[3])");
	check(&t2, 3, 29);

	/* ...and finally a case where the alignment is different for both */
	copy = memcpy(&t2, &t1.pad0[1], sizeof(t1) - 1);
	if (copy != &t2)
		cheribsdtest_failure_errx("copy != &t2");
	if (cheri_gettag(t2.y) != 0)
		cheribsdtest_failure_errx("dst has capability after unaligned "
		    "write");
	for (i = 0; i < 31; i++) {
		if (t2.pad0[i] != i+1)
			cheribsdtest_failure_errx("t2.pad0[%d] != %d", i, i+1);
		if (t2.pad1[i] != i+1)
			cheribsdtest_failure_errx("t2.pad1[%d] != %d", i, i+1);
	}

	cheribsdtest_success();
}

CHERIBSDTEST(string_memmove_c, "Test explicit capability memmove")
{
	int i;
	void * __capability cpy;
	struct Test t1, t2;

	invalidate(&t1);
	for (i = 0; i < 32; i++) {
		t1.pad0[i] = i;
		t1.pad1[i] = i;
	}
	expected_y = t1.y = CAP(&t2);

	/* Simple case: aligned start and end */
	invalidate(&t2);
	cpy = memmove_c(CAP(&t2), CAP(&t1), sizeof(t1));
	if ((__cheri_fromcap void *)cpy != &t2)
		cheribsdtest_failure_errx("memmove_c did not return dst (&t2)");
	check(&t2, 0, 32);

	/* Test that it still works with an unaligned start... */
	invalidate(&t2);
	cpy = memmove_c(CAP(&t2.pad0[3]), CAP(&t1.pad0[3]), sizeof(t1) - 3);
	if ((__cheri_fromcap void*)cpy != &t2.pad0[3])
		cheribsdtest_failure_errx("memmove_c did not return dst "
		    "(&t2.pad0[3])");
	check(&t2, 3, 32);

	/* ...or and unaligned end... */
	invalidate(&t2);
	cpy = memmove_c(CAP(&t2), CAP(&t1), sizeof(t1) - 3);
	if ((__cheri_fromcap void *)cpy != &t2)
		cheribsdtest_failure_errx("memmove_c did not return dst (&t2)");
	check(&t2, 0, 29);

	/* ...or both... */
	invalidate(&t2);
	cpy = memmove_c(CAP(&t2.pad0[3]), CAP(&t1.pad0[3]), sizeof(t1) - 6);
	if ((__cheri_fromcap void*)cpy != &t2.pad0[3])
		cheribsdtest_failure_errx("memmove_c did not return dst "
		    "(&t2.pad0[3])");
	check(&t2, 3, 29);

	/* ...and case where the alignment is different for both... */
	invalidate(&t2);
	cpy = memmove_c(CAP(&t2), CAP(&t1.pad0[1]), sizeof(t1) - 1);
	if ((__cheri_fromcap void*)cpy != &t2)
		cheribsdtest_failure_errx("memmove_c did not return dst (&t2)");
	/* This should have invalidated the capability */
	if (cheri_gettag(t2.y) != 0)
		cheribsdtest_failure_errx("dst has capability after unaligned "
		    "write");
	for (i = 0; i < 31; i++) {
		if (t2.pad0[i] != i+1)
			cheribsdtest_failure_errx("t2.pad0[%d] != %d", i, i+1);
		if (t2.pad1[i] != i+1)
			cheribsdtest_failure_errx("t2.pad1[%d] != %d", i, i+1);
	}

	/*
	 * ...and finally finally tests that offsets are taken into
	 * account when checking alignment.  These are regression tests
	 * for a bug in memmove_c.
	 */
	/* aligned base, unaligned offset + base */
	invalidate(&t2);
	cpy = memmove_c(
	    __builtin_cheri_offset_increment(CAP(&t2), 3),
	    __builtin_cheri_offset_increment(CAP(&t1), 3),
	    sizeof(t1)-6);
	if ((__cheri_fromcap void*)cpy != &t2.pad0[3])
		cheribsdtest_failure_errx("memmove_c did not return dst "
		    "(&t2.pad0[3])");
	check(&t2, 3, 29);

	/* unaligned base, aligned offset + base */
	invalidate(&t2);
	cpy = memmove_c(
	    __builtin_cheri_offset_increment(CAP(t2.pad0-1), 1),
	    __builtin_cheri_offset_increment(CAP(t1.pad0-1), 1),
	    sizeof(t1));
	if ((__cheri_fromcap void*)cpy != &t2.pad0)
		cheribsdtest_failure_errx("(void*)cpy != &t2.pad0");
	check(&t2, 0, 32);

	/* Unaligned, but offset=32 */
	invalidate(&t2);
	cpy = memmove_c(
	    __builtin_cheri_offset_increment(CAP(t2.pad0-1), 32),
	    __builtin_cheri_offset_increment(CAP(t1.pad0-1), 32),
	    sizeof(t1) - 31);
	if ((__cheri_fromcap void*)cpy != t2.pad0+31)
		cheribsdtest_failure_errx("(void*)cpy != t2.pad0+31");
	check(&t2, 31, 32);

	/* XXX-BD: test overlapping cases */

	cheribsdtest_success();
}

CHERIBSDTEST(string_memmove, "Test implicit capability memmove")
{
	int i;
	void *copy;
	struct Test t1, t2;

	invalidate(&t1);
	for (i = 0; i < 32; i++) {
		t1.pad0[i] = i;
		t1.pad1[i] = i;
	}
	expected_y = t1.y = CAP(&t2);

	/* Simple case: aligned start and end */
	invalidate(&t2);
	copy = memmove(&t2, &t1, sizeof(t1));
	if (copy != &t2)
		cheribsdtest_failure_errx("copy != &t2");
	check(&t2, 0, 32);

	/* Test that it still works with an unaligned start... */
	invalidate(&t2);
	copy = memmove(&t2.pad0[3], &t1.pad0[3], sizeof(t1) - 3);
	if ((void*)copy != &t2.pad0[3])
		cheribsdtest_failure_errx("memmove_c did not return dst "
		    "(&t2.pad0[3])");
	check(&t2, 3, 32);

	/* ...or an unaligned end... */
	invalidate(&t2);
	copy = memmove(&t2, &t1, sizeof(t1) - 3);
	if (copy != &t2)
		cheribsdtest_failure_errx("copy != &t2");
	check(&t2, 0, 29);

	/* ...or both... */
	invalidate(&t2);
	copy = memmove(&t2.pad0[3], &t1.pad0[3], sizeof(t1) - 6);
	if ((void*)copy != &t2.pad0[3])
		cheribsdtest_failure_errx("memmove_c did not return dst "
		    "(&t2.pad0[3])");
	check(&t2, 3, 29);

	/* ...and finally a case where the alignment is different for both */
	copy = memmove(&t2, &t1.pad0[1], sizeof(t1) - 1);
	if (copy != &t2)
		cheribsdtest_failure_errx("copy != &t2");
	if (cheri_gettag(t2.y) != 0)
		cheribsdtest_failure_errx("dst has capability after unaligned "
		    "write");
	for (i = 0; i < 31; i++) {
		if (t2.pad0[i] != i+1)
			cheribsdtest_failure_errx("t2.pad0[%d] != %d", i, i+1);
		if (t2.pad1[i] != i+1)
			cheribsdtest_failure_errx("t2.pad1[%d] != %d", i, i+1);
	}

	/* XXX-BD: test overlapping cases */

	cheribsdtest_success();
}

/*
 * XXXAR: We use cheribsdtest_memcpy()/cheribsdtest_memmove() so that the compiler
 * can't replace it with an inline loop. We could also use -fno-builtin but that
 * could interfere with the other tests.
 */
CHERIBSDTEST(unaligned_capability_copy_memcpy,
    "Check that a memcpy() of valid capabilities to an unaligned destination "
    "strips tags")
{
	/* Copying a tagged capability to an unaligned destination should trap. */
	void * __capability src_buffer[2];
	_Alignas(void * __capability) char dest_buffer[2 * sizeof(void* __capability) + 1];

	/* Check that dest buffer is capability aligned so that dest + 1 isn't */
	/* TODO: __builtin_is_aligned does not work on arrays (yet) */
	CHERIBSDTEST_VERIFY(__builtin_is_aligned((void*)dest_buffer, sizeof(void* __capability)));
	CHERIBSDTEST_VERIFY(__builtin_is_aligned((void*)src_buffer, sizeof(void * __capability)));

	src_buffer[0] = cheri_setoffset(NULL, 0x1234);
	src_buffer[1] = cheri_setoffset(NULL, 0x4321);
	CHERIBSDTEST_VERIFY(!cheri_gettag(src_buffer[0]));
	CHERIBSDTEST_VERIFY(!cheri_gettag(src_buffer[1]));
	/* This should succeed */
	cheribsdtest_memcpy(dest_buffer + 1 /* unaligned! */, src_buffer, sizeof(src_buffer));
	/* TODO: verify the contents of the buffer? */

	/* Even if we have a valid cap and operate misaligned, we should not fault. */
	src_buffer[1] = (__cheri_tocap void* __capability)&expected_y;
	CHERIBSDTEST_VERIFY(!cheri_gettag(src_buffer[0]));
	CHERIBSDTEST_VERIFY(cheri_gettag(src_buffer[1]));

	cheribsdtest_memcpy(dest_buffer + 1 /* unaligned! */, src_buffer, sizeof(src_buffer));
	CHERIBSDTEST_VERIFY(!cheri_gettag(((void * __capability *)dest_buffer)[0]));
	CHERIBSDTEST_VERIFY(!cheri_gettag(((void * __capability *)dest_buffer)[1]));
	/* TODO: verify the contents of the buffer? */

	cheribsdtest_success();
}

CHERIBSDTEST(unaligned_capability_copy_memmove,
    "Check that a memmove() of valid capabilities to an unaligned destination "
    "strips tags")
{
	/* Copying a tagged capability to an unaligned destination should trap. */
	void * __capability src_buffer[2];
	_Alignas(void * __capability) char dest_buffer[2 * sizeof(void* __capability) + 1];

	/* Check that dest buffer is capability aligned so that dest + 1 isn't */
	/* TODO: __builtin_is_aligned does not work on arrays (yet) */
	CHERIBSDTEST_VERIFY(__builtin_is_aligned((void*)dest_buffer, sizeof(void* __capability)));
	CHERIBSDTEST_VERIFY(__builtin_is_aligned((void*)src_buffer, sizeof(void * __capability)));

	src_buffer[0] = cheri_setoffset(NULL, 0x1234);
	src_buffer[1] = cheri_setoffset(NULL, 0x4321);
	CHERIBSDTEST_VERIFY(!cheri_gettag(src_buffer[0]));
	CHERIBSDTEST_VERIFY(!cheri_gettag(src_buffer[1]));
	/* This should succeed */
	cheribsdtest_memmove(dest_buffer + 1 /* unaligned! */, src_buffer, sizeof(src_buffer));
	/* TODO: verify the contents of the buffer? */

	/* Even if we have a valid cap and operate misaligned, we should not fault. */
	src_buffer[1] = (__cheri_tocap void* __capability)&expected_y;
	CHERIBSDTEST_VERIFY(!cheri_gettag(src_buffer[0]));
	CHERIBSDTEST_VERIFY(cheri_gettag(src_buffer[1]));

	cheribsdtest_memmove(dest_buffer + 1 /* unaligned! */, src_buffer, sizeof(src_buffer));
	CHERIBSDTEST_VERIFY(!cheri_gettag(((void * __capability *)dest_buffer)[0]));
	CHERIBSDTEST_VERIFY(!cheri_gettag(((void * __capability *)dest_buffer)[1]));
	/* TODO: verify the contents of the buffer? */

	cheribsdtest_success();
}

#ifdef KERNEL_MEMCPY_TESTS
CHERIBSDTEST(string_kern_memcpy_c,
    "Test explicit capability memcpy (kernel version)")
{
	int i;
	void * __capability cpy;
	struct Test t1, t2;

	invalidate(&t1);
	for (i = 0; i < 32; i++) {
		t1.pad0[i] = i;
		t1.pad1[i] = i;
	}
	expected_y = t1.y = CAP(&t2);
	check(&t1, 0, 32);

	/* Check all combinations of start and end alignments */
	for (size_t head = 0; head < sizeof(t2.pad0); head++) {
		for (size_t tail = 0; tail < sizeof(t2.pad1); tail++) {
			int len = sizeof(t2) - head - (sizeof(t2.pad1) - tail);
			invalidate(&t2);
			cpy = kern_memcpy_c(CAP(&t2.pad0[head]),
			    CAP(&t1.pad0[head]),
			    len);
			if ((__cheri_fromcap void*)cpy != &t2.pad0[head])
				cheribsdtest_failure_errx(
				    "kern_memcpy_c did not return dst "
				    "(&t2.pad0[%zu])", head);
			check(&t2, head, tail);
		}
	}

	/* ...and case where the alignment is different for both... */
	invalidate(&t2);
	cpy = kern_memcpy_c(CAP(&t2), CAP(&t1.pad0[1]), sizeof(t1) - 1);
	if ((__cheri_fromcap void*)cpy != &t2)
		cheribsdtest_failure_errx("kern_memcpy_c did not return dst (&t2)");
	/* This should have invalidated the capability */
	if (cheri_gettag(t2.y) != 0)
		cheribsdtest_failure_errx("dst has capability after unaligned "
		    "write");
	for (i = 0; i < 31; i++) {
		if (t2.pad0[i] != i+1)
			cheribsdtest_failure_errx("t2.pad0[%d] != %d", i, i+1);
		if (t2.pad1[i] != i+1)
			cheribsdtest_failure_errx("t2.pad1[%d] != %d", i, i+1);
	}

	/*
	 * ...and finally finally tests that offsets are taken into
	 * account when checking alignment.  These are regression tests
	 * for a bug in kern_memcpy_c.
	 */
	/* aligned base, unaligned offset + base */
	invalidate(&t2);
	cpy = kern_memcpy_c(
	    __builtin_cheri_offset_increment(CAP(&t2), 3),
	    __builtin_cheri_offset_increment(CAP(&t1), 3),
	    sizeof(t1)-6);
	if ((__cheri_fromcap void*)cpy != &t2.pad0[3])
		cheribsdtest_failure_errx("kern_memcpy_c did not return dst "
		    "(&t2.pad0[3])");
	check(&t2, 3, 29);

	/* unaligned base, aligned offset + base */
	// FIXME: This currently gives an aligned base.  We should make the CAP
	// macro take a base and length so that it can do CIncBase / CSetLen on
	// CHERI256, CFromPtr / CSetBounds on CHERI128
	invalidate(&t2);
	cpy = kern_memcpy_c(
	    __builtin_cheri_offset_increment(CAP(t2.pad0-1), 1),
	    __builtin_cheri_offset_increment(CAP(t1.pad0-1), 1),
	    sizeof(t1));
	if ((__cheri_fromcap void*)cpy != &t2.pad0)
		cheribsdtest_failure_errx("(void*)cpy != &t2.pad0");
	check(&t2, 0, 32);

	/* Unaligned, but offset=32 */
	invalidate(&t2);
	cpy = kern_memcpy_c(
	    __builtin_cheri_offset_increment(CAP(t2.pad0-1), 32),
	    __builtin_cheri_offset_increment(CAP(t1.pad0-1), 32),
	    sizeof(t1) - 31);
	if ((__cheri_fromcap void*)cpy != t2.pad0+31)
		cheribsdtest_failure_errx("(void*)cpy != t2.pad0+31");
	check(&t2, 31, 32);

	cheribsdtest_success();
}

CHERIBSDTEST(string_kern_memmove_c,
    "Test explicit capability memmove (kernel version)")
{
	int i;
	void * __capability cpy;
	struct Test t1, t2;

	invalidate(&t1);
	for (i = 0; i < 32; i++) {
		t1.pad0[i] = i;
		t1.pad1[i] = i;
	}
	expected_y = t1.y = CAP(&t2);

	/* Check all combinations of start and end alignments */
	for (size_t head = 0; head < sizeof(t2.pad0); head++) {
		for (size_t tail = 0; tail < sizeof(t2.pad0); tail++) {
			int len = sizeof(t2) - head - (sizeof(t2.pad1) - tail);
			invalidate(&t2);
			cpy = kern_memmove_c(CAP(&t2.pad0[head]),
			    CAP(&t1.pad0[head]),
			    len);
			if ((__cheri_fromcap void*)cpy != &t2.pad0[head])
				cheribsdtest_failure_errx(
				    "kern_memcpy_c did not return dst "
				    "(&t2.pad0[%zu])", head);
			check(&t2, head, tail);
		}
	}

	/* ...and case where the alignment is different for both... */
	invalidate(&t2);
	cpy = kern_memmove_c(CAP(&t2), CAP(&t1.pad0[1]), sizeof(t1) - 1);
	if ((__cheri_fromcap void*)cpy != &t2)
		cheribsdtest_failure_errx("kern_memmove_c did not return dst (&t2)");
	/* This should have invalidated the capability */
	if (cheri_gettag(t2.y) != 0)
		cheribsdtest_failure_errx("dst has capability after unaligned "
		    "write");
	for (i = 0; i < 31; i++) {
		if (t2.pad0[i] != i+1)
			cheribsdtest_failure_errx("t2.pad0[%d] != %d", i, i+1);
		if (t2.pad1[i] != i+1)
			cheribsdtest_failure_errx("t2.pad1[%d] != %d", i, i+1);
	}

	/*
	 * ...and finally finally tests that offsets are taken into
	 * account when checking alignment.  These are regression tests
	 * for a bug in kern_memmove_c.
	 */
	/* aligned base, unaligned offset + base */
	invalidate(&t2);
	cpy = kern_memmove_c(
	    __builtin_cheri_offset_increment(CAP(&t2), 3),
	    __builtin_cheri_offset_increment(CAP(&t1), 3),
	    sizeof(t1)-6);
	if ((__cheri_fromcap void*)cpy != &t2.pad0[3])
		cheribsdtest_failure_errx("kern_memmove_c did not return dst "
		    "(&t2.pad0[3])");
	check(&t2, 3, 29);

	/* unaligned base, aligned offset + base */
	invalidate(&t2);
	cpy = kern_memmove_c(
	    __builtin_cheri_offset_increment(CAP(t2.pad0-1), 1),
	    __builtin_cheri_offset_increment(CAP(t1.pad0-1), 1),
	    sizeof(t1));
	if ((__cheri_fromcap void*)cpy != &t2.pad0)
		cheribsdtest_failure_errx("(void*)cpy != &t2.pad0");
	check(&t2, 0, 32);

	/* Unaligned, but offset=32 */
	invalidate(&t2);
	cpy = kern_memmove_c(
	    __builtin_cheri_offset_increment(CAP(t2.pad0-1), 32),
	    __builtin_cheri_offset_increment(CAP(t1.pad0-1), 32),
	    sizeof(t1) - 31);
	if ((__cheri_fromcap void*)cpy != t2.pad0+31)
		cheribsdtest_failure_errx("(void*)cpy != t2.pad0+31");
	check(&t2, 31, 32);

	/* XXX-BD: test overlapping cases */

	cheribsdtest_success();
}
#endif
