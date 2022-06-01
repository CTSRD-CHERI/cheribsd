/*-
 * Copyright (c) 2021 Robert N. M. Watson
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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
#include <sys/queue.h>
#include <sys/signal.h>
#include <sys/stddef.h>
#include <sys/sysctl.h>
#include <sys/time.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

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

/*
 * Tests for subobject bounds derived in various ways and against various
 * container object types, as well as annotations to exempt them.
 *
 * These tests are currently only for pure-capability code, as we don't enable
 * subobject bounds for hybrid code compilation.
 */
#ifndef __CHERI_PURE_CAPABILITY__
#error "Requires pure-capability compilation"
#endif

/*
 * Simple underflow and overflow tests on pointers taken to struct fields.
 * The field we test with in these cases is aligned neither to the start nor
 * the end of the structure.
 */
struct struct_char {
	char underflow;
	char c;
	char overflow;
};

CHERIBSDTEST(test_bounds_subobject_struct_char,
    "Check subobject bounds on a 1-character field in a structure")
{
	struct struct_char sc;
	void * __capability cp;

	cp = &sc.c;
	CHERIBSDTEST_CHECK_CAP_BOUNDS_PRECISE(cp, sizeof(sc.c));
	cheribsdtest_success();
}

struct struct_int {
	char underflow;
	int i;
	char overflow;
};

CHERIBSDTEST(test_bounds_subobject_struct_int,
    "Check subobject bounds on an integer field in a structure")
{
	struct struct_int si;
	void * __capability cp;

	cp = &si.i;
	CHERIBSDTEST_CHECK_CAP_BOUNDS_PRECISE(cp, sizeof(si.i));
	cheribsdtest_success();
}

struct struct_chararray1 {
	char underflow;
	char chararray1[1];
	char overflow;
};

CHERIBSDTEST(test_bounds_subobject_struct_chararray1,
    "Check subobject bounds on a char array of size 1 within a struct")
{
	struct struct_chararray1 sc1;
	void * __capability cp;

	cp = &sc1.chararray1;
	CHERIBSDTEST_CHECK_CAP_BOUNDS_PRECISE(cp, sizeof(sc1.chararray1));
	cheribsdtest_success();
}

struct struct_chararray2 {
	char underflow;
	char chararray2[2];
	char overflow;
};

CHERIBSDTEST(test_bounds_subobject_struct_chararray2,
    "Check subobject bounds on a char array of size 2 within a struct")
{
	struct struct_chararray2 sc2;
	void * __capability cp;

	cp = (void * __capability)&sc2.chararray2;
	CHERIBSDTEST_CHECK_CAP_BOUNDS_PRECISE(cp, sizeof(sc2.chararray2));
	cheribsdtest_success();
}

struct struct_chararray128 {
	char underflow;
	char chararray128[128];
	char overflow;
};

CHERIBSDTEST(test_bounds_subobject_struct_chararray128,
    "Check subobject bounds on a char array of size 128 within a struct")
{
	struct struct_chararray128 sc128;
	void * __capability cp;

	cp = &sc128.chararray128;
	CHERIBSDTEST_CHECK_CAP_BOUNDS_PRECISE(cp, sizeof(sc128.chararray128));
	cheribsdtest_success();
}

struct struct_chararray129 {
	char underflow;
	char chararray129[129];
	char overflow;
};

CHERIBSDTEST(test_bounds_subobject_struct_chararray129,
    "Check subobject bounds on a char array of size 129 within a struct")
{
	struct struct_chararray129 sc129;
	void * __capability cp;

	cp = &sc129.chararray129;
	CHERIBSDTEST_CHECK_CAP_BOUNDS_PRECISE(cp, sizeof(sc129.chararray129));
	cheribsdtest_success();
}

struct struct_chararray2048 {
	char underflow;
	char chararray2048[2048];
	char overflow;
};

CHERIBSDTEST(test_bounds_subobject_struct_chararray2048,
    "Check subobject bounds on a char array of size 2048 within a struct")
{
	struct struct_chararray2048 sc2048;
	void * __capability cp;

	cp = &sc2048.chararray2048;
	CHERIBSDTEST_CHECK_CAP_BOUNDS_PRECISE(cp, sizeof(sc2048.chararray2048));
	cheribsdtest_success();
}

/*
 * Above 2048, guarantees vary by architecture, so stop testing here.  Might
 * want to add a Morello-specific test for a larger size, if we think that is
 * needed?
 */

/*
 * Check that an in-bounds store to a subobject array does not fault.  Reuses
 * 2048-byte character array type.
 */
extern volatile struct struct_chararray2048 sc2048_sideeffect;
volatile struct struct_chararray2048 sc2048_sideeffect;

CHERIBSDTEST(test_bounds_subjobject_struct_chararray2048_inbounds,
    "Check in-bounds store in subjobject character array of size 2048")
{

	sc2048_sideeffect.chararray2048[2047] = 1;
	cheribsdtest_success();
}

/*
 * Check one underflow, and one overflow, explicitly, which should generate
 * faults.  Reuses 2048-byte character array type.
 */
extern volatile char * __capability subobject_ptr_outofbounds;
volatile char * __capability subobject_ptr_outofbounds;

CHERIBSDTEST(test_bounds_subobject_struct_chararray2048_overflow,
    "Check that an overflow of a 2048-byte subobject array faults",
    .ct_flags = CT_FLAG_SIGNAL | CT_FLAG_SI_CODE | CT_FLAG_SI_TRAPNO,
    .ct_signum = SIGPROT,
    .ct_si_code = PROT_CHERI_BOUNDS,
    .ct_si_trapno = TRAPNO_LOAD_STORE)
{

	subobject_ptr_outofbounds = &sc2048_sideeffect.chararray2048[2047];
	subobject_ptr_outofbounds++;
	*subobject_ptr_outofbounds = 1;
	cheribsdtest_failure_errx(
	    "Unexpected store success out-of-bounds on subobject array");
}

/*
 * Check that a trailing 1-byte array is suitably enforced, in preparation for
 * variable-length array tests.
 */
struct struct_trailing_chararray1 {
	char underflow;
	char chararray1[1];
};

CHERIBSDTEST(test_bounds_subobject_struct_trailing_chararray1,
    "Check subobject bounds on a trailing non-exempt 1-byte character array")
{
	struct struct_trailing_chararray1 stc1;
	void * __capability cp;

	cp = &stc1.chararray1;
	CHERIBSDTEST_CHECK_CAP_BOUNDS_PRECISE(cp, sizeof(stc1.chararray1));
	cheribsdtest_success();
}

/*
 * Check that we get the expected union bounds when taking pointers to
 * individual entries, allowing those pointers to be cast back (... but
 * allowing internal overflows out...).
 */
union union_two_chararrays {
	char chararray16[16];
	char chararray32[32];
};

CHERIBSDTEST(test_bounds_subobject_union_two_chararrays,
    "Check that unions do enforce subobject bounds on individual structures")
{
	union union_two_chararrays twoarrays;
	void * __capability chararray16p, * __capability chararray32p;

	chararray16p = &twoarrays.chararray16;
	chararray32p = &twoarrays.chararray32;
	CHERIBSDTEST_VERIFY(cheri_getlength(chararray16p) == sizeof(twoarrays));
	CHERIBSDTEST_VERIFY(cheri_getlength(chararray32p) == sizeof(twoarrays));
	cheribsdtest_success();
}

/*
 * Check that a C11 flexible array member is suitably enforced.
 */
struct struct_trailing_chararray_fla {
	char underflow;
	char chararray[];
};
#define	FLA_LENGTH	16

CHERIBSDTEST(test_bounds_subobject_struct_trailing_chararray_fla,
    "Check subobject bounds on a flexible array member")
{
	struct struct_trailing_chararray_fla *stcf = alloca(FLA_LENGTH);
	void * __capability cp;

	cp = &stcf->chararray;
	CHERIBSDTEST_CHECK_CAP_BOUNDS_PRECISE(cp, FLA_LENGTH -
	    offsetof(struct struct_trailing_chararray_fla, chararray));
	cheribsdtest_success();
}

/*
 * Check that GCC zero-length arrays are suitably enforced.
 */
struct struct_trailing_chararray_zla {
	char underflow;
	char chararray[0];
};
#define	ZLA_LENGTH	16

CHERIBSDTEST(test_bounds_subobject_struct_trailing_chararray_zla,
    "Check subobject bounds on a zero length array")
{
	struct struct_trailing_chararray_zla *stca = alloca(ZLA_LENGTH);
	void * __capability cp;

	cp = &stca->chararray;
	CHERIBSDTEST_CHECK_CAP_BOUNDS_PRECISE(cp, ZLA_LENGTH -
	    offsetof(struct struct_trailing_chararray_zla, chararray));
	cheribsdtest_success();
}

/*
 * Tests to check exemptions to subobject bounds via various mechanisms.
 */
struct struct_exempt_char {
	char underflow;
	char c __attribute((cheri_no_subobject_bounds));
	char overflow;
};

CHERIBSDTEST(test_bounds_subobject_struct_exempt_char,
    "Check that a char within a struct can be exempted from subobject bounds")
{
	struct struct_exempt_char sec;
	void * __capability cp, * __capability refcp;

	/*
	 * Convert 'cp' from a pointer back into one to its parent structure,
	 * and then test for equality of all fields including bounds.  Along
	 * the way, check the offset to avoid surprises.
	 */
	cp = &sec.c;
	refcp = &sec;
	CHERIBSDTEST_VERIFY(cheri_getoffset(cp) ==
	    offsetof(struct struct_exempt_char, c));
	cp = (void *)((intptr_t)cp - offsetof(struct struct_exempt_char, c));
	CHERIBSDTEST_CHECK_EQ_CAP(cp, refcp);
	cheribsdtest_success();
}

/*
 * Check that remaining-size annotation is working for bounded-length arrays
 * at the end of structures.
 */
struct struct_remaininglength_chararray16 {
	char underflow;
	char chararray16[16]
	    __attribute__((cheri_subobject_bounds_use_remaining_size));
};
#define	RLA_LENGTH	64

CHERIBSDTEST(test_bounds_subobject_chararray_remaininglength,
    "Check the remaining length struct annotation")
{
	struct struct_trailing_chararray_fla *stcf = alloca(RLA_LENGTH);
	void * __capability cp;

	cp = &stcf->chararray;
	CHERIBSDTEST_CHECK_CAP_BOUNDS_PRECISE(cp, RLA_LENGTH -
	    offsetof(struct struct_remaininglength_chararray16, chararray16));
	cheribsdtest_success();
}

/*
 * Check that the remaining-size annotation, with a defined length, is working
 * for bounded-length arrays at the end of structures.
 */
#define	RLAS_STATIC_LENGTH	16
#define	RLAS_STATIC_BOUND	24
#define	RLAS_DYNAMIC_LENGTH	32
struct struct_remaininglength_size_chararray {
	char underflow;
	char chararray[RLAS_STATIC_LENGTH]
	    __attribute__
	    ((cheri_subobject_bounds_use_remaining_size(RLAS_STATIC_BOUND)));
};

CHERIBSDTEST(test_bounds_subobject_chararray_remaininglength_size,
    "Check the remaining length structure annotation with a fixed size")
{
	struct struct_remaininglength_size_chararray *srsc =
	    alloca(RLAS_DYNAMIC_LENGTH);
	void * __capability cp;

	cp = &srsc->chararray;
	CHERIBSDTEST_CHECK_CAP_BOUNDS_PRECISE(cp, RLAS_STATIC_BOUND);
	cheribsdtest_success();
}

/*
 * Check that some of the queue(3) macros are working as expected, as worked
 * examples of subobject bounds exemptions in the standard headers.  Actually
 * perform the linked-list operations rather than just testing that the bounds
 * look right -- so we should fault if subobject bounds are enabled and this
 * is not working.
 */
extern volatile int side_effect;
volatile int side_effect;

struct struct_queue_slist_entry {
	char underflow;
	SLIST_ENTRY(struct_queue_slist_entry) entry;
	int i;
};

CHERIBSDTEST(test_bounds_subobject_struct_exempt_queue_slist,
    "Check queue(3) SLIST macros subobject bounds exemptions")
{
	SLIST_HEAD(, struct_queue_slist_entry) slist;
	struct struct_queue_slist_entry entry1, entry2, *entryp;

	bzero(&slist, sizeof(slist));
	bzero(&entry1, sizeof(entry1));
	entry1.i = 1;
	bzero(&entry2, sizeof(entry2));
	entry2.i = 2;
	SLIST_INSERT_HEAD(&slist, &entry1, entry);
	SLIST_INSERT_HEAD(&slist, &entry2, entry);
	SLIST_FOREACH(entryp, &slist, entry) {
		side_effect += entryp->i;
	}
	cheribsdtest_success();
}

struct struct_queue_stailq_entry {
	char underflow;
	STAILQ_ENTRY(struct_queue_stailq_entry) entry;
	int i;
};

CHERIBSDTEST(test_bounds_subobject_struct_exempt_queue_stailq,
    "Check queue(3) STAILQ macros subobject bounds exemptions")
{
	STAILQ_HEAD(, struct_queue_stailq_entry) stailq;
	struct struct_queue_stailq_entry entry1, entry2, *entryp;

	bzero(&stailq, sizeof(stailq));
	bzero(&entry1, sizeof(entry1));
	entry1.i = 1;
	bzero(&entry2, sizeof(entry2));
	entry2.i = 2;
	STAILQ_INSERT_HEAD(&stailq, &entry1, entry);
	STAILQ_INSERT_HEAD(&stailq, &entry2, entry);
	STAILQ_FOREACH(entryp, &stailq, entry) {
		side_effect += entryp->i;
	}
	cheribsdtest_success();
}

struct struct_queue_list_entry {
	char underflow;
	LIST_ENTRY(struct_queue_list_entry) entry;
	int i;
};

CHERIBSDTEST(test_bounds_subobject_struct_exempt_queue_list,
    "Check queue(3) LIST macros subobject bounds exemptions")
{
	LIST_HEAD(, struct_queue_list_entry) list;
	struct struct_queue_list_entry entry1, entry2, *entryp;

	bzero(&list, sizeof(list));
	bzero(&entry1, sizeof(entry1));
	entry1.i = 1;
	bzero(&entry2, sizeof(entry2));
	entry2.i = 2;
	LIST_INSERT_HEAD(&list, &entry1, entry);
	LIST_INSERT_HEAD(&list, &entry2, entry);
	LIST_FOREACH(entryp, &list, entry) {
		side_effect += entryp->i;
	}
	cheribsdtest_success();
}

struct struct_queue_tailq_entry {
	char underflow;
	TAILQ_ENTRY(struct_queue_tailq_entry) entry;
	int i;
};

CHERIBSDTEST(test_bounds_subobject_struct_exempt_queue_tailq,
    "Check queue(3) TAILQ macros subobject bounds exemptions")
{
	TAILQ_HEAD(, struct_queue_tailq_entry) tailq;
	struct struct_queue_tailq_entry entry1, entry2, *entryp;

	bzero(&tailq, sizeof(tailq));
	bzero(&entry1, sizeof(entry1));
	entry1.i = 1;
	bzero(&entry2, sizeof(entry2));
	entry2.i = 2;
	TAILQ_INSERT_HEAD(&tailq, &entry1, entry);
	TAILQ_INSERT_HEAD(&tailq, &entry2, entry);
	TAILQ_FOREACH(entryp, &tailq, entry) {
		side_effect += entryp->i;
	}
	cheribsdtest_success();
}
