/*-
 * Copyright (c) 2017 Robert N. M. Watson
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

#include <string.h>

#include "cheribsdtest.h"

/*
 * Tests to ensure that Thread-Local Storage (TLS) works as expected.
 * Currently, very limited: just check that pointers and capabilites are
 * suitably aligned by default, and that __aligned works on larger objects.
 * In the future, should test a variety of properties, such as safe access
 * from multiple threads, bounds on TLS variables, etc.  And, likely, also in
 * sandboxes.
 */
static __thread char tls_dummy_char0 __used;
static __thread void *tls_ptr0;
static __thread char tls_dummy_char1 __used;
static __thread void *tls_ptr1;

static __thread char tls_dummy_char2 __used;
static __thread void * __capability tls_cap0;
static __thread char tls_dummy_char3 __used;
static __thread void * __capability tls_cap1;

static __thread char tls_array_4k[4096] __aligned(4096);

CHERIBSDTEST(tls_align_ptr, "Test alignment of TLS pointers")
{
	int alignment, expected;

	/* All pointers should be aligned at pointer size. */
	expected = sizeof(void *);

	/* First of two pointers to test. */
	alignment = 1 << (ffsl((unsigned long)&tls_ptr0) - 1);
	if (alignment < expected)
		cheribsdtest_failure_errx("Underaligned TLS pointer 0 (got: %d; "
		    "expected %d)", alignment, expected);

	/* Second of two pointers to test. */
	alignment = 1 << (ffsl((unsigned long)&tls_ptr1) - 1);
	if (alignment < expected)
		cheribsdtest_failure_errx("Underaligned TLS pointer 1 (got: %d; "
		    "expected %d)", alignment, expected);
	cheribsdtest_success();
}

CHERIBSDTEST(tls_align_cap, "Test alignment of TLS capabilities")
{
	int alignment, expected;

	/* All capability pointers should be aligned at capability size. */
	expected = CHERICAP_SIZE;

	/* First of two capabilities to test. */
	alignment = 1 << (ffsl((unsigned long)&tls_cap0) - 1);
	if (alignment < expected)
		cheribsdtest_failure_errx("Underaligned TLS capability 0 (got: "
		    "%d; expected %d)", alignment, expected);

	/* Second of two pointers to test. */
	alignment = 1 << (ffsl((unsigned long)&tls_cap1) - 1);
	if (alignment < expected)
		cheribsdtest_failure_errx("Underaligned TLS capability 1 (got: "
		    "%d; expected %d)", alignment, expected);
	cheribsdtest_success();
}

CHERIBSDTEST(tls_align_4k, "Test alignment of TLS 4K array")
{
	int alignment, expected;

	alignment = 1 << (ffsl((unsigned long)&tls_array_4k) - 1);
	expected = 4096;
	if (alignment < expected)
		cheribsdtest_failure_errx("Underaligned TLS 4K array (got: %d; "
		    "expected %d)", alignment, expected);
	cheribsdtest_success();
}
