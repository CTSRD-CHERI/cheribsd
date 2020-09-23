/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2018 Alex Richadson <arichardson@FreeBSD.org>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
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
#include "plt_test.h"

extern void* _get_library_cgp_with_null_caller_cgp(void);

static inline void
check_library_cgp(const void* library_cgp, const void* original_cgp)
{
	require(cheri_gettag(library_cgp)); // $cgp should have a tag
	// And should have a offset of 42 and nonzero base+length
	require_not_eq(cheri_getbase(library_cgp), 0);
	require_not_eq(cheri_getlen(library_cgp), 0);
	require_not_eq(cheri_getbase(original_cgp), 0);
	require_not_eq(cheri_getlen(original_cgp), 0);
	// Check that we have permit_load and permit_load_capability on the library $cgp
	require_eq((cheri_getperm(library_cgp) & CHERI_PERM_EXECUTE), 0);
	require_eq((cheri_getperm(library_cgp) & CHERI_PERM_STORE), 0);
	require_eq((cheri_getperm(library_cgp) & CHERI_PERM_STORE_CAP), 0);
	require_eq((cheri_getperm(library_cgp) & CHERI_PERM_EXECUTE), 0);
	require_eq((cheri_getperm(library_cgp) & CHERI_PERM_LOAD), CHERI_PERM_LOAD);
	require_eq((cheri_getperm(library_cgp) & CHERI_PERM_LOAD_CAP), CHERI_PERM_LOAD_CAP);

	// Check that the library $cgp is different from the current $cgp
	require_not_eq(cheri_getbase(library_cgp), cheri_getbase(original_cgp));
}

static void test(void) {
	print("Starting test!\n");
	// Clear $cgp before calling the library function:
	const void* original_cgp = cheri_getcgp();
	print("Caller $cgp: "); print_cap(original_cgp); print("\n");
	// Call the library function from assembly and clear $cgp first
	// const void* library_cgp = _get_library_cgp_with_null_caller_cgp();
	const void* library_cgp = get_library_cgp();
	__compiler_membar();
	print("Got library $cgp (back in C function)\n");
	print("Result: "); print_cap(library_cgp); print("\n");
	check_library_cgp(library_cgp, original_cgp);

	int expected_offset = load_global_int();
	require_eq(expected_offset, 42);

	// Now do the same with the library cgp + offset:
	const void* library_cgp_plus_int = get_library_cgp_plus_global_int();
	print("Got library $cgp plus int:\n");
	print("Result: "); print_cap(library_cgp_plus_int); print("\n");

	// This should have offset 42:
	require_eq(cheri_getoffset(library_cgp_plus_int), expected_offset);
	// and also all the other properties:
	check_library_cgp(library_cgp_plus_int, original_cgp);
}

TEST_MAIN()
