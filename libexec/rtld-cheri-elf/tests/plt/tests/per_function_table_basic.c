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
extern int some_global_int;
void* no_globals_used(void) __noinline;
static void* no_globals_get_pcc(void) __noinline;
int test_global_function(void) __noinline;
static int test_local_function(void) __noinline;

int some_global_int = 11;

static void
print_cgp(const void* cgp, const char* func) {
	print("$cgp in ");
	print(func);
	print(" ");
	print_cap(cgp);
	print("\n");
}

// This function is noinline so that the functions using it don't pull in all
// the global string constants used by require_eq
// This makes it a lot easier to calculate the number of globals needed
static __noinline void
_check_cgp_size(const void* cgp, size_t num_globals, const char* func)
{
	print_cgp(cgp, func);
	require_eq(cheri_gettag(cgp), 1);
	require_eq(cheri_getlen(cgp), num_globals * sizeof(void*));
	// Check that we have permit_load and permit_load_capability on the library $cgp
	// And also verify that it is not writable and not executable
	require_eq((cheri_getperm(cgp) & CHERI_PERM_EXECUTE), 0);
	require_eq((cheri_getperm(cgp) & CHERI_PERM_STORE), 0);
	require_eq((cheri_getperm(cgp) & CHERI_PERM_STORE_CAP), 0);
	require_eq((cheri_getperm(cgp) & CHERI_PERM_EXECUTE), 0);
	require_eq((cheri_getperm(cgp) & CHERI_PERM_LOAD), CHERI_PERM_LOAD);
	require_eq((cheri_getperm(cgp) & CHERI_PERM_LOAD_CAP), CHERI_PERM_LOAD_CAP);
}

#define CHECK_CGP_SIZE(cgp, num_globals) _check_cgp_size(cgp, num_globals, __func__)

__noinline void* no_globals_used(void) {
	void* cgp = cheri_getcgp();
	// No globals used in this function -> $cgp should be null
	return cgp;
}

__noinline static void* no_globals_get_pcc(void) {
	// This function is tiny -> pcc bounds should be at most 10 instructions
	return cheri_getpcc();
}

__noinline int test_global_function(void) {
	// One global used in this function -> $cgp should be exactly
	// 3 caps: global_int and  _check_cgp_size()+__func__
	CHECK_CGP_SIZE(cheri_getcgp(), 3);
	return global_int + 10;
}

__noinline static int test_local_function(void) {
	// Two globals used in this function -> $cgp should be exactly
	// 3 caps: test_global_function, some_global_int and  _check_cgp_size()+__func__
	CHECK_CGP_SIZE(cheri_getcgp(), 4);
	return test_global_function() + some_global_int;
}

static void test_pcc_values(const void* main_func_pcc) {
	print("$pcc inside the main test function: ");
	print_cap(main_func_pcc);
	print("\n");
	const void* minimal_pcc = no_globals_get_pcc();
	print("$pcc inside a minimal function: ");
	print_cap(minimal_pcc);
	print("\n");
	// $pcc should not start at 0 but instead at the start of &
	require_not_eq(cheri_getbase(minimal_pcc), 0);
	// Should be less than 12 instructions
	require(cheri_getlen(minimal_pcc) <= 0x30);
	// getpcc should be one of the first few instructions:
	require(cheri_getoffset(minimal_pcc) <= 0x14);

	const void* addrof_test_local_function = &test_local_function;
	print("capability for test_global_function (stub for a local function): ");
	print_cap(addrof_test_local_function);
	print("\n");
	require_not_eq(cheri_getbase(addrof_test_local_function), 0);
	// should point to just after the two capabilities:
	require_eq(cheri_getoffset(addrof_test_local_function), 2 * sizeof(void*));
	// Should be 2 capabilities + 4 instructions:
	require_eq(cheri_getlen(addrof_test_local_function), 2 * sizeof(void*) + 4 * 4);

	const void* addrof_test_global_function = &test_global_function;
	print("capability for test_global_function (stub for a global function): ");
	print_cap(addrof_test_global_function);
	print("\n");
	require_not_eq(cheri_getbase(addrof_test_global_function), 0);
	// should point to just after the two capabilities:
	require_eq(cheri_getoffset(addrof_test_global_function), 2 * sizeof(void*));
	// Should be 2 capabilities + 4 instructions:
	require_eq(cheri_getlen(addrof_test_global_function), 2 * sizeof(void*) + 4 * 4);

	const void* pcc_in_other_lib = get_library_pcc();
	print("$pcc inside a external library function: ");
	print_cap(pcc_in_other_lib);
	print("\n");
	// The other library is compiled with PLT abi (but without per-function
	// captable). Therefore the bounds on pcc should also be very tight:
	// $pcc should not start at 0 but instead at the start of get_library_pcc()
	require_not_eq(cheri_getbase(pcc_in_other_lib), 0);
	require(cheri_getlen(pcc_in_other_lib) <= 0x30);
	require(cheri_getoffset(pcc_in_other_lib) <= 0x14);
}

static void test_cgp_values(const void* main_func_cgp __unused) {
	// TODO: test $cgp for main test function
	require_eq(test_global_function(), 52);
	require_eq(test_local_function(), 63);

	// Check the no globals cgp here because if we did it inside
	// no_globals_used() the check macros would cause use of global vars.
	const void* no_globals_cgp = no_globals_used();
	// no_globals_used $cgp should be a tagged value with length zero:
	_check_cgp_size(no_globals_cgp, 0, "no_globals_cgp");
}

static void test(void) {
	const void* test_cgp = cheri_getcgp();
	print("Starting test!\n");
	print_cgp(test_cgp, __func__);

	// First check that pcc in a per-function table is very constrained:
	test_pcc_values(cheri_getpcc());

	// Then test the $cgp values:
	test_cgp_values(test_cgp);

	// Call a function in the external library (compiled without
	// per-function captable) and check the result is correct.
	const void* library_cgp_plus_int = get_library_cgp_plus_global_int();
	print("Got library $cgp plus int:\n");
	print("Result: "); print_cap(library_cgp_plus_int); print("\n");
	// This should have offset 42:
	require_eq(cheri_getoffset(library_cgp_plus_int), 42);
}

TEST_MAIN()
