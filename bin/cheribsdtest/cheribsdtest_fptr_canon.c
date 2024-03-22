/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Jessica Clarke
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) under Innovate
 * UK project 105694, "Digital Security by Design (DSbD) Technology Platform
 * Prototype".
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

#include <dlfcn.h>

#include <cheribsdtest_dynamic.h>

#include "cheribsdtest.h"

CHERIBSDTEST(fptr_canon_cross,
    "Check that function pointers are canonical across objects",
    .ct_xfail_reason = XFAIL_C18N_FPTR_CANON)
{
	void (* volatile fptr_inside)(void);
	void (* volatile fptr_outside)(void);

	fptr_inside = cheribsdtest_dynamic_get_dummy_fptr();
	fptr_outside = &cheribsdtest_dynamic_dummy_func;

	CHERIBSDTEST_VERIFY2(cheri_ptr_equal_exact(fptr_inside, fptr_outside),
	    "inside %#p differs from outside %#p", fptr_inside, fptr_outside);

	cheribsdtest_success();
}

CHERIBSDTEST(fptr_canon_dlsym,
    "Check that function pointers are canonical for dlsym",
    .ct_xfail_reason = XFAIL_C18N_FPTR_CANON)
{
	void (* volatile fptr_inside)(void);
	void (* volatile fptr_dlsym)(void);

	fptr_inside = cheribsdtest_dynamic_get_dummy_fptr();
	fptr_dlsym = (void (*)(void))dlsym(RTLD_DEFAULT,
	    "cheribsdtest_dynamic_dummy_func");

	CHERIBSDTEST_VERIFY2(cheri_ptr_equal_exact(fptr_inside, fptr_dlsym),
	    "inside %#p differs from dlsym %#p", fptr_inside, fptr_dlsym);

	cheribsdtest_success();
}

CHERIBSDTEST(fptr_canon_dlfunc,
    "Check that function pointers are canonical for dlfunc",
    .ct_xfail_reason = XFAIL_C18N_FPTR_CANON)
{
	void (* volatile fptr_inside)(void);
	void (* volatile fptr_dlfunc)(void);

	fptr_inside = cheribsdtest_dynamic_get_dummy_fptr();
	fptr_dlfunc = (void (*)(void))dlfunc(RTLD_DEFAULT,
	    "cheribsdtest_dynamic_dummy_func");

	CHERIBSDTEST_VERIFY2(cheri_ptr_equal_exact(fptr_inside, fptr_dlfunc),
	    "inside %#p differs from dlfunc %#p", fptr_inside, fptr_dlfunc);

	cheribsdtest_success();
}
