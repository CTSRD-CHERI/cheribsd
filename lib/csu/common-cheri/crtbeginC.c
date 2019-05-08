/*-
 * Copyright (c) 2014 Robert N. M. Watson
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

#include <sys/types.h>

#include <assert.h>
#include <stdlib.h>

void	crt_call_constructors(void);

/*
 * In version 3 of the CHERI sandbox ABI, function pointers are capabilities.
 * The CTORs list is the single exception: CTORs are used to set up globals
 * that contain function pointers so (until we have proper linker support) we
 * are still generating them as a sequence of PCC-relative integers.
 */
typedef unsigned long long mips_function_ptr;
typedef void (*cheri_function_ptr)(void);

extern mips_function_ptr __ctors_start[];
extern mips_function_ptr __ctors_end;

extern mips_function_ptr __dtors_start[];
extern mips_function_ptr __dtors_end;

extern void *__dso_handle;
void *__dso_handle;


/* For cheri purecap shared libraries we should not have any .ctors/.ctors */
#ifndef SHLIB_INIT
/*
 * Execute constructors; invoked by the crt_sb.S startup code.
 *
 * NB: This code and approach is borrowed from the MIPS ABI, and works as long
 * as CHERI code generation continues to use 64-bit integers for pointers.  If
 * that changes, this might need to become more capability-appropriate.
 */
void
crt_call_constructors(void)
{
	/*
	 * TODO: once lld converts ctors to init_array print a warning
	 * message that the binary should be relinked
	 */
	mips_function_ptr *func = &__ctors_start[0];
	mips_function_ptr *end = __builtin_cheri_offset_set(func,
	    (char*)&__ctors_end - (char*)func);
	for (; func != end; func++) {
		if (*func != (mips_function_ptr)-1) {
			cheri_function_ptr cheri_func =
				(cheri_function_ptr)__builtin_cheri_offset_set(
						__builtin_cheri_program_counter_get(), *func);
			cheri_func();
		}
	}
}
#endif
