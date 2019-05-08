/*-
 * Copyright (c) 2012-2015 David Chisnall
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
#include <string.h>
#include "cheri_c_test.h"

static char pointees[] = "0123456789";
static volatile char *buffer[] = {
	&pointees[0],
	&pointees[1],
	&pointees[2],
	&pointees[3],
	&pointees[4],
	&pointees[5],
	&pointees[6],
	&pointees[7],
	&pointees[8],
	&pointees[9],
};

/*
 * memmove() needs to be a separate function so that the compiler cannot optimize
 * away memmove calls or use inlined loops (since we are then no longer testing
 * the memmove() implementation). We could also compile this file with
 * -fno-builtin but a linker error due to a missing function is easier to diagnose.
 */
#ifdef TEST_COMPILER_MEMMOVE
#define cheritest_memmove __builtin_memmove
#else
extern void* cheritest_memmove(void*, const void*, size_t);
#endif


BEGIN_TEST(libc_memmove)
	cheritest_memmove(buffer, &buffer[2], sizeof(buffer) - 2*sizeof(char*));
	for (int i=0 ; i<8 ; i++)
	{
		assert_eq(*buffer[i], '0' + i + 2);
	}
END_TEST

