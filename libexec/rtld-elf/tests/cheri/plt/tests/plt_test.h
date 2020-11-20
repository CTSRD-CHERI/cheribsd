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
#include <sys/cdefs.h>
#include <sys/types.h>
#include <cheri/cheric.h>

#include "testlib_exports.h"

void __start(void);

extern void __plt_test_local_exit(int code);
#define exit(code) __plt_test_local_exit(code)
#define write(fd, buf, n) __plt_test_local_write(fd, buf, n)
extern ssize_t __plt_test_local_write(int fd, const void *buf, size_t nbytes);
extern const char* ltoa_unsafe(long l, int base);


#define print(msg) __plt_test_local_write(1, msg, __builtin_strlen(msg))
#define require(cond) do {				\
	if (!(cond)) {					\
		print("Test failed: " #cond "\n");	\
		exit(1);				\
	}						\
} while(0)

#define TEST_MAIN() \
	void __start(void) { \
		test(); \
		print("Success!\n"); \
		exit(0); \
	}

static __always_inline __used void
print_long(long l, int base)
{
	print(ltoa_unsafe(l, base));
}

static __always_inline __used void
print_cap(const void* __capability cap) {
	print("v:"); print_long(cheri_gettag(cap), 10);
	print(" s:"); print_long(cheri_getsealed(cap), 10);
	print(" p:"); print_long(cheri_getperm(cap), 16);
	print(" b:"); print_long(cheri_getbase(cap), 16);
	print(" l:"); print_long(cheri_getlen(cap), 16);
	print(" o:"); print_long(cheri_getoffset(cap), 16);
	print(" t:"); print_long(cheri_gettype(cap), 10);
}

static __always_inline __used void
_require_eq(register_t r1, register_t r2, const char* r1s, const char* r2s, int line)
{
	if (r1 != r2) {
		print("Test failed at line ");
		print_long(line, 10);
		print(": expected same value but ");
		print(r1s);
		print(" (");
		print_long(r1, 10);
		print("/");
		print_long(r1, 16);
		print(") != ");
		print(r2s);
		print(" (");
		print_long(r2, 10);
		print("/");
		print_long(r2, 16);
		print(")\n");
		exit(1);
	}
}

static __always_inline __used
void _require_not_eq(register_t r1, register_t r2, const char* r1s, const char* r2s, int line)
{
	if (r1 == r2) {
		print("Test failed at line ");
		print_long(line, 10);
		print(": expected different value but ");
		print(r1s);
		print(" (");
		print_long(r1, 10);
		print("/");
		print_long(r1, 16);
		print(") == ");
		print(r2s);
		print(" (");
		print_long(r2, 10);
		print("/");
		print_long(r2, 16);
		print(")\n");
		exit(1);
	}
}

#define require_eq(r1, r2) _require_eq(r1, r2, #r1, #r2, __LINE__)
#define require_not_eq(r1, r2) _require_not_eq(r1, r2, #r1, #r2, __LINE__)
