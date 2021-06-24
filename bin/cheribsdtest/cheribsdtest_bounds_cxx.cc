/*-
 * Copyright (c) 2021 Jessica Clarke
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

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <memory>

#include "cheribsdtest.h"

template <typename T>
static void
test_bounds_common(T *allocation)
{
	size_t size = sizeof(T);
	size_t allocation_offset = cheri_getoffset(allocation);
	size_t allocation_len = cheri_getlen(allocation);
	size_t rounded_size = CHERI_REPRESENTABLE_LENGTH(size);

	/* The allocation should be tagged */
	CHERIBSDTEST_VERIFY(cheri_gettag(allocation));

	/* The allocation should have no padding before the cursor */
	if (allocation_offset != 0)
		cheribsdtest_failure_errx("non-zero offset (%ju)",
		    allocation_offset);

	/* The allocation should have tight bounds */
	if (allocation_len != rounded_size)
		cheribsdtest_failure_errx(
		    "incorrect length (expected %ju, "
		    "rounded from %ju, got %ju)",
		    rounded_size, size, allocation_len);

	cheribsdtest_success();
}

template <size_t size>
static void
test_bounds_new(void)
{
	using T = struct { char buf[size]; };
	T *p = new T;
	test_bounds_common(p);
}

template <size_t size>
static void
test_bounds_make_unique(void)
{
	using T = struct { char buf[size]; };
	std::unique_ptr<T> p = std::make_unique<T>();
	test_bounds_common(p.get());
}

template <size_t size>
static void
test_bounds_make_shared(void)
{
	using T = struct { char buf[size]; };
	std::shared_ptr<T> p = std::make_shared<T>();
	test_bounds_common(p.get());
}

#define TEST_NEW(size, ...)						\
	CHERIBSDTEST(test_bounds_new_##size,				\
	"Check bounds on operator new allocation of size " #size,	\
	__VA_ARGS__)							\
	{								\
		test_bounds_new<size>();				\
	}

#define TEST_MAKE_UNIQUE(size, ...)					\
	CHERIBSDTEST(test_bounds_make_unique_##size,			\
	"Check bounds on make_unique allocation of size " #size,	\
	__VA_ARGS__)							\
	{								\
		test_bounds_make_unique<size>();			\
	}

#define TEST_MAKE_SHARED(size, ...)					\
	CHERIBSDTEST(test_bounds_make_shared_##size,			\
	"Check bounds on make_shared allocation of size " #size,	\
	.ct_xfail_reason =						\
	    "doesn't bound and pad to exclude control block",		\
	__VA_ARGS__)							\
	{								\
		test_bounds_make_shared<size>();			\
	}

TEST_NEW(1);
TEST_NEW(2);
TEST_NEW(4);
TEST_NEW(8);
TEST_NEW(16);
TEST_NEW(32);
TEST_NEW(64);
TEST_NEW(128);
TEST_NEW(256);
TEST_NEW(512);
TEST_NEW(1024);
TEST_NEW(2048);
TEST_NEW(4096);
TEST_NEW(8192);
TEST_NEW(16384);
TEST_NEW(32768);
TEST_NEW(65536);
TEST_NEW(3);
TEST_NEW(17);
TEST_NEW(65537);

TEST_MAKE_UNIQUE(1);
TEST_MAKE_UNIQUE(2);
TEST_MAKE_UNIQUE(4);
TEST_MAKE_UNIQUE(8);
TEST_MAKE_UNIQUE(16);
TEST_MAKE_UNIQUE(32);
TEST_MAKE_UNIQUE(64);
TEST_MAKE_UNIQUE(128);
TEST_MAKE_UNIQUE(256);
TEST_MAKE_UNIQUE(512);
TEST_MAKE_UNIQUE(1024);
TEST_MAKE_UNIQUE(2048);
TEST_MAKE_UNIQUE(4096);
TEST_MAKE_UNIQUE(8192);
TEST_MAKE_UNIQUE(16384);
TEST_MAKE_UNIQUE(32768);
TEST_MAKE_UNIQUE(65536);
TEST_MAKE_UNIQUE(3);
TEST_MAKE_UNIQUE(17);
TEST_MAKE_UNIQUE(65537);

TEST_MAKE_SHARED(1);
TEST_MAKE_SHARED(2);
TEST_MAKE_SHARED(4);
TEST_MAKE_SHARED(8);
TEST_MAKE_SHARED(16);
TEST_MAKE_SHARED(32);
TEST_MAKE_SHARED(64);
TEST_MAKE_SHARED(128);
TEST_MAKE_SHARED(256);
TEST_MAKE_SHARED(512);
TEST_MAKE_SHARED(1024);
TEST_MAKE_SHARED(2048);
TEST_MAKE_SHARED(4096);
TEST_MAKE_SHARED(8192);
TEST_MAKE_SHARED(16384);
TEST_MAKE_SHARED(32768);
TEST_MAKE_SHARED(65536);
TEST_MAKE_SHARED(3);
TEST_MAKE_SHARED(17);
TEST_MAKE_SHARED(65537);
