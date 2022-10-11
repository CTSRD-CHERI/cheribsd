/*-
 * Copyright (c) 2015-2016, 2021 Robert N. M. Watson
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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
#include <sys/sysctl.h>
#include <sys/time.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <machine/sysarch.h>

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
 * Check for high-precision bounds for a variety of small object sizes,
 * allocated from the stack.  These should be precise regardless of capability
 * compression, as the allocator promises to align things suitably.  Test
 * statically sized allocation, explicitly alloca()'d arrays, and also C
 * variable-length arrays (VLAs).
 */
static void
test_bounds_precise(void * __capability c, size_t expected_len)
{
	size_t len, offset;

	offset = cheri_getoffset(c);
	len = cheri_getlen(c);

#ifdef __CHERI_PURE_CAPABILITY__
	CHERIBSDTEST_CHECK_CAP_BOUNDS_PRECISE(c, expected_len);
#else
	/*
	 * In hybrid mode we don't increase alignment of allocations to ensure
	 * precise bounds, so the offset may be non-zero if the bounds were
	 * not precisely representable. For now, simply  check that we got at
	 * least the expected length but no more than twice that.
	 *
	 * See https://github.com/CTSRD-CHERI/llvm-project/issues/431
	 */
	CHERIBSDTEST_VERIFY2(len >= expected_len,
	    "length (%jd) smaller than expected lower bound %jd: %#lp",
	    len, expected_len, c);
#ifndef __riscv  /* RISC-V does not bound __cheri_tocap casts in hybrid mode */
	CHERIBSDTEST_VERIFY2(len <= 2 * expected_len,
	    "length (%jd) greater than expected upper bound %jd: %#lp",
	    len, 2 * expected_len, c);
#endif
#endif
	cheribsdtest_success();
}

static __noinline void
test_bounds_stack_alloca(size_t len)
{
	void * __capability c = (__cheri_tocap void * __capability)alloca(len);

	test_bounds_precise(c, len);
}

static __noinline void
test_bounds_stack_vla(size_t len)
{
	char vla[len];
	void * __capability c = (__cheri_tocap void * __capability)&vla;

	test_bounds_precise(c, len);
}

CHERIBSDTEST(test_bounds_stack_static_uint8,
    "Check bounds on 8-bit static stack allocation")
{
	uint8_t u8;
	uint8_t * __capability u8p = (__cheri_tocap uint8_t * __capability)&u8;

	test_bounds_precise(u8p, sizeof(*u8p));
}

CHERIBSDTEST(test_bounds_stack_alloca_uint8,
    "Check bounds on 8-bit alloca stack allocation")
{
	test_bounds_stack_alloca(sizeof(uint8_t));
}

CHERIBSDTEST(test_bounds_stack_vla_uint8,
    "Check bounds on 8-bit VLA stack allocation")
{
	test_bounds_stack_vla(sizeof(uint8_t));
}

CHERIBSDTEST(test_bounds_stack_static_uint16,
    "Check bounds on 16-bit static stack allocation")
{
	uint16_t u16;
	uint16_t * __capability u16p = (__cheri_tocap uint16_t * __capability)&u16;

	test_bounds_precise(u16p, sizeof(*u16p));
}

CHERIBSDTEST(test_bounds_stack_alloca_uint16,
    "Check bounds on 16-bit alloca stack allocation")
{
	test_bounds_stack_alloca(sizeof(uint16_t));
}

CHERIBSDTEST(test_bounds_stack_vla_uint16,
    "Check bounds on 16-bit VLA stack allocation")
{
	test_bounds_stack_vla(sizeof(uint16_t));
}

CHERIBSDTEST(test_bounds_stack_static_uint32,
    "Check bounds 32-bit static stack allocation")
{
	uint32_t u32;
	uint32_t * __capability u32p = (__cheri_tocap uint32_t * __capability)&u32;

	test_bounds_precise(u32p, sizeof(*u32p));
}

CHERIBSDTEST(test_bounds_stack_alloca_uint32,
    "Check bounds 32-bit alloca stack allocation")
{
	test_bounds_stack_alloca(sizeof(uint32_t));
}

CHERIBSDTEST(test_bounds_stack_vla_uint32,
    "Check bounds 32-bit VLA stack allocation")
{
	test_bounds_stack_vla(sizeof(uint32_t));
}

CHERIBSDTEST(test_bounds_stack_static_uint64,
    "Check bounds on 64-bit static stack allocation")
{
	uint64_t u64;
	uint64_t * __capability u64p = (__cheri_tocap uint64_t * __capability)&u64;

	test_bounds_precise(u64p, sizeof(*u64p));
}

CHERIBSDTEST(test_bounds_stack_alloca_uint64,
    "Check bounds on 64-bit alloca stack allocation")
{
	test_bounds_stack_alloca(sizeof(uint64_t));
}

CHERIBSDTEST(test_bounds_stack_vla_uint64,
    "Check bounds on 64-bit VLA stack allocation")
{
	test_bounds_stack_vla(sizeof(uint64_t));
}

CHERIBSDTEST(test_bounds_stack_static_cap,
    "Check bounds on a capability static stack allocation")
{
	void * __capability c;
	void * __capability * __capability cp =
	    (__cheri_tocap void * __capability * __capability)&c;

	test_bounds_precise(cp, sizeof(*cp));
}

CHERIBSDTEST(test_bounds_stack_alloca_cap,
    "Check bounds on a capability alloca stack allocation")
{
	test_bounds_stack_alloca(sizeof(void * __capability));
}

CHERIBSDTEST(test_bounds_stack_vla_cap,
    "Check bounds on a capability VLA stack allocation")
{
	test_bounds_stack_vla(sizeof(void * __capability));
}

CHERIBSDTEST(test_bounds_stack_static_16,
    "Check bounds on a 16-byte static stack allocation")
{
	uint8_t array[16];
	uint8_t * __capability arrayp = (__cheri_tocap uint8_t * __capability)&array[0];

	test_bounds_precise(arrayp, sizeof(array));
}

CHERIBSDTEST(test_bounds_stack_alloca_16,
    "Check bounds on a 16-byte alloca stack allocation")
{
	test_bounds_stack_alloca(16);
}

CHERIBSDTEST(test_bounds_stack_vla_16,
    "Check bounds on a 16-byte VLA stack allocation")
{
	test_bounds_stack_vla(16);
}

CHERIBSDTEST(test_bounds_stack_static_32,
    "Check bounds on a 32-byte static stack allocation")
{
	uint8_t array[32];
	uint8_t * __capability arrayp = (__cheri_tocap uint8_t * __capability)&array[0];

	test_bounds_precise(arrayp, sizeof(array));
}

CHERIBSDTEST(test_bounds_stack_alloca_32,
    "Check bounds on a 32-byte alloca stack allocation")
{
	test_bounds_stack_alloca(32);
}

CHERIBSDTEST(test_bounds_stack_vla_32,
    "Check bounds on a 32-byte VLA stack allocation")
{
	test_bounds_stack_vla(32);
}

CHERIBSDTEST(test_bounds_stack_static_64,
    "Check bounds on a 64-byte static stack allocation")
{
	uint8_t array[64];
	uint8_t * __capability arrayp = (__cheri_tocap uint8_t * __capability)&array[0];

	test_bounds_precise(arrayp, sizeof(array));
}

CHERIBSDTEST(test_bounds_stack_alloca_64,
    "Check bounds on a 64-byte alloca stack allocation")
{
	test_bounds_stack_alloca(64);
}

CHERIBSDTEST(test_bounds_stack_vla_64,
    "Check bounds on a 64-byte VLA stack allocation")
{
	test_bounds_stack_vla(64);
}

CHERIBSDTEST(test_bounds_stack_static_128,
    "Check bounds on a 128-byte static stack allocation")
{
	uint8_t array[128];
	uint8_t * __capability arrayp = (__cheri_tocap uint8_t * __capability)&array[0];

	test_bounds_precise(arrayp, sizeof(array));
}

CHERIBSDTEST(test_bounds_stack_alloca_128,
    "Check bounds on a 128-byte alloca stack allocation")
{
	test_bounds_stack_alloca(128);
}

CHERIBSDTEST(test_bounds_stack_vla_128,
    "Check bounds on a 128-byte VLA stack allocation")
{
	test_bounds_stack_vla(128);
}

CHERIBSDTEST(test_bounds_stack_static_256,
    "Check bounds on a 256-byte static stack allocation")
{
	uint8_t array[256];
	uint8_t * __capability arrayp = (__cheri_tocap uint8_t * __capability)&array[0];

	test_bounds_precise(arrayp, sizeof(array));
}

CHERIBSDTEST(test_bounds_stack_alloca_256,
    "Check bounds on a 256-byte alloca stack allocation")
{
	test_bounds_stack_alloca(256);
}

CHERIBSDTEST(test_bounds_stack_vla_256,
    "Check bounds on a 256-byte VLA stack allocation")
{
	test_bounds_stack_vla(256);
}

CHERIBSDTEST(test_bounds_stack_static_512,
    "Check bounds on a 512-byte static stack allocation")
{
	uint8_t array[512];
	uint8_t * __capability arrayp = (__cheri_tocap uint8_t * __capability)&array[0];

	test_bounds_precise(arrayp, sizeof(array));
}

CHERIBSDTEST(test_bounds_stack_alloca_512,
    "Check bounds on a 512-byte alloca stack allocation")
{
	test_bounds_stack_alloca(512);
}

CHERIBSDTEST(test_bounds_stack_vla_512,
    "Check bounds on a 512-byte VLA stack allocation")
{
	test_bounds_stack_vla(512);
}

CHERIBSDTEST(test_bounds_stack_static_1024,
    "Check bounds on a 1,024-byte static stack allocation")
{
	uint8_t array[1024];
	uint8_t * __capability arrayp = (__cheri_tocap uint8_t * __capability)&array[0];

	test_bounds_precise(arrayp, sizeof(array));
}

CHERIBSDTEST(test_bounds_stack_alloca_1024,
    "Check bounds on a 1,024-byte alloca stack allocation")
{
	test_bounds_stack_alloca(1024);
}

CHERIBSDTEST(test_bounds_stack_vla_1024,
    "Check bounds on a 1,024-byte VLA stack allocation")
{
	test_bounds_stack_vla(1024);
}

CHERIBSDTEST(test_bounds_stack_static_2048,
    "Check bounds on a 2,048-byte static stack allocation")
{
	uint8_t array[2048];
	uint8_t * __capability arrayp = (__cheri_tocap uint8_t * __capability)&array[0];

	test_bounds_precise(arrayp, sizeof(array));
}

CHERIBSDTEST(test_bounds_stack_alloca_2048,
    "Check bounds on a 2,048-byte alloca stack allocation")
{
	test_bounds_stack_alloca(2048);
}

CHERIBSDTEST(test_bounds_stack_vla_2048,
    "Check bounds on a 2,048-byte VLA stack allocation")
{
	test_bounds_stack_vla(2048);
}

CHERIBSDTEST(test_bounds_stack_static_4096,
    "Check bounds on a 4,096-byte static stack allocation")
{
	uint8_t array[4096];
	uint8_t * __capability arrayp = (__cheri_tocap uint8_t * __capability)&array[0];

	test_bounds_precise(arrayp, sizeof(array));
}

CHERIBSDTEST(test_bounds_stack_alloca_4096,
    "Check bounds on a 4,096-byte alloca stack allocation")
{
	test_bounds_stack_alloca(4096);
}

CHERIBSDTEST(test_bounds_stack_vla_4096,
    "Check bounds on a 4,096-byte VLA stack allocation")
{
	test_bounds_stack_vla(4096);
}

CHERIBSDTEST(test_bounds_stack_static_8192,
    "Check bounds on a 8,192-byte static stack allocation")
{
	uint8_t array[8192];
	uint8_t * __capability arrayp = (__cheri_tocap uint8_t * __capability)&array[0];

	test_bounds_precise(arrayp, sizeof(array));
}

CHERIBSDTEST(test_bounds_stack_alloca_8192,
    "Check bounds on a 8,192-byte alloca stack allocation")
{
	test_bounds_stack_alloca(8192);
}

CHERIBSDTEST(test_bounds_stack_vla_8192,
    "Check bounds on a 8,192-byte VLA stack allocation")
{
	test_bounds_stack_vla(8192);
}

CHERIBSDTEST(test_bounds_stack_static_16384,
    "Check bounds on a 16,384-byte static stack allocation")
{
	uint8_t array[16384];
	uint8_t * __capability arrayp = (__cheri_tocap uint8_t * __capability)&array[0];

	test_bounds_precise(arrayp, sizeof(array));
}

CHERIBSDTEST(test_bounds_stack_alloca_16384,
    "Check bounds on a 16,384-byte alloca stack allocation")
{
	test_bounds_stack_alloca(16384);
}

CHERIBSDTEST(test_bounds_stack_vla_16384,
    "Check bounds on a 16,384-byte VLA stack allocation")
{
	test_bounds_stack_vla(16384);
}

CHERIBSDTEST(test_bounds_stack_static_32768,
    "Check bounds on a 32,768-byte static stack allocation")
{
	uint8_t array[32768];
	uint8_t * __capability arrayp = (__cheri_tocap uint8_t * __capability)&array[0];

	test_bounds_precise(arrayp, sizeof(array));
}

CHERIBSDTEST(test_bounds_stack_alloca_32768,
    "Check bounds on a 32,768-byte alloca stack allocation")
{
	test_bounds_stack_alloca(32768);
}

CHERIBSDTEST(test_bounds_stack_vla_32768,
    "Check bounds on a 32,768-byte VLA stack allocation")
{
	test_bounds_stack_vla(32768);
}

CHERIBSDTEST(test_bounds_stack_static_65536,
    "Check bounds on a 65,536-byte static stack allocation")
{
	uint8_t array[65536];
	uint8_t * __capability arrayp = (__cheri_tocap uint8_t * __capability)&array[0];

	test_bounds_precise(arrayp, sizeof(array));
}

CHERIBSDTEST(test_bounds_stack_alloca_65536,
    "Check bounds on a 65,536-byte alloca stack allocation")
{
	test_bounds_stack_alloca(65536);
}

CHERIBSDTEST(test_bounds_stack_vla_65536,
    "Check bounds on a 65,536-byte VLA stack allocation")
{
	test_bounds_stack_vla(65536);
}

CHERIBSDTEST(test_bounds_stack_static_131072,
    "Check bounds on a 131,072-byte static stack allocation")
{
	uint8_t array[131072];
	uint8_t * __capability arrayp = (__cheri_tocap uint8_t * __capability)&array[0];

	test_bounds_precise(arrayp, sizeof(array));
}

CHERIBSDTEST(test_bounds_stack_alloca_131072,
    "Check bounds on a 131,072-byte alloca stack allocation")
{
	test_bounds_stack_alloca(131072);
}

CHERIBSDTEST(test_bounds_stack_vla_131072,
    "Check bounds on a 131,072-byte VLA stack allocation")
{
	test_bounds_stack_vla(131072);
}

CHERIBSDTEST(test_bounds_stack_static_262144,
    "Check bounds on a 262,144-byte static stack allocation")
{
	uint8_t array[262144];
	uint8_t * __capability arrayp = (__cheri_tocap uint8_t * __capability)&array[0];

	test_bounds_precise(arrayp, sizeof(array));
}

CHERIBSDTEST(test_bounds_stack_alloca_262144,
    "Check bounds on a 262,144-byte alloca stack allocation")
{
	test_bounds_stack_alloca(262144);
}

CHERIBSDTEST(test_bounds_stack_vla_262144,
    "Check bounds on a 262,144-byte VLA stack allocation")
{
	test_bounds_stack_vla(262144);
}

CHERIBSDTEST(test_bounds_stack_static_524288,
    "Check bounds on a 524,288-byte static stack allocation")
{
	uint8_t array[524288];
	uint8_t * __capability arrayp = (__cheri_tocap uint8_t * __capability)&array[0];

	test_bounds_precise(arrayp, sizeof(array));
}

CHERIBSDTEST(test_bounds_stack_alloca_524288,
    "Check bounds on a 524,288-byte alloca stack allocation")
{
	test_bounds_stack_alloca(524288);
}

CHERIBSDTEST(test_bounds_stack_vla_524288,
    "Check bounds on a 524,288-byte VLA stack allocation")
{
	test_bounds_stack_vla(524288);
}

CHERIBSDTEST(test_bounds_stack_static_1048576,
    "Check bounds on a 1,048,576-byte static stack allocation")
{
	uint8_t array[1048576];
	uint8_t * __capability arrayp = (__cheri_tocap uint8_t * __capability)&array[0];

	test_bounds_precise(arrayp, sizeof(array));
}

CHERIBSDTEST(test_bounds_stack_alloca_1048576,
    "Check bounds on a 1,048,576-byte alloca stack allocation")
{
	test_bounds_stack_alloca(1048576);
}

CHERIBSDTEST(test_bounds_stack_vla_1048576,
    "Check bounds on a 1,048,576-byte VLA stack allocation")
{
	test_bounds_stack_vla(1048576);
}
