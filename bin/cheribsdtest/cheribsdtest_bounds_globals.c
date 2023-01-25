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
 * Global variables of various types, with pointers to them.  Some are static,
 * which may allow the compiler to make code-generation optimisations based on
 * analysing the whole compilation unit.  Others are non-static so that (at
 * least we hope) the compiler is more likely to do what it says on the tin.
 * Regardless of the way the globals are actually generated, we'd like to see
 * correct bounds.  We make statically initialised pointers non-static in the
 * hopes that they will be set up by the linker.
 *
 * Further down the file, similar tests are run on globals allocated in
 * another compilation unit, but declared here with different C-language
 * types.  Regardless of what the types say about the sizes, pointers to the
 * globals should have the correct dynamic sizes in their underlying
 * capabilities.
 *
 * XXXRW: For now, no expectations about non-CheriABI code.
 */

/*
 * Template for a test function, which assumes there is a global (test) and
 * corresponding statically initialised pointer (testp).  Check that both
 * taking a pointer to the global, and using the existing pointer, return
 * offsets and sizes as desired.
 */
#define TEST_BOUNDS(test, desc, ...)						\
	CHERIBSDTEST(bounds_##test,				\
	"Check bounds on " desc,					\
	.ct_xfail_reason = XFAIL_HYBRID_BOUNDS_GLOBALS_STATIC,		\
	__VA_ARGS__)							\
	{                                                               \
		void *__capability allocation =                         \
		    (__cheri_tocap void *__capability) & test;          \
		void *__capability global_ptr = test##p;                \
		test_bounds_impl(allocation, global_ptr, sizeof(test)); \
	}

static void
test_bounds_impl(void *__capability allocation, void *__capability global_ptr, size_t size)
{
	size_t allocation_offset = cheri_getoffset(allocation);
	size_t allocation_len = cheri_getlen(allocation);
	size_t pointer_offset = cheri_getoffset(global_ptr);
	size_t pointer_len = cheri_getlen(global_ptr);
	size_t rounded_size = CHERI_REPRESENTABLE_LENGTH(size);

	/* Both the local cast and the global pointer should be tagged */
	CHERIBSDTEST_VERIFY(cheri_gettag(allocation));
	CHERIBSDTEST_VERIFY(cheri_gettag(global_ptr));

	/* Global offset. */
	if (allocation_offset != 0)
		cheribsdtest_failure_errx(
		    "global: non-zero offset (%ju)", allocation_offset);

	/* Global length. */
	if (allocation_len != rounded_size)
		cheribsdtest_failure_errx(
		    "global: incorrect length (expected %ju, "
		    "rounded from %ju, got %ju)",
		    rounded_size, size, allocation_len);

	/* Pointer offset. */
	if (pointer_offset != 0)
		cheribsdtest_failure_errx(
		    "pointer: non-zero offset (%ju)", pointer_offset);

	/* Pointer length. */
	if (pointer_len != rounded_size)
		cheribsdtest_failure_errx(
		    "pointer: incorrect length (expected %ju, "
		    "rounded from %ju, got %ju)",
		    rounded_size, size, pointer_len);
	cheribsdtest_success();
}

/*
 * Basic integer types.
 */
static uint8_t			 global_static_uint8;
extern void * __capability	 global_static_uint8p;
void * __capability		 global_static_uint8p =
		    (__cheri_tocap void * __capability)&global_static_uint8;

extern uint8_t			 global_uint8;
uint8_t				 global_uint8;
extern void * __capability	 global_uint8p;
void * __capability		 global_uint8p =
		    (__cheri_tocap void * __capability)&global_uint8;

static uint16_t			 global_static_uint16;
extern void * __capability	 global_static_uint16p;
void * __capability		 global_static_uint16p =
		    (__cheri_tocap void * __capability)&global_static_uint16;

extern uint16_t			 global_uint16;
uint16_t			 global_uint16;
extern void * __capability	 global_uint16p;
void * __capability		 global_uint16p =
		    (__cheri_tocap void * __capability)&global_uint16;

static uint32_t			 global_static_uint32;
extern void * __capability	 global_static_uint32p;
void * __capability		 global_static_uint32p =
		    (__cheri_tocap void * __capability)&global_static_uint32;

extern uint32_t			 global_uint32;
uint32_t			 global_uint32;
extern void * __capability	 global_uint32p;
void * __capability		 global_uint32p =
		    (__cheri_tocap void * __capability)&global_uint32;

static uint64_t	 global_static_uint64;
extern void * __capability	 global_static_uint64p;
void * __capability		 global_static_uint64p =
		    (__cheri_tocap void * __capability)&global_static_uint64;

extern uint64_t			 global_uint64;
uint64_t			 global_uint64;
extern void * __capability	 global_uint64p;
void * __capability		 global_uint64p =
		    (__cheri_tocap void * __capability)&global_uint64;

TEST_BOUNDS(global_static_uint8, "global static uint8_t");
TEST_BOUNDS(global_uint8, "global uint8_t");
TEST_BOUNDS(global_static_uint16, "static uint16_t");
TEST_BOUNDS(global_uint16, "global uint16_t");
TEST_BOUNDS(global_static_uint32, "global static uint32_t");
TEST_BOUNDS(global_uint32, "global uint32_t");
TEST_BOUNDS(global_static_uint64, "global static uint64_t");
TEST_BOUNDS(global_uint64, "global uint64_t");

/*
 * Arrays of bytes with annoying (often prime) sizes.
 */
static uint8_t			 global_static_uint8_array1[1];
extern void * __capability	 global_static_uint8_array1p;
void * __capability		 global_static_uint8_array1p =
		    (__cheri_tocap void * __capability)&global_static_uint8_array1;

extern uint8_t			 global_uint8_array1[1];
uint8_t				 global_uint8_array1[1];
extern void * __capability	 global_uint8_array1p;
void * __capability		 global_uint8_array1p =
		    (__cheri_tocap void * __capability)&global_uint8_array1;

static uint8_t			 global_static_uint8_array3[3];
extern void * __capability	 global_static_uint8_array3p;
void * __capability		 global_static_uint8_array3p =
		    (__cheri_tocap void * __capability)&global_static_uint8_array3;

extern uint8_t			 global_uint8_array3[3];
uint8_t				 global_uint8_array3[3];
extern void * __capability	 global_uint8_array3p;
void * __capability		 global_uint8_array3p =
		    (__cheri_tocap void * __capability)&global_uint8_array3;

static uint8_t			 global_static_uint8_array17[17];
extern void * __capability	 global_static_uint8_array17p;
void * __capability		 global_static_uint8_array17p =
		    (__cheri_tocap void * __capability)&global_static_uint8_array17;

extern uint8_t			 global_uint8_array17[17];
uint8_t				 global_uint8_array17[17];
extern void * __capability	 global_uint8_array17p;
void * __capability		 global_uint8_array17p =
		    (__cheri_tocap void * __capability)&global_uint8_array17;

static uint8_t			 global_static_uint8_array65537[65537];
extern void * __capability	 global_static_uint8_array65537p;
void * __capability		 global_static_uint8_array65537p =
		    (__cheri_tocap void * __capability)&global_static_uint8_array65537;

extern uint8_t			 global_uint8_array65537[65537];
uint8_t				 global_uint8_array65537[65537];
extern void * __capability	 global_uint8_array65537p;
void * __capability		 global_uint8_array65537p =
		    (__cheri_tocap void * __capability)&global_uint8_array65537;

TEST_BOUNDS(global_static_uint8_array1, "global static uint8_t[1]");
TEST_BOUNDS(global_uint8_array1, "global uint8_t[1]");
TEST_BOUNDS(global_static_uint8_array3, "global static uint8_t[3]")
TEST_BOUNDS(global_uint8_array3, "global uint8_t[3]");
TEST_BOUNDS(global_static_uint8_array17, "global static uint_t[17]");
TEST_BOUNDS(global_uint8_array17, "global uint_t[17]");
TEST_BOUNDS(global_static_uint8_array65537, "global static uint8_t[65537]");
TEST_BOUNDS(global_uint8_array65537, "global uint8_t[65537]");

/*
 * Arrays of bytes with power-of-two sizes starting with size 32.
 */
static uint8_t			 global_static_uint8_array32[32];
extern void * __capability	 global_static_uint8_array32p;
void * __capability		 global_static_uint8_array32p =
		    (__cheri_tocap void * __capability)&global_static_uint8_array32;

extern uint8_t			 global_uint8_array32[32];
uint8_t		 		 global_uint8_array32[32];
extern void * __capability	 global_uint8_array32p;
void * __capability		 global_uint8_array32p =
		    (__cheri_tocap void * __capability)&global_uint8_array32;

static uint8_t	 global_static_uint8_array64[64];
extern void * __capability	 global_static_uint8_array64p;
void * __capability		 global_static_uint8_array64p =
		    (__cheri_tocap void * __capability)&global_static_uint8_array64;

extern uint8_t			 global_uint8_array64[64];
uint8_t				 global_uint8_array64[64];
extern void * __capability	 global_uint8_array64p;
void * __capability		 global_uint8_array64p =
		    (__cheri_tocap void * __capability)&global_uint8_array64;

static uint8_t			 global_static_uint8_array128[128];
extern void * __capability	 global_static_uint8_array128p;
void * __capability		 global_static_uint8_array128p =
		    (__cheri_tocap void * __capability)&global_static_uint8_array128;

extern uint8_t			 global_uint8_array128[128];
uint8_t				 global_uint8_array128[128];
extern void * __capability	 global_uint8_array128p;
void * __capability		 global_uint8_array128p =
		    (__cheri_tocap void * __capability)&global_uint8_array128;

static uint8_t			 global_static_uint8_array256[256];
extern void * __capability	 global_static_uint8_array256p;
void * __capability		 global_static_uint8_array256p =
		    (__cheri_tocap void * __capability)&global_static_uint8_array256;

extern uint8_t			 global_uint8_array256[256];
uint8_t				 global_uint8_array256[256];
extern void * __capability	 global_uint8_array256p;
void * __capability		 global_uint8_array256p =
		    (__cheri_tocap void * __capability)&global_uint8_array256;

static uint8_t			 global_static_uint8_array512[512];
extern void * __capability	 global_static_uint8_array512p;
void * __capability		 global_static_uint8_array512p =
		    (__cheri_tocap void * __capability)&global_static_uint8_array512;

extern uint8_t			 global_uint8_array512[512];
uint8_t				 global_uint8_array512[512];
extern void * __capability	 global_uint8_array512p;
void * __capability		 global_uint8_array512p =
		    (__cheri_tocap void * __capability)&global_uint8_array512;

static uint8_t			 global_static_uint8_array1024[1024];
extern void * __capability	 global_static_uint8_array1024p;
void * __capability		 global_static_uint8_array1024p =
		    (__cheri_tocap void * __capability)&global_static_uint8_array1024;

extern uint8_t			 global_uint8_array1024[1024];
uint8_t				 global_uint8_array1024[1024];
extern void * __capability	 global_uint8_array1024p;
void * __capability		 global_uint8_array1024p =
		    (__cheri_tocap void * __capability)&global_uint8_array1024;

static uint8_t			 global_static_uint8_array2048[2048];
extern void * __capability	 global_static_uint8_array2048p;
void * __capability		 global_static_uint8_array2048p =
		    (__cheri_tocap void * __capability)&global_static_uint8_array2048;

extern uint8_t			 global_uint8_array2048[2048];
uint8_t				 global_uint8_array2048[2048];
extern void * __capability	 global_uint8_array2048p;
void * __capability		 global_uint8_array2048p =
		    (__cheri_tocap void * __capability)&global_uint8_array2048;

static uint8_t			 global_static_uint8_array4096[4096];
extern void * __capability	 global_static_uint8_array4096p;
void * __capability		 global_static_uint8_array4096p =
		    (__cheri_tocap void * __capability)&global_static_uint8_array4096;

extern uint8_t			 global_uint8_array4096[4096];
uint8_t				 global_uint8_array4096[4096];
extern void * __capability	 global_uint8_array4096p;
void * __capability		 global_uint8_array4096p =
		    (__cheri_tocap void * __capability)&global_uint8_array4096;

static uint8_t			 global_static_uint8_array8192[8192];
extern void * __capability	 global_static_uint8_array8192p;
void * __capability		 global_static_uint8_array8192p =
		    (__cheri_tocap void * __capability)&global_static_uint8_array8192;

extern uint8_t			 global_uint8_array8192[8192];
uint8_t				 global_uint8_array8192[8192];
extern void * __capability	 global_uint8_array8192p;
void * __capability		 global_uint8_array8192p =
		    (__cheri_tocap void * __capability)&global_uint8_array8192;

static uint8_t			 global_static_uint8_array16384[16384];
extern void * __capability	 global_static_uint8_array16384p;
void * __capability		 global_static_uint8_array16384p =
		    (__cheri_tocap void * __capability)&global_static_uint8_array16384;

extern uint8_t			 global_uint8_array16384[16384];
uint8_t				 global_uint8_array16384[16384];
extern void * __capability	 global_uint8_array16384p;
void * __capability		 global_uint8_array16384p =
		    (__cheri_tocap void * __capability)&global_uint8_array16384;

static uint8_t			 global_static_uint8_array32768[32768];
extern void * __capability	 global_static_uint8_array32768p;
void * __capability		 global_static_uint8_array32768p =
		    (__cheri_tocap void * __capability)&global_static_uint8_array32768;

extern uint8_t			 global_uint8_array32768[32768];
uint8_t				 global_uint8_array32768[32768];
extern void * __capability	 global_uint8_array32768p;
void * __capability		 global_uint8_array32768p =
		    (__cheri_tocap void * __capability)&global_uint8_array32768;

static uint8_t			 global_static_uint8_array65536[65536];
extern void * __capability	 global_static_uint8_array65536p;
void * __capability		 global_static_uint8_array65536p =
		    (__cheri_tocap void * __capability)&global_static_uint8_array65536;

extern uint8_t			 global_uint8_array65536[65536];
uint8_t				 global_uint8_array65536[65536];
extern void * __capability	 global_uint8_array65536p;
void * __capability		 global_uint8_array65536p =
		    (__cheri_tocap void * __capability)&global_uint8_array65536;

TEST_BOUNDS(global_static_uint8_array32, "global static uint8_t[32]");
TEST_BOUNDS(global_uint8_array32, "global uint8_t[32]");
TEST_BOUNDS(global_static_uint8_array64, "global static uint8_t[64]");
TEST_BOUNDS(global_uint8_array64, "global uint8_t[64]");
TEST_BOUNDS(global_static_uint8_array128, "global static uint8_t[128]");
TEST_BOUNDS(global_uint8_array128, "global uint8_t[128]");
TEST_BOUNDS(global_static_uint8_array256, "global static uint8_t[256]");
TEST_BOUNDS(global_uint8_array256, "global uint8_t[256]");
TEST_BOUNDS(global_static_uint8_array512, "global static uint8_t[512]");
TEST_BOUNDS(global_uint8_array512, "global uint8_t[512]");
TEST_BOUNDS(global_static_uint8_array1024, "global static uint8_t[1024]");
TEST_BOUNDS(global_uint8_array1024, "global uint8_t[1024]");
TEST_BOUNDS(global_static_uint8_array2048, "global static uint8_t[2048]");
TEST_BOUNDS(global_uint8_array2048, "global uint8_t[2048]");
TEST_BOUNDS(global_static_uint8_array4096, "global static uint8_t[4096]");
TEST_BOUNDS(global_uint8_array4096, "global uint8_t[4096]");
TEST_BOUNDS(global_static_uint8_array8192, "global uint8_t[8192]");
TEST_BOUNDS(global_uint8_array8192, "global uint8_t[8192]");
TEST_BOUNDS(global_static_uint8_array16384, "global static uint8_t[16384]");
TEST_BOUNDS(global_uint8_array16384, "global uint8_t[16384]");
TEST_BOUNDS(global_static_uint8_array32768, "global static uint8_t[32768]");
TEST_BOUNDS(global_uint8_array32768, "global uint8_t[32768]");
TEST_BOUNDS(global_static_uint8_array65536, "global static uint8_t[65536]");
TEST_BOUNDS(global_uint8_array65536, "global uint8_t[65536]");

/*
 * Tests on globals allocated in another compilation unit.  Sometimes with
 * correct local type information, and sometimes with incorrect local type
 * information.
 */

/* 1-byte global with correct type information. */
extern uint8_t			 extern_global_uint8;
extern void * __capability	 extern_global_uint8p;
void * __capability		 extern_global_uint8p =
		    (__cheri_tocap void * __capability)&extern_global_uint8;

/* 2-byte global with incorrect type information. */
extern uint8_t			 extern_global_uint16;
extern void * __capability	 extern_global_uint16p;
void * __capability		 extern_global_uint16p =
		    (__cheri_tocap void * __capability)&extern_global_uint16;

/* 4-byte global with correct type information. */
extern uint32_t			 extern_global_uint32;
extern void * __capability	 extern_global_uint32p;
void * __capability		 extern_global_uint32p =
		    (__cheri_tocap void * __capability)&extern_global_uint32;

/* 8-byte global with incorrect type information. */
extern uint32_t			 extern_global_uint64;
extern void * __capability	 extern_global_uint64p;
void * __capability		 extern_global_uint64p =
		    (__cheri_tocap void * __capability)&extern_global_uint64;

/* 1-byte global with incorrect type information. */
extern uint8_t			 extern_global_array1[2];
extern void * __capability	 extern_global_array1p;
void * __capability		 extern_global_array1p =
		    (__cheri_tocap void * __capability)&extern_global_array1;

/* 7-byte global with correct type information. */
extern uint8_t			 extern_global_array7[7];
extern void * __capability	 extern_global_array7p;
void * __capability		 extern_global_array7p =
		    (__cheri_tocap void * __capability)&extern_global_array7;

/* 65,537-byte global with incorrect type information. */
extern uint8_t			 extern_global_array65537[127];
extern void * __capability	 extern_global_array65537p;
void * __capability		 extern_global_array65537p =
		    (__cheri_tocap void * __capability)&extern_global_array65537;

/* 16-byte global with correct type information. */
extern uint8_t			 extern_global_array16[16];
extern void * __capability	 extern_global_array16p;
void * __capability		 extern_global_array16p =
		    (__cheri_tocap void * __capability)&extern_global_array16;

/* 256-byte global with incorrect type information. */
extern uint8_t			 extern_global_array256[128];
extern void * __capability	 extern_global_array256p;
void * __capability		 extern_global_array256p =
		    (__cheri_tocap void * __capability)&extern_global_array256;

/* 65,536-byte global with correct type information. */
extern uint8_t			 extern_global_array65536[65536];
extern void * __capability	 extern_global_array65536p;
void * __capability		 extern_global_array65536p =
		    (__cheri_tocap void * __capability)&extern_global_array65536;

/*
 * Checks against C-based types.
 */
TEST_BOUNDS(extern_global_uint8, "extern global uint8_t (C size)");
TEST_BOUNDS(extern_global_uint32, "extern global uint32_t (C size)");
TEST_BOUNDS(extern_global_array7, "extern global uint8_t[7] (C size)");
TEST_BOUNDS(extern_global_array16, "extern global uint8_t[16] (C size)");
TEST_BOUNDS(extern_global_array65536, "extern global uint8_t[16] (C size)");
/*
 * Template for a test function, which assumes there is a global (test) and
 * corresponding statically initialised pointer (testp).  Check that both
 * taking a pointer to the global, and using the existing pointer, return
 * offsets and sizes as desired.  Unlike above, take an explicit type argument
 * from which to generate a size, whereas above we assume the C type of the
 * variable is a correct source of size information.
 */
#define	TEST_DYNAMIC_BOUNDS(test, type, ...)				\
	CHERIBSDTEST(bounds_##test,				\
	"Check bounds on extern global " #type " (dynamic size)",	\
	.ct_xfail_reason = XFAIL_HYBRID_BOUNDS_GLOBALS_EXTERN,		\
	__VA_ARGS__)							\
	{								\
		void * __capability allocation =			\
		    (__cheri_tocap void * __capability)&test;		\
		test_bounds_impl(allocation, test##p, sizeof(type));	\
	}

/*
 * Checks to ensure we are using linker-provided size information, and not C
 * types.  Use a priori knowledge of the types to check lengths.
 */
TEST_DYNAMIC_BOUNDS(extern_global_uint16, uint16_t);
TEST_DYNAMIC_BOUNDS(extern_global_uint64, uint64_t);
TEST_DYNAMIC_BOUNDS(extern_global_array1, uint8_t[1]);
TEST_DYNAMIC_BOUNDS(extern_global_array65537, uint8_t[65537]);
TEST_DYNAMIC_BOUNDS(extern_global_array256, uint8_t[256]);
