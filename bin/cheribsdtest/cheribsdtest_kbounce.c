/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2018 SRI International
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

#if !__has_feature(capabilities)
#error "This code requires a CHERI-aware compiler"
#endif

#include <sys/param.h>
#include <sys/kbounce.h>
#include <sys/mman.h>

#include "cheribsdtest.h"

#define	BUFLEN		PAGE_SIZE
#define	GUARDLEN	PAGE_SIZE

/*
 * Fill a buffer with the offset of each byte (mod 255).
 */
static void
fillbuf(char *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		buf[i] = i & 0xFF;
}

/*
 * Fill a destination buffer with the bitwise complement of the source
 * buffer to prevent accidental matches.
 */
static void
spoilbuf(char *buf, size_t len)
{
	size_t i;

	fillbuf(buf, len);
	for (i = 0; i < len; i++)
		buf[i] = ~buf[i];
}

/*
 * Check that the bytes of a buffer in the range (buf + offset) to
 * (buf + offset + len - 1) are those expected from fillbuf().
 */
static void
checkbuf(const char *buf, size_t offset, size_t len, const char *where)
{
	size_t i;

	for (i = offset; i < offset + len; i++) {
		if (buf[i] != (char)(i & 0xFF))
			cheribsdtest_failure_errx("%s: buf[%zu] != 0x%02x (0x%02x)",
			    where, i, (char)(i & 0xFF), buf[i]);
	}
}

CHERIBSDTEST(sys_kbounce, "Exercise copyin/out via kbounce(2) syscall")
{
	char *buf, *dst, *src;

	/* XXX-BD: can/should we use MAP_GUARD? */
	/*
	 * Allocate space for two buffers of BUFLEN size with guard
	 * regions around them.  Guard regsions fare for paranoia,
	 * mmap'd buffers insure page alignment.
	 */
	buf = mmap(NULL, (BUFLEN * 2) + (PAGE_SIZE * 3), PROT_READ | PROT_WRITE,
	    MAP_ANON | MAP_PRIVATE, -1, 0);
	if (buf == MAP_FAILED)
		cheribsdtest_failure_err("mmap of %d failed",
		    (BUFLEN * 2)+ (PAGE_SIZE * 3));
	if (mprotect(buf, GUARDLEN, PROT_NONE) == -1)
		cheribsdtest_failure_err("mprotect of first guard region failed");
	if (mprotect(buf + GUARDLEN + BUFLEN, GUARDLEN, PROT_NONE) == -1)
		cheribsdtest_failure_err("mprotect of second guard region failed");
	if (mprotect(buf + (2 * (GUARDLEN + BUFLEN)), GUARDLEN, PROT_NONE) ==
	    -1)
		cheribsdtest_failure_err("mprotect of third guard region failed");

	src = buf + GUARDLEN;
	dst = src + BUFLEN + GUARDLEN;

	fillbuf(src, BUFLEN);
	checkbuf(src, 0, BUFLEN, "src");

	spoilbuf(dst, BUFLEN);
	if (kbounce(src, dst, BUFLEN, 0) != 0)
		cheribsdtest_failure_err("kbounce(%p, %p, %d, 0)", src,
		    dst, BUFLEN);
	checkbuf(src, 0, BUFLEN, "full buffer");

	for (size_t off = 0; off < sizeof(void * __capability); off++) {
		/*
		 * Lengths to test.
		 *
		 * BUFLEN is special and means "however much is left."
		 * Negative values mean "up to the end, less the value."
		 *
		 * 1-32 insures one aligned 128-bit object * at any offset.
		 * BUFLEN and -1 to -31 tests all ending alignments.
		 */
		const int lengths[] = {
			1, 2, 3, 4, 5, 6, 7, 8,
			9, 10, 11, 12, 13, 14, 15, 16,
			17, 18, 19, 20, 21, 22, 23, 24,
			25, 26, 27, 28, 29, 30, 31, 32,
			BUFLEN, -1, -2, -3, -4, -5, -6, -7,
			-8, -9, -10, -11, -12, -13, -14, -15,
			-16, -17, -18, -19, -20, -21, -22, -23,
			-24, -25, -26, -27, -28, -29, -30, -31,
			0 };
		for (int l = 0; lengths[l] != 0; l++) {
			char *srcptr, *dstptr;
			size_t len;

			spoilbuf(dst, BUFLEN);	/* Spoil the whole buffer */

			srcptr = src + off;
			dstptr = dst + off;
			if (lengths[l] == BUFLEN)
				len = BUFLEN - off;
			else if (lengths[l] < 0)
				len = BUFLEN - off + lengths[l];
			else
				len = lengths[l];

			if (kbounce(srcptr, dstptr, len, 0) != 0)
				cheribsdtest_failure_err("kbounce(\n  %#p,\n  %#p,\n%zu, 0)",
				    srcptr, dstptr, len);
			checkbuf(src, off, len, "partial buffer");
		}
	}

	cheribsdtest_success();
}
