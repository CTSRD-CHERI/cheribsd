/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2009, 2010 Xin LI <delphij@FreeBSD.org>
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
__FBSDID("$FreeBSD$");

#include <sys/libkern.h>
#include <sys/limits.h>

/*
 * Portable strlen() for 32-bit and 64-bit systems.
 *
 * The expression:
 *
 *	((x - 0x01....01) & ~x & 0x80....80)
 *
 * would evaluate to a non-zero value iff any of the bytes in the
 * original word is zero.
 *
 * The algorithm above is found on "Hacker's Delight" by
 * Henry S. Warren, Jr.
 *
 * Note: this leaves performance on the table and each architecture
 * would be best served with a tailor made routine instead, even if
 * using the same trick.
 */

/* Magic numbers for the algorithm */
#if LONG_BIT == 32
static const unsigned long mask01 = 0x01010101;
static const unsigned long mask80 = 0x80808080;
#elif LONG_BIT == 64
static const unsigned long mask01 = 0x0101010101010101;
static const unsigned long mask80 = 0x8080808080808080;
#else
#error Unsupported word size
#endif

/*
 * Helper macro to return string length if we caught the zero
 * byte.
 */
#define testbyte(x)				\
	do {					\
		if (p[x] == '\0')		\
		    return (p - str + x);	\
	} while (0)

size_t
(strlen)(const char *str)
{
	const char *p;
	const unsigned long *lp;
	long va, vb;
	bool byte_check;

	/*
	 * Before trying the hard (unaligned byte-by-byte access) way
	 * to figure out whether there is a nul character, try to see
	 * if there is a nul character is within this accessible word
	 * first.
	 *
	 * p and (p & ~LONGPTR_MASK) must be equally accessible since
	 * they always fall in the same memory page, as long as page
	 * boundaries is integral multiple of word size.
	 *
	 * This is not true for CHERI, so we skip directly to byte
	 * access if not word-aligned.
	 */
	lp = (const unsigned long *)rounddown2(str, sizeof(long));
#ifdef __CHERI_PURE_CAPABILITY__
	byte_check = ((const char *)lp < str);
	if (byte_check)
		lp++;
#else
	va = (*lp - mask01);
	vb = ((~*lp) & mask80);
	lp++;
	byte_check = (bool)(va & vb);
#endif
	if (byte_check)
		/* Check if we have \0 in the first part */
		for (p = str; p < (const char *)lp; p++)
			if (*p == '\0')
				return (p - str);

	/* Scan the rest of the string using word sized operation */
#ifdef __CHERI_PURE_CAPABILITY__
	for (; cheri_getlen(lp) - cheri_getoffset(lp) >= sizeof(long); lp++)
#else
	for (; ; lp++)
#endif
	{
		va = (*lp - mask01);
		vb = ((~*lp) & mask80);
		if (va & vb) {
			p = (const char *)(lp);
			testbyte(0);
			testbyte(1);
			testbyte(2);
			testbyte(3);
#if (LONG_BIT >= 64)
			testbyte(4);
			testbyte(5);
			testbyte(6);
			testbyte(7);
#endif
		}
	}

#ifdef __CHERI_PURE_CAPABILITY__
	/* Check if we need to scan byte-by-byte at the end of the string */
	if ((ptraddr_t)lp != cheri_gettop(lp)) {
		for (p = (const char *)lp; ; p++)
			if (*p == '\0')
				return (p - str);
	}
#endif

	/* NOTREACHED */
	return (0);
}
// CHERI CHANGES START
// {
//   "updated": 20221205,
//   "target_type": "kernel",
//   "changes_purecap": [
//     "pointer_shape",
//     "unsupported",
//     "pointer_alignment"
//   ]
// }
// CHERI CHANGES END
