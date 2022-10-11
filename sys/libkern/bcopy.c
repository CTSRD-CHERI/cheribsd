/*-
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 1990 The Regents of the University of California.
 *
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if defined(LIBC_SCCS) && !defined(lint)
#if 0
static char *sccsid = "from: @(#)bcopy.c      5.11 (Berkeley) 6/21/91";
#endif
#if 0
static char *rcsid = "$NetBSD: bcopy.c,v 1.2 1997/04/16 22:09:41 thorpej Exp $";
#endif
#endif /* LIBC_SCCS and not lint */
#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#ifdef _KERNEL
#include <sys/systm.h>
#else
#include <string.h>
#endif

#include <cheri/cheric.h>

#undef memcpy
#undef memmove

/*
 * sizeof(word) MUST BE A POWER OF TWO
 * SO THAT wmask BELOW IS ALL ONES
 */
#if __has_feature(capabilities)
typedef	uintcap_t word;
#else
typedef	long	word;		/* "word" used for optimal copy speed */
#endif

#define	wsize	sizeof(word)
#define wmask	(wsize - 1)

/*
 * Copy a block of memory, handling overlap.
 * This is the routine that actually implements
 * (the portable versions of) bcopy, memcpy, and memmove.
 */
static void *
_memcpy(void *dst0, const void *src0, size_t length, bool keeptags)
{
	char		*dst;
	const char	*src;
	size_t		t;

	dst = dst0;
	src = src0;

	if (length == 0 || dst == src) {	/* nothing to do */
		goto done;
	}

	/*
	 * Macros: loop-t-times; and loop-t-times, t>0
	 */
#define	TLOOP(s) if (t) TLOOP1(s)
#define	TLOOP1(s) do { s; } while (--t)

	if ((unsigned long)dst < (unsigned long)src) {
		/*
		 * Copy forward.
		 */
		t = (size_t)src;	/* only need low bits */

		if ((t | (ptraddr_t)dst) & wmask) {
			/*
			 * Try to align operands.  This cannot be done
			 * unless the low bits match.
			 */
			if ((t ^ (ptraddr_t)dst) & wmask || length < wsize) {
				t = length;
			} else {
				t = wsize - (t & wmask);
			}

			length -= t;
			TLOOP1(*dst++ = *src++);
		}
		/*
		 * Copy whole words, then mop up any trailing bytes.
		 */
		t = length / wsize;
#if __has_feature(capabilities)
		if (!keeptags) {
			TLOOP(*(word *)dst = (word)cheri_cleartag(
			        (void * __capability)*(const word *)src);
			    src += wsize; dst += wsize);
		} else
#endif
			TLOOP(*(word *)dst = *(const word *)src; src += wsize;
			    dst += wsize);
		t = length & wmask;
		TLOOP(*dst++ = *src++);
	} else {
		/*
		 * Copy backwards.  Otherwise essentially the same.
		 * Alignment works as before, except that it takes
		 * (t&wmask) bytes to align, not wsize-(t&wmask).
		 */
		src += length;
		dst += length;
		t = (size_t)src;

		if ((t | (ptraddr_t)dst) & wmask) {
			if ((t ^ (ptraddr_t)dst) & wmask || length <= wsize) {
				t = length;
			} else {
				t &= wmask;
			}

			length -= t;
			TLOOP1(*--dst = *--src);
		}
		t = length / wsize;
#if __has_feature(capabilities)
		if (!keeptags) {
			TLOOP(src -= wsize; dst -= wsize;
			    *(word *)dst = (word)cheri_cleartag(
			        (void * __capability)*(const word *)src));
		} else
#endif
			TLOOP(src -= wsize; dst -= wsize;
			    *(word *)dst = *(const word *)src);
		t = length & wmask;
		TLOOP(*--dst = *--src);
	}
done:
	return (dst0);
}

void *
memcpy(void *dst0, const void *src0, size_t length)
{
	return _memcpy(dst0, src0, length, true);
}

__strong_reference(memcpy, memmove);

#if __has_feature(capabilities)
void *
memcpynocap(void *dst0, const void *src0, size_t length)
{
	return _memcpy(dst0, src0, length, false);
}

__strong_reference(memcpynocap, memmovenocap);
#endif
// CHERI CHANGES START
// {
//   "updated": 20200708,
//   "target_type": "kernel",
//   "changes_purecap": [
//     "uintcap_arithmetic"
//   ]
// }
// CHERI CHANGES END
