/*-
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
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

#if !defined(STANDALONE)
#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)bcopy.c	8.1 (Berkeley) 6/4/93";
#endif /* LIBC_SCCS and not lint */
#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");
#include <sys/types.h>
#include <stdint.h>
#else
typedef long vaddr_t;
#endif
/*
 * sizeof(word) MUST BE A POWER OF TWO
 * SO THAT wmask BELOW IS ALL ONES
 */
typedef	long word;		/* "word" used for medium copy speed */

#define	wsize	sizeof(word)
#define	wmask	(wsize - 1)

/* "pointer" used for optimal copy speed when pointers are large */
#ifdef __CHERI__
typedef	__uintcap_t ptr;
#define CAPABILITY __capability
#else
typedef	uintptr_t ptr;
#define CAPABILITY
#endif

#define PWIDTH __POINTER_WIDTH__/8

#define	psize	sizeof(ptr)
#define	pmask	(psize - 1)
#define bigptr	(psize>wsize)

#define MIPSLOOP(index, last, cStatements, increment)			\
{									\
	index -= increment;						\
	do {								\
		asm (							\
			"daddiu %[indexIn], %[indexIn], " #increment "\n" \
			:[indexOut] "=r"(index)				\
			:[indexIn] "r"(index)				\
		);							\
		cStatements						\
	} while (index!=last);						\
}

/*
 * Copy a block of memory, handling overlap.
 * This is the routine that actually implements
 * (the portable versions of) bcopy, memcpy, and memmove.
 */

#if defined(MEMCPY_C)
void * CAPABILITY
memcpy_c(void * CAPABILITY dst0, const void * CAPABILITY src0, size_t length)
#elif defined(MEMMOVE)
void *
memmove
(void *dst0, const void *src0, size_t length)
#elif defined(CMEMMOVE)
void *
cmemmove
(void *dst0, const void *src0, size_t length)
#elif defined(MEMMOVE_C)
void * CAPABILITY
memmove_c
(void * CAPABILITY dst0, const void * CAPABILITY src0, size_t length)
#elif defined(MEMCPY)
void *
memcpy
(void *dst0, const void *src0, size_t length)
#elif defined(CMEMCPY_C)
void * CAPABILITY
cmemcpy_c(void * CAPABILITY dst0, const void * CAPABILITY src0, size_t length)
#elif defined(CMEMCPY)
void *
cmemcpy
(void *dst0, const void *src0, size_t length)
#elif defined(BCOPY)
void
bcopy(const void *src0, void *dst0, size_t length)
#else
#error One of BCOPY, MEMCPY, or MEMMOVE must be defined.
#endif
{
	if (length == 0 || src0 == dst0)		/* nothing to do */
		goto done;

#ifdef __CHERI__
	char * CAPABILITY dst =
	    __builtin_cheri_bounds_set((__cheri_cast void * CAPABILITY)dst0,length);
	const char * CAPABILITY src =
	    __builtin_cheri_bounds_set((__cheri_cast const void * CAPABILITY)src0,length);
#else
	char *dst = dst0;
	const char *src = src0;
#endif
	size_t t;

#if defined(MEMMOVE) || defined(BCOPY) || defined(CMEMMOVE) || defined(MEMMOVE_C)
	const int handle_overlap = 1;
#else
	const int handle_overlap = 0;
#endif

	if (dst < src || !handle_overlap) {
		/*
		 * Copy forward.
		 */
		t = (vaddr_t)src;	/* only need low bits */
		if ((t | (vaddr_t)dst) & wmask) {
			/*
			 * Try to align operands.  This cannot be done
			 * unless the low bits match.
			 */
			if ((t ^ (vaddr_t)dst) & wmask || length < wsize)
				t = length;
			else
				t = wsize - (t & wmask);
			length -= t;
			dst += t;
			src += t;
			t = -t;
			MIPSLOOP(t, -1, dst[t]=src[t];, 1);
		}
		/*
		 * If pointers are bigger than words, try to copy by words.
		 */
		if (bigptr) {
			t = (vaddr_t)src;	/* only need low bits */
			if ((t | (vaddr_t)dst) & pmask) {
				/*
				 * Try to align operands.  This cannot be done
				 * unless the low bits match.
				 */
				if ((t ^ (vaddr_t)dst) & pmask || length < psize)
					t = length / wsize;
				else
					t = (psize - (t & pmask)) / wsize;
				if (t) {
					length -= t*wsize;
					dst += t*wsize;
					src += t*wsize;
					t = -t*wsize;
					MIPSLOOP(t, -8,
					    *((word * CAPABILITY)(dst+t)) =
					    *((word * CAPABILITY)(src+t));,
					    8/*wsize*/);
				}
			}
		}
		/*
		 * Copy whole words, then mop up any trailing bytes.
		 */
		t = length / psize;
		if (t) {
			src += t*psize;
			dst += t*psize;
			t = -(t*psize);
#if !defined(_MIPS_SZCAP)
			MIPSLOOP(t, -psize, *((ptr * CAPABILITY)(dst+t)) =
			    *((ptr * CAPABILITY)(src+t));, 8/*sizeof(ptr)*/);
#elif _MIPS_SZCAP==128
			MIPSLOOP(t, -psize, *((ptr * CAPABILITY)(dst+t)) =
			    *((ptr * CAPABILITY)(src+t));, 16/*sizeof(ptr)*/);
#elif _MIPS_SZCAP==256
			MIPSLOOP(t, -psize, *((ptr * CAPABILITY)(dst+t)) =
			    *((ptr * CAPABILITY)(src+t));, 32/*sizeof(ptr)*/);
#endif
		}
		t = length & pmask;
		if (t) {
			src += t;
			dst += t;
			t = -t;
			if (t) MIPSLOOP(t, -1, dst[t]=src[t];, 1);
		}
	} else {
		/*
		 * Copy backwards.  Otherwise essentially the same.
		 * Alignment works as before, except that it takes
		 * (t&wmask) bytes to align, not wsize-(t&wmask).
		 */
		src += length;
		dst += length;
		t = (vaddr_t)src;
		if ((t | (vaddr_t)dst) & wmask) {
			if ((t ^ (vaddr_t)dst) & wmask || length <= wsize)
				t = length;
			else
				t &= wmask;
			length -= t;
			dst -= t;
			src -= t;
			t--;
			MIPSLOOP(t, 0, dst[t]=src[t];, -1);
		}
		if (bigptr) {
			t = (vaddr_t)src;	/* only need low bits */
			if ((t | (vaddr_t)dst) & pmask) {
				if ((t ^ (vaddr_t)dst) & pmask || length < psize)
					t = length / wsize;
				else
					t = (t & pmask) / wsize;
				if (t) {
					length -= t*wsize;
					dst -= t*wsize;
					src -= t*wsize;
					t = ((t-1)*wsize);
					MIPSLOOP(t, 0,
					    *((word * CAPABILITY)(dst+t)) =
					    *((word * CAPABILITY)(src+t));,
					    -8/*wsize*/);
				}
			}
		}
		t = length / psize;
		if (t) {
			src -= t*psize;
			dst -= t*psize;
			t = ((t-1)*psize);
#if !defined(_MIPS_SZCAP)
			MIPSLOOP(t, 0, *((ptr * CAPABILITY)(dst+t)) =
			    *((ptr * CAPABILITY)(src+t));, -8/*sizeof(ptr)*/);
#elif _MIPS_SZCAP==128
			MIPSLOOP(t, 0, *((ptr * CAPABILITY)(dst+t)) =
			    *((ptr * CAPABILITY)(src+t));, -16/*sizeof(ptr)*/);
#elif _MIPS_SZCAP==256
			MIPSLOOP(t, 0, *((ptr * CAPABILITY)(dst+t)) =
			    *((ptr * CAPABILITY)(src+t));, -32/*sizeof(ptr)*/);
#endif

		}
		t = length & pmask;
		if (t) {
			dst -= t;
			src -= t;
			t--;
			MIPSLOOP(t, 0, dst[t]=src[t];, -1);
		}
	}
done:
#if !defined(BCOPY)
	return (dst0);
#else
	return;
#endif
}
