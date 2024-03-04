/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * Copyright (c) 2014 David T. Chisnall
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Ronnie Kon at Mindcraft Inc., Kevin Lew and Elmer Yglesias.
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
/*
 * CHERI CHANGES START
 * {
 *   "updated": 20181121,
 *   "target_type": "lib",
 *   "changes": [
 *     "integer_provenance"
 *   ],
 *   "change_comment": "memswap"
 * }
 * CHERI CHANGES END
 */

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#if __has_feature(capabilities)
typedef __uintcap_t big_primitive_type;
#else
typedef long big_primitive_type;
#endif

#ifdef I_AM_HEAPSORT_B
#include "block_abi.h"
#define COMPAR(x, y) CALL_BLOCK(compar, x, y)
typedef DECLARE_BLOCK(int, heapsort_block, const void *, const void *);
#else
#define COMPAR(x, y) compar(x, y)
#endif

/*
 * Swap two areas of size number of bytes.
 *
 * Optimize the copying of large objects which are strictly aligned.  In
 * particular, on CHERI systems, copy objects with pointer alignment via
 * capability operations to avoid clearing tags.
 *
 * It is conceivable that an unaligned object could contain pointers, but
 * it would not be a valid C object so we ignore that possibility because
 * qsort() is defined to sort C objects and such under-aligned objects would
 * not be valid C objects.
 *
 * We only test the alignment of one argument because one being aligned
 * when the other is not would violate the invariants of the array.
 */
#define	SWAP(a, b, size) { \
	if ((size) % sizeof(big_primitive_type) == 0 && \
	    (size_t)(a) % sizeof(big_primitive_type) == 0) { \
		size_t count = (size) / sizeof(big_primitive_type); \
		big_primitive_type tmp; \
		big_primitive_type *ap, *bp; \
		ap = (big_primitive_type *)(a); \
		bp = (big_primitive_type *)(b); \
		do { \
			tmp = *ap; \
			*ap++ = *bp; \
			*bp++ = tmp; \
		} while (--count); \
	} else { \
		size_t count = size; \
		char tmp; \
		do { \
			tmp = *(a); \
			*a++ = *(b); \
			*b++ = tmp; \
		} while (--count); \
	} \
}

/* Copy one block of size size to another. */
#define COPY(a, b, size) { \
	if ((size) % sizeof(big_primitive_type) == 0 && \
	    (size_t)(a) % sizeof(big_primitive_type) == 0) { \
		size_t count = size / sizeof(big_primitive_type); \
		big_primitive_type *tmp1 = (big_primitive_type *)(a); \
		big_primitive_type *tmp2 = (big_primitive_type *)(b); \
		do { \
			*tmp1++ = *tmp2++; \
		} while (--count); \
	} else { \
		size_t count = size; \
		char *tmp1 = (a); \
		char *tmp2 = (b); \
		do { \
			*tmp1++ = *tmp2++; \
		} while (--count); \
	} \
}

/*
 * Build the list into a heap, where a heap is defined such that for
 * the records K1 ... KN, Kj/2 >= Kj for 1 <= j/2 <= j <= N.
 *
 * There two cases.  If j == nmemb, select largest of Ki and Kj.  If
 * j < nmemb, select largest of Ki, Kj and Kj+1.
 */
#define CREATE(initval, nmemb, par_i, child_i, par, child, size) { \
	for (par_i = initval; (child_i = par_i * 2) <= nmemb; \
	    par_i = child_i) { \
		child = base + child_i * size; \
		if (child_i < nmemb && COMPAR(child, child + size) < 0) { \
			child += size; \
			++child_i; \
		} \
		par = base + par_i * size; \
		if (COMPAR(child, par) <= 0) \
			break; \
		SWAP(par, child, size); \
	} \
}

/*
 * Select the top of the heap and 'heapify'.  Since by far the most expensive
 * action is the call to the compar function, a considerable optimization
 * in the average case can be achieved due to the fact that k, the displaced
 * elememt, is usually quite small, so it would be preferable to first
 * heapify, always maintaining the invariant that the larger child is copied
 * over its parent's record.
 *
 * Then, starting from the *bottom* of the heap, finding k's correct place,
 * again maintianing the invariant.  As a result of the invariant no element
 * is 'lost' when k is assigned its correct place in the heap.
 *
 * The time savings from this optimization are on the order of 15-20% for the
 * average case. See Knuth, Vol. 3, page 158, problem 18.
 *
 * XXX Don't break the #define SELECT line, below.  Reiser cpp gets upset.
 */
#define SELECT(par_i, child_i, nmemb, par, child, size, k) { \
	for (par_i = 1; (child_i = par_i * 2) <= nmemb; par_i = child_i) { \
		child = base + child_i * size; \
		if (child_i < nmemb && COMPAR(child, child + size) < 0) { \
			child += size; \
			++child_i; \
		} \
		par = base + par_i * size; \
		COPY(par, child, size); \
	} \
	for (;;) { \
		child_i = par_i; \
		par_i = child_i / 2; \
		child = base + child_i * size; \
		par = base + par_i * size; \
		if (child_i == 1 || COMPAR(k, par) < 0) { \
			COPY(child, k, size); \
			break; \
		} \
		COPY(child, par, size); \
	} \
}

#ifdef I_AM_HEAPSORT_B
int heapsort_b(void *, size_t, size_t, heapsort_block);
#else
int heapsort(void *, size_t, size_t,
    int (*)(const void *, const void *));
#endif
/*
 * Heapsort -- Knuth, Vol. 3, page 145.  Runs in O (N lg N), both average
 * and worst.  While heapsort is faster than the worst case of quicksort,
 * the BSD quicksort does median selection so that the chance of finding
 * a data set that will trigger the worst case is nonexistent.  Heapsort's
 * only advantage over quicksort is that it requires little additional memory.
 */
#ifdef I_AM_HEAPSORT_B
int
heapsort_b(void *vbase, size_t nmemb, size_t size, heapsort_block compar)
#else
int
heapsort(void *vbase, size_t nmemb, size_t size,
    int (*compar)(const void *, const void *))
#endif
{
	size_t i, j, l;
	char *base, *k, *p, *t;

	if (nmemb <= 1)
		return (0);

	if (!size) {
		errno = EINVAL;
		return (-1);
	}

	if ((k = malloc(size)) == NULL)
		return (-1);

	/*
	 * Items are numbered from 1 to nmemb, so offset from size bytes
	 * below the starting address.
	 */
	base = (char *)vbase - size;

	for (l = nmemb / 2 + 1; --l;)
		CREATE(l, nmemb, i, j, t, p, size);

	/*
	 * For each element of the heap, save the largest element into its
	 * final slot, save the displaced element (k), then recreate the
	 * heap.
	 */
	while (nmemb > 1) {
		COPY(k, base + nmemb * size, size);
		COPY(base + nmemb * size, base + size, size);
		--nmemb;
		SELECT(i, j, nmemb, t, p, size, k);
	}
	free(k);
	return (0);
}
