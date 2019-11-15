/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.
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
/*static char *sccsid = "from: @(#)malloc.c	5.11 (Berkeley) 2/23/91";*/
static char *rcsid = "$FreeBSD$";
#endif /* LIBC_SCCS and not lint */

/*
 * malloc.c (Caltech) 2/21/82
 * Chris Kingsley, kingsley@cit-20.
 *
 * This is a very fast storage allocator.  It allocates blocks of a small
 * number of different sizes, and keeps free lists of each size.  Blocks that
 * don't exactly fit are passed up to the next larger size.  In this
 * implementation, the available sizes are 2^n-4 (or 2^n-10) bytes long.
 * This is designed for use in a virtual memory environment.
 */

#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include "rtld.h"
#include "rtld_printf.h"
#include "paths.h"

/*
 * Pre-allocate mmap'ed pages
 */
#define	NPOOLPAGES	(128*1024/pagesz)
static caddr_t		pagepool_start, pagepool_end;

/*
 * The overhead on a block is at least 4 bytes.  When free, this space
 * contains a pointer to the next free block, and the bottom two bits must
 * be zero.  When in use, the first byte is set to MAGIC, and the second
 * byte is the size index.  The remaining bytes are for alignment.
 * If range checking is enabled then a second word holds the size of the
 * requested block, less 1, rounded up to a multiple of sizeof(RMAGIC).
 * The order of elements is critical: ov_magic must overlay the low order
 * bits of ov_next, and ov_magic can not be a valid ov_next bit pattern.
 */
union	overhead {
	union	overhead *ov_next;	/* when free */
	struct {
		u_char	ovu_magic;	/* magic number */
		u_char	ovu_index;	/* bucket # */
	} ovu;
#define	ov_magic	ovu.ovu_magic
#define	ov_index	ovu.ovu_index
};

static void morecore(int bucket);
static int morepages(int n);

#define	MAGIC		0xef		/* magic # on accounting info */

/*
 * nextf[i] is the pointer to the next free block of size
 * (FIRST_BUCKET_SIZE << i).  The overhead information precedes the data
 * area returned to the user.
 */
#define	FIRST_BUCKET_SIZE	8
#define	NBUCKETS 30
static	union overhead *nextf[NBUCKETS];

static	int pagesz;			/* page size */

/*
 * The array of supported page sizes is provided by the user, i.e., the
 * program that calls this storage allocator.  That program must initialize
 * the array before making its first call to allocate storage.  The array
 * must contain at least one page size.  The page sizes must be stored in
 * increasing order.
 */

void *
__crt_malloc(size_t nbytes)
{
	union overhead *op;
	int bucket;
	size_t amt;

	/*
	 * First time malloc is called, setup page size.
	 */
	if (pagesz == 0)
		pagesz = pagesizes[0];
	/*
	 * Convert amount of memory requested into closest block size
	 * stored in hash buckets which satisfies request.
	 * Account for space used per block for accounting.
	 */
	amt = FIRST_BUCKET_SIZE;
	bucket = 0;
	while (nbytes > amt - sizeof(*op)) {
		amt <<= 1;
		bucket++;
		if (amt == 0 || bucket >= NBUCKETS)
			return (NULL);
	}
	if (bucket >= NBUCKETS)
		return (NULL);
	/*
	 * If nothing in hash bucket right now,
	 * request more memory from the system.
	 */
  	if ((op = nextf[bucket]) == NULL) {
  		morecore(bucket);
  		if ((op = nextf[bucket]) == NULL)
  			return (NULL);
	}
	/* remove from linked list */
  	nextf[bucket] = op->ov_next;
	op->ov_magic = MAGIC;
	op->ov_index = bucket;
  	return ((char *)(op + 1));
}

void *
__crt_calloc(size_t num, size_t size)
{
	void *ret;

	if (size != 0 && (num * size) / size != num) {
		/* size_t overflow. */
		return (NULL);
	}

	if ((ret = __crt_malloc(num * size)) != NULL)
		memset(ret, 0, num * size);

	return (ret);
}

/*
 * Allocate more memory to the indicated bucket.
 */
static void
morecore(int bucket)
{
	union overhead *op;
	int sz;		/* size of desired block */
  	int amt;			/* amount to allocate */
  	int nblks;			/* how many blocks we get */

	sz = FIRST_BUCKET_SIZE << bucket;
	if (sz < pagesz) {
		amt = pagesz;
  		nblks = amt / sz;
	} else {
		amt = sz;
		nblks = 1;
	}
	if (amt > pagepool_end - pagepool_start)
		if (morepages(amt/pagesz + NPOOLPAGES) == 0)
			return;
	op = (union overhead *)(void *)pagepool_start;
	pagepool_start += amt;

	/*
	 * Add new memory allocated to that on
	 * free list for this hash bucket.
	 */
  	nextf[bucket] = op;
  	while (--nblks > 0) {
		op->ov_next = (union overhead *)(void *)((caddr_t)op + sz);
		op = (union overhead *)(void *)((caddr_t)op + sz);
  	}
}

void
__crt_free(void *cp)
{
	int size;
	union overhead *op;

  	if (cp == NULL)
  		return;
	op = (union overhead *)(void *)((caddr_t)cp - sizeof (union overhead));
	if (op->ov_magic != MAGIC)
		return;				/* sanity */
  	size = op->ov_index;
	op->ov_next = nextf[size];	/* also clobbers ov_magic */
  	nextf[size] = op;
}

void *
__crt_realloc(void *cp, size_t nbytes)
{
	u_int onb;
	int i;
	union overhead *op;
  	char *res;

  	if (cp == NULL)
		return (__crt_malloc(nbytes));
	op = (union overhead *)((caddr_t)cp - sizeof (union overhead));
	if (op->ov_magic != MAGIC)
		return (NULL);	/* Double-free or bad argument */
	i = op->ov_index;
	onb = 1 << (i + 3);
	if (onb < (u_int)pagesz)
		onb -= sizeof(*op);
	else
		onb += pagesz - sizeof(*op);
	/* avoid the copy if same size block */
	if (i != 0) {
		i = 1 << (i + 2);
		if (i < pagesz)
			i -= sizeof(*op);
		else
			i += pagesz - sizeof(*op);
	}
	if (nbytes <= onb && nbytes > (size_t)i)
		return (cp);
  	if ((res = __crt_malloc(nbytes)) == NULL)
		return (NULL);
	bcopy(cp, res, (nbytes < onb) ? nbytes : onb);
	__crt_free(cp);
  	return (res);
}

static int
morepages(int n)
{
	caddr_t	addr;
	int offset;

	if (pagepool_end - pagepool_start > pagesz) {
		addr = (caddr_t)roundup2((long)pagepool_start, pagesz);
		if (munmap(addr, pagepool_end - addr) != 0) {
#ifdef IN_RTLD
			rtld_fdprintf(STDERR_FILENO, _BASENAME_RTLD ": "
			    "morepages: cannot munmap %p: %s\n",
			    addr, rtld_strerror(errno));
#endif
		}
	}

	offset = (long)pagepool_start - rounddown2((long)pagepool_start,
	    pagesz);

	pagepool_start = mmap(0, n * pagesz, PROT_READ | PROT_WRITE,
	    MAP_ANON | MAP_PRIVATE, -1, 0);
	if (pagepool_start == MAP_FAILED) {
#ifdef IN_RTLD
		rtld_fdprintf(STDERR_FILENO, _BASENAME_RTLD ": morepages: "
		    "cannot mmap anonymous memory: %s\n",
		    rtld_strerror(errno));
#endif
		return (0);
	}
	pagepool_end = pagepool_start + n * pagesz;
	pagepool_start += offset;

	return (n);
}
