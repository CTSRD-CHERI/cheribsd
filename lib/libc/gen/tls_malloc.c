/*-
 * Copyright 1996-1998 John D. Polstra.
 * Copyright (c) 2015-2017 SRI International
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Copyright (c) 1983 Regents of the University of California.
 * Copyright (c) 2015-2017 SRI International
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
 *
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/mman.h>

#ifdef __CHERI_PURE_CAPABILITY__
#include <cheri/cheric.h>
#endif

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libc_private.h"
#include "spinlock.h"

#ifndef __CHERI_PURE_CAPABILITY__
#define	cheri_csetbounds(ptr, size)	((void *)(ptr))
#endif

static spinlock_t tls_malloc_lock = _SPINLOCK_INITIALIZER;
#define	TLS_MALLOC_LOCK		_SPINLOCK(&tls_malloc_lock)
#define	TLS_MALLOC_UNLOCK	_SPINUNLOCK(&tls_malloc_lock)
union overhead;
static void morecore(int);
static void init_pagebucket(void);

/*
 * The overhead on a block is one pointer. When free, this space
 * contains a pointer to the next free block. When in use, the first
 * byte is set to MAGIC, and the second byte is the size index.
 */
union	overhead {
	union	overhead *ov_next;	/* when free */
	struct {
		u_char	ovu_magic;	/* magic number */
		u_char	ovu_index;	/* bucket # */
	} ovu;
#define	ov_magic	ovu.ovu_magic
#define	ov_index	ovu.ovu_index
#define	ov_size		ovu.ovu_size
};

#define	MAGIC		0xef		/* magic # on accounting info */

/*
 * nextf[i] is the pointer to the next free block of size 2^(i+3).  The
 * smallest allocatable block is 8 bytes.  The overhead information
 * precedes the data area returned to the user.
 */
#define	NBUCKETS 30
static	union overhead *nextf[NBUCKETS];

static	size_t pagesz;			/* page size */
static	int pagebucket;			/* page size bucket */


#define	NPOOLPAGES	(32*1024/_pagesz)

static caddr_t	pagepool_start, pagepool_end;
static size_t	n_pagepools, max_pagepools;
static char	**pagepool_list;
static size_t	_pagesz;

static int
__morepages(int n)
{
	int	fd = -1;
	char **new_pagepool_list;

	n += NPOOLPAGES;	/* round up allocation. */

	if (n_pagepools >= max_pagepools) {
		if (max_pagepools == 0)
			max_pagepools = _pagesz / (sizeof(char *) * 2);

		max_pagepools *= 2;
		if ((new_pagepool_list = mmap(0,
		    max_pagepools * sizeof(char *), PROT_READ|PROT_WRITE,
		    MAP_ANON, fd, 0)) == MAP_FAILED)
			return (0);
		memcpy(new_pagepool_list, pagepool_list,
		    sizeof(char *) * n_pagepools);
		if (pagepool_list != NULL) {
			if (munmap(pagepool_list,
			    max_pagepools * sizeof(char *) / 2) != 0) {
				abort();
			}
		}
		pagepool_list = new_pagepool_list;
	}

	if (pagepool_end - pagepool_start > (ssize_t)_pagesz) {
#ifndef __CHERI_PURE_CAPABILITY__
		caddr_t addr = (caddr_t)roundup2((vaddr_t)pagepool_start, _pagesz);
#else
		/*
		 * XXX: CHERI128: Need to avoid rounding down to an imprecise
		 * capability.
		 */
		caddr_t	addr = cheri_setoffset(pagepool_start,
		    roundup2(cheri_getoffset(pagepool_start), _pagesz));
#endif
		if (munmap(addr, pagepool_end - addr) != 0) {
			abort();
#ifdef __CHERI_PURE_CAPABILITY__
		} else {
			/* Shrink the pool */
			pagepool_list[n_pagepools - 1] =
			    cheri_csetbounds(pagepool_list[n_pagepools - 1],
			    cheri_getlen(pagepool_list[n_pagepools - 1]) -
			    (pagepool_end - addr));
#endif
		}
	}

	if ((pagepool_start = mmap(0, n * _pagesz,
			PROT_READ|PROT_WRITE,
			MAP_ANON|MAP_CHERI_DDC , fd, 0)) == (caddr_t)-1) {
		return 0;
	}
	pagepool_end = pagepool_start + n * _pagesz;
	pagepool_list[n_pagepools++] = pagepool_start;

	return n;
}

static void
__init_heap(size_t pagesz)
{

	_pagesz = pagesz;
}

static void *
__rederive_pointer(void *ptr)
{
#ifndef __CHERI_PURE_CAPABILITY__
	return (ptr);
#else
	size_t i;
	vm_offset_t addr;

	addr = cheri_getbase(ptr) + cheri_getoffset(ptr);
	TLS_MALLOC_LOCK;
	for (i = 0; i < n_pagepools; i++) {
		char *pool = pagepool_list[i];
		vm_offset_t base = cheri_getbase(pool);

		if (addr >= base && addr < base + cheri_getlen(pool))
			return(cheri_setoffset(pool, addr - base));
	}
	TLS_MALLOC_UNLOCK;

	return (NULL);
#endif
}

void *
tls_malloc(size_t nbytes)
{
	union overhead *op;
	int bucket;
	size_t amt;

	/*
	 * First time malloc is called, setup page size and
	 * align break pointer so all data will be page aligned.
	 */
	TLS_MALLOC_LOCK;
	if (pagesz == 0) {
		pagesz = PAGE_SIZE;
		init_pagebucket();
		__init_heap(pagesz);
	}
	TLS_MALLOC_UNLOCK;
	assert(pagesz != 0);
	/*
	 * Convert amount of memory requested into closest block size
	 * stored in hash buckets which satisfies request.
	 * Account for space used per block for accounting.
	 */
	if (nbytes <= pagesz - sizeof (*op)) {
		amt = 32;	/* size of first bucket */
		bucket = 2;
	} else {
		amt = pagesz;
		bucket = pagebucket;
	}
	while (nbytes > (size_t)amt - sizeof(*op)) {
		amt <<= 1;
		if (amt == 0)
			return (NULL);
		bucket++;
	}
	/*
	 * If nothing in hash bucket right now,
	 * request more memory from the system.
	 */
	TLS_MALLOC_LOCK;
	if ((op = nextf[bucket]) == NULL) {
		morecore(bucket);
		if ((op = nextf[bucket]) == NULL)
			return (NULL);
	}
	/* remove from linked list */
	nextf[bucket] = op->ov_next;
	TLS_MALLOC_UNLOCK;
	op->ov_magic = MAGIC;
	op->ov_index = bucket;
	return (cheri_csetbounds(op + 1, nbytes));
}

void *
tls_calloc(size_t num, size_t size)
{
	void *ret;

	if (size != 0 && (num * size) / size != num) {
		/* size_t overflow. */
		return (NULL);
	}

	if ((ret = tls_malloc(num * size)) != NULL)
		memset(ret, 0, num * size);

	return (ret);
}

/*
 * Allocate more memory to the indicated bucket.
 */
static void
morecore(int bucket)
{
	char *buf;
	union overhead *op;
	size_t sz;			/* size of desired block */
	int amt;			/* amount to allocate */
	int nblks;			/* how many blocks we get */

	/*
	 * sbrk_size <= 0 only for big, FLUFFY, requests (about
	 * 2^30 bytes on a VAX, I think) or for a negative arg.
	 */
	sz = 1 << (bucket + 3);
	assert(sz > 0);
	if (sz < pagesz) {
		amt = pagesz;
		nblks = amt / sz;
	} else {
		amt = sz + pagesz;
		nblks = 1;
	}
	if (amt > pagepool_end - pagepool_start)
		if (__morepages(amt/pagesz) == 0)
			return;

	buf = cheri_csetbounds(pagepool_start, amt);
	pagepool_start += amt;

	/*
	 * Add new memory allocated to that on
	 * free list for this hash bucket.
	 */
	nextf[bucket] = op = cheri_csetbounds(buf, sz);
	while (--nblks > 0) {
		op->ov_next = (union overhead *)cheri_csetbounds(buf + sz, sz);
		buf += sz;
		op = op->ov_next;
	}
}

static union overhead *
find_overhead(void * cp)
{
	union overhead *op;

#ifdef __CHERI_PURE_CAPABILITY__
	if (!cheri_gettag(cp))
		return (NULL);
#endif
	op = __rederive_pointer(cp);
	if (op == NULL)
		return (NULL);
	op--;

	if (op->ov_magic == MAGIC)
		return (op);

	/*
	 * XXX: the above will fail if the users calls free or realloc
	 * with a pointer that has had CSetBounds applied to it.  We
	 * should save all allocation ranges to allow us to find the
	 * metadata.
	 */
	abort();
	return (NULL);
}

void
tls_free(void *cp)
{
	int bucket;
	union overhead *op;

	if (cp == NULL)
		return;
	op = find_overhead(cp);
	if (op == NULL)
		return;
	TLS_MALLOC_LOCK;
	bucket = op->ov_index;
	assert(bucket < NBUCKETS);
	op->ov_next = nextf[bucket];	/* also clobbers ov_magic */
	nextf[bucket] = op;
	TLS_MALLOC_UNLOCK;
}

static void
init_pagebucket(void)
{
	int bucket;
	size_t amt;

	bucket = 0;
	amt = 8;
	while ((unsigned)pagesz > amt) {
		amt <<= 1;
		bucket++;
	}
	pagebucket = bucket;
}

void *
tls_malloc_aligned(size_t size, size_t align)
{
	vaddr_t memshift;
	void *mem, *res;
	if (align < sizeof(void *))
		align = sizeof(void *);

	mem = tls_malloc(size + sizeof(void *) + align - 1);
	memshift = roundup2((vaddr_t)mem + sizeof(void *), align) - (vaddr_t)mem;
	res = (void *)((uintptr_t)mem + memshift);
	*(void **)((uintptr_t)res - sizeof(void *)) = mem;
	return (res);
}

void *
tls_calloc_aligned(size_t number, size_t size, size_t align)
{
	void *buf;

	if (size != 0 && number > SIZE_MAX / size)
		return (NULL);
	buf = tls_malloc_aligned(number * size, align);
	memset(buf, 0, number * size);
	return (buf);
}

void
tls_free_aligned(void *ptr)
{
	void *mem;
	uintptr_t x;

	if (ptr == NULL)
		return;

	x = (uintptr_t)ptr;
	x -= sizeof(void *);
	mem = *(void **)x;
	tls_free(mem);
}
