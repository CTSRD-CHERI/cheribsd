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
};

#define	MAGIC		0xef		/* magic # on accounting info */

/*
 * nextf[i] is the pointer to the next free block of size
 * (FIRST_BUCKET_SIZE << i).  The overhead information precedes the
 * data area returned to the user.
 */
#define	FIRST_BUCKET_SIZE	32
#define	NBUCKETS 30
static	union overhead *nextf[NBUCKETS];

static	size_t pagesz;			/* page size */


#define	NPOOLPAGES	(32*1024/_pagesz)

static caddr_t	pagepool_start, pagepool_end;
static size_t	n_pagepools, max_pagepools;
static char	**pagepool_list;
static size_t	_pagesz;

static int
__morepages(int n)
{
	size_t	size;
	char **new_pagepool_list;

	n += NPOOLPAGES;	/* round up allocation. */
	size = n * _pagesz;
#ifdef __CHERI_PURE_CAPABILITY__
	size = __builtin_cheri_round_representable_length(size);
#endif

	if (n_pagepools >= max_pagepools) {
		if (max_pagepools == 0)
			max_pagepools = _pagesz / (sizeof(char *) * 2);

		max_pagepools *= 2;
		if ((new_pagepool_list = mmap(0,
		    max_pagepools * sizeof(char *), PROT_READ|PROT_WRITE,
		    MAP_ANON, -1, 0)) == MAP_FAILED)
			return (0);
#ifdef __CHERI_PURE_CAPABILITY__
		/* Check that the result is writable */
		assert(cheri_getperm(new_pagepool_list) & CHERI_PERM_STORE);
#endif
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
		caddr_t extra_start = __builtin_align_up(pagepool_start,
		    _pagesz);
		size_t extra_bytes = pagepool_end - extra_start;
#ifndef __CHERI_PURE_CAPABILITY__
		if (munmap(extra_start, extra_bytes) != 0)
			abort();
#else
		/*
		 * In many cases we could safely unmap part of the end
		 * (since there's only one pointer to the allocation in
		 * pagepool_list to be updated), but we need to be careful
		 * to avoid making the result unrepresentable.  For now,
		 * just leak the virtual addresses and MAP_GUARD the
		 * unused pages.
		 */
		if (mmap(extra_start, extra_bytes, PROT_NONE,
		    MAP_FIXED | MAP_GUARD | MAP_CHERI_NOSETBOUNDS, -1, 0)
		    == MAP_FAILED)
			abort();
#endif
	}

	if ((pagepool_start = mmap(0, size, PROT_READ|PROT_WRITE,
	    MAP_ANON, -1, 0)) == MAP_FAILED)
		return (0);

	pagepool_end = pagepool_start + size;
	pagepool_list[n_pagepools++] = pagepool_start;

	return (size / pagesz);
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

	addr = cheri_getaddress(ptr);
	TLS_MALLOC_LOCK;
	for (i = 0; i < n_pagepools; i++) {
		char *pool = pagepool_list[i];
		if (cheri_is_address_inbounds(pool, addr))
			return (cheri_setaddress(pool, addr));
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
		__init_heap(pagesz);
	}
	TLS_MALLOC_UNLOCK;
	assert(pagesz != 0);
	/*
	 * Convert amount of memory requested into closest block size
	 * stored in hash buckets which satisfies request.
	 * Account for space used per block for accounting.
	 */
	amt = FIRST_BUCKET_SIZE;
	bucket = 0;
	while (nbytes > (size_t)amt - sizeof(*op)) {
		amt <<= 1;
		if (amt == 0)
			return (NULL);
		bucket++;
	}
	if (bucket >= NBUCKETS)
		return (NULL);
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

	sz = FIRST_BUCKET_SIZE << bucket;
	assert(sz > 0);
	if (sz < pagesz) {
		amt = pagesz;
		nblks = amt / sz;
	} else {
		amt = sz; /* XXX: round up */
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
