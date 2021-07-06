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
#ifdef CAPREVOKE
#include <cheri/revoke.h>
#include <sys/stdatomic.h>
#include <cheri/libcaprevoke.h>
#endif
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
#define	cheri_setbounds(ptr, size)	((void *)(ptr))
#define	cheri_andperm(ptr, size)	((void *)(ptr))
#define	CHERI_PERMS_USERSPACE_DATA	0
#define	CHERI_PERM_CHERIABI_VMMAP	0
#endif

static spinlock_t tls_malloc_lock = _SPINLOCK_INITIALIZER;
#define	TLS_MALLOC_LOCK		if (__isthreaded) _SPINLOCK(&tls_malloc_lock)
#define	TLS_MALLOC_UNLOCK	if (__isthreaded) _SPINUNLOCK(&tls_malloc_lock)
union overhead;
static void morecore(int);
static void *__tls_malloc_aligned(size_t size, size_t align);

/*
 * The overhead on a block is one pointer. When free, this space
 * contains a pointer to the next free block. When in use, the first
 * byte is set to MAGIC, and the second byte is the size index.
 */
union	overhead {
	struct {
	union	overhead *ov_next;	/* when free */
	};
	struct {
		u_char	ovu_magic;	/* magic number */
		u_char	ovu_index;	/* bucket # */
	} ovu;
#define	ov_magic	ovu.ovu_magic
#define	ov_index	ovu.ovu_index
};

struct pagepool_header {
	size_t			 ph_size;
#ifdef __CHERI_PURE_CAPABILITY__
	size_t			 ph_pad1;
	/* XXXBD: more padding on 256-bit... */
#endif
	struct pagepool_header	*ph_next;
#ifdef CAPREVOKE
	void			*ph_shadow;
	void			*ph_pad2; /* Align strongly */
#endif
};

#define	MALLOC_ALIGNMENT	sizeof(union overhead)

#define	MAGIC		0xef		/* magic # on accounting info */

/*
 * nextf[i] is the pointer to the next free block of size
 * (FIRST_BUCKET_SIZE << i).  The overhead information precedes the
 * data area returned to the user.
 */
#define	FIRST_BUCKET_SHIFT	5
#define	FIRST_BUCKET_SIZE	(1 << FIRST_BUCKET_SHIFT)
#define	NBUCKETS 30
static	union overhead *nextf[NBUCKETS];

#ifdef CAPREVOKE
/*
 * In the CAPREVOKE case, we encode the bucket in the next pointer's low
 * bit in the quarantine pool.  The static assert ensures that remains
 * possible.
 */
_Static_assert(NBUCKETS < FIRST_BUCKET_SIZE,
    "Not enough alignment to encode bucket in pointer bits");
#define	MAX_QUARANTINE	(1024 * 1024)
static union overhead *quarantine_bufs[NBUCKETS];
static size_t quarantine_size;
#endif

static const size_t pagesz = PAGE_SIZE;			/* page size */

#define	NPOOLPAGES	(32*1024/pagesz)

static caddr_t	pagepool_start, pagepool_end;
static struct pagepool_header	*curpp;

#ifdef CAPREVOKE
volatile const struct cheri_revoke_info *cri;

static void paint_shadow(void *mem, size_t size);
static void clear_shadow(void *mem, size_t size);
static void do_revoke();
#endif

static int
__morepages(int n)
{
	size_t	size;
	struct pagepool_header *newpp;

	n += NPOOLPAGES;	/* round up allocation. */
	size = n * pagesz;
#ifdef __CHERI_PURE_CAPABILITY__
	size = CHERI_REPRESENTABLE_LENGTH(size);
#endif

	if (pagepool_end - pagepool_start > (ssize_t)pagesz) {
		caddr_t extra_start = __builtin_align_up(pagepool_start,
		    pagesz);
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

	if ((newpp = mmap(0, size, PROT_READ|PROT_WRITE, MAP_ANON, -1,
	    0)) == MAP_FAILED)
		return (0);

	newpp->ph_next = curpp;
	newpp->ph_size = size;
	curpp = newpp;
	pagepool_start = (char *)(newpp + 1);
	pagepool_end = pagepool_start + (size - sizeof(*newpp));

	return (size / pagesz);
}

static void *
__rederive_pointer(void *ptr)
{
#ifndef __CHERI_PURE_CAPABILITY__
	return (ptr);
#else
	struct pagepool_header *pp;
	vm_offset_t addr;

	addr = cheri_getaddress(ptr);
	TLS_MALLOC_LOCK;
	/*
	 * It's OK if more pools are added, they can't contain our pointer
	 * and we never mutate the list except when adding to the front.
	 */
	pp = curpp;
	TLS_MALLOC_UNLOCK;
	while (pp != NULL) {
		char *pool = (char *)pp;
		if (cheri_is_address_inbounds(pool, addr))
			return (cheri_setaddress(pool, addr));
		pp = pp->ph_next;
	}

	return (NULL);
#endif
}

static void *
bound_ptr(void *mem, size_t nbytes)
{
	void *ptr;

	ptr = cheri_setbounds(mem, nbytes);
	ptr = cheri_andperm(ptr,
	    CHERI_PERMS_USERSPACE_DATA & ~CHERI_PERM_CHERIABI_VMMAP);
	return (ptr);
}

#ifdef CAPREVOKE
static void
try_revoke(int target_bucket)
{
	int bucket;
	union overhead *op, *next_op;

	/*
	 * Don't revoke unless there is enough in quarantine and some of
	 * it would be returned to the bucket we want to refill.
	 */
	 if (quarantine_bufs[target_bucket] == NULL ||
	     quarantine_size < MAX_QUARANTINE)
	     return;

	for (bucket = 0; bucket < NBUCKETS; bucket++) {
		for (op = quarantine_bufs[bucket]; op != NULL;
		    op = op->ov_next)
			paint_shadow(op, FIRST_BUCKET_SIZE << bucket);
	}
	atomic_thread_fence(memory_order_acq_rel);

	do_revoke();

	 for (bucket = 0; bucket < NBUCKETS; bucket++) {
		for (op = quarantine_bufs[bucket]; op != NULL;
		    op = op->ov_next)
			clear_shadow(op, FIRST_BUCKET_SIZE << bucket);
	}
	atomic_thread_fence(memory_order_acq_rel);

	for (bucket = 0; bucket < NBUCKETS; bucket++) {
		op = quarantine_bufs[bucket];
		while (op != NULL) {
			next_op = op->ov_next;
			op->ov_next = nextf[bucket];
			nextf[bucket] = op;
		}
	}
	quarantine_size = 0;
}
#endif

static void *
__tls_malloc(size_t nbytes)
{
	union overhead *op;
	int bucket;
	size_t amt;

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
#ifdef CAPREVOKE
	if ((op = nextf[bucket]) == NULL)
		try_revoke(bucket);
#endif
	if ((op = nextf[bucket]) == NULL) {
		morecore(bucket);
		if ((op = nextf[bucket]) == NULL) {
			TLS_MALLOC_UNLOCK;
			return (NULL);
		}
	}
	/* remove from linked list */
	nextf[bucket] = op->ov_next;
	TLS_MALLOC_UNLOCK;
	op->ov_magic = MAGIC;
	op->ov_index = bucket;
	return (op + 1);
}

void *
tls_malloc(size_t nbytes)
{
	void *mem;
#ifdef __CHERI_PURE_CAPABILITY__
	size_t align, mask;

	mask = CHERI_REPRESENTABLE_ALIGNMENT_MASK(nbytes);
	nbytes = CHERI_REPRESENTABLE_LENGTH(nbytes);
	align = 1 + ~mask;

	if (mask != SIZE_MAX && align > MALLOC_ALIGNMENT)
		mem = __tls_malloc_aligned(nbytes, align);
	else
#endif
		mem = __tls_malloc(nbytes);
	return (bound_ptr(mem, nbytes));
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

	buf = cheri_setbounds(pagepool_start, amt);
	pagepool_start += amt;

	/*
	 * Add new memory allocated to that on
	 * free list for this hash bucket.
	 */
	nextf[bucket] = op = (union overhead *)(void *)cheri_setbounds(buf, sz);
	while (--nblks > 0) {
		op->ov_next = (union overhead *)(void *)cheri_setbounds(buf + sz, sz);
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

#ifdef __CHERI_PURE_CAPABILITY__
	/*
	 * In pure-capability mode our allocation might have come from
	 * __tls_malloc_aligned.  In that case we need to get back to the
	 * real overhead pointer.  To make sure we aren't tricked, the
	 * pointer must:
	 *  - Be an internal allocator pointer (have the VMMAP permision).
	 *  - Point somewhere before us and within the current pagepool.
	 */
	if (cheri_gettag(op->ov_next) &&
	    (cheri_getperm(op->ov_next) & CHERI_PERM_CHERIABI_VMMAP) != 0) {
		vaddr_t base, pp_base;

		pp_base = cheri_getbase(op);
		base = cheri_getbase(op->ov_next);
		if (base >= pp_base && base < cheri_getaddress(op))
			op = op->ov_next;
	}
#endif
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

static void
nextf_insert(void *mem, size_t size, int xbucket)
{
	union overhead *op;
	int bucket;

	bucket = __builtin_ctzl(size) - __builtin_ctzl(FIRST_BUCKET_SIZE);
	if (bucket != xbucket) abort();
	op = mem;
	op->ov_next = nextf[bucket];
	nextf[bucket] = op;
}

#ifdef CAPREVOKE
static void
paint_shadow(void *mem, size_t size)
{
	struct pagepool_header *pp;
	int error;

	if (cri == NULL) {
		error = cheri_revoke_shadow(CHERI_REVOKE_SHADOW_INFO_STRUCT,
		    NULL, (void **)&cri);
		assert(error == 0);
	}

	pp = cheri_setoffset(pp, 0);
	/*
	 * Defer initializing ph_shadow since odds are good we'll never
	 * need it.
	 */
	if (pp->ph_shadow == NULL)
		if (cheri_revoke_shadow(CHERI_REVOKE_SHADOW_NOVMMAP, pp,
		    &pp->ph_shadow) != 0)
			abort();
	caprev_shadow_nomap_set_raw(cri->base_mem_nomap, pp->ph_shadow,
	    (vaddr_t)mem, size);
}

static void
clear_shadow(void *mem, size_t size)
{
	struct pagepool_header *pp;

	pp = cheri_setoffset(pp, 0);
	caprev_shadow_nomap_clear_raw(cri->base_mem_nomap, pp->ph_shadow,
	    (vaddr_t)mem, size);
}

static void
do_revoke(void)
{
	int error;

	atomic_thread_fence(memory_order_acq_rel);
	cheri_revoke_epoch start_epoch = cri->epochs.enqueue;
	while (!cheri_revoke_epoch_clears(cri->epochs.dequeue, start_epoch)) {
		error = cheri_revoke(
		    CHERI_REVOKE_LAST_PASS | CHERI_REVOKE_LOAD_SIDE,
		    start_epoch, NULL);
		assert(error == 0);
	}
}
#endif /* CAPREVOKE */

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
	if (bucket < NBUCKETS)
		abort();
#ifdef CAPREVOKE
	op->ov_next = quarantine_bufs[bucket];
	quarantine_bufs[bucket] = op;
	quarantine_size += FIRST_BUCKET_SIZE << bucket;
#else
	nextf_insert(op, FIRST_BUCKET_SIZE << bucket, bucket);
#endif
	TLS_MALLOC_UNLOCK;
}

static void *
__tls_malloc_aligned(size_t size, size_t align)
{
	vaddr_t memshift;
	void *mem, *res;
	if (align < sizeof(void *))
		align = sizeof(void *);

	mem = __tls_malloc(size + sizeof(void *) + align - 1);
	memshift = roundup2((vaddr_t)mem + sizeof(void *), align) - (vaddr_t)mem;
	res = (void *)((uintptr_t)mem + memshift);
	*(void **)((uintptr_t)res - sizeof(void *)) = mem;
	return (res);
}

void *
tls_malloc_aligned(size_t nbytes, size_t align)
{
#ifdef __CHERI_PURE_CAPABILITY__
	size_t mask;

	mask = CHERI_REPRESENTABLE_ALIGNMENT_MASK(nbytes);
	nbytes = CHERI_REPRESENTABLE_LENGTH(nbytes);
	if (align < 1 + ~mask)
		align = 1 + ~mask;
#endif
	return (bound_ptr(__tls_malloc_aligned(nbytes, align), nbytes));

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
#ifndef __CHERI_PURE_CAPABILITY__
	uintptr_t x;

	if (ptr == NULL)
		return;
	x = (uintptr_t)ptr;
	x -= sizeof(void *);
	mem = *(void **)x;
#else
	mem = ptr;
#endif
	tls_free(mem);
}
