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
#include <sys/queue.h>

#ifdef __CHERI_PURE_CAPABILITY__
#include <cheri/cheric.h>
#endif
#ifdef CAPREVOKE
#include <cheri/revoke.h>
#include <sys/stdatomic.h>
#include <cheri/libcaprevoke.h>
#endif

#include <assert.h>
#include <errno.h>
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
#define	CHERI_PERM_SW_VMEM		0
#endif

static spinlock_t tls_malloc_lock = _SPINLOCK_INITIALIZER;
#define	TLS_MALLOC_LOCK		if (__isthreaded) _SPINLOCK(&tls_malloc_lock)
#define	TLS_MALLOC_UNLOCK	if (__isthreaded) _SPINUNLOCK(&tls_malloc_lock)
static void morecore(int);
static void *__tls_malloc_aligned(size_t size, size_t align);

/*
 * The overhead on a block is one pointer. When free, this space
 * contains a pointer to the next free block. When in use, the first
 * byte is set to MAGIC, and the second byte is the size index.
 */
struct overhead {
	union {
		SLIST_ENTRY(overhead) ov_next;	/* when free */
		struct overhead *ov_real_allocation;	/* when realigned */
		struct {
			u_char	ovu_magic;	/* magic number */
			u_char	ovu_index;	/* bucket # */
		} ovu;
	};
#define	ov_magic	ovu.ovu_magic
#define	ov_index	ovu.ovu_index
};
SLIST_HEAD(ov_listhead, overhead);

struct pagepool_header {
	size_t			 ph_size;
#ifdef __CHERI_PURE_CAPABILITY__
	size_t			 ph_pad1;
#endif
	SLIST_ENTRY(pagepool_header) ph_next;
#ifdef CAPREVOKE
	void			*ph_shadow;
	void			*ph_pad2; /* align to 4 * sizeof(void *) */
#endif
};

#define	MALLOC_ALIGNMENT	sizeof(struct overhead)

#define	MAGIC		0xef		/* magic # on accounting info */

/*
 * nextf[i] is the head of the list of the next free block of size
 * (FIRST_BUCKET_SIZE << i).  The overhead information precedes the
 * data area returned to the user.
 */
#define	FIRST_BUCKET_SHIFT	5
#define	FIRST_BUCKET_SIZE	(1 << FIRST_BUCKET_SHIFT)
#define	NBUCKETS 30
static struct ov_listhead nextf[NBUCKETS];

#ifdef CAPREVOKE
#define	MAX_QUARANTINE	(1024 * 1024)
static struct ov_listhead quarantine_bufs[NBUCKETS];
static size_t quarantine_size;
#endif

static const size_t pagesz = PAGE_SIZE;			/* page size */

#define	NPOOLPAGES	(32*1024/pagesz)

static caddr_t	pagepool_start, pagepool_end;
static SLIST_HEAD(, pagepool_header) curpp = SLIST_HEAD_INITIALIZER(curpp);

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

	newpp->ph_size = size;
	SLIST_INSERT_HEAD(&curpp, newpp, ph_next);
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

	TLS_MALLOC_LOCK;
	SLIST_FOREACH(pp, &curpp, ph_next) {
		if (cheri_is_address_inbounds(pp, cheri_getbase(ptr))) {
			TLS_MALLOC_UNLOCK;
			return (cheri_setaddress(pp, cheri_getaddress(ptr)));
		}
	}
	TLS_MALLOC_UNLOCK;
	return (NULL);
#endif
}

static void *
bound_ptr(void *mem, size_t nbytes)
{
	void *ptr;

	ptr = cheri_setbounds(mem, nbytes);
	ptr = cheri_andperm(ptr,
	    CHERI_PERMS_USERSPACE_DATA & ~CHERI_PERM_SW_VMEM);
	return (ptr);
}

#ifdef CAPREVOKE
static void
try_revoke(int target_bucket)
{
	int bucket;
	struct overhead *op;

	/*
	 * Don't revoke unless there is enough in quarantine and some of
	 * it would be returned to the bucket we want to refill.
	 */
	if (quarantine_size < MAX_QUARANTINE ||
	    SLIST_EMPTY(&quarantine_bufs[target_bucket]))
		return;

	if (cri == NULL) {
		int error;

		error = cheri_revoke_get_shadow(CHERI_REVOKE_SHADOW_INFO_STRUCT,
		    NULL, (void **)&cri);

		if (error == ENOSYS) {
			/*
			 * Revocation is not supported; this is the baseline.
			 * Just pretend like it worked.
			 */
			goto dequarantine;
		}

		assert(error == 0);
	}


	for (bucket = 0; bucket < NBUCKETS; bucket++) {
		SLIST_FOREACH(op, &quarantine_bufs[bucket], ov_next)
			paint_shadow(op, FIRST_BUCKET_SIZE << bucket);
	}
	atomic_thread_fence(memory_order_acq_rel);

	do_revoke();

	for (bucket = 0; bucket < NBUCKETS; bucket++) {
		SLIST_FOREACH(op, &quarantine_bufs[bucket], ov_next)
			clear_shadow(op, FIRST_BUCKET_SIZE << bucket);
	}
	atomic_thread_fence(memory_order_acq_rel);

dequarantine:
	for (bucket = 0; bucket < NBUCKETS; bucket++) {
		while (!SLIST_EMPTY(&quarantine_bufs[bucket]))
			SLIST_REMOVE_HEAD(&quarantine_bufs[bucket], ov_next);
	}
	quarantine_size = 0;
}
#endif

static void *
__tls_malloc(size_t nbytes)
{
	struct overhead *op;
	struct ov_listhead *bucketp;
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
	bucketp = &nextf[bucket];
	/*
	 * If nothing in hash bucket right now,
	 * request more memory from the system.
	 */
	TLS_MALLOC_LOCK;
#ifdef CAPREVOKE
	if (SLIST_EMPTY(bucketp))
		try_revoke(bucket);
#endif
	if (SLIST_EMPTY(bucketp)) {
		morecore(bucket);
		if (SLIST_EMPTY(bucketp)) {
			TLS_MALLOC_UNLOCK;
			return (NULL);
		}
	}
	/* remove from linked list */
	op = SLIST_FIRST(bucketp);
	SLIST_REMOVE_HEAD(bucketp, ov_next);
	TLS_MALLOC_UNLOCK;
	/*
	 * XXXQEMU: Clear the overhead struct to remove any capability
	 * permissions in ov_real_allocation.
	 *
	 * Based on a tag and permissions of ov_real_allocation, find_overhead()
	 * determines if an allocation is aligned. The QEMU user mode for
	 * CheriABI doesn't implement tagged memory and find_overhead() might
	 * incorrectly assume the allocation is aligned because of a
	 * non-cleared tag. Having the permissions cleared, find_overhead()
	 * behaves as expected under the user mode.
	 *
	 * This is a workaround and should be reverted once the user mode
	 * implements tagged memory.
	 */
	memset(op, 0, sizeof(*op));
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
	struct overhead *op;
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
	for (; nblks > 0; nblks--) {
		op = (struct overhead *)(void *)cheri_setbounds(buf, sz);
		SLIST_INSERT_HEAD(&nextf[bucket], op, ov_next);
		buf += sz;
	}
}

static struct overhead *
find_overhead(void * cp)
{
	struct overhead *op;

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
	if (cheri_gettag(op->ov_real_allocation) &&
	    (cheri_getperm(op->ov_real_allocation) & CHERI_PERM_SW_VMEM) != 0) {
		ptraddr_t base, pp_base;

		pp_base = cheri_getbase(op);
		base = cheri_getbase(op->ov_real_allocation);
		if (base >= pp_base && base < cheri_getaddress(op)) {
			op = op->ov_real_allocation;
			op--;
		}
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

#ifdef CAPREVOKE
static void
paint_shadow(void *mem, size_t size)
{
	struct pagepool_header *pp;

	pp = cheri_setoffset(pp, 0);
	/*
	 * Defer initializing ph_shadow since odds are good we'll never
	 * need it.
	 */
	if (pp->ph_shadow == NULL)
		if (cheri_revoke_get_shadow(CHERI_REVOKE_SHADOW_NOVMMAP, pp,
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
	cheri_revoke_epoch_t start_epoch = cri->epochs.enqueue;
	while (!cheri_revoke_epoch_clears(cri->epochs.dequeue, start_epoch)) {
		error = cheri_revoke(CHERI_REVOKE_LAST_PASS, start_epoch, NULL);
		assert(error == 0);
	}
}
#endif /* CAPREVOKE */

void
tls_free(void *cp)
{
	int bucket;
	struct overhead *op;

	if (cp == NULL)
		return;
	op = find_overhead(cp);
	if (op == NULL)
		return;
	TLS_MALLOC_LOCK;
	bucket = op->ov_index;
	assert(bucket < NBUCKETS);
#ifdef CAPREVOKE
	SLIST_INSERT_HEAD(&quarantine_bufs[bucket], op, ov_next);
	quarantine_size += FIRST_BUCKET_SIZE << bucket;
#else
	SLIST_INSERT_HEAD(&nextf[bucket], op, ov_next);
#endif
	TLS_MALLOC_UNLOCK;
}

static void *
__tls_malloc_aligned(size_t size, size_t align)
{
	ptraddr_t memshift;
	void *mem;
	struct overhead *op;
	if (align < sizeof(void *))
		align = sizeof(void *);

	mem = __tls_malloc(size + sizeof(*op) + align - 1);
	memshift = roundup2((ptraddr_t)mem + sizeof(*op), align) -
	    (ptraddr_t)mem;
	op = (struct overhead *)((uintptr_t)mem + memshift);
	(op - 1)->ov_real_allocation = mem;
	return ((void *)op);
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
