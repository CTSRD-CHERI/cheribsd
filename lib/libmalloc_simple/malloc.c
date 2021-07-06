/*-
 * Copyright (c) 1983 Regents of the University of California.
 * Copyright (c) 2015 SRI International
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
#ifdef CAPREVOKE
#include <cheri/revoke.h>
#include <sys/stdatomic.h>
#endif
#include <sys/types.h>

#ifdef CAPREVOKE
#include <cheri/libcaprevoke.h>
#endif
#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "malloc_heap.h"

#ifdef IN_RTLD
#include "simple_printf.h"

#undef assert
#define	assert	ASSERT
#define	error_printf(...)	rtld_fdprintf(STDERR_FILENO, __VA_ARGS__)
#elif defined(IN_LIBTHR)
#include "thr_private.h"
#define	error_printf(...)	_thread_fdprintf(STDERR_FILENO, __VA_ARGS__)
#else
#include <stdio.h>
#define	error_printf(...)	fprintf(stderr, __VA_ARGS__)
#endif

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
#define	MAX_PAINTED	(4 * MAX_QUARANTINE)
static	union overhead *quarantine_bufs[NBUCKETS];
static	union overhead *painted_bufs[NBUCKETS];
static	size_t quarantine_size, painted_size;
static	volatile const struct cheri_revoke_info *cri;
static	cheri_revoke_epoch painted_epoch;
#endif

static	size_t pagesz;			/* page size */


#if defined(MALLOC_DEBUG) || defined(RCHECK) || defined(IN_RTLD) || defined(IN_LIBTHR)
#define	ASSERT(p)   if (!(p)) botch(#p)
static void
botch(const char *s)
{
	error_printf("\r\nassertion botched: %s\r\n", s);
#if !defined(IN_RTLD) && !defined(IN_LIBTHR)
	(void) fflush(stderr);		/* just in case user buffered it */
#endif
	abort();
}
#else
#define	ASSERT(p)
#endif

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
free_painted(void)
{
	int bucket;
	union overhead *op, *next_op;;

	for (bucket = 0; bucket < NBUCKETS; bucket++)
		for (op = painted_bufs[bucket]; op != NULL; op = op->ov_next)
			__clear_shadow(op, FIRST_BUCKET_SIZE << bucket);

	/* XXX: how do we know that no thread is revoking? */
	atomic_thread_fence(memory_order_acq_rel);

	for (bucket = 0; bucket < NBUCKETS; bucket++) {
		op = painted_bufs[bucket];
		while (op != NULL) {
			next_op = op->ov_next;
			op->ov_next = nextf[bucket];
			nextf[bucket] = op;
			op = next_op;
		}
	}
	painted_size = 0;
}

static void
try_revoke(int target_bucket)
{
	int bucket, error;
	union overhead *op, *next_op;

	/* See if prior painting has resulted in revoked pointers. */
	/*
	 * NB: despite the NULL check below, cri is always non-NULL if
	 * used here.  We defer initilization as long as possible to
	 * avoid the extra syscall in the common case.
	 */
	if (painted_size > 0 &&
	    cheri_revoke_epoch_clears(cri->epochs.dequeue, painted_epoch))
		free_painted();

	if (quarantine_size < MAX_QUARANTINE && painted_size < MAX_PAINTED)
		return;

	if (cri == NULL) {
		error = cheri_revoke_shadow(CHERI_REVOKE_SHADOW_INFO_STRUCT,
		    NULL, __DECONST(void **, &cri));
		assert(error == 0);
	}

	/* Paint all buffers in quarantine */
	for (bucket = 0; bucket < NBUCKETS; bucket++) {
		op = quarantine_bufs[bucket];
		while (op != NULL) {
			next_op = op->ov_next;
			__paint_shadow(op, FIRST_BUCKET_SIZE << bucket);
			op->ov_next = painted_bufs[bucket];
			painted_bufs[bucket] = op;
			op = next_op;
		}
	}
	painted_size += quarantine_size;
	quarantine_size = 0;
	atomic_thread_fence(memory_order_acq_rel);
	painted_epoch = cri->epochs.enqueue;

	/*
	 * Don't force revocation unless we've exceeded MAX_PAINTED and
	 * it would return memory we actually want.  Otherwise, just
	 * hope the base malloc does the job for us.
	 */
	if (painted_size < MAX_PAINTED || painted_bufs[target_bucket] == NULL)
		return;

	while (!cheri_revoke_epoch_clears(cri->epochs.dequeue, painted_epoch)) {
		error = cheri_revoke(
		    CHERI_REVOKE_LAST_PASS | CHERI_REVOKE_LOAD_SIDE,
		    painted_epoch, NULL);
		assert(error == 0);
	}

	free_painted();

}
#endif

static void *
__simple_malloc_unaligned(size_t nbytes)
{
	union overhead *op;
	int bucket;
	size_t amt;

	/*
	 * First time malloc is called, setup page size and
	 * align break pointer so all data will be page aligned.
	 */
	if (pagesz == 0) {
		pagesz = PAGE_SIZE;
		__init_heap(pagesz);
	}
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
#ifdef CAPREVOKE
	if ((op = nextf[bucket]) == NULL)
		try_revoke(bucket);
#endif
	if ((op = nextf[bucket]) == NULL) {
		morecore(bucket);
		if ((op = nextf[bucket]) == NULL)
			return (NULL);
	}
	/* remove from linked list */
	nextf[bucket] = op->ov_next;
	op->ov_magic = MAGIC;
	op->ov_index = bucket;
	return (op + 1);
}

static void *
__simple_malloc_aligned(size_t nbytes, size_t align)
{
	vaddr_t memshift;
	void *mem, *res;
	if (align < sizeof(void *))
		align = sizeof(void *);

	mem = __simple_malloc_unaligned(nbytes + sizeof(void *) + align - 1);
	memshift = roundup2((vaddr_t)mem + sizeof(void *), align) -
	    (vaddr_t)mem;

	res = (void *)((uintptr_t)mem + memshift);
	*(void **)((uintptr_t)res - sizeof(void *)) = mem;
	return (res);
}

static void *
__simple_malloc(size_t nbytes)
{
	void *mem;

#ifdef __CHERI_PURE_CAPABILITY__
	size_t align, mask;

	mask = CHERI_REPRESENTABLE_ALIGNMENT_MASK(nbytes);
	nbytes = CHERI_REPRESENTABLE_LENGTH(nbytes);
	align = 1 + ~mask;

	if (mask != SIZE_MAX && align > MALLOC_ALIGNMENT)
		mem = __simple_malloc_aligned(nbytes, align);
	else
#endif
	mem = __simple_malloc_unaligned(nbytes);

	return (bound_ptr(mem, nbytes));
}

static void *
__simple_calloc(size_t num, size_t size)
{
	void *ret;

	if (size != 0 && (num * size) / size != num) {
		/* size_t overflow. */
		return (NULL);
	}

	if ((ret = __simple_malloc(num * size)) != NULL)
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
#ifdef MALLOC_DEBUG
	ASSERT(sz > 0);
#else
	if (sz <= 0)
		return;
#endif
	if (sz < pagesz) {
		amt = pagesz;
		nblks = amt / sz;
	} else {
		amt = sz;
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

	if (!cheri_gettag(cp))
		return (NULL);
	op = __rederive_pointer(cp);
	if (op == NULL) {
		error_printf("%s: no region found for %#p\n", __func__, cp);
		return (NULL);
	}
	op--;

#ifdef __CHERI_PURE_CAPABILITY__
	/*
	 * In pure-capability mode our allocation might have come from
	 * __simple_malloc_aligned.  In that case we need to get back to the
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
		if (base >= pp_base && base < cheri_getaddress(op)) {
			op = op->ov_next;
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
	error_printf("%s: Attempting to free or realloc unallocated memory\n",
	    __func__);
	error_printf("%s: cp %#lp\n", __func__, cp);
	return (NULL);
}

static void
__simple_free(void *cp)
{
	int bucket;
	union overhead *op;

	if (cp == NULL)
		return;
	op = find_overhead(cp);
	if (op == NULL)
		return;
	bucket = op->ov_index;
	ASSERT(bucket < NBUCKETS);
#ifdef CAPREVOKE
	op->ov_next = quarantine_bufs[bucket];
	quarantine_bufs[bucket] = op;
	quarantine_size += FIRST_BUCKET_SIZE << bucket;
#else
	op->ov_next = nextf[bucket];	/* also clobbers ov_magic */
	nextf[bucket] = op;
#endif
}

static void *
__simple_realloc(void *cp, size_t nbytes)
{
	size_t cur_space;	/* Space in the current bucket */
	size_t smaller_space;	/* Space in the next smaller bucket */
	union overhead *op;
	char *res;

#ifdef __CHERI_PURE_CAPABILITY__
	/* Round up here because we might need to set bounds... */
	nbytes = CHERI_REPRESENTABLE_LENGTH(nbytes);
#endif

	if (cp == NULL)
		return (__simple_malloc(nbytes));
	op = find_overhead(cp);
	if (op == NULL)
		return (NULL);
	cur_space = (FIRST_BUCKET_SIZE << op->ov_index) - sizeof(*op);

	/*
	 * XXX-BD: Arguably we should be tracking the actual allocation
	 * not just the bucket size so that we can do a full malloc+memcpy
	 * when the caller has restricted the length of the pointer passed
	 * realloc() but is growing the buffer within the current bucket.
	 *
	 * As it is, this code contains a leak where realloc recovers access
	 * to the contents in foo:
	 * char *foo = malloc(10);
	 * strcpy(foo, "abcdefghi");
	 * cheri_csetbouds(foo, 5);
	 * foo = realloc(foo, 10);
	 */
	if (op->ov_index != 0) {
		smaller_space = (FIRST_BUCKET_SIZE << (op->ov_index - 1)) -
		    sizeof(*op);
		if (nbytes <= cur_space && nbytes > smaller_space)
			return (bound_ptr(op + 1, nbytes));
	}

	res = __simple_malloc(nbytes);
	if (res == NULL)
		return (NULL);
	/*
	 * Only copy data the caller had access to even if this is less
	 * than the size of the original allocation.  This risks surprise
	 * for some programmers, but to do otherwise risks information leaks.
	 */
	memcpy(res, cp, (nbytes <= cheri_bytes_remaining(cp)) ?
	    nbytes : cheri_bytes_remaining(cp));
	res = cheri_andperm(res, cheri_getperm(cp));
	__simple_free(cp);
	return (res);
}

#if defined(IN_RTLD) || defined(IN_LIBTHR)
void * __crt_malloc(size_t nbytes);
void * __crt_calloc(size_t num, size_t size);
void * __crt_realloc(void *cp, size_t nbytes);
void __crt_free(void *cp);

void *
__crt_malloc(size_t nbytes)
{

	return (__simple_malloc(nbytes));
}

void *
__crt_calloc(size_t num, size_t size)
{

	return (__simple_calloc(num, size));
}

void *
__crt_realloc(void *cp, size_t nbytes)
{

	return (__simple_realloc(cp, nbytes));
}

void
__crt_free(void *cp)
{

	__simple_free(cp);
}
#else
void *
malloc(size_t nbytes)
{

	return (__simple_malloc(nbytes));
}

void *
calloc(size_t num, size_t size)
{

	return (__simple_calloc(num, size));
}

void *
realloc(void *cp, size_t nbytes)
{

	return (__simple_realloc(cp, nbytes));
}

void
free(void *cp)
{

	__simple_free(cp);
}
#endif
