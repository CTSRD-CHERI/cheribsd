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
#include <sys/types.h>
#include <sys/mman.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#ifdef CAPREVOKE
#include <sys/stdatomic.h>
#include <cheri/revoke.h>
#include <cheri/libcaprevoke.h>
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "malloc_heap.h"

#ifdef IN_RTLD
#include "simple_printf.h"
#define	error_printf(...)	rtld_fdprintf(STDERR_FILENO, __VA_ARGS__)
#elif defined(IN_LIBTHR)
#include "thr_private.h"
#define	error_printf(...)	_thread_fdprintf(STDERR_FILENO, __VA_ARGS__)
#else
#include <stdio.h>
#define	error_printf(...)	fprintf(stderr, __VA_ARGS__)
#endif

struct pagepool_header {
	size_t			ph_size;
#ifdef __CHERI_PURE_CAPABILITY__
	size_t			ph_pad1;
#endif
	struct pagepool_header	*ph_next;
#ifdef CAPREVOKE
	void			*ph_shadow;
#else
	void			*ph_pad2;
#endif
};

#define	NPOOLPAGES	(32*1024/_pagesz)

caddr_t		pagepool_start, pagepool_end;
static struct pagepool_header	*curpp;

static size_t _pagesz;

#ifdef CAPREVOKE
static volatile const struct cheri_revoke_info *cri;
#endif

int
__morepages(int n)
{
	size_t	size;
	struct pagepool_header *newpp;

	n += NPOOLPAGES;	/* round up allocation. */
	size = n * _pagesz;
#ifdef __CHERI_PURE_CAPABILITY__
	size = CHERI_REPRESENTABLE_LENGTH(size);
#endif

	if (pagepool_end - pagepool_start > (ssize_t)_pagesz) {
		caddr_t extra_start = __builtin_align_up(pagepool_start,
		    _pagesz);
		size_t extra_bytes = pagepool_end - extra_start;
#ifndef __CHERI_PURE_CAPABILITY__
		if (munmap(extra_start, extra_bytes) != 0)
			error_printf("%s: munmap %p failed\n", __func__, addr);
#else
		/*
		 * XXX: CHERI128: Need to avoid rounding down to an imprecise
		 * capability.
		 * In many cases we could safely unmap part of the end
		 * (since there's only one pointer to the allocation in
		 * pagepool_list to be updated), but we need to be careful
		 * to avoid making the result unrepresentable.  For now,
		 * just leak the virtual addresses and MAP_GUARD the
		 * unused pages.
		 */
		if (mmap(extra_start, extra_bytes, PROT_NONE,
		    MAP_FIXED | MAP_GUARD | MAP_CHERI_NOSETBOUNDS, -1, 0) ==
		    MAP_FAILED)
			error_printf("%s: mmap MAP_GUARD %p failed\n",
			    __func__, extra_start);
#endif
	}

	if ((newpp = mmap(0, size, PROT_READ|PROT_WRITE, MAP_ANON, -1,
	    0)) == MAP_FAILED) {
		error_printf("%s: mmap of pagepool failed\n", __func__);
		return (0);
	}
	newpp->ph_next = curpp;
	newpp->ph_size = size;
	curpp = newpp;
	pagepool_start = (char *)(newpp + 1);
	pagepool_end = pagepool_start + (size - sizeof(*newpp));

	return (size / _pagesz);
}

void
__init_heap(size_t pagesz)
{

	_pagesz = pagesz;
}

void *
__rederive_pointer(void *ptr)
{
	struct pagepool_header *pp;
	vm_offset_t addr;

	addr = cheri_getaddress(ptr);
	pp = curpp;
	while (pp != NULL) {
		char *pool = (char *)pp;
		if (cheri_is_address_inbounds(pool, addr))
			return (cheri_setaddress(pool, addr));
		pp = pp->ph_next;
	}

	return (NULL);
}


#ifdef CAPREVOKE
void
__paint_shadow(void *mem, size_t size)
{
	struct pagepool_header *pp;

	pp = cheri_setoffset(mem, 0);
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

void
__clear_shadow(void *mem, size_t size)
{
	struct pagepool_header *pp;

	pp = cheri_setoffset(mem, 0);
	caprev_shadow_nomap_clear_raw(cri->base_mem_nomap,
	    pp->ph_shadow, (vaddr_t)mem, size);
}

void
__do_revoke(void)
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
