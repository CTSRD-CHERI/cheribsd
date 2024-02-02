/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2013 EMC Corp.
 * Copyright (c) 2011 Jeffrey Roberson <jeff@freebsd.org>
 * Copyright (c) 2008 Mayur Shardul <mayur.shardul@gmail.com>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _VM_RADIX_H_
#define _VM_RADIX_H_

#include <vm/_vm_radix.h>

#ifdef _KERNEL
#include <sys/pctrie.h>
#include <vm/vm_page.h>
#include <vm/vm.h>

void		vm_radix_wait(void);
void		vm_radix_zinit(void);
void		*vm_radix_node_alloc(struct pctrie *ptree);
void		vm_radix_node_free(struct pctrie *ptree, void *node);
extern smr_t	vm_radix_smr;

static __inline void
vm_radix_init(struct vm_radix *rtree)
{
	pctrie_init(&rtree->rt_trie);
}

static __inline bool
vm_radix_is_empty(struct vm_radix *rtree)
{
	return (pctrie_is_empty(&rtree->rt_trie));
}

PCTRIE_DEFINE_SMR(VM_RADIX, vm_page, pindex, vm_radix_node_alloc, vm_radix_node_free,
    vm_radix_smr);

/*
 * Inserts the key-value pair into the trie.
 * Panics if the key already exists.
 */
static __inline int
vm_radix_insert(struct vm_radix *rtree, vm_page_t page)
{
	return (VM_RADIX_PCTRIE_INSERT(&rtree->rt_trie, page));
}

/*
 * Returns the value stored at the index assuming there is an external lock.
 *
 * If the index is not present, NULL is returned.
 */
static __inline vm_page_t
vm_radix_lookup(struct vm_radix *rtree, vm_pindex_t index)
{
	return (VM_RADIX_PCTRIE_LOOKUP(&rtree->rt_trie, index));
}

/*
 * Returns the value stored at the index without requiring an external lock.
 *
 * If the index is not present, NULL is returned.
 */
static __inline vm_page_t
vm_radix_lookup_unlocked(struct vm_radix *rtree, vm_pindex_t index)
{
	return (VM_RADIX_PCTRIE_LOOKUP_UNLOCKED(&rtree->rt_trie, index));
}

/*
 * Returns the page with the least pindex that is greater than or equal to the
 * specified pindex, or NULL if there are no such pages.
 *
 * Requires that access be externally synchronized by a lock.
 */
static __inline vm_page_t
vm_radix_lookup_ge(struct vm_radix *rtree, vm_pindex_t index)
{
	return (VM_RADIX_PCTRIE_LOOKUP_GE(&rtree->rt_trie, index));
}

/*
 * Returns the page with the greatest pindex that is less than or equal to the
 * specified pindex, or NULL if there are no such pages.
 *
 * Requires that access be externally synchronized by a lock.
 */
static __inline vm_page_t
vm_radix_lookup_le(struct vm_radix *rtree, vm_pindex_t index)
{
	return (VM_RADIX_PCTRIE_LOOKUP_LE(&rtree->rt_trie, index));
}

/*
 * Remove the specified index from the trie, and return the value stored at
 * that index.  If the index is not present, return NULL.
 */
static __inline vm_page_t
vm_radix_remove(struct vm_radix *rtree, vm_pindex_t index)
{
	return (VM_RADIX_PCTRIE_REMOVE_LOOKUP(&rtree->rt_trie, index));
}

/*
 * Remove and free all the nodes from the radix tree.
 */
static __inline void
vm_radix_reclaim_allnodes(struct vm_radix *rtree)
{
	VM_RADIX_PCTRIE_RECLAIM(&rtree->rt_trie);
}

/*
 * Replace an existing page in the trie with another one.
 * Panics if there is not an old page in the trie at the new page's index.
 */
static __inline vm_page_t
vm_radix_replace(struct vm_radix *rtree, vm_page_t newpage)
{
	return (VM_RADIX_PCTRIE_REPLACE(&rtree->rt_trie, newpage));
}

#endif /* _KERNEL */
#endif /* !_VM_RADIX_H_ */
