/*	$OpenBSD: vmparam.h,v 1.2 1998/09/15 10:50:12 pefo Exp $	*/
/*	$NetBSD: vmparam.h,v 1.5 1994/10/26 21:10:10 cgd Exp $	*/

/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1988 University of Utah.
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department and Ralph Campbell.
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
 *	from: Utah Hdr: vmparam.h 1.16 91/01/18
 *	@(#)vmparam.h	8.2 (Berkeley) 4/22/94
 *	JNPR: vmparam.h,v 1.3.2.1 2007/09/10 06:01:28 girish
 * $FreeBSD$
 */

#ifndef _MACHINE_VMPARAM_H_
#define	_MACHINE_VMPARAM_H_

/*
 * Machine dependent constants mips processors.
 */

/*
 * Virtual memory related constants, all in bytes
 */
#ifndef MAXTSIZ
#define	MAXTSIZ		(128UL*1024*1024)	/* max text size */
#endif
#ifndef DFLDSIZ
#define	DFLDSIZ		(128UL*1024*1024)	/* initial data size limit */
#endif
#ifndef MAXDSIZ
#define	MAXDSIZ		(1*1024UL*1024*1024)	/* max data size */
#endif
#ifndef DFLSSIZ
#define	DFLSSIZ		(8UL*1024*1024)		/* initial stack size limit */
#endif
#ifndef MAXSSIZ
#define	MAXSSIZ		(64UL*1024*1024)	/* max stack size */
#endif
#ifndef SGROWSIZ
#define	SGROWSIZ	(128UL*1024)		/* amount to grow stack */
#endif

/*
 * Mach derived constants
 */

/* user/kernel map constants */
#define	VM_MIN_ADDRESS		((vm_offset_t)0x00000000)
#define	VM_MAX_ADDRESS		((vm_offset_t)(intptr_t)(int32_t)0xffffffff)

#define	VM_MINUSER_ADDRESS	((vm_offset_t)0x00000000)

#ifdef __mips_n64
#define	VM_MAXUSER_ADDRESS	(VM_MINUSER_ADDRESS + (NPDEPG * NBSEG))
#if __has_feature(capabilities)

/*
 * Lay out some bitmaps for us, ranging from VM_CHERI_REVOKE_BM_BASE
 * to VM_CHERI_REVOKE_BM_TOP:
 *
 * TOP:
 * 	- one bit per otype (BM_OTYPE)
 * 	- one bit per page, checked for VMMAP-bearing caps (BM_MEM_MAP)
 * 	- one bit per cap, checked for non-VMMAP-bearing caps (BM_MEM_NOMAP)
 * BASE:
 *
 * The granularities of these bitmaps are specified in the _GSZ_ constants.
 * For the present settings, a *byte* of these bitmaps spans....
 * 	- 8 otypes
 * 	- 8 pages (32KiB of memory)
 * 	- 128 bytes of memory (on CC and CHERI-128; 256 bytes on CHERI-256)
 * Requests to access the shadow space must, therefore, be at least that
 * aligned!
 *
 * XXX
 * For the moment, we use a relatively naive layout that lets us easily vary
 * the granularity of the different shadow spaces; when we're happy with
 * these, we should repack the shadow spaces.  It's quite likely, for
 * example, that BSZ_MEM_MAP and BSZ_OTYPE add up to less than the implicit
 * and unused shadow of the MEM_NOMAP bitmap within itself. (Because the bitmaps
 * cannot contain capabilities, their virtual addresses will never be used
 * as keys.)
 */

#define VM_CHERI_REVOKE_GSZ_OTYPE		((vm_offset_t)1)
#define VM_CHERI_REVOKE_GSZ_MEM_MAP	((vm_offset_t)PAGE_SIZE)
#define VM_CHERI_REVOKE_GSZ_MEM_NOMAP	\
    ((vm_offset_t)sizeof (void * __capability))

#define VM_CHERI_REVOKE_BSZ_MEM_NOMAP	(VM_MAXUSER_ADDRESS \
					 / VM_CHERI_REVOKE_GSZ_MEM_NOMAP / 8)
#define VM_CHERI_REVOKE_BSZ_MEM_MAP	(VM_MAXUSER_ADDRESS \
					 / VM_CHERI_REVOKE_GSZ_MEM_MAP / 8)
#define VM_CHERI_REVOKE_BSZ_OTYPE	((1 << CHERI_OTYPE_BITS) \
					 / VM_CHERI_REVOKE_GSZ_OTYPE / 8)
/* XXX TODO SetCID revocation? */

#define VM_CHERI_REVOKE_BM_TOP	VM_MAXUSER_ADDRESS

/*
 * Pad all the capability revocation material out to CHERI capability
 * representability so that we can construct a single capability at the start
 * of each revocation pass.
 */
#define VM_CHERI_REVOKE_PAD_SIZE	((VM_CHERI_REVOKE_BSZ_MEM_NOMAP \
				  + VM_CHERI_REVOKE_BSZ_MEM_MAP \
				  + VM_CHERI_REVOKE_BSZ_OTYPE \
				  + PAGE_SIZE + 0x7FFFFF) & ~0x7FFFFF)
#define VM_CHERI_REVOKE_BM_BASE	\
    (VM_CHERI_REVOKE_BM_TOP - VM_CHERI_REVOKE_PAD_SIZE)

#define VM_CHERI_REVOKE_BM_MEM_NOMAP	VM_CHERI_REVOKE_BM_BASE
#define VM_CHERI_REVOKE_BM_MEM_MAP	( VM_CHERI_REVOKE_BM_MEM_NOMAP  \
					+ VM_CHERI_REVOKE_BSZ_MEM_NOMAP )
#define VM_CHERI_REVOKE_BM_OTYPE	( VM_CHERI_REVOKE_BM_MEM_MAP  \
					+ VM_CHERI_REVOKE_BSZ_MEM_MAP )
#define VM_CHERI_REVOKE_INFO_PAGE	( VM_CHERI_REVOKE_BM_OTYPE  \
					+ VM_CHERI_REVOKE_BSZ_OTYPE )

#define	SHAREDPAGE		(VM_CHERI_REVOKE_BM_BASE - PAGE_SIZE)
#define	USRSTACK		(SHAREDPAGE & ~0xFFFF)

#else
/*
 * USRSTACK needs to start a little below 0x8000000 because the R8000
 * and some QED CPUs perform some virtual address checks before the
 * offset is calculated.
 */
#define	SHAREDPAGE		(VM_MAXUSER_ADDRESS - PAGE_SIZE)
#define	USRSTACK		(SHAREDPAGE & ~0xFFFF)
#endif

#define	VM_MIN_KERNEL_ADDRESS	((vm_offset_t)0xc000000000000000)
#define	VM_MAX_KERNEL_ADDRESS	(VM_MIN_KERNEL_ADDRESS + (NPDEPG * NBSEG))
#else
#define	VM_MAXUSER_ADDRESS	((vm_offset_t)0x80000000)
#define	VM_MIN_KERNEL_ADDRESS	((vm_offset_t)0xC0000000)
#define	VM_MAX_KERNEL_ADDRESS	((vm_offset_t)0xFFFFC000)
#define	SHAREDPAGE		(VM_MAXUSER_ADDRESS - PAGE_SIZE)
#define	USRSTACK		SHAREDPAGE
#endif

#define	KERNBASE		((vm_offset_t)(intptr_t)(int32_t)0x80000000)
#ifdef __mips_n64
#define	FREEBSD32_SHAREDPAGE	(((vm_offset_t)0x80000000) - PAGE_SIZE)
#define	FREEBSD32_USRSTACK	FREEBSD32_SHAREDPAGE
#endif


/*
 * Disable superpage reservations.
 */
#ifndef	VM_NRESERVLEVEL
#define	VM_NRESERVLEVEL		0
#endif

/*
 * The largest allocation size is 1MB.
 */
#define	VM_NFREEORDER		9


/*
 * How many physical pages per kmem arena virtual page.
 */
#ifndef VM_KMEM_SIZE_SCALE
#define	VM_KMEM_SIZE_SCALE	(3)
#endif

/*
 * Optional floor (in bytes) on the size of the kmem arena.
 */
#ifndef VM_KMEM_SIZE_MIN
#define	VM_KMEM_SIZE_MIN	(12 * 1024 * 1024)
#endif

/*
 * Optional ceiling (in bytes) on the size of the kmem arena: 40% of the
 * kernel map.
 */
#ifndef VM_KMEM_SIZE_MAX
#define	VM_KMEM_SIZE_MAX	((VM_MAX_KERNEL_ADDRESS - \
    VM_MIN_KERNEL_ADDRESS + 1) * 2 / 5)
#endif

/* initial pagein size of beginning of executable file */
#ifndef VM_INITIAL_PAGEIN
#define	VM_INITIAL_PAGEIN	16
#endif

#define	UMA_MD_SMALL_ALLOC

/*
 * max number of non-contig chunks of physical RAM you can have
 */
#define	VM_PHYSSEG_MAX		32

/*
 * The physical address space is sparsely populated.
 */
#define	VM_PHYSSEG_SPARSE

/*
 * Create two free page pools: VM_FREEPOOL_DEFAULT is the default pool
 * from which physical pages are allocated and VM_FREEPOOL_DIRECT is
 * the pool from which physical pages for small UMA objects are
 * allocated.
 */
#define	VM_NFREEPOOL		2
#define	VM_FREEPOOL_DEFAULT	0
#define	VM_FREEPOOL_DIRECT	1

/*
 * Create up to two free lists on !__mips_n64: VM_FREELIST_DEFAULT is for
 * physical pages that are above the largest physical address that is
 * accessible through the direct map (KSEG0) and VM_FREELIST_LOWMEM is for
 * physical pages that are below that address.  VM_LOWMEM_BOUNDARY is the
 * physical address for the end of the direct map (KSEG0).
 */
#ifdef __mips_n64
#define	VM_NFREELIST		1
#define	VM_FREELIST_DEFAULT	0
#define	VM_FREELIST_DIRECT	VM_FREELIST_DEFAULT
#else
#define	VM_NFREELIST		2
#define	VM_FREELIST_DEFAULT	0
#define	VM_FREELIST_LOWMEM	1
#define	VM_FREELIST_DIRECT	VM_FREELIST_LOWMEM
#define	VM_LOWMEM_BOUNDARY	((vm_paddr_t)0x20000000)
#endif

#define	ZERO_REGION_SIZE	(64 * 1024)	/* 64KB */

#ifndef __mips_n64
#define	SFBUF
#define	SFBUF_MAP
#define	PMAP_HAS_DMAP	0
#else
#define	PMAP_HAS_DMAP	1
#endif

#define	PHYS_TO_DMAP(x)	MIPS_PHYS_TO_DIRECT(x)
#define	DMAP_TO_PHYS(x)	MIPS_DIRECT_TO_PHYS(x)

/*
 * No non-transparent large page support in the pmap.
 */
#define	PMAP_HAS_LARGEPAGES	0

/*
 * Need a page dump array for minidump.
 */
#define MINIDUMP_PAGE_TRACKING	1

#endif /* !_MACHINE_VMPARAM_H_ */
// CHERI CHANGES START
// {
//   "updated": 20180629,
//   "target_type": "header",
//   "changes": [
//     "support"
//   ],
//   "change_comment": ""
// }
// CHERI CHANGES END
