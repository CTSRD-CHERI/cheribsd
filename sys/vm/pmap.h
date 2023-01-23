/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * The Mach Operating System project at Carnegie-Mellon University.
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
 *	from: @(#)pmap.h	8.1 (Berkeley) 6/11/93
 *
 *
 * Copyright (c) 1987, 1990 Carnegie-Mellon University.
 * All rights reserved.
 *
 * Author: Avadis Tevanian, Jr.
 *
 * Permission to use, copy, modify and distribute this software and
 * its documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND
 * FOR ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie the
 * rights to redistribute these changes.
 *
 * $FreeBSD$
 */

/*
 *	Machine address mapping definitions -- machine-independent
 *	section.  [For machine-dependent section, see "machine/pmap.h".]
 */

#ifndef	_PMAP_VM_
#define	_PMAP_VM_
/*
 * Each machine dependent implementation is expected to
 * keep certain statistics.  They may do this anyway they
 * so choose, but are expected to return the statistics
 * in the following structure.
 */
struct pmap_statistics {
	long resident_count;	/* # of pages mapped (total) */
	long wired_count;	/* # of pages wired */
};
typedef struct pmap_statistics *pmap_statistics_t;

/*
 * Each machine-dependent implementation is required to provide:
 *
 * vm_memattr_t	pmap_page_get_memattr(vm_page_t);
 * boolean_t	pmap_page_is_mapped(vm_page_t);
 * boolean_t	pmap_page_is_write_mapped(vm_page_t);
 * void		pmap_page_set_memattr(vm_page_t, vm_memattr_t);
 */
#include <machine/pmap.h>

#ifdef _KERNEL
struct thread;

/*
 * Updates to kernel_vm_end are synchronized by the kernel_map's system mutex.
 */
extern vm_offset_t kernel_vm_end;

/*
 * Flags for pmap_enter().  The bits in the low-order byte are reserved
 * for the protection code (vm_prot_t) that describes the fault type.
 * Bits 24 through 31 are reserved for the pmap's internal use.
 */
#define	PMAP_ENTER_NOSLEEP	0x00000100
#define	PMAP_ENTER_WIRED	0x00000200
#define	PMAP_ENTER_LARGEPAGE	0x00000400
#define	PMAP_ENTER_RESERVED	0xFF000000

/*
 * Define the maximum number of machine-dependent reference bits that are
 * cleared by a call to pmap_ts_referenced().  This limit serves two purposes.
 * First, it bounds the cost of reference bit maintenance on widely shared
 * pages.  Second, it prevents numeric overflow during maintenance of a
 * widely shared page's "act_count" field.  An overflow could result in the
 * premature deactivation of the page.
 */
#define	PMAP_TS_REFERENCED_MAX	5

void		 pmap_activate(struct thread *td);
void		 pmap_advise(pmap_t pmap, vm_offset_t sva, vm_offset_t eva,
		    int advice);
void		 pmap_align_superpage(vm_object_t, vm_ooffset_t, vm_offset_t *,
		    vm_size_t);
#ifdef CHERI_CAPREVOKE
static const int PMAP_CAPLOADGEN_HASCAPS   = 0x1;
static const int PMAP_CAPLOADGEN_NONEWMAPS = 0x2; // no new mappings
static const int PMAP_CAPLOADGEN_UPDATETLB = 0x4;
static const int PMAP_CAPLOADGEN_XBUSIED   = 0x8; // input page xbusied, !wired
enum pmap_caploadgen_res {
	PMAP_CAPLOADGEN_OK              = 0, /* Update done */
	PMAP_CAPLOADGEN_ALREADY         = 1, /* Update already applied */
	PMAP_CAPLOADGEN_CLEAN           = 2, /* Like _ALREADY, and !CAPSTORE */
	PMAP_CAPLOADGEN_UNABLE          = 3, /* No valid PTE at this address */
	PMAP_CAPLOADGEN_TEARDOWN        = 4, /* Mapping being torn down */
	PMAP_CAPLOADGEN_SCAN_RO_WIRED   = 5, /* mapped RO and wired */
	PMAP_CAPLOADGEN_SCAN_RO_XBUSIED = 6, /* mapped RO and xbusy */
	PMAP_CAPLOADGEN_SCAN_RW_XBUSIED = 7, /* mapped RW and xbusy */
};
int		 pmap_caploadgen_update(pmap_t, vm_offset_t, vm_page_t *,
		    int flags);
void		 pmap_caploadgen_next(pmap_t pmap);
#endif
void		 pmap_clear_modify(vm_page_t m);
void		 pmap_copy(pmap_t, pmap_t, vm_offset_t, vm_size_t, vm_offset_t);
void		 pmap_copy_page(vm_page_t, vm_page_t);
#if __has_feature(capabilities)
void		 pmap_copy_page_tags(vm_page_t, vm_page_t);
#endif
void		 pmap_copy_pages(vm_page_t ma[], vm_offset_t a_offset,
		    vm_page_t mb[], vm_offset_t b_offset, int xfersize);

/*
 * CHERI capability revocation imposes the following novel demand on pmap_enter
 * and its friends: the page must be suitable for insertion at the current
 * revocation epoch.  In particular, if a load-side sweep is in progres, either
 * the page must not be carrying capabilities, the new mapping must lack read
 * permission, or all capabilities within the page must be checked for
 * revocation.  This responsibility falls to **the caller of pmap_enter**!
 */
int		 pmap_enter(pmap_t pmap, vm_offset_t va, vm_page_t m,
		    vm_prot_t prot, u_int flags, int8_t psind);
void		 pmap_enter_object(pmap_t pmap, vm_offset_t start,
		    vm_offset_t end, vm_page_t m_start, vm_prot_t prot);
void		 pmap_enter_quick(pmap_t pmap, vm_offset_t va, vm_page_t m,
		    vm_prot_t prot);
vm_paddr_t	 pmap_extract(pmap_t pmap, vm_offset_t va);
vm_page_t	 pmap_extract_and_hold(pmap_t pmap, vm_offset_t va,
		    vm_prot_t prot);
void		 pmap_growkernel(vm_offset_t);
void		 pmap_init(void);
boolean_t	 pmap_is_modified(vm_page_t m);
boolean_t	 pmap_is_prefaultable(pmap_t pmap, vm_offset_t va);
boolean_t	 pmap_is_referenced(vm_page_t m);
boolean_t	 pmap_is_valid_memattr(pmap_t, vm_memattr_t);
vm_pointer_t	 pmap_map(vm_pointer_t *, vm_paddr_t, vm_paddr_t, int);
int		 pmap_mincore(pmap_t pmap, vm_offset_t addr,
		    vm_paddr_t *pap);
void		 pmap_object_init_pt(pmap_t pmap, vm_offset_t addr,
		    vm_object_t object, vm_pindex_t pindex, vm_size_t size);
boolean_t	 pmap_page_exists_quick(pmap_t pmap, vm_page_t m);
void		 pmap_page_init(vm_page_t m);
int		 pmap_page_wired_mappings(vm_page_t m);
int		 pmap_pinit(pmap_t);
void		 pmap_pinit0(pmap_t);
void		 pmap_protect(pmap_t, vm_offset_t, vm_offset_t, vm_prot_t);
void		 pmap_qenter(vm_offset_t, vm_page_t *, int);
void		 pmap_qremove(vm_offset_t, int);
vm_pointer_t	 pmap_quick_enter_page(vm_page_t);
void		 pmap_quick_remove_page(vm_offset_t);
void		 pmap_release(pmap_t);
void		 pmap_remove(pmap_t, vm_offset_t, vm_offset_t);
void		 pmap_remove_all(vm_page_t m);
void		 pmap_remove_pages(pmap_t);
void		 pmap_remove_write(vm_page_t m);
void		 pmap_sync_icache(pmap_t, vm_offset_t, vm_size_t);
int		 pmap_ts_referenced(vm_page_t m);
#ifdef CPU_CHERI
void		 pmap_sync_capdirty(pmap_t);
#endif
void		 pmap_unwire(pmap_t pmap, vm_offset_t start, vm_offset_t end);
void		 pmap_zero_page(vm_page_t);
void		 pmap_zero_page_area(vm_page_t, int off, int size);

#define	pmap_resident_count(pm)	((pm)->pm_stats.resident_count)
#define	pmap_wired_count(pm)	((pm)->pm_stats.wired_count)

/*
 * This isn't the ideal place to put these, but avoids having to do it for
 * every architecture.  If tags become more widely used, we might need to do
 * so.
 */
#if !__has_feature(capabilities)
#define	pmap_copy_page_tags(src, dst)	pmap_copy_page((src), (dst))
#endif

#endif /* _KERNEL */
#endif /* _PMAP_VM_ */
// CHERI CHANGES START
// {
//   "updated": 20221205,
//   "target_type": "header",
//   "changes": [
//     "support"
//   ],
//   "changes_purecap": [
//     "pointer_as_integer"
//   ],
//   "change_comment": ""
// }
// CHERI CHANGES END
