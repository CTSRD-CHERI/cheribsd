/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1991 Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department and William Jolitz of UUNET Technologies Inc.
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
 * Derived from hp300 version by Mike Hibler, this version by William
 * Jolitz uses a recursive map [a pde points to the page directory] to
 * map the page tables using the pagetables themselves. This is done to
 * reduce the impact on kernel virtual memory for lots of sparse address
 * space, and to reduce the cost of memory to each process.
 *
 *	from: hp300: @(#)pmap.h	7.2 (Berkeley) 12/16/90
 *	from: @(#)pmap.h	7.4 (Berkeley) 5/12/91
 * $FreeBSD$
 */

#ifndef _MACHINE_PMAP_H_
#define	_MACHINE_PMAP_H_

/*
 * Page-directory and page-table entries follow this format, with a few
 * of the fields not present here and there, depending on a lot of things.
 */
				/* ---- Intel Nomenclature ---- */
#define	PG_V		0x001	/* P	Valid			*/
#define PG_RW		0x002	/* R/W	Read/Write		*/
#define PG_U		0x004	/* U/S  User/Supervisor		*/
#define	PG_NC_PWT	0x008	/* PWT	Write through		*/
#define	PG_NC_PCD	0x010	/* PCD	Cache disable		*/
#define PG_A		0x020	/* A	Accessed		*/
#define	PG_M		0x040	/* D	Dirty			*/
#define	PG_PS		0x080	/* PS	Page size (0=4k,1=4M)	*/
#define	PG_PTE_PAT	0x080	/* PAT	PAT index		*/
#define	PG_G		0x100	/* G	Global			*/
#define	PG_AVAIL1	0x200	/*    /	Available for system	*/
#define	PG_AVAIL2	0x400	/*   <	programmers use		*/
#define	PG_AVAIL3	0x800	/*    \				*/
#define	PG_PDE_PAT	0x1000	/* PAT	PAT index		*/
#if defined(PAE) || defined(PAE_TABLES)
#define	PG_NX		(1ull<<63) /* No-execute */
#endif


/* Our various interpretations of the above */
#define PG_W		PG_AVAIL1	/* "Wired" pseudoflag */
#define	PG_MANAGED	PG_AVAIL2
#define	PG_PROMOTED	PG_AVAIL3	/* PDE only */
#if defined(PAE) || defined(PAE_TABLES)
#define	PG_FRAME	(0x000ffffffffff000ull)
#define	PG_PS_FRAME	(0x000fffffffe00000ull)
#else
#define	PG_FRAME	(~PAGE_MASK)
#define	PG_PS_FRAME	(0xffc00000)
#endif
#define	PG_PROT		(PG_RW|PG_U)	/* all protection bits . */
#define PG_N		(PG_NC_PWT|PG_NC_PCD)	/* Non-cacheable */

/* Page level cache control fields used to determine the PAT type */
#define PG_PDE_CACHE	(PG_PDE_PAT | PG_NC_PWT | PG_NC_PCD)
#define PG_PTE_CACHE	(PG_PTE_PAT | PG_NC_PWT | PG_NC_PCD)

/*
 * Promotion to a 2 or 4MB (PDE) page mapping requires that the corresponding
 * 4KB (PTE) page mappings have identical settings for the following fields:
 */
#define PG_PTE_PROMOTE	(PG_MANAGED | PG_W | PG_G | PG_PTE_PAT | \
	    PG_M | PG_A | PG_NC_PCD | PG_NC_PWT | PG_U | PG_RW | PG_V)

/*
 * Page Protection Exception bits
 */

#define PGEX_P		0x01	/* Protection violation vs. not present */
#define PGEX_W		0x02	/* during a Write cycle */
#define PGEX_U		0x04	/* access from User mode (UPL) */
#define PGEX_RSV	0x08	/* reserved PTE field is non-zero */
#define PGEX_I		0x10	/* during an instruction fetch */

/*
 * Size of Kernel address space.  This is the number of page table pages
 * (4MB each) to use for the kernel.  256 pages == 1 Gigabyte.
 * This **MUST** be a multiple of 4 (eg: 252, 256, 260, etc).
 * For PAE, the page table page unit size is 2MB.  This means that 512 pages
 * is 1 Gigabyte.  Double everything.  It must be a multiple of 8 for PAE.
 */
#if defined(PAE) || defined(PAE_TABLES)
#define KVA_PAGES	(512*4)
#else
#define KVA_PAGES	(256*4)
#endif

/*
 * Pte related macros
 */
#define VADDR(pdi, pti) ((vm_offset_t)(((pdi)<<PDRSHIFT)|((pti)<<PAGE_SHIFT)))

/*
 * The initial number of kernel page table pages that are constructed
 * by locore must be sufficient to map vm_page_array.  That number can
 * be calculated as follows:
 *     max_phys / PAGE_SIZE * sizeof(struct vm_page) / NBPDR
 * PAE:      max_phys 16G, sizeof(vm_page) 76, NBPDR 2M, 152 page table pages.
 * PAE_TABLES: max_phys 4G,  sizeof(vm_page) 68, NBPDR 2M, 36 page table pages.
 * Non-PAE:  max_phys 4G,  sizeof(vm_page) 68, NBPDR 4M, 18 page table pages.
 */
#ifndef NKPT
#if defined(PAE)
#define	NKPT		240
#elif defined(PAE_TABLES)
#define	NKPT		60
#else
#define	NKPT		30
#endif
#endif

#ifndef NKPDE
#define NKPDE	(KVA_PAGES)	/* number of page tables/pde's */
#endif

/*
 * The *PTDI values control the layout of virtual memory
 */
#define	KPTDI		0		/* start of kernel virtual pde's */
#define	LOWPTDI		1		/* low memory map pde */
#define	KERNPTDI	2		/* start of kernel text pde */
#define	PTDPTDI		(NPDEPTD - 1 - NPGPTD)	/* ptd entry that points
						   to ptd! */
#define	TRPTDI		(NPDEPTD - 1)	/* u/k trampoline ptd */

/*
 * XXX doesn't really belong here I guess...
 */
#define ISA_HOLE_START    0xa0000
#define ISA_HOLE_LENGTH (0x100000-ISA_HOLE_START)

#ifndef LOCORE

#include <sys/queue.h>
#include <sys/_cpuset.h>
#include <sys/_lock.h>
#include <sys/_mutex.h>

#include <vm/_vm_radix.h>

#if defined(PAE) || defined(PAE_TABLES)

typedef uint64_t pdpt_entry_t;
typedef uint64_t pd_entry_t;
typedef uint64_t pt_entry_t;

#define	PTESHIFT	(3)
#define	PDESHIFT	(3)

#else

typedef uint32_t pd_entry_t;
typedef uint32_t pt_entry_t;

#define	PTESHIFT	(2)
#define	PDESHIFT	(2)

#endif

/*
 * Address of current address space page table maps and directories.
 */
#ifdef _KERNEL
extern pt_entry_t PTmap[];
extern pd_entry_t PTD[];
extern pd_entry_t PTDpde[];

#if defined(PAE) || defined(PAE_TABLES)
extern pdpt_entry_t *IdlePDPT;
#endif
extern pd_entry_t *IdlePTD;	/* physical address of "Idle" state directory */

/*
 * Translate a virtual address to the kernel virtual address of its page table
 * entry (PTE).  This can be used recursively.  If the address of a PTE as
 * previously returned by this macro is itself given as the argument, then the
 * address of the page directory entry (PDE) that maps the PTE will be
 * returned.
 *
 * This macro may be used before pmap_bootstrap() is called.
 */
#define	vtopte(va)	(PTmap + i386_btop(va))

/*
 * Translate a virtual address to its physical address.
 *
 * This macro may be used before pmap_bootstrap() is called.
 */
#define	vtophys(va)	pmap_kextract((vm_offset_t)(va))

/*
 * KPTmap is a linear mapping of the kernel page table.  It differs from the
 * recursive mapping in two ways: (1) it only provides access to kernel page
 * table pages, and not user page table pages, and (2) it provides access to
 * a kernel page table page after the corresponding virtual addresses have
 * been promoted to a 2/4MB page mapping.
 *
 * KPTmap is first initialized by locore to support just NPKT page table
 * pages.  Later, it is reinitialized by pmap_bootstrap() to allow for
 * expansion of the kernel page table.
 */
extern pt_entry_t *KPTmap;

/*
 * Extract from the kernel page table the physical address that is mapped by
 * the given virtual address "va".
 *
 * This function may be used before pmap_bootstrap() is called.
 */
static __inline vm_paddr_t
pmap_kextract(vm_offset_t va)
{
	vm_paddr_t pa;

	if ((pa = PTD[va >> PDRSHIFT]) & PG_PS) {
		pa = (pa & PG_PS_FRAME) | (va & PDRMASK);
	} else {
		/*
		 * Beware of a concurrent promotion that changes the PDE at
		 * this point!  For example, vtopte() must not be used to
		 * access the PTE because it would use the new PDE.  It is,
		 * however, safe to use the old PDE because the page table
		 * page is preserved by the promotion.
		 */
		pa = KPTmap[i386_btop(va)];
		pa = (pa & PG_FRAME) | (va & PAGE_MASK);
	}
	return (pa);
}

#if (defined(PAE) || defined(PAE_TABLES))

#define	pde_cmpset(pdep, old, new)	atomic_cmpset_64_i586(pdep, old, new)
#define	pte_load_store(ptep, pte)	atomic_swap_64_i586(ptep, pte)
#define	pte_load_clear(ptep)		atomic_swap_64_i586(ptep, 0)
#define	pte_store(ptep, pte)		atomic_store_rel_64_i586(ptep, pte)

extern pt_entry_t pg_nx;

#else /* !(PAE || PAE_TABLES) */

#define	pde_cmpset(pdep, old, new)	atomic_cmpset_int(pdep, old, new)
#define	pte_load_store(ptep, pte)	atomic_swap_int(ptep, pte)
#define	pte_load_clear(ptep)		atomic_swap_int(ptep, 0)
#define	pte_store(ptep, pte) do { \
	*(u_int *)(ptep) = (u_int)(pte); \
} while (0)

#endif /* !(PAE || PAE_TABLES) */

#define	pte_clear(ptep)			pte_store(ptep, 0)

#define	pde_store(pdep, pde)		pte_store(pdep, pde)

#endif /* _KERNEL */

/*
 * Pmap stuff
 */
struct	pv_entry;
struct	pv_chunk;

struct md_page {
	TAILQ_HEAD(,pv_entry)	pv_list;
	int			pat_mode;
};

struct pmap {
	struct mtx		pm_mtx;
	pd_entry_t		*pm_pdir;	/* KVA of page directory */
	TAILQ_HEAD(,pv_chunk)	pm_pvchunk;	/* list of mappings in pmap */
	cpuset_t		pm_active;	/* active on cpus */
	struct pmap_statistics	pm_stats;	/* pmap statistics */
	LIST_ENTRY(pmap) 	pm_list;	/* List of all pmaps */
#if defined(PAE) || defined(PAE_TABLES)
	pdpt_entry_t		*pm_pdpt;	/* KVA of page directory pointer
						   table */
#endif
	struct vm_radix		pm_root;	/* spare page table pages */
	vm_page_t		pm_ptdpg[NPGPTD];
};

typedef struct pmap	*pmap_t;

#ifdef _KERNEL
extern struct pmap	kernel_pmap_store;
#define kernel_pmap	(&kernel_pmap_store)

#define	PMAP_LOCK(pmap)		mtx_lock(&(pmap)->pm_mtx)
#define	PMAP_LOCK_ASSERT(pmap, type) \
				mtx_assert(&(pmap)->pm_mtx, (type))
#define	PMAP_LOCK_DESTROY(pmap)	mtx_destroy(&(pmap)->pm_mtx)
#define	PMAP_LOCK_INIT(pmap)	mtx_init(&(pmap)->pm_mtx, "pmap", \
				    NULL, MTX_DEF | MTX_DUPOK)
#define	PMAP_LOCKED(pmap)	mtx_owned(&(pmap)->pm_mtx)
#define	PMAP_MTX(pmap)		(&(pmap)->pm_mtx)
#define	PMAP_TRYLOCK(pmap)	mtx_trylock(&(pmap)->pm_mtx)
#define	PMAP_UNLOCK(pmap)	mtx_unlock(&(pmap)->pm_mtx)
#endif

/*
 * For each vm_page_t, there is a list of all currently valid virtual
 * mappings of that page.  An entry is a pv_entry_t, the list is pv_list.
 */
typedef struct pv_entry {
	vm_offset_t	pv_va;		/* virtual address for mapping */
	TAILQ_ENTRY(pv_entry)	pv_next;
} *pv_entry_t;

/*
 * pv_entries are allocated in chunks per-process.  This avoids the
 * need to track per-pmap assignments.
 */
#define	_NPCM	11
#define	_NPCPV	336
struct pv_chunk {
	pmap_t			pc_pmap;
	TAILQ_ENTRY(pv_chunk)	pc_list;
	uint32_t		pc_map[_NPCM];	/* bitmap; 1 = free */
	TAILQ_ENTRY(pv_chunk)	pc_lru;
	struct pv_entry		pc_pventry[_NPCPV];
};

#ifdef	_KERNEL

extern caddr_t CADDR3;
extern pt_entry_t *CMAP3;
extern vm_paddr_t phys_avail[];
extern vm_paddr_t dump_avail[];
extern char *ptvmmap;		/* poor name! */
extern vm_offset_t virtual_avail;
extern vm_offset_t virtual_end;

#define	pmap_page_get_memattr(m)	((vm_memattr_t)(m)->md.pat_mode)
#define	pmap_page_is_write_mapped(m)	(((m)->aflags & PGA_WRITEABLE) != 0)
#define	pmap_unmapbios(va, sz)	pmap_unmapdev((va), (sz))

/*
 * Only the following functions or macros may be used before pmap_bootstrap()
 * is called: pmap_kenter(), pmap_kextract(), pmap_kremove(), vtophys(), and
 * vtopte().
 */
void	pmap_bootstrap(vm_paddr_t);
int	pmap_cache_bits(int mode, boolean_t is_pde);
int	pmap_change_attr(vm_offset_t, vm_size_t, int);
void	pmap_init_pat(void);
void	pmap_kenter(vm_offset_t va, vm_paddr_t pa);
void	*pmap_kenter_temporary(vm_paddr_t pa, int i);
void	pmap_kremove(vm_offset_t);
void	*pmap_mapbios(vm_paddr_t, vm_size_t);
void	*pmap_mapdev(vm_paddr_t, vm_size_t);
void	*pmap_mapdev_attr(vm_paddr_t, vm_size_t, int);
boolean_t pmap_page_is_mapped(vm_page_t m);
void	pmap_page_set_memattr(vm_page_t m, vm_memattr_t ma);
bool	pmap_ps_enabled(pmap_t pmap);
void	pmap_unmapdev(vm_offset_t, vm_size_t);
pt_entry_t *pmap_pte(pmap_t, vm_offset_t) __pure2;
void	pmap_invalidate_page(pmap_t, vm_offset_t);
void	pmap_invalidate_range(pmap_t, vm_offset_t, vm_offset_t);
void	pmap_invalidate_all(pmap_t);
void	pmap_invalidate_cache(void);
void	pmap_invalidate_cache_pages(vm_page_t *pages, int count);
void	pmap_invalidate_cache_range(vm_offset_t sva, vm_offset_t eva,
	    boolean_t force);
void	*pmap_trm_alloc(size_t size, int flags);
void	pmap_trm_free(void *addr, size_t size);

void	invltlb_glob(void);

#endif /* _KERNEL */

#endif /* !LOCORE */

#endif /* !_MACHINE_PMAP_H_ */
