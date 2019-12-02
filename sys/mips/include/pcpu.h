/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 1999 Luoqi Chen <luoqi@freebsd.org>
 * Copyright (c) Peter Wemm <peter@netplex.com.au>
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
 *
 *	from: src/sys/alpha/include/pcpu.h,v 1.15 2004/11/05 19:16:44 jhb
 * $FreeBSD$
 */

#ifndef _MACHINE_PCPU_H_
#define	_MACHINE_PCPU_H_

#include <machine/cpufunc.h>
#include <machine/pte.h>

#ifdef CHERI_PURECAP_KERNEL
#include <cheri/cheric.h>
#endif

#if defined(MIPS_EXC_CNTRS)
#define	PCPU_MIPS_COUNTERS						\
	register_t	pc_tlb_miss_cnt;	/* TLB miss count */    \
	register_t	pc_tlb_invalid_cnt;	/* TLB invalid count */ \
	register_t	pc_tlb_mod_cnt;		/* TLB modification count */ \
#define	PCPU_NUM_EXC_CNTRS	3
#else
#define PCPU_MIPS_COUNTERS
#define	PCPU_NUM_EXC_CNTRS	0
#endif

#if defined(CHERI_PURECAP_KERNEL)
/*
 * Add an extra MD PCPU field for a cached copy of the current thread
 * kernel stack capability.
 * This must be kept in sync when context switching.
 */
#define PCPU_MD_CAPABILITY_FIELDS					\
	void	*pc_kstack_cap;		/* cached curthread kstack capability */
#else
#define PCPU_MD_CAPABILITY_FIELDS
#endif

#define	PCPU_MD_COMMON_FIELDS						\
	pd_entry_t	*pc_segbase;		/* curthread segbase */	\
	struct	pmap	*pc_curpmap;		/* pmap of curthread */	\
	PCPU_MIPS_COUNTERS						\
	u_int32_t	pc_next_asid;		/* next ASID to alloc */ \
	u_int32_t	pc_asid_generation;	/* current ASID generation */ \
	u_int		pc_pending_ipis;	/* IPIs pending to this CPU */ \
	struct	pcpu	*pc_self;		/* globally-uniqe self pointer */\
	PCPU_MD_CAPABILITY_FIELDS

#ifdef	__mips_n64

#if defined(CHERI_PURECAP_KERNEL) && defined(CPU_CHERI128)
// struct pcpu aligns to 512 bytes boundary
#define PCPU_MD_MIPS64_PAD (112 - (PCPU_NUM_EXC_CNTRS * 8))
#elif defined(CHERI_PURECAP_KERNEL) && defined(CPU_CHERI)
// struct pcpu aligns to 1024 bytes boundary
#define PCPU_MD_MIPS64_PAD (320 - (PCPU_NUM_EXC_CNTRS * 8))
#else /* ! defined(CHERI_PURECAP_KERNEL) */
// struct pcpu aligns to 512 bytes boundary
#define PCPU_MD_MIPS64_PAD (245 - (PCPU_NUM_EXC_CNTRS * 8))
#endif /* ! defined(CHERI_PURECAP_KERNEL) */
#define	PCPU_MD_MIPS64_FIELDS						\
	PCPU_MD_COMMON_FIELDS						\
	char		__pad[PCPU_MD_MIPS64_PAD]

#else /* ! defined(__mips_n64) */

#define	PCPU_MD_MIPS32_FIELDS						\
	PCPU_MD_COMMON_FIELDS						\
	pt_entry_t	*pc_cmap1_ptep;		/* PTE for copy window 1 KVA */ \
	pt_entry_t	*pc_cmap2_ptep;		/* PTE for copy window 2 KVA */ \
	vm_offset_t	pc_cmap1_addr;		/* KVA page for copy window 1 */ \
	vm_offset_t	pc_cmap2_addr;		/* KVA page for copy window 2 */ \
	vm_offset_t	pc_qmap_addr;		/* KVA page for temporary mappings */ \
	pt_entry_t	*pc_qmap_ptep;		/* PTE for temporary mapping KVA */ \
	char		__pad[(101 - (PCPU_NUM_EXC_CNTRS * 4))]
#endif /* ! defined(__mips_n64) */

#ifdef	__mips_n64
#define	PCPU_MD_FIELDS	PCPU_MD_MIPS64_FIELDS
#else
#define	PCPU_MD_FIELDS	PCPU_MD_MIPS32_FIELDS
#endif

#ifdef _KERNEL

extern char pcpu_space[MAXCPU][PAGE_SIZE * 2];
#ifndef CHERI_PURECAP_KERNEL
#define	PCPU_ADDR(cpu)		(struct pcpu *)(pcpu_space[(cpu)])
#else /* CHERI_PURECAP_KERNEL */
#define PCPU_ADDR(cpu)		cheri_csetbounds((struct pcpu *)(pcpu_space[(cpu)]), sizeof(struct pcpu))
#endif /* CHERI_PURECAP_KERNEL*/

extern struct pcpu *pcpup;
#define	PCPUP	pcpup

/*
 * Since we use a wired TLB entry to map the same VA to a different
 * physical page for each CPU, get_pcpu() must use the pc_self
 * field to obtain a globally-unique pointer.
 */
#define	get_pcpu()		(PCPUP->pc_self)

#define	PCPU_ADD(member, value)	(PCPUP->pc_ ## member += (value))
#define	PCPU_GET(member)	(PCPUP->pc_ ## member)
#define	PCPU_INC(member)	PCPU_ADD(member, 1)
#define	PCPU_PTR(member)	(&PCPUP->pc_ ## member)
#define	PCPU_SET(member,value)	(PCPUP->pc_ ## member = (value))
#define PCPU_LAZY_INC(member)   (++PCPUP->pc_ ## member)

#ifdef SMP
/*
 * Instantiate the wired TLB entry at PCPU_TLB_ENTRY to map 'pcpu' at 'pcpup'.
 */
void	mips_pcpu_tlb_init(struct pcpu *pcpu);
#endif

#endif	/* _KERNEL */

#endif	/* !_MACHINE_PCPU_H_ */
// CHERI CHANGES START
// {
//   "updated": 20190523,
//   "target_type": "header",
//   "changes_purecap": [
//     "pointer_shape",
//     "support"
//   ],
//   "changes_comment": "pcpu_addr, kstack"
// }
// CHERI CHANGES END
