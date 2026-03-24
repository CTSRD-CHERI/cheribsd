/*-
 * Copyright (c) 2025-2026 Alfredo Mazzinghi <alfredo@capabilitieslimited.co.uk>
 * Copyright (c) 2025-2026 Capabilities Limited
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

#ifndef _MACHINE_CHERI_REVOKE_H_
#define _MACHINE_CHERI_REVOKE_H_

#include <sys/kassert.h>
#include <machine/param.h>

#ifdef _KERNEL
#ifdef CHERI_CAPREVOKE_KERNEL
/*
 * Kernel revocation per-CPU state.
 * These are accessed via non-CLG trapping memory in the fault handlers.
 * Note that a whole page is allocated for each CPU and it includes
 * non-CLG trapping stack space for the CLG fault handler.
 */
struct kmem_revoke_pcpu {
	struct pcpu *pcpup;		/* Kernel pcpu data (not in DMAP) */
	void *dmap_cap;			/* Direct map capability */
	vm_paddr_t dmap_phys_base;	/* DMAP base phys addr */
	void *shadow_cap;		/* Kernel shadow bitmap capability */
	void *clg_fault_kstack;		/* CLG fault handler stack (DMAP cap) */
};

struct kmem_revoke_pcpu *kmem_revoke_md_init_pcpu0(struct pcpu *pcpup);
struct kmem_revoke_pcpu *kmem_revoke_md_alloc_pcpu(int domain,
    struct pcpu *pcpup);
int do_kmem_fault_revoke(struct kmem_revoke_pcpu *pcpu_state);
#endif /* CHERI_CAPREVOKE_KERNEL */
#endif /* _KERNEL */

#endif	/* !_MACHINE_CHERI_REVOKE_H_ */
