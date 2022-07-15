/*
 * Copyright (C) 2015 Mihai Carabas <mihai.carabas@gmail.com>
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
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef _VMM_ARM64_H_
#define _VMM_ARM64_H_

#include <machine/reg.h>
#include <machine/vfp.h>
#include <machine/hypervisor.h>
#include <machine/pcpu.h>

#include "mmu.h"
#include "io/vgic_v3.h"
#include "io/vtimer.h"

struct hypctx {
	struct trapframe tf;

	/*
	 * EL1 control registers.
	 * Be careful changing the layout of these as we access them from
	 * assembly when switching between the host and guest.
	 */
#if __has_feature(capabilities)
	uint64_t	cctlr_el0;
	uint64_t	cctlr_el1;
	uintcap_t	cid_el0;
	uintcap_t	ddc_el0;
	uintcap_t	rcsp_el0;
	uintcap_t	rctpidr_el0;
	uintcap_t	rddc_el0;

	uintcap_t	elr_el1;	/* Exception Link Register */
	uintcap_t	sp_el0;		/* Stack pointer */
	uintcap_t	tpidr_el0;	/* EL0 Software ID Register */
	uintcap_t	tpidrro_el0;	/* Read-only Thread ID Register */
	uintcap_t	tpidr_el1;	/* EL1 Software ID Register */
	uintcap_t	vbar_el1;	/* Vector Base Address Register */
#else
	uint64_t	elr_el1;	/* Exception Link Register */
	uint64_t	sp_el0;		/* Stack pointer */
	uint64_t	tpidr_el0;	/* EL0 Software ID Register */
	uint64_t	tpidrro_el0;	/* Read-only Thread ID Register */
	uint64_t	tpidr_el1;	/* EL1 Software ID Register */
	uint64_t	vbar_el1;	/* Vector Base Address Register */
#endif

	uint64_t	actlr_el1;	/* Auxiliary Control Register */
	uint64_t	afsr0_el1;	/* Auxiliary Fault Status Register 0 */
	uint64_t	afsr1_el1;	/* Auxiliary Fault Status Register 1 */
	uint64_t	amair_el1;	/* Auxiliary Memory Attribute Indirection Register */
	uint64_t	contextidr_el1;	/* Current Process Identifier */
	uint64_t	cpacr_el1;	/* Architectural Feature Access Control Register */
	uint64_t	csselr_el1;	/* Cache Size Selection Register */
	uint64_t	esr_el1;	/* Exception Syndrome Register */
	uint64_t	far_el1;	/* Fault Address Register */
	uint64_t	mair_el1;	/* Memory Attribute Indirection Register */
	uint64_t	mdccint_el1;	/* Monitor DCC Interrupt Enable Register */
	uint64_t	mdscr_el1;	/* Monitor Debug System Control Register */
	uint64_t	par_el1;	/* Physical Address Register */
	uint64_t	sctlr_el1;	/* System Control Register */
	uint64_t	tcr_el1;	/* Translation Control Register */
	uint64_t	ttbr0_el1;	/* Translation Table Base Register 0 */
	uint64_t	ttbr1_el1;	/* Translation Table Base Register 1 */
	uint64_t	spsr_el1;	/* Saved Program Status Register */

	uint64_t	pmcr_el0;	/* Performance Monitors Control Register */
	uint64_t	pmccntr_el0;
	uint64_t	pmccfiltr_el0;
	uint64_t	pmcntenset_el0;
	uint64_t	pmintenset_el1;
	uint64_t	pmovsset_el0;
	uint64_t	pmselr_el0;
	uint64_t	pmuserenr_el0;
	uint64_t	pmevcntr_el0[31];
	uint64_t	pmevtyper_el0[31];

	uint64_t	dbgbcr_el1[16];	/* Debug Breakpoint Control Registers */
	uint64_t	dbgbvr_el1[16];	/* Debug Breakpoint Value Registers */
	uint64_t	dbgwcr_el1[16];	/* Debug Watchpoint Control Registers */
	uint64_t	dbgwvr_el1[16];	/* Debug Watchpoint Value Registers */

	/* EL2 control registers */
	uint64_t	cptr_el2;	/* Architectural Feature Trap Register */
	uint64_t	hcr_el2;	/* Hypervisor Configuration Register */
	uint64_t	mdcr_el2;	/* Monitor Debug Configuration Register */
	uint64_t	vpidr_el2;	/* Virtualization Processor ID Register */
	uint64_t	vmpidr_el2;	/* Virtualization Multiprocessor ID Register */
	uint32_t	vcpu;
	struct hyp	*hyp;
	struct {
		uint64_t	far_el2;	/* Fault Address Register */
		uint64_t	hpfar_el2;	/* Hypervisor IPA Fault Address Register */
	} exit_info;

	struct vtimer_cpu 	vtimer_cpu;
	struct vgic_v3_cpu_if	vgic_cpu_if;
	struct vgic_v3_redist	vgic_redist;
#ifdef VFP
	struct vfpstate	vfpstate;
#endif
};

struct hyp {
	struct hypctx	ctx[VM_MAXCPU];
	struct vgic_v3_dist vgic_dist;
	struct vm	*vm;
	struct vtimer	vtimer;
	uint64_t	vmid_generation;
	uint64_t	vttbr_el2;
	uint64_t	el2_addr;	/* The address of this in el2 space */
	bool		vgic_attached;
};

uint64_t	vmm_call_hyp(uint64_t, ...);
void 		vmm_cleanup(void *hyp_stub_vectors);
uint64_t 	vmm_enter_guest(struct hypctx *hypctx);
uint64_t 	vmm_read_ich_vtr_el2(void);
uint64_t 	vmm_read_cnthctl_el2(void);
uint64_t 	vmm_read_tcr_el2(void);

#define	eprintf(fmt, ...)	printf("%s:%d " fmt, __func__, __LINE__, ##__VA_ARGS__)
//#define	eprintf(fmt, ...)	do {} while(0)

#define	VMID_GENERATION_MASK 		((1UL<<8) - 1)
#define	build_vttbr(vmid, ptaddr) 	\
		((((vmid) & VMID_GENERATION_MASK) << VTTBR_VMID_SHIFT) | \
						(uint64_t)(ptaddr))

#define	MPIDR_SMP_MASK 		(0x3 << 30)
#define	MPIDR_AFF1_LEVEL(x) 	(((x) >> 2) << 8)
#define	MPIDR_AFF0_LEVEL(x) 	(((x) & 0x3) << 0)

/*
 * Return true if the exception was caused by a translation fault in the stage 2
 * translation regime. The DFSC encoding for a translation fault has the format
 * 0b0001LL, where LL (bits [1:0]) represents the level where the fault occured
 * (page D7-2280 of the ARMv8 Architecture Manual).
 */
#define	ISS_DATA_DFSC_TF(esr_iss)	\
		(!((esr_iss) & 0b111000) && ((esr_iss) & 0b000100))
#define	FAR_EL2_PAGE_OFFSET(x)		((x) & PAGE_MASK)

#define	DEBUG_ME	0

#define	arm64_get_active_vcpu()		((struct hypctx *)PCPU_GET(vcpu))

#endif /* !_VMM_ARM64_H_ */
