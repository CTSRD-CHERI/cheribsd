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

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/smp.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/pcpu.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/vmem.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/vm_param.h>

#include <machine/armreg.h>
#include <machine/vm.h>
#include <machine/cpufunc.h>
#include <machine/cpu.h>
#include <machine/machdep.h>
#include <machine/vmm.h>
#include <machine/vmm_dev.h>
#include <machine/atomic.h>
#include <machine/hypervisor.h>
#include <machine/pmap.h>

#include "mmu.h"
#include "arm64.h"
#include "hyp.h"
#include "reset.h"
#include "io/vgic_v3.h"
#include "io/vtimer.h"

#define	HANDLED		1
#define	UNHANDLED	0

#define	UNUSED		0

/* Number of bits in an EL2 virtual address */
#define	EL2_VIRT_BITS	48
CTASSERT((1ul << EL2_VIRT_BITS) >= HYP_VM_MAX_ADDRESS);

/* TODO: Move the host hypctx off the stack */
#define	VMM_STACK_PAGES	4
#define	VMM_STACK_SIZE	(VMM_STACK_PAGES * PAGE_SIZE)

static int vmm_pmap_levels, vmm_virt_bits;

/* Register values passed to arm_setup_vectors to set in the hypervisor */
struct vmm_init_regs {
	uint64_t tcr_el2;
	uint64_t vtcr_el2;
};

MALLOC_DEFINE(M_HYP, "ARM VMM HYP", "ARM VMM HYP");

extern char hyp_init_vectors[];
extern char hyp_vectors[];
extern char hyp_stub_vectors[];

static vm_paddr_t hyp_code_base;
static size_t hyp_code_len;

static char *stack[MAXCPU];
static vm_offset_t stack_hyp_va[MAXCPU];

static vmem_t *el2_mem_alloc;

static void arm_setup_vectors(void *arg);
static void vmm_pmap_clean_stage2_tlbi(void);
static void vmm_pmap_invalidate_page(uint64_t, vm_offset_t, bool);
static void vmm_pmap_invalidate_all(uint64_t);

static inline void
arm64_set_active_vcpu(struct hypctx *hypctx)
{

	PCPU_SET(vcpu, hypctx);
}

static void
arm_setup_vectors(void *arg)
{
	struct vmm_init_regs *el2_regs;
	char *stack_top;
	uint32_t sctlr_el2;
	register_t daif;

	el2_regs = arg;
	arm64_set_active_vcpu(NULL);

	daif = intr_disable();

	/*
	 * Install the temporary vectors which will be responsible for
	 * initializing the VMM when we next trap into EL2.
	 *
	 * x0: the exception vector table responsible for hypervisor
	 * initialization on the next call.
	 */
	vmm_call_hyp(vtophys(&vmm_hyp_code));

	/* Create and map the hypervisor stack */
	stack_top = (char *)stack_hyp_va[PCPU_GET(cpuid)] + VMM_STACK_SIZE;

	/*
	 * Configure the system control register for EL2:
	 *
	 * SCTLR_EL2_M: MMU on
	 * SCTLR_EL2_C: Data cacheability not affected
	 * SCTLR_EL2_I: Instruction cacheability not affected
	 * SCTLR_EL2_A: Instruction alignment check
	 * SCTLR_EL2_SA: Stack pointer alignment check
	 * SCTLR_EL2_WXN: Treat writable memory as execute never
	 * ~SCTLR_EL2_EE: Data accesses are little-endian
	 */
	sctlr_el2 = SCTLR_EL2_RES1;
	sctlr_el2 |= SCTLR_EL2_M | SCTLR_EL2_C | SCTLR_EL2_I;
	sctlr_el2 |= SCTLR_EL2_A | SCTLR_EL2_SA;
	sctlr_el2 |= SCTLR_EL2_WXN;
	sctlr_el2 &= ~SCTLR_EL2_EE;

	/* Special call to initialize EL2 */
	vmm_call_hyp(vmmpmap_to_ttbr0(), stack_top, el2_regs->tcr_el2,
	    sctlr_el2, el2_regs->vtcr_el2);

	intr_restore(daif);
}

static void
arm_teardown_vectors(void *arg)
{
	register_t daif;

	/*
	 * vmm_cleanup() will disable the MMU. For the next few instructions,
	 * before the hardware disables the MMU, one of the following is
	 * possible:
	 *
	 * a. The instruction addresses are fetched with the MMU disabled,
	 * and they must represent the actual physical addresses. This will work
	 * because we call the vmm_cleanup() function by its physical address.
	 *
	 * b. The instruction addresses are fetched using the old translation
	 * tables. This will work because we have an identity mapping in place
	 * in the translation tables and vmm_cleanup() is called by its physical
	 * address.
	 */
	daif = intr_disable();
	/* TODO: Invalidate the cache */
	vmm_call_hyp(HYP_CLEANUP, vtophys(hyp_stub_vectors));
	intr_restore(daif);

	arm64_set_active_vcpu(NULL);
}

static uint64_t
vmm_vtcr_el2_sl(u_int levels)
{
#if PAGE_SIZE == PAGE_SIZE_4K
	switch(levels) {
	case 2:
		return (VTCR_EL2_SL0_4K_LVL2);
	case 3:
		return (VTCR_EL2_SL0_4K_LVL1);
	case 4:
		return (VTCR_EL2_SL0_4K_LVL0);
	default:
		panic("%s: Invalid number of page table levels %u", __func__,
		    levels);
	}
#elif PAGE_SIZE == PAGE_SIZE_16K
	switch(levels) {
	case 2:
		return (VTCR_EL2_SL0_16K_LVL2);
	case 3:
		return (VTCR_EL2_SL0_16K_LVL1);
	case 4:
		return (VTCR_EL2_SL0_16K_LVL0);
	default:
		panic("%s: Invalid number of page table levels %u", __func__,
		    levels);
	}
#else
#error Unsupported page size
#endif
}

static int
arm_init(int ipinum)
{
	struct vmm_init_regs el2_regs;
	vm_offset_t next_hyp_va;
	vm_paddr_t vmm_base;
	uint64_t id_aa64mmfr0_el1, pa_range_bits, pa_range_field;
	uint64_t ich_vtr_el2;
	uint64_t cnthctl_el2;
	register_t daif;
	int cpu, i;
	bool rv __diagused;

	if (!virt_enabled()) {
		printf("arm_init: Processor doesn't have support for virtualization.\n");
		return (ENXIO);
	}

	if (!vgic_present()) {
		printf("arm_init: No GICv3 found\n");
		return (ENODEV);
	}

	if (!get_kernel_reg(ID_AA64MMFR0_EL1, &id_aa64mmfr0_el1)) {
		printf("arm_init: Unable to read ID_AA64MMFR0_EL1\n");
		return (ENXIO);
	}
	pa_range_field = ID_AA64MMFR0_PARange_VAL(id_aa64mmfr0_el1);
	/*
	 * Use 3 levels to give us up to 39 bits with 4k pages, or
	 * 47 bits with 16k pages.
	 */
	/* TODO: Check the number of levels for 64k pages */
	vmm_pmap_levels = 3;
	switch (pa_range_field) {
	case ID_AA64MMFR0_PARange_4G:
		printf("arm_init: Not enough physical address bits\n");
		return (ENXIO);
	case ID_AA64MMFR0_PARange_64G:
		vmm_virt_bits = 36;
#if PAGE_SIZE == PAGE_SIZE_16K
		/* TODO: Test */
		vmm_pmap_levels = 2;
#endif
		break;
	default:
		vmm_virt_bits = 39;
		break;
	}
	pa_range_bits = pa_range_field >> ID_AA64MMFR0_PARange_SHIFT;

	/* Initialise the EL2 MMU */
	if (!vmmpmap_init()) {
		printf("arm_init: Failed to init the EL2 MMU\n");
		return (ENOMEM);
	}

	/* Set up the stage 2 pmap callbacks */
	MPASS(pmap_clean_stage2_tlbi == NULL);
	pmap_clean_stage2_tlbi = vmm_pmap_clean_stage2_tlbi;
	pmap_stage2_invalidate_page = vmm_pmap_invalidate_page;
	pmap_stage2_invalidate_all = vmm_pmap_invalidate_all;

	/* Create the vmem allocator */
	el2_mem_alloc = vmem_create("VMM EL2", 0, 0, PAGE_SIZE, 0, M_WAITOK, 0);

	/* Create the mappings for the hypervisor translation table. */
	hyp_code_len = roundup2(&vmm_hyp_code_end - &vmm_hyp_code, PAGE_SIZE);

	/* We need an physical identity mapping for when we activate the MMU */
	hyp_code_base = vmm_base = vtophys(&vmm_hyp_code);
	rv = vmmpmap_enter(vmm_base, hyp_code_len, vtophys(&vmm_hyp_code),
	    VM_PROT_READ | VM_PROT_EXECUTE);
	MPASS(rv);

	next_hyp_va = roundup2(vtophys(&vmm_hyp_code) + hyp_code_len, L2_SIZE);

	/* Create a per-CPU hypervisor stack */
	CPU_FOREACH(cpu) {
		stack[cpu] = malloc(VMM_STACK_SIZE, M_HYP, M_WAITOK | M_ZERO);
		stack_hyp_va[cpu] = next_hyp_va;

		for (i = 0; i < VMM_STACK_PAGES; i++) {
			rv = vmmpmap_enter(stack_hyp_va[cpu] + (i * PAGE_SIZE),
			    PAGE_SIZE, vtophys(stack[cpu] + (i * PAGE_SIZE)),
			    VM_PROT_READ | VM_PROT_WRITE);
			MPASS(rv);
		}
		next_hyp_va += L2_SIZE;
	}

	el2_regs.tcr_el2 = TCR_EL2_RES1;
	el2_regs.tcr_el2 |= min(pa_range_bits << TCR_EL2_PS_SHIFT,
	    TCR_EL2_PS_52BITS);
	el2_regs.tcr_el2 |= TCR_EL2_T0SZ(64 - EL2_VIRT_BITS);
	el2_regs.tcr_el2 |= TCR_EL2_IRGN0_WBWA | TCR_EL2_ORGN0_WBWA;
#if PAGE_SIZE == PAGE_SIZE_4K
	el2_regs.tcr_el2 |= TCR_EL2_TG0_4K;
#elif PAGE_SIZE == PAGE_SIZE_16K
	el2_regs.tcr_el2 |= TCR_EL2_TG0_16K;
#else
#error Unsupported page size
#endif
#ifdef SMP
	el2_regs.tcr_el2 |= TCR_EL2_SH0_IS;
#endif

	/*
	 * Configure the Stage 2 translation control register:
	 *
	 * VTCR_IRGN0_WBWA: Translation table walks access inner cacheable
	 * normal memory
	 * VTCR_ORGN0_WBWA: Translation table walks access outer cacheable
	 * normal memory
	 * VTCR_EL2_TG0_4K/16K: Stage 2 uses the same page size as the kernel
	 * VTCR_EL2_SL0_4K_LVL1: Stage 2 uses concatenated level 1 tables
	 * VTCR_EL2_SH0_IS: Memory associated with Stage 2 walks is inner
	 * shareable
	 */
	el2_regs.vtcr_el2 = VTCR_EL2_RES1;
	el2_regs.vtcr_el2 |=
	    min(pa_range_bits << VTCR_EL2_PS_SHIFT, VTCR_EL2_PS_48BIT);
	el2_regs.vtcr_el2 |= VTCR_EL2_IRGN0_WBWA | VTCR_EL2_ORGN0_WBWA;
	el2_regs.vtcr_el2 |= VTCR_EL2_T0SZ(64 - vmm_virt_bits);
	el2_regs.vtcr_el2 |= vmm_vtcr_el2_sl(vmm_pmap_levels);
#if PAGE_SIZE == PAGE_SIZE_4K
	el2_regs.vtcr_el2 |= VTCR_EL2_TG0_4K;
#elif PAGE_SIZE == PAGE_SIZE_16K
	el2_regs.vtcr_el2 |= VTCR_EL2_TG0_16K;
#else
#error Unsupported page size
#endif
#ifdef SMP
	el2_regs.vtcr_el2 |= VTCR_EL2_SH0_IS;
#endif

	smp_rendezvous(NULL, arm_setup_vectors, NULL, &el2_regs);

	/* Add memory to the vmem allocator (checking there is space) */
	if (vmm_base > L2_SIZE) {
		/*
		 * Ensure there is an L2 block before the vmm code to check
		 * for buffer overflows on earlier data. Include the PAGE_SIZE
		 * of the minimum we can allocate.
		 */
		vmm_base -= L2_SIZE + PAGE_SIZE;
		vmm_base = rounddown2(vmm_base, L2_SIZE);

		/*
		 * Check there is memory before the vmm code to add.
		 *
		 * Reserve the L2 block at address 0 so NULL dereference will
		 * raise an exception
		 */
		if (vmm_base > L2_SIZE)
			vmem_add(el2_mem_alloc, L2_SIZE, next_hyp_va - L2_SIZE,
			    M_WAITOK);
	}

	/*
	 * Add the memory after the stacks. There is most of an L2 block
	 * between the last stack and the first allocation so this should
	 * be safe without adding more padding.
	 */
	if (next_hyp_va < HYP_VM_MAX_ADDRESS - PAGE_SIZE)
		vmem_add(el2_mem_alloc, next_hyp_va,
		    HYP_VM_MAX_ADDRESS - next_hyp_va, M_WAITOK);


	daif = intr_disable();
	ich_vtr_el2 = vmm_call_hyp(HYP_READ_REGISTER, HYP_REG_ICH_VTR);
	cnthctl_el2 = vmm_call_hyp(HYP_READ_REGISTER, HYP_REG_CNTHCTL);
	intr_restore(daif);

	vgic_v3_init(ich_vtr_el2);
	vtimer_init(cnthctl_el2);

	return (0);
}

static int
arm_cleanup(void)
{
	int cpu;

	smp_rendezvous(NULL, arm_teardown_vectors, NULL, NULL);

#ifdef INVARIANTS
	CPU_FOREACH(cpu) {
		vmmpmap_remove(stack_hyp_va[cpu], VMM_STACK_PAGES * PAGE_SIZE,
		    false);
	}

	vmmpmap_remove(hyp_code_base, hyp_code_len, false);
#endif

	vtimer_cleanup();

	vmmpmap_fini();
	for (cpu = 0; cpu < nitems(stack); cpu++)
		free(stack[cpu], M_HYP);

	pmap_clean_stage2_tlbi = NULL;

	return (0);
}

static void *
arm_vminit(struct vm *vm, pmap_t pmap)
{
	struct hyp *hyp;
	struct hypctx *hypctx;
	vmem_addr_t vm_addr;
	vm_size_t size;
	bool last_vcpu, rv __diagused;
	int err __diagused, i, maxcpus;

	/* Ensure this is the only data on the page */
	size = roundup2(sizeof(struct hyp), PAGE_SIZE);
	hyp = malloc(size, M_HYP, M_WAITOK | M_ZERO);
	MPASS(((vm_offset_t)hyp & PAGE_MASK) == 0);

	hyp->vm = vm;
	hyp->vgic_attached = false;

	maxcpus = vm_get_maxcpus(vm);
	for (i = 0; i < maxcpus; i++) {
		hypctx = &hyp->ctx[i];
		hypctx->vcpu = i;
		hypctx->hyp = hyp;

		reset_vm_el01_regs(hypctx);
		reset_vm_el2_regs(hypctx);
	}

	vtimer_vminit(hyp);
	vgic_v3_vminit(hyp);
	for (i = 0; i < VM_MAXCPU; i++) {
		hypctx = &hyp->ctx[i];
		vtimer_cpuinit(hypctx);
		last_vcpu = (i == VM_MAXCPU - 1);
		vgic_v3_cpuinit(hypctx, last_vcpu);
	}

	/* XXX: Can this fail? */
	err = vmem_alloc(el2_mem_alloc, size, M_NEXTFIT | M_WAITOK,
	    &vm_addr);
	MPASS(err == 0);
	MPASS((vm_addr & PAGE_MASK) == 0);
	hyp->el2_addr = vm_addr;

	rv = vmmpmap_enter(hyp->el2_addr, size, vtophys(hyp),
	    VM_PROT_READ | VM_PROT_WRITE);
	MPASS(rv);

	return (hyp);
}

static int
arm_vmm_pinit(pmap_t pmap)
{

	pmap_pinit_stage(pmap, PM_STAGE2, vmm_pmap_levels);
	return (1);
}

static struct vmspace *
arm_vmspace_alloc(vm_offset_t min, vm_offset_t max)
{
	return (vmspace_alloc(min, max, arm_vmm_pinit));
}

static void
arm_vmspace_free(struct vmspace *vmspace)
{

	pmap_remove_pages(vmspace_pmap(vmspace));
	vmspace_free(vmspace);
}

static void
vmm_pmap_clean_stage2_tlbi(void)
{
	vmm_call_hyp(HYP_CLEAN_S2_TLBI);
}

static void
vmm_pmap_invalidate_page(uint64_t vttbr, vm_offset_t va, bool final_only)
{
	vmm_call_hyp(HYP_S2_TLBI_RANGE, vttbr, va, PAGE_SIZE, final_only);
}

static void
vmm_pmap_invalidate_all(uint64_t vttbr)
{
	vmm_call_hyp(HYP_S2_TLBI_ALL, vttbr);
}

static enum vm_reg_name
get_vm_reg_name(uint32_t reg_nr, uint32_t mode __attribute__((unused)))
{
	switch(reg_nr) {
		case 0:
			return VM_REG_GUEST_X0;
		case 1:
			return VM_REG_GUEST_X1;
		case 2:
			return VM_REG_GUEST_X2;
		case 3:
			return VM_REG_GUEST_X3;
		case 4:
			return VM_REG_GUEST_X4;
		case 5:
			return VM_REG_GUEST_X5;
		case 6:
			return VM_REG_GUEST_X6;
		case 7:
			return VM_REG_GUEST_X7;
		case 8:
			return VM_REG_GUEST_X8;
		case 9:
			return VM_REG_GUEST_X9;
		case 10:
			return VM_REG_GUEST_X10;
		case 11:
			return VM_REG_GUEST_X11;
		case 12:
			return VM_REG_GUEST_X12;
		case 13:
			return VM_REG_GUEST_X13;
		case 14:
			return VM_REG_GUEST_X14;
		case 15:
			return VM_REG_GUEST_X15;
		case 16:
			return VM_REG_GUEST_X16;
		case 17:
			return VM_REG_GUEST_X17;
		case 18:
			return VM_REG_GUEST_X18;
		case 19:
			return VM_REG_GUEST_X19;
		case 20:
			return VM_REG_GUEST_X20;
		case 21:
			return VM_REG_GUEST_X21;
		case 22:
			return VM_REG_GUEST_X22;
		case 23:
			return VM_REG_GUEST_X23;
		case 24:
			return VM_REG_GUEST_X24;
		case 25:
			return VM_REG_GUEST_X25;
		case 26:
			return VM_REG_GUEST_X26;
		case 27:
			return VM_REG_GUEST_X27;
		case 28:
			return VM_REG_GUEST_X28;
		case 29:
			return VM_REG_GUEST_X29;
		case 30:
			return VM_REG_GUEST_LR;
		case 31:
			return VM_REG_GUEST_SP;
		case 32:
			return VM_REG_GUEST_ELR;
		case 33:
			return VM_REG_GUEST_SPSR;
		case 34:
			return VM_REG_ELR_EL2;
		default:
			break;
	}

	return (VM_REG_LAST);
}

static inline void
arm64_print_hyp_regs(struct vm_exit *vme)
{
	printf("esr_el2:   0x%08x\n", vme->u.hyp.esr_el2);
	printf("far_el2:   0x%016lx\n", vme->u.hyp.far_el2);
	printf("hpfar_el2: 0x%016lx\n", vme->u.hyp.hpfar_el2);
}

static void
arm64_gen_inst_emul_data(struct hypctx *hypctx, uint32_t esr_iss,
    struct vm_exit *vme_ret)
{
	struct vm_guest_paging *paging;
	struct vie *vie;
	uint32_t esr_sas, reg_num;
	uint64_t page_off;

	/*
	 * Get the page address from HPFAR_EL2.
	 */
	vme_ret->u.inst_emul.gpa =
	    HPFAR_EL2_FIPA_ADDR(hypctx->exit_info.hpfar_el2);
	/* Bits [11:0] are the same as bits [11:0] from the virtual address. */
	page_off = FAR_EL2_PAGE_OFFSET(hypctx->exit_info.far_el2);
	vme_ret->u.inst_emul.gpa += page_off;

	esr_sas = (esr_iss & ISS_DATA_SAS_MASK) >> ISS_DATA_SAS_SHIFT;
	reg_num = (esr_iss & ISS_DATA_SRT_MASK) >> ISS_DATA_SRT_SHIFT;

	vie = &vme_ret->u.inst_emul.vie;
	vie->access_size = 1 << esr_sas;
	vie->sign_extend = (esr_iss & ISS_DATA_SSE) ? 1 : 0;
	vie->dir = (esr_iss & ISS_DATA_WnR) ? VM_DIR_WRITE : VM_DIR_READ;
	vie->reg = get_vm_reg_name(reg_num, UNUSED);

	paging = &vme_ret->u.inst_emul.paging;
	paging->far = hypctx->exit_info.far_el2;
	paging->ttbr0_el1 = hypctx->ttbr0_el1;
	paging->ttbr1_el1 = hypctx->ttbr1_el1;
	paging->flags = hypctx->tf.tf_spsr & (PSR_M_MASK | PSR_M_32);
	if ((hypctx->sctlr_el1 & SCTLR_M) != 0)
		paging->flags |= VM_GP_MMU_ENABLED;
}

static void
arm64_gen_reg_emul_data(uint32_t esr_iss, struct vm_exit *vme_ret)
{
	uint32_t reg_num;
	struct vre *vre;

	/* u.hyp member will be replaced by u.reg_emul */
	vre = &vme_ret->u.reg_emul.vre;

	vre->inst_syndrome = esr_iss;
	/* ARMv8 Architecture Manual, p. D7-2273: 1 means read */
	vre->dir = (esr_iss & ISS_MSR_DIR) ? VM_DIR_READ : VM_DIR_WRITE;
	reg_num = ISS_MSR_Rt(esr_iss);
	vre->reg = get_vm_reg_name(reg_num, UNUSED);
}

static int
handle_el1_sync_excp(struct hyp *hyp, int vcpu, struct vm_exit *vme_ret,
    pmap_t pmap)
{
	struct hypctx *hypctx;
	uint64_t gpa;
	uint32_t esr_ec, esr_iss;

	hypctx = &hyp->ctx[vcpu];
	esr_ec = ESR_ELx_EXCEPTION(hypctx->tf.tf_esr);
	esr_iss = hypctx->tf.tf_esr & ESR_ELx_ISS_MASK;

	switch(esr_ec) {
	case EXCP_UNKNOWN:
		eprintf("Unknown exception from guest\n");
		arm64_print_hyp_regs(vme_ret);
		vme_ret->exitcode = VM_EXITCODE_HYP;
		break;
	case EXCP_TRAP_WFI_WFE:
		if ((hypctx->tf.tf_esr & 0x3) == 0) /* WFI */
			vme_ret->exitcode = VM_EXITCODE_WFI;
		else
			vme_ret->exitcode = VM_EXITCODE_HYP;
		break;
	case EXCP_HVC:
		vme_ret->exitcode = VM_EXITCODE_HVC;
		break;
	case EXCP_MSR:
		arm64_gen_reg_emul_data(esr_iss, vme_ret);
		vme_ret->exitcode = VM_EXITCODE_REG_EMUL;
		break;

	case EXCP_INSN_ABORT_L:
	case EXCP_DATA_ABORT_L:
		switch (hypctx->tf.tf_esr & ISS_DATA_DFSC_MASK) {
		case ISS_DATA_DFSC_TF_L0:
		case ISS_DATA_DFSC_TF_L1:
		case ISS_DATA_DFSC_TF_L2:
		case ISS_DATA_DFSC_TF_L3:
		case ISS_DATA_DFSC_AFF_L1:
		case ISS_DATA_DFSC_AFF_L2:
		case ISS_DATA_DFSC_AFF_L3:
		case ISS_DATA_DFSC_PF_L1:
		case ISS_DATA_DFSC_PF_L2:
		case ISS_DATA_DFSC_PF_L3:
			hypctx = &hyp->ctx[vcpu];
			gpa = HPFAR_EL2_FIPA_ADDR(hypctx->exit_info.hpfar_el2);
			if (vm_mem_allocated(hyp->vm, vcpu, gpa)) {
				vme_ret->exitcode = VM_EXITCODE_PAGING;
				vme_ret->inst_length = 0;
				vme_ret->u.paging.esr = hypctx->tf.tf_esr;
				vme_ret->u.paging.gpa = gpa;
			} else if (esr_ec == EXCP_DATA_ABORT_L) {
				arm64_gen_inst_emul_data(&hyp->ctx[vcpu],
				    esr_iss, vme_ret);
				vme_ret->exitcode = VM_EXITCODE_INST_EMUL;
			} else {
				eprintf(
				  "Unsupported instruction fault from guest\n");
				arm64_print_hyp_regs(vme_ret);
				vme_ret->exitcode = VM_EXITCODE_HYP;
			}
			break;
		default:
			eprintf(
			    "Unsupported data/instruction fault from guest\n");
			arm64_print_hyp_regs(vme_ret);
			vme_ret->exitcode = VM_EXITCODE_HYP;
			break;
		}

		break;

	default:
		eprintf("Unsupported synchronous exception from guest: 0x%x\n",
		    esr_ec);
		arm64_print_hyp_regs(vme_ret);
		vme_ret->exitcode = VM_EXITCODE_HYP;
		break;
	}

	/* We don't don't do any instruction emulation here */
	return (UNHANDLED);
}

static int
arm64_handle_world_switch(struct hyp *hyp, int vcpu, int excp_type,
    struct vm_exit *vme, pmap_t pmap)
{
	int handled;

	switch (excp_type) {
	case EXCP_TYPE_EL1_SYNC:
		/* The exit code will be set by handle_el1_sync_excp(). */
		handled = handle_el1_sync_excp(hyp, vcpu, vme, pmap);
		break;

	case EXCP_TYPE_EL1_IRQ:
	case EXCP_TYPE_EL1_FIQ:
		/* The host kernel will handle IRQs and FIQs. */
		vme->exitcode = VM_EXITCODE_BOGUS;
		handled = UNHANDLED;
		break;

	case EXCP_TYPE_EL1_ERROR:
	case EXCP_TYPE_EL2_SYNC:
	case EXCP_TYPE_EL2_IRQ:
	case EXCP_TYPE_EL2_FIQ:
	case EXCP_TYPE_EL2_ERROR:
		eprintf("Unhandled exception type: %s\n", __STRING(excp_type));
		vme->exitcode = VM_EXITCODE_BOGUS;
		handled = UNHANDLED;
		break;

	default:
		eprintf("Unknown exception type: %d\n", excp_type);
		vme->exitcode = VM_EXITCODE_BOGUS;
		handled = UNHANDLED;
		break;
	}

	return (handled);
}

static int
arm_vmrun(void *arg, int vcpu, register_t pc, pmap_t pmap,
    struct vm_eventinfo *evinfo)
{
	uint64_t excp_type;
	int handled;
	register_t daif;
	struct hyp *hyp;
	struct hypctx *hypctx;
	struct vm *vm;
	struct vm_exit *vme;

	hyp = (struct hyp *)arg;
	vm = hyp->vm;
	vme = vm_exitinfo(vm, vcpu);

	hypctx = &hyp->ctx[vcpu];
	hypctx->tf.tf_elr = (uint64_t)pc;

	for (;;) {
		daif = intr_disable();

		/* Check if the vcpu is suspended */
		if (vcpu_suspended(evinfo)) {
			intr_restore(daif);
			vm_exit_suspended(vm, vcpu, pc);
			break;
		}

		/* Activate the stage2 pmap so the vmid is valid */
		pmap_activate_vm(pmap);
		hyp->vttbr_el2 = pmap_to_ttbr0(pmap);

		/*
		 * TODO: What happens if a timer interrupt is asserted exactly
		 * here, but for the previous VM?
		 */
		arm64_set_active_vcpu(hypctx);
		vgic_v3_flush_hwstate(hypctx);

		/* Call into EL2 to switch to the guest */
		excp_type = vmm_call_hyp(HYP_ENTER_GUEST,
		    hyp->el2_addr, vcpu);

		vgic_v3_sync_hwstate(hypctx);

		/*
		 * Deactivate the stage2 pmap. vmm_pmap_clean_stage2_tlbi
		 * depends on this meaning we activate the VM before entering
		 * the vm again
		 */
		PCPU_SET(curvmpmap, NULL);
		intr_restore(daif);

		if (excp_type == EXCP_TYPE_MAINT_IRQ)
			continue;

		vme->pc = hypctx->tf.tf_elr;
		vme->inst_length = INSN_SIZE;
		vme->u.hyp.exception_nr = excp_type;
		vme->u.hyp.esr_el2 = hypctx->tf.tf_esr;
		vme->u.hyp.far_el2 = hypctx->exit_info.far_el2;
		vme->u.hyp.hpfar_el2 = hypctx->exit_info.hpfar_el2;

		handled = arm64_handle_world_switch(hyp, vcpu, excp_type, vme,
		    pmap);
		if (handled == UNHANDLED)
			/* Exit loop to emulate instruction. */
			break;
		else
			/* Resume guest execution from the next instruction. */
			hypctx->tf.tf_elr += vme->inst_length;
	}

	return (0);
}

static void
arm_pcpu_vmcleanup(void *arg)
{
	struct hyp *hyp;
	int i, maxcpus;

	hyp = arg;
	maxcpus = vm_get_maxcpus(hyp->vm);
	for (i = 0; i < maxcpus; i++) {
		if (arm64_get_active_vcpu() == &hyp->ctx[i]) {
			arm64_set_active_vcpu(NULL);
			break;
		}
	}
}

static void
arm_vmcleanup(void *arg)
{
	struct hyp *hyp = arg;
	struct hypctx *hypctx;
	int i;

	for (i = 0; i < VM_MAXCPU; i++) {
		hypctx = &hyp->ctx[i];
		vtimer_cpucleanup(hypctx);
		vgic_v3_cpucleanup(hypctx);
	}

	vtimer_vmcleanup(hyp);
	vgic_v3_vmcleanup(hyp);

	smp_rendezvous(NULL, arm_pcpu_vmcleanup, NULL, hyp);

	/* Unmap the VM hyp struct from the hyp mode translation table */
	vmmpmap_remove(hyp->el2_addr, roundup2(sizeof(*hyp), PAGE_SIZE),
	    true);

	free(hyp, M_HYP);
}

/*
 * Return register value. Registers have different sizes and an explicit cast
 * must be made to ensure proper conversion.
 */
static void *
hypctx_regptr(struct hypctx *hypctx, int reg)
{
	switch (reg) {
	case VM_REG_GUEST_X0:
		return (&hypctx->tf.tf_x[0]);
	case VM_REG_GUEST_X1:
		return (&hypctx->tf.tf_x[1]);
	case VM_REG_GUEST_X2:
		return (&hypctx->tf.tf_x[2]);
	case VM_REG_GUEST_X3:
		return (&hypctx->tf.tf_x[3]);
	case VM_REG_GUEST_X4:
		return (&hypctx->tf.tf_x[4]);
	case VM_REG_GUEST_X5:
		return (&hypctx->tf.tf_x[5]);
	case VM_REG_GUEST_X6:
		return (&hypctx->tf.tf_x[6]);
	case VM_REG_GUEST_X7:
		return (&hypctx->tf.tf_x[7]);
	case VM_REG_GUEST_X8:
		return (&hypctx->tf.tf_x[8]);
	case VM_REG_GUEST_X9:
		return (&hypctx->tf.tf_x[9]);
	case VM_REG_GUEST_X10:
		return (&hypctx->tf.tf_x[10]);
	case VM_REG_GUEST_X11:
		return (&hypctx->tf.tf_x[11]);
	case VM_REG_GUEST_X12:
		return (&hypctx->tf.tf_x[12]);
	case VM_REG_GUEST_X13:
		return (&hypctx->tf.tf_x[13]);
	case VM_REG_GUEST_X14:
		return (&hypctx->tf.tf_x[14]);
	case VM_REG_GUEST_X15:
		return (&hypctx->tf.tf_x[15]);
	case VM_REG_GUEST_X16:
		return (&hypctx->tf.tf_x[16]);
	case VM_REG_GUEST_X17:
		return (&hypctx->tf.tf_x[17]);
	case VM_REG_GUEST_X18:
		return (&hypctx->tf.tf_x[18]);
	case VM_REG_GUEST_X19:
		return (&hypctx->tf.tf_x[19]);
	case VM_REG_GUEST_X20:
		return (&hypctx->tf.tf_x[20]);
	case VM_REG_GUEST_X21:
		return (&hypctx->tf.tf_x[21]);
	case VM_REG_GUEST_X22:
		return (&hypctx->tf.tf_x[22]);
	case VM_REG_GUEST_X23:
		return (&hypctx->tf.tf_x[23]);
	case VM_REG_GUEST_X24:
		return (&hypctx->tf.tf_x[24]);
	case VM_REG_GUEST_X25:
		return (&hypctx->tf.tf_x[25]);
	case VM_REG_GUEST_X26:
		return (&hypctx->tf.tf_x[26]);
	case VM_REG_GUEST_X27:
		return (&hypctx->tf.tf_x[27]);
	case VM_REG_GUEST_X28:
		return (&hypctx->tf.tf_x[28]);
	case VM_REG_GUEST_X29:
		return (&hypctx->tf.tf_x[29]);
	case VM_REG_GUEST_LR:
		return (&hypctx->tf.tf_lr);
	case VM_REG_GUEST_SP:
		return (&hypctx->tf.tf_sp);
	case VM_REG_GUEST_ELR: /* This is bogus */
		return (&hypctx->tf.tf_elr);
	case VM_REG_GUEST_SPSR: /* This is bogus */
		return (&hypctx->tf.tf_spsr);
	case VM_REG_ELR_EL2:
		return (&hypctx->tf.tf_elr);
	default:
		break;
	}
	return (NULL);
}

static int
arm_getreg(void *arg, int vcpu, int reg, uint64_t *retval)
{
	void *regp;
	int running, hostcpu;
	struct hyp *hyp = arg;

	running = vcpu_is_running(hyp->vm, vcpu, &hostcpu);
	if (running && hostcpu != curcpu)
		panic("arm_getreg: %s%d is running", vm_name(hyp->vm), vcpu);

	if ((regp = hypctx_regptr(&hyp->ctx[vcpu], reg)) != NULL) {
		if (reg == VM_REG_GUEST_SPSR)
			*retval = *(uint32_t *)regp;
		else
			*retval = *(uint64_t *)regp;
		return (0);
	} else {
		return (EINVAL);
	}
}

static int
arm_setreg(void *arg, int vcpu, int reg, uint64_t val)
{
	void *regp;
	struct hyp *hyp = arg;
	int running, hostcpu;

	running = vcpu_is_running(hyp->vm, vcpu, &hostcpu);
	if (running && hostcpu != curcpu)
		panic("hyp_setreg: %s%d is running", vm_name(hyp->vm), vcpu);

	if ((regp = hypctx_regptr(&hyp->ctx[vcpu], reg)) != NULL) {
		if (reg == VM_REG_GUEST_SPSR)
			*(uint32_t *)regp = (uint32_t)val;
		else
			*(uint64_t *)regp = val;
		return (0);
	} else {
		return (EINVAL);
	}
}

static int
arm_getcap(void *arg, int vcpu, int type, int *retval)
{
	int ret;

	ret = ENOENT;

	switch (type) {
	case VM_CAP_UNRESTRICTED_GUEST:
		*retval = 1;
		ret = 0;
		break;
	default:
		break;
	}

	return (ret);
}

static int
arm_setcap(void *arg, int vcpu, int type, int val)
{

	return (ENOENT);
}

static
void arm_restore(void)
{
	;
}

struct vmm_ops vmm_ops_arm = {
	.init = arm_init,
	.cleanup = arm_cleanup,
	.resume = arm_restore,
	.vminit = arm_vminit,
	.vmrun = arm_vmrun,
	.vmcleanup = arm_vmcleanup,
	.vmgetreg = arm_getreg,
	.vmsetreg = arm_setreg,
	.vmgetcap = arm_getcap,
	.vmsetcap = arm_setcap,
	.vmspace_alloc	= arm_vmspace_alloc,
	.vmspace_free	= arm_vmspace_free,
};
