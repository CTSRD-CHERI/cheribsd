/*-
 * Copyright (c) 2012-2014 Andrew Turner
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
 * $FreeBSD$
 */

#include "assym.inc"
#include "opt_kstack_pages.h"
#include <sys/syscall.h>
#include <machine/asm.h>
#include <machine/armreg.h>
#include <machine/hypervisor.h>
#include <machine/param.h>
#include <machine/pte.h>
#include <machine/vm.h>
#include <machine/vmparam.h>

#include <machine/cherireg.h>

#define	VIRT_BITS	48

#if PAGE_SIZE == PAGE_SIZE_16K
/*
 * The number of level 3 tables to create. 32 will allow for 1G of address
 * space, the same as a single level 2 page with 4k pages.
 */
#define	L3_PAGE_COUNT	32
#endif

	.globl	kernbase
	.set	kernbase, KERNBASE

/*
 * We assume:
 *  MMU      on with an identity map, or off
 *  D-Cache: off
 *  I-Cache: on or off
 *  We are loaded at a 2MiB aligned address
 *
 *  In CHERI kernels we assume that DDC is a valid root capability
 *  covering the whole address space and PCC is a valid root
 *  executable capability covering the whole address space.
 */

/*
 * Relocate kernel vaddr to the boot identity mapping
 */
.macro early_idmap_addr dreg, sym, delta
	ldr	\dreg, =\sym
	add	\dreg, \dreg, \delta
.endmacro

/*
 * Build kernel pointer for the given data symbol
 * assuming the kernel mmu mapping is enabled
 */
.macro buildptr dregn, sym, size
	ldr	x\dregn, =\sym
#ifdef __CHERI_PURE_CAPABILITY__
	cvtd	c\dregn, x\dregn
	scbnds	c\dregn, c\dregn, \size
#endif
.endmacro

.macro buildptr_range sregn, eregn, start_sym, end_sym, clrperm = x
	ldr	x\sregn, =\start_sym
	ldr	x\eregn, =\end_sym
#ifdef __CHERI_PURE_CAPABILITY__
	sub	x\eregn, x\eregn, x\sregn
	cvtd	c\sregn, x\sregn
	scbnds	c\sregn, c\sregn, x\eregn
	clrperm	c\sregn, c\sregn, \clrperm
	add	c\eregn, c\sregn, x\eregn
#endif
.endmacro

/*
 * Jump into the kernel virtual address at the given position
 * This also restricts the kernel PCC
 */
.macro enter_kern_vaddr regn, scratch1n, scratch2n, dstsym
	ldr	x\regn, =\dstsym
#ifdef __CHERI_PURE_CAPABILITY__
	orr	x\regn, x\regn, #1	/* c64 mode */
	ldr	x\scratch2n, =etext	/* XXX-AM: TODO use correct end symbol */
	ldr	x\scratch1n, =KERNBASE
	sub	x\scratch2n, x\scratch2n, x\scratch1n
	cvtp	c\scratch1n, x\scratch1n
	//scbnds	c\scratch1n, c\scratch1n, x\scratch2n /* XXX-AM: needs reordering of ELF sections */
	scvalue	c\regn, c\scratch1n, x\regn
	clrperm	c\regn, c\regn, w
#endif
	br	PTR(\regn)
.endmacro

/*
 * Helper to clear ddc and all other general-purpose capability registers,
 * except c0.
 */
.macro clear_capregs
#ifdef __CHERI_PURE_CAPABILITY__
	msr	ddc, czr
	mov	x1, xzr
	mov	x2, xzr
	mov	x3, xzr
	mov	x4, xzr
	mov	x5, xzr
	mov	x6, xzr
	mov	x7, xzr
	mov	x8, xzr
	mov	x9, xzr
	mov	x10, xzr
	mov	x11, xzr
	mov	x12, xzr
	mov	x13, xzr
	mov	x14, xzr
	mov	x15, xzr
	mov	x16, xzr
	mov	x17, xzr
	mov	x18, xzr
	mov	x19, xzr
	mov	x20, xzr
	mov	x21, xzr
	mov	x22, xzr
	mov	x23, xzr
	mov	x24, xzr
	mov	x25, xzr
	mov	x26, xzr
	mov	x27, xzr
	mov	x28, xzr
	mov	x29, xzr
	mov	x30, xzr
#endif
.endmacro

/*
 * Initialize morello on a cpu
 */
.macro morello_cpu_init
#if __has_feature(capabilities)
	/* Enable Morello instructions at EL0 and EL1 */
	mrs	x2, cpacr_el1
	bic	x2, x2, CPACR_CEN_MASK
	orr	x2, x2, CPACR_CEN_TRAP_NONE
	msr	cpacr_el1, x2
	isb

	/*
	 * Allow access to CNTVCT_EL0 without PCC System permission and enable
	 * capability sealing for branch and link at EL0.
	 *
	 * XXXBFG should this be done somewhere else? Maybe eventually per-process or
	 * compartment?
	 */
	mrs x2, cctlr_el0
	orr x2, x2, #(CCTLR_PERMVCT_MASK | CCTLR_SBL_MASK)
	msr cctlr_el0, x2

#ifdef __CHERI_PURE_CAPABILITY__
	/*
	 * Enable capablity sealing for branch and link at EL1
	 * Use PCC/DDC address interpretation.
	 * Use DDC as base for adrdp.
	 */
	mrs	x2, cctlr_el1
	bic	x2, x2, #(CCTLR_PCCBO_MASK | CCTLR_DDCBO_MASK | CCTLR_ADRDPB_MASK)
	orr	x2, x2, #(CCTLR_SBL_MASK)
	msr	cctlr_el1, x2

	/* We assume that we enter here in a64 mode. */
	bx	#4
	.arch_extension c64
#endif
#endif
.endmacro

ENTRY(_start)
#ifdef __CHERI_PURE_CAPABILITY__
	.arch_extension noc64
	.arch_extension a64c
#endif

	/*
	 * Drop to EL1
	 * Note: this is done while still in A64 mode.
	 */
	bl	drop_to_el1

	/* Initialize morello capability ISA and switch to C64 if needed */
	morello_cpu_init

	/*
	 * Disable the MMU. We may have entered the kernel with it on and
	 * will need to update the tables later. If this has been set up
	 * with anything other than a VA == PA map then this will fail,
	 * but in this case the code to find where we are running from
	 * would have also failed.
	 */
	dsb	sy
	mrs	x2, sctlr_el1
	bic	x2, x2, SCTLR_M
	msr	sctlr_el1, x2
	isb

	/* Set the context id */
	msr	contextidr_el1, xzr

	/* Get the virt -> phys offset */
	bl	get_virt_delta

	/*
	 * At this point:
	 * x29 = PA - VA
	 * x28 = Our physical load address
	 */

	/* Create the page tables */
	bl	create_pagetables

	/*
	 * At this point:
	 * x27 = TTBR0 table phys addr
	 * x26 = Kernel L1 table phys addr
	 * x24 = TTBR1 table phys addr
	 */

	/* Enable the mmu */
	bl	start_mmu

	/* Load the new ttbr0 pagetable */
	early_idmap_addr x27, pagetable_l0_ttbr0, x29

	/* Jump to the virtual address space */
	enter_kern_vaddr 15, 7, 8, virtdone

virtdone:
	/* Set up the stack */
	mov	x7, #(PAGE_SIZE * KSTACK_PAGES)
	buildptr 25, initstack, x7
	/* Preserve initstack in x/c25 for bootparams */
	add	PTR(7), PTR(25), x7
	/*
	 * Can not yet enforce bounds between PCB and KSTACK as we have
	 * no place to store the PCB pointer here.
	 * XXX-AM: It could be another bootparam if needed
	 */
	mov	PTRN(sp), PTR(7)
	sub	PTRN(sp), PTRN(sp), #PCB_SIZE

	/* Zero the BSS */
	buildptr_range 15, 14, _bss_start, _end
1:
	str	xzr, [PTR(15)], #8
	cmp	PTR(15), PTR(14)
	b.lo	1b

#if defined(PERTHREAD_SSP)
	/* Set sp_el0 to the boot canary for early per-thread SSP to work */
	adrp	x15, boot_canary
	add	x15, x15, :lo12:boot_canary
	msr	sp_el0, x15
#endif

	/* Backup the module pointer */
	mov	x19, x0

#if __has_feature(capabilities)
#ifdef __CHERI_PURE_CAPABILITY__
	/* Do capability relocations */
	mrs	c1, ddc
	adr	c2, #0
	/* Assume can we reach _DYNAMIC from PCC */
	adrp	c0, _DYNAMIC
	add	c0, c0, :lo12:_DYNAMIC
	bl	elf_reloc_self
#endif
	/* Initialize capabilities. */
	mrs	c0, ddc
	bl	cheri_init_capabilities
#endif

	/* Make the page table base a virtual address */
	sub	x26, x26, x29
	sub	x24, x24, x29
#ifdef __CHERI_PURE_CAPABILITY__
	/*
	 * Convert modulep into a capability
	 * XXX-AM: can we set bounds on this?
	 * TODO: clear perms
	 */
	cvtd	c19, x19

	/* Rebuild L1PT and L0PT capabilities */
	mov	x6, #PAGE_SIZE
	ldr	x7, =.Lpagetable_clrperms
	cvtd	c24, x24
	scbnds	c24, c24, x6
	clrperm	c24, c24, x7
	cvtd	c26, x26
	scbnds	c26, c26, x6
	clrperm	c26, c26, x7
#endif

	/* Negate the delta so it is VA -> PA */
	neg	x29, x29

	sub	PTRN(sp), PTRN(sp), #BOOTPARAMS_SIZE
	mov	PTR(0), PTRN(sp)

	str	PTR(19), [PTR(0), #BP_MODULEP]
	str	PTR(26), [PTR(0), #BP_KERN_L1PT]
	str	x29, [PTR(0), #BP_KERN_DELTA]
	str	PTR(25), [PTR(0), #BP_KERN_STACK]
	str	PTR(24), [PTR(0), #BP_KERN_L0PT]
	str	x27, [PTR(0), #BP_KERN_TTBR0]
	str	x23, [PTR(0), #BP_BOOT_EL]

	/* trace back starts here */
	mov	fp, #0

	/* Branch to C code */
	clear_capregs
	bl	initarm
	/* We are done with the boot params */
	add	PTRN(sp), PTRN(sp), #BOOTPARAMS_SIZE

#ifdef PAC
	/*
	 * Enable pointer authentication in the kernel. We set the keys for
	 * thread0 in initarm so have to wait until it returns to enable it.
	 * If we were to enable it in initarm then any authentication when
	 * returning would fail as it was called with pointer authentication
	 * disabled.
	 */
	bl	ptrauth_start
#endif

	bl	mi_startup

	/* We should not get here */
	brk	0

	.align 3
END(_start)
#ifdef __CHERI_PURE_CAPABILITY__
.Lpagetable_clrperms:
	.quad ~(CHERI_PERM_GLOBAL | CHERI_PERM_LOAD | CHERI_PERM_STORE)
#endif

#ifdef SMP
/*
 * mpentry(unsigned long)
 *
 * Called by a core when it is being brought online.
 * The data in x0 is passed straight to init_secondary.
 */
ENTRY(mpentry)
#ifdef __CHERI_PURE_CAPABILITY__
	.arch_extension noc64
	.arch_extension a64c
#endif
	/* Disable interrupts */
	msr	daifset, #DAIF_INTR

	/* Drop to EL1 */
	bl	drop_to_el1

	/* Initialize morello capability ISA and switch to C64 if needed */
	morello_cpu_init

	/* Set the context id */
	msr	contextidr_el1, xzr

	/* Get the virt -> phys offset */
	bl	get_virt_delta

	/* Load the kernel page table */
	early_idmap_addr x24, pagetable_l0_ttbr1, x29
	/* Load the identity page table */
	early_idmap_addr x27, pagetable_l0_ttbr0_bootstrap, x29

	/* Enable the mmu */
	bl	start_mmu

	/* Load the new ttbr0 pagetable */
	early_idmap_addr x27, pagetable_l0_ttbr0, x29

	/* Jump to the virtual address space */
	enter_kern_vaddr 15, 7, 8, mp_virtdone

mp_virtdone:
	/* Start using the AP boot stack */
	LDR_LABEL(PTR(4), PTR(4), bootstack)
	mov	PTRN(sp), PTR(4)

#if defined(PERTHREAD_SSP)
	/* Set sp_el0 to the boot canary for early per-thread SSP to work */
	adrp	x15, boot_canary
	add	x15, x15, :lo12:boot_canary
	msr	sp_el0, x15
#endif

	/* Load the kernel ttbr0 pagetable */
	msr	ttbr0_el1, x27
	isb

	/* Invalidate the TLB */
	tlbi	vmalle1
	dsb	sy
	isb

	clear_capregs

	b	init_secondary
END(mpentry)
#endif

/*
 * If we are started in EL2, configure the required hypervisor
 * registers and drop to EL1.
 */
LENTRY(drop_to_el1)
#ifdef __CHERI_PURE_CAPABILITY__
	.arch_extension noc64
	.arch_extension a64c
#endif
	mrs	x23, CurrentEL
	lsr	x23, x23, #2
	cmp	x23, #0x2
	b.eq	1f
	ret
1:
	/*
	 * Disable the MMU. If the HCR_EL2.E2H field is set we will clear it
	 * which may break address translation.
	 */
	dsb	sy
	mrs	x2, sctlr_el2
	bic	x2, x2, SCTLR_M
	msr	sctlr_el2, x2
	isb

	/* Configure the Hypervisor */
	ldr	x2, =(HCR_RW | HCR_APK | HCR_API)
	msr	hcr_el2, x2

	/* Load the Virtualization Process ID Register */
	mrs	x2, midr_el1
	msr	vpidr_el2, x2

	/* Load the Virtualization Multiprocess ID Register */
	mrs	x2, mpidr_el1
	msr	vmpidr_el2, x2

	/* Set the bits that need to be 1 in sctlr_el1 */
	ldr	x2, .Lsctlr_res1
	msr	sctlr_el1, x2

	/* Don't trap to EL2 for exceptions */
	mov	x2, #CPTR_RES1
	msr	cptr_el2, x2

#if __has_feature(capabilities)
	/*
	 * Wait for the write to cptr_el2 to complete. It will enable the
	 * use of capabilities at EL2 that we need below. When not using
	 * capabilities this is unneeded as the eret instruction will
	 * act as in place of this barrier.
	 */
	isb
#endif

	/* Don't trap to EL2 for CP15 traps */
	msr	hstr_el2, xzr

	/* Enable access to the physical timers at EL1 */
	mrs	x2, cnthctl_el2
	orr	x2, x2, #(CNTHCTL_EL1PCTEN | CNTHCTL_EL1PCEN)
	msr	cnthctl_el2, x2

	/* Set the counter offset to a known value */
	msr	cntvoff_el2, xzr

	/* Hypervisor trap functions */
	adrp	x2, hyp_vectors
	add	x2, x2, :lo12:hyp_vectors
#if __has_feature(capabilities)
	cvtp	c2, x2
	msr	cvbar_el2, c2
#else
	msr	vbar_el2, x2
#endif

	mov	x2, #(PSR_F | PSR_I | PSR_A | PSR_D | PSR_M_EL1h)
	msr	spsr_el2, x2

	/* Configure GICv3 CPU interface */
	mrs	x2, id_aa64pfr0_el1
	/* Extract GIC bits from the register */
	ubfx	x2, x2, #ID_AA64PFR0_GIC_SHIFT, #ID_AA64PFR0_GIC_BITS
	/* GIC[3:0] == 0001 - GIC CPU interface via special regs. supported */
	cmp	x2, #(ID_AA64PFR0_GIC_CPUIF_EN >> ID_AA64PFR0_GIC_SHIFT)
	b.ne	2f

	mrs	x2, icc_sre_el2
	orr	x2, x2, #ICC_SRE_EL2_EN	/* Enable access from insecure EL1 */
	orr	x2, x2, #ICC_SRE_EL2_SRE	/* Enable system registers */
	msr	icc_sre_el2, x2
2:

	/* Set the address to return to our return address */
#if __has_feature(capabilities)
	cvtp	c30, x30
	msr	celr_el2, c30
#else
	msr	elr_el2, x30
#endif
	isb

	eret
#ifdef __CHERI_PURE_CAPABILITY__
	.arch_extension c64
#endif

	.align 3
.Lsctlr_res1:
	.quad SCTLR_RES1
LEND(drop_to_el1)

#define	VECT_EMPTY	\
	.align 7;	\
	1:	b	1b

	.align 11
hyp_vectors:
	VECT_EMPTY	/* Synchronous EL2t */
	VECT_EMPTY	/* IRQ EL2t */
	VECT_EMPTY	/* FIQ EL2t */
	VECT_EMPTY	/* Error EL2t */

	VECT_EMPTY	/* Synchronous EL2h */
	VECT_EMPTY	/* IRQ EL2h */
	VECT_EMPTY	/* FIQ EL2h */
	VECT_EMPTY	/* Error EL2h */

	VECT_EMPTY	/* Synchronous 64-bit EL1 */
	VECT_EMPTY	/* IRQ 64-bit EL1 */
	VECT_EMPTY	/* FIQ 64-bit EL1 */
	VECT_EMPTY	/* Error 64-bit EL1 */

	VECT_EMPTY	/* Synchronous 32-bit EL1 */
	VECT_EMPTY	/* IRQ 32-bit EL1 */
	VECT_EMPTY	/* FIQ 32-bit EL1 */
	VECT_EMPTY	/* Error 32-bit EL1 */

/*
 * Get the delta between the physical address we were loaded to and the
 * virtual address we expect to run from. This is used when building the
 * initial page table.
 */
LENTRY(get_virt_delta)
	/* Load the physical address of virt_map */
	adrp	PTR(29), virt_map
	add	PTR(29), PTR(29), :lo12:virt_map
	/* Load the virtual address of virt_map stored in virt_map */
	ldr	x28, [PTR(29)]
	/* Find PA - VA as PA' = VA' - VA + PA = VA' + (PA - VA) = VA' + x29 */
	sub	x29, x29, x28
	/* Find the load address for the kernel */
	mov	x28, #(KERNBASE)
	add	x28, x28, x29
	ret

	.align 3
virt_map:
	.quad	virt_map
LEND(get_virt_delta)

/*
 * This builds the page tables containing the identity map, and the kernel
 * virtual map.
 *
 * It relys on:
 *  We were loaded to an address that is on a 2MiB boundary
 *  All the memory must not cross a 1GiB boundaty
 *  x28 contains the physical address we were loaded from
 *  x29 contains the load address delta (PA - VA)
 *
 * Returns:
 *  x27 TTBR0 table phys addr
 *  x26 Kernel L1 table phys addr
 *  x24 TTBR1 table phys addr
 *
 * TODO: This is out of date.
 *  There are at least 5 pages before that address for the page tables
 *   The pages used are:
 *    - The Kernel L2 table
 *    - The Kernel L1 table
 *    - The Kernel L0 table             (TTBR1)
 *    - The identity (PA = VA) L1 table
 *    - The identity (PA = VA) L0 table (TTBR0)
 */
LENTRY(create_pagetables)
	/* Save the Link register */
	mov	PTR(5), PTR(30)

	/* Clean the page table */
	/*
	 * Get pointer to the pagetable in the .init_pagetable section
	 * We need to manually relocate the address to access it using
	 * the boot identity map
	 */
	ldr	x6, =pagetable
	add	x6, x6, x29
	ldr	x27, =pagetable_end
	add	x27, x27, x29
#ifdef __CHERI_PURE_CAPABILITY__
	sub	x7, x27, x6
	cvtd	c6, x6
	scbnds	c6, c6, x7
	ldr	x7, =.Lpagetable_clrperms
	clrperm	c6, c6, x7
	scvalue	c27, c6, x27
#endif
	mov	PTR(26), PTR(6)	/* Save start addr for later */
1:
	stp	xzr, xzr, [PTR(6)], #16
	stp	xzr, xzr, [PTR(6)], #16
	stp	xzr, xzr, [PTR(6)], #16
	stp	xzr, xzr, [PTR(6)], #16
	cmp	PTR(6), PTR(27)
	b.lo	1b

	/*
	 * Build the TTBR1 maps.
	 */

	/* Find the size of the kernel */
	mov	x6, #(KERNBASE)

#if defined(LINUX_BOOT_ABI)
	/* X19 is used as 'map FDT data' flag */
	mov	x19, xzr

	/* No modules or FDT pointer ? */
	cbz	x0, booti_no_fdt

	/*
	 * Test if x0 points to modules descriptor(virtual address) or
	 * to FDT (physical address)
	 */
	cmp	x0, x6		/* x6 is #(KERNBASE) */
	b.lo	booti_fdt
#endif

	/* Booted with modules pointer */
	/* Find modulep - begin */
	sub	x8, x0, x6
	/*
	 * Add space for the module data. When PAGE_SIZE is 4k this will
	 * add at least 2 level 2 blocks (2 * 2MiB). When PAGE_SIZE is
	 * larger it will be at least as large as we use smaller level 3
	 * pages.
	 */
	ldr	x7, =((6 * 1024 * 1024) - 1)
	add	x8, x8, x7
	b	common

#if defined(LINUX_BOOT_ABI)
booti_fdt:
	/* Booted by U-Boot booti with FDT data */
	/* Set 'map FDT data' flag */
	mov	x19, #1

booti_no_fdt:
	/* Booted by U-Boot booti without FTD data */
	/* Find the end - begin */
	ldr     x7, =_end
	sub     x8, x7, x6

	/*
	 * Add one 2MiB page for copy of FDT data (maximum FDT size),
	 * one for metadata and round up
	 */
	ldr	x7, =(3 * L2_SIZE - 1)
	add	x8, x8, x7
#endif

common:
#if PAGE_SIZE != PAGE_SIZE_4K
	/*
	 * Create L3 pages. The kernel will be loaded at a 2M aligned
	 * address, however L2 blocks are too large when the page size is
	 * not 4k to map the kernel with such an aligned address. However,
	 * when the page size is larger than 4k, L2 blocks are too large to
	 * map the kernel with such an alignment.
	 */

	/* Get the number of l3 pages to allocate, rounded down */
	lsr	x10, x8, #(L3_SHIFT)

	/* Create the kernel space L2 table */
	mov	PTR(6), PTR(26)
	mov	x7, #(ATTR_S1_IDX(VM_MEMATTR_WRITE_BACK))
	mov	x8, #(KERNBASE)
	mov	x9, x28
	bl	build_l3_page_pagetable

	/* Move to the l2 table */
	ldr	x9, =(PAGE_SIZE * L3_PAGE_COUNT)
	add	PTR(26), PTR(26), x9

	/* Link the l2 -> l3 table */
	mov	x9, x6
	mov	PTR(6), PTR(26)
	bl	link_l2_pagetable
#else
	/* Get the number of l2 pages to allocate, rounded down */
	lsr	x10, x8, #(L2_SHIFT)

	/* Create the kernel space L2 table */
	mov	PTR(6), PTR(26)
	mov	x7, #(ATTR_S1_IDX(VM_MEMATTR_WRITE_BACK))
	mov	x8, #(KERNBASE)
	mov	x9, x28
	bl	build_l2_block_pagetable
#endif

	/* Move to the l1 table */
	add	PTR(26), PTR(26), #PAGE_SIZE

	/* Link the l1 -> l2 table */
	mov	x9, x6
	mov	PTR(6), PTR(26)
	bl	link_l1_pagetable

	/* Move to the l0 table */
	add	PTR(24), PTR(26), #PAGE_SIZE

	/* Link the l0 -> l1 table */
	mov	x9, x6
	mov	PTR(6), PTR(24)
	mov	x10, #1
	bl	link_l0_pagetable

	/*
	 * Build the TTBR0 maps.  As TTBR0 maps, they must specify ATTR_S1_nG.
	 * They are only needed early on, so the VA = PA map is uncached.
	 */
	add	PTR(27), PTR(24), #PAGE_SIZE

	mov	PTR(6), PTR(27)		/* The initial page table */

	/* Create the VA = PA map */
	mov	x7, #(ATTR_S1_nG | ATTR_S1_IDX(VM_MEMATTR_WRITE_BACK))
	adrp	PTR(16), _start
	and	x16, x16, #(~L2_OFFSET)
	mov	x9, x16		/* PA start */
	mov	x8, x16		/* VA start (== PA start) */
	mov	x10, #1
	bl	build_l2_block_pagetable

#if defined(SOCDEV_PA)
#ifdef __CHERI_PURE_CAPABILITY__
#error "TODO Implement for purecap kernel"
#endif
	/* Create a table for the UART */
	mov	x7, #(ATTR_S1_nG | ATTR_S1_IDX(VM_MEMATTR_DEVICE))
	ldr	x9, =(L2_SIZE)
	add	x16, x16, x9	/* VA start */
	mov	x8, x16

	/* Store the socdev virtual address */
	add	x17, x8, #(SOCDEV_PA & L2_OFFSET)
	adrp	x9, socdev_va
	str	x17, [x9, :lo12:socdev_va]

	mov	x9, #(SOCDEV_PA & ~L2_OFFSET)	/* PA start */
	mov	x10, #1
	bl	build_l2_block_pagetable
#endif

#if defined(LINUX_BOOT_ABI)
	/* Map FDT data ? */
	cbz	x19, 1f

	/* Create the mapping for FDT data (2 MiB max) */
	mov	x7, #(ATTR_S1_nG | ATTR_S1_IDX(VM_MEMATTR_WRITE_BACK))
	ldr	x9, =(L2_SIZE)
	add	x16, x16, x9	/* VA start */
	mov	x8, x16
	mov	x9, x0			/* PA start */
	/* Update the module pointer to point at the allocated memory */
	and	x0, x0, #(L2_OFFSET)	/* Keep the lower bits */
	add	x0, x0, x8		/* Add the aligned virtual address */

	mov	x10, #1
	bl	build_l2_block_pagetable

1:
#endif

	/* Move to the l1 table */
	add	PTR(27), PTR(27), #PAGE_SIZE

	/* Link the l1 -> l2 table */
	mov	x9, x6
	mov	PTR(6), PTR(27)
	bl	link_l1_pagetable

	/* Move to the l0 table */
	add	PTR(27), PTR(27), #PAGE_SIZE

	/* Link the l0 -> l1 table */
	mov	x9, x6
	mov	PTR(6), PTR(27)
	mov	x10, #1
	bl	link_l0_pagetable

#ifdef __CHERI_PURE_CAPABILITY__
	/*
	 * Return physical addresses instead of capabilities
	 * into the identity-mapped early address space.
	 */
	gcvalue x24, c24
	gcvalue x26, c26
	gcvalue x27, c27
#endif

	/* Restore the Link register */
	mov	PTR(30), PTR(5)
	ret
LEND(create_pagetables)

/*
 * Builds an L0 -> L1 table descriptor
 *
 *  x/c6  = L0 table
 *  x8  = Virtual Address
 *  x9  = L1 PA (trashed)
 *  x10 = Entry count (trashed)
 *  x11, x12 and x13 are trashed
 */
LENTRY(link_l0_pagetable)
	/*
	 * Link an L0 -> L1 table entry.
	 */
	/* Find the table index */
	lsr	x11, x8, #L0_SHIFT
	and	x11, x11, #L0_ADDR_MASK

	/* Build the L0 block entry */
	mov	x12, #L0_TABLE
	orr	x12, x12, #(TATTR_UXN_TABLE | TATTR_AP_TABLE_NO_EL0)

	/* Only use the output address bits */
	lsr	x9, x9, #PAGE_SHIFT
1:	orr	x13, x12, x9, lsl #PAGE_SHIFT

	/* Store the entry */
	str	x13, [PTR(6), x11, lsl #3]

	sub	x10, x10, #1
	add	x11, x11, #1
	add	x9, x9, #1
	cbnz	x10, 1b

	ret
LEND(link_l0_pagetable)

/*
 * Builds an L1 -> L2 table descriptor
 *
 *  x/c6  = L1 table
 *  x8  = Virtual Address
 *  x9  = L2 PA (trashed)
 *  x11, x12 and x13 are trashed
 */
LENTRY(link_l1_pagetable)
	/*
	 * Link an L1 -> L2 table entry.
	 */
	/* Find the table index */
	lsr	x11, x8, #L1_SHIFT
	and	x11, x11, #Ln_ADDR_MASK

	/* Build the L1 block entry */
	mov	x12, #L1_TABLE

	/* Only use the output address bits */
	lsr	x9, x9, #PAGE_SHIFT
	orr	x13, x12, x9, lsl #PAGE_SHIFT

	/* Store the entry */
	str	x13, [PTR(6), x11, lsl #3]

	ret
LEND(link_l1_pagetable)

/*
 * Builds count 2 MiB page table entry
 *  x/c6  = L2 table
 *  x7  = Block attributes
 *  x8  = VA start
 *  x9  = PA start (trashed)
 *  x10 = Entry count (trashed)
 *  x11, x12 and x13 are trashed
 */
LENTRY(build_l2_block_pagetable)
	/*
	 * Build the L2 table entry.
	 */
	/* Find the table index */
	lsr	x11, x8, #L2_SHIFT
	and	x11, x11, #Ln_ADDR_MASK

	/* Build the L2 block entry */
	orr	x12, x7, #L2_BLOCK
#if __has_feature(capabilities)
	orr	x12, x12, #(ATTR_CAP_RW)
#endif
	orr	x12, x12, #(ATTR_DEFAULT)
	orr	x12, x12, #(ATTR_S1_UXN)

	/* Only use the output address bits */
	lsr	x9, x9, #L2_SHIFT

	/* Set the physical address for this virtual address */
1:	orr	x13, x12, x9, lsl #L2_SHIFT

	/* Store the entry */
	str	x13, [PTR(6), x11, lsl #3]

	sub	x10, x10, #1
	add	x11, x11, #1
	add	x9, x9, #1
	cbnz	x10, 1b

	ret
LEND(build_l2_block_pagetable)

#if PAGE_SIZE != PAGE_SIZE_4K
/*
 * Builds an L2 -> L3 table descriptor
 *
 *  x/c6  = L2 table
 *  x8  = Virtual Address
 *  x9  = L3 PA (trashed)
 *  x11, x12 and x13 are trashed
 */
LENTRY(link_l2_pagetable)
	/*
	 * Link an L2 -> L3 table entry.
	 */
	/* Find the table index */
	lsr	x11, x8, #L2_SHIFT
	and	x11, x11, #Ln_ADDR_MASK

	/* Build the L1 block entry */
	mov	x12, #L2_TABLE

	/* Only use the output address bits */
	lsr	x9, x9, #PAGE_SHIFT
	orr	x13, x12, x9, lsl #PAGE_SHIFT

	/* Store the entry */
	str	x13, [PTR(6), x11, lsl #3]

	ret
LEND(link_l2_pagetable)

/*
 * Builds count level 3 page table entries
 *  x/c6  = L3 table
 *  x7  = Block attributes
 *  x8  = VA start
 *  x9  = PA start (trashed)
 *  x10 = Entry count (trashed)
 *  x11, x12 and x13 are trashed
 */
LENTRY(build_l3_page_pagetable)
	/*
	 * Build the L3 table entry.
	 */
	/* Find the table index */
	lsr	x11, x8, #L3_SHIFT
	and	x11, x11, #Ln_ADDR_MASK

	/* Build the L3 page entry */
	orr	x12, x7, #L3_PAGE
#if __has_feature(capabilities)
	orr	x12, x12, #(ATTR_CAP_RW)
#endif
	orr	x12, x12, #(ATTR_DEFAULT)
	orr	x12, x12, #(ATTR_S1_UXN)

	/* Only use the output address bits */
	lsr	x9, x9, #L3_SHIFT

	/* Set the physical address for this virtual address */
1:	orr	x13, x12, x9, lsl #L3_SHIFT

	/* Store the entry */
	str	x13, [PTR(6), x11, lsl #3]

	sub	x10, x10, #1
	add	x11, x11, #1
	add	x9, x9, #1
	cbnz	x10, 1b

	ret
LEND(build_l3_page_pagetable)
#endif

LENTRY(start_mmu)
	dsb	sy

	/* Load the exception vectors */
	ldr	x2, =exception_vectors
#if __has_feature(capabilities)
	cvtp	c2, x2
	msr	cvbar_el1, c2
#ifdef __CHERI_PURE_CAPABILITY__
	/* Enter exception handlers in C64 mode */
	mrs	x2, cctlr_el1
	orr	x2, x2, #(CCTLR_EL1_C64E_MASK)
	msr	cctlr_el1, x2
#endif
#else
	msr	vbar_el1, x2
#endif

	/* Load ttbr0 and ttbr1 */
	msr	ttbr0_el1, x27
	msr	ttbr1_el1, x24
	isb

	/* Clear the Monitor Debug System control register */
	msr	mdscr_el1, xzr

	/* Invalidate the TLB */
	tlbi	vmalle1is
	dsb	ish
	isb

	ldr	x2, mair
	msr	mair_el1, x2

	/*
	 * Setup TCR according to the PARange and ASIDBits fields
	 * from ID_AA64MMFR0_EL1 and the HAFDBS field from the
	 * ID_AA64MMFR1_EL1.  More precisely, set TCR_EL1.AS
	 * to 1 only if the ASIDBits field equals 0b0010.
	 */
	ldr	x2, tcr
	mrs	x3, id_aa64mmfr0_el1

	/* Copy the bottom 3 bits from id_aa64mmfr0_el1 into TCR.IPS */
	bfi	x2, x3, #(TCR_IPS_SHIFT), #(TCR_IPS_WIDTH)
	and	x3, x3, #(ID_AA64MMFR0_ASIDBits_MASK)

	/* Check if the HW supports 16 bit ASIDS */
	cmp	x3, #(ID_AA64MMFR0_ASIDBits_16)
	/* If so x3 == 1, else x3 == 0 */
	cset	x3, eq
	/* Set TCR.AS with x3 */
	bfi	x2, x3, #(TCR_ASID_SHIFT), #(TCR_ASID_WIDTH)

	/*
	 * Check if the HW supports access flag and dirty state updates,
	 * and set TCR_EL1.HA and TCR_EL1.HD accordingly.
	 */
	mrs	x3, id_aa64mmfr1_el1
	and	x3, x3, #(ID_AA64MMFR1_HAFDBS_MASK)
	cmp	x3, #1
	b.ne	1f
	orr 	x2, x2, #(TCR_HA)
	b	2f
1:
	cmp	x3, #2
	b.ne	2f
	orr 	x2, x2, #(TCR_HA | TCR_HD)
2:
	msr	tcr_el1, x2

	/*
	 * Setup SCTLR.
	 */
	ldr	x2, sctlr_set
	ldr	x3, sctlr_clear
	mrs	x1, sctlr_el1
	bic	x1, x1, x3	/* Clear the required bits */
	orr	x1, x1, x2	/* Set the required bits */
	msr	sctlr_el1, x1
	isb

	ret

	.align 3
mair:
	.quad	MAIR_ATTR(MAIR_DEVICE_nGnRnE, VM_MEMATTR_DEVICE_nGnRnE) | \
		MAIR_ATTR(MAIR_NORMAL_NC, VM_MEMATTR_UNCACHEABLE)   |	\
		MAIR_ATTR(MAIR_NORMAL_WB, VM_MEMATTR_WRITE_BACK)    |	\
		MAIR_ATTR(MAIR_NORMAL_WT, VM_MEMATTR_WRITE_THROUGH) |	\
		MAIR_ATTR(MAIR_DEVICE_nGnRE, VM_MEMATTR_DEVICE_nGnRE)
tcr:
#if PAGE_SIZE == PAGE_SIZE_4K
#define	TCR_TG	(TCR_TG1_4K | TCR_TG0_4K)
#elif PAGE_SIZE == PAGE_SIZE_16K
#define	TCR_TG	(TCR_TG1_16K | TCR_TG0_16K)
#else
#error Unsupported page size
#endif

#if __has_feature(capabilities)
#define	TCR_MORELLO	(TCR_HPD0 | TCR_HPD1 | TCR_HWU0 | TCR_HWU1)
#else
#define	TCR_MORELLO	0
#endif

	.quad (TCR_TxSZ(64 - VIRT_BITS) | TCR_TG | \
	    TCR_CACHE_ATTRS | TCR_SMP_ATTRS | TCR_MORELLO)
sctlr_set:
	/* Bits to set */
	.quad (SCTLR_LSMAOE | SCTLR_nTLSMD | SCTLR_UCI | SCTLR_SPAN | \
	    SCTLR_nTWE | SCTLR_nTWI | SCTLR_UCT | SCTLR_DZE | \
	    SCTLR_I | SCTLR_SED | SCTLR_SA0 | SCTLR_SA | SCTLR_C | \
	    SCTLR_M | SCTLR_CP15BEN)
sctlr_clear:
	/* Bits to clear */
	.quad (SCTLR_EE | SCTLR_E0E | SCTLR_IESB | SCTLR_WXN | SCTLR_UMA | \
	    SCTLR_ITD | SCTLR_A)
LEND(start_mmu)

ENTRY(abort)
	b abort
END(abort)

	.section .init_pagetable, "aw", %nobits
	.align PAGE_SHIFT
	/*
	 * 6 initial tables (in the following order):
	 *           L2 for kernel (High addresses)
	 *           L1 for kernel
	 *           L0 for kernel
	 *           L1 bootstrap for user   (Low addresses)
	 *           L0 bootstrap for user
	 *           L0 for user
	 */
pagetable:
#if PAGE_SIZE != PAGE_SIZE_4K
	.space	(PAGE_SIZE * L3_PAGE_COUNT)
pagetable_l2_ttbr1:
#endif
	.space	PAGE_SIZE
pagetable_l1_ttbr1:
	.space	PAGE_SIZE
	.globl pagetable_l0_ttbr1
	.type	pagetable_l0_ttbr1,#object
pagetable_l0_ttbr1:
	.space	PAGE_SIZE
	.size	pagetable_l0_ttbr1, . - pagetable_l0_ttbr1
pagetable_l2_ttbr0_bootstrap:
	.space	PAGE_SIZE
pagetable_l1_ttbr0_bootstrap:
	.space	PAGE_SIZE
pagetable_l0_ttbr0_bootstrap:
	.space	PAGE_SIZE
pagetable_l0_ttbr0:
	.space	PAGE_SIZE

pagetable_end:

	.type	el2_pagetable,#object
el2_pagetable:
	.space	PAGE_SIZE
	.size	el2_pagetable, . - el2_pagetable

	.align	4
	.type	initstack,#object
initstack:
	.space	(PAGE_SIZE * KSTACK_PAGES)
initstack_end:
	.size	initstack, initstack_end - initstack

/*
 * sigcode has to be labeled as an #object type so that the symbols
 * resolve to the correct address as a source for copies.  This also
 * ensures that captable pointers to it will be able to read it.  This
 * is fine as the code is never executed directly in the kernel, just
 * copied to places for userland to execute.
 */
#define	SIGCODE(sym)						\
	.section .rodata; .globl sym; .align 2; .type sym,#object; sym:	\
	.cfi_startproc

#ifdef COMPAT_FREEBSD64
SIGCODE(freebsd64_sigcode)
	blr	x8
	mov	x0, sp
	add	x0, x0, #SF_UC64

1:
	mov	x8, #SYS_sigreturn
	svc	0

	/* sigreturn failed, exit */
	mov	x8, #SYS_exit
	svc	0

	b	1b
	/* This may be copied to the stack, keep it 16-byte aligned */
	.align	3
END(freebsd64_sigcode)
freebsd64_esigcode:

	.data
	.align	3
	.global	freebsd64_szsigcode
	.type	freebsd64_szsigcode,#object
	.size	freebsd64_szsigcode, 8
freebsd64_szsigcode:
	.quad	freebsd64_esigcode - freebsd64_sigcode
#endif

SIGCODE(aarch32_sigcode)
	.word 0xe1a0000d	// mov r0, sp
	.word 0xe2800040	// add r0, r0, #SIGF_UC
	.word 0xe59f700c	// ldr r7, [pc, #12]
	.word 0xef000000	// swi #0
	.word 0xe59f7008	// ldr r7, [pc, #8]
	.word 0xef000000	// swi #0
	.word 0xeafffffa	// b . - 16
	.word SYS_sigreturn
	.word SYS_exit
	.align	3
END(aarch32_sigcode)
aarch32_esigcode:

	.data
	.global sz_aarch32_sigcode
	.type	sz_aarch32_sigcode,#object
	.size	sz_aarch32_sigcode, 8
sz_aarch32_sigcode:
	.quad aarch32_esigcode - aarch32_sigcode
