/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2015-2018 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 * Copyright (c) 2019-2021 Mitchell Horne <mhorne@FreeBSD.org>
 * Copyright (c) 2022-2024 The FreeBSD Foundation
 *
 * Portions of this software were developed by SRI International and the
 * University of Cambridge Computer Laboratory under DARPA/AFRL contract
 * FA8750-10-C-0237 ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Portions of this software were developed by the University of Cambridge
 * Computer Laboratory as part of the CTSRD Project, with support from the
 * UK Higher Education Innovation Fund (HEIF).
 *
 * Portions of this software were developed by Mitchell Horne
 * <mhorne@FreeBSD.org> under sponsorship from the FreeBSD Foundation.
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

#include "assym.inc"

#include <machine/asm.h>
#ifdef __CHERI_PURE_CAPABILITY__
#include <machine/cherireg.h>
#endif
#include <machine/cpu.h>
#include <machine/param.h>
#include <machine/pte.h>
#include <machine/riscvreg.h>
#include <machine/sbi.h>

.macro set_stvec ptrreg
#ifdef __CHERI_PURE_CAPABILITY__
#ifdef __riscv_xcheri
	csrw	stcc, \ptrreg
#else
	csrw	stvecc, \ptrreg
#endif
#else /* !defined(__CHERI_PURE_CAPABILITY__) */
	csrw	stvec, \ptrreg
#endif
.endmacro

/*
 * Set the CPU exception vector register.
 * Trashes t0, t1.
 */
.macro set_exception_handler
#ifdef __CHERI_PURE_CAPABILITY__
	llc	ct0, cpu_exception_handler
	set_stvec	ct0
#else /* !defined(__CHERI_PURE_CAPABILITY__) */
	la	t0, cpu_exception_handler
#if __has_feature(capabilities)
#ifdef __riscv_xcheri
	cspecialr	ct1, pcc
	scaddr	ct1, ct1, t0
	li	t0, 1
	csetflags ct1, ct1, t0
	cspecialw	stcc, ct1
#else
	modesw.cap
.option push
.option capmode
	auipc	ct1, 0
	scaddr	ct1, ct1, t0
	csrw	stvecc, ct1
	modesw.int
.option pop
#endif
#else /* !__has_feature(capabilities) */
	csrw	stvec, t0
#endif /* __has_feature(capabilities) */
#endif /* defined(__CHERI_PURE_CAPABILITY__) */
.endmacro

	.globl	kernbase
	.set	kernbase, KERNBASE

	.text
/*
 * Alternate entry point. Used when booting via SBI firmware. It must be placed
 * at the beginning of the .text section. Arguments are as follows:
 *  - a0 = hart ID
 *  - a1 = dtbp
 *
 * Multiple CPUs might enter from this point, so we perform a hart lottery and
 * send the losers to mpentry.
 */
	.globl _alt_start
_alt_start:
	/* Set the global pointer */
#ifdef __CHERI_PURE_CAPABILITY__
	cmv	cgp, cnull
#else
.option push
.option norelax
	lla	gp, __global_pointer$
.option pop
#endif

#ifdef __CHERI_PURE_CAPABILITY__
.option push
.option nocapmode

	/*
	 * The boot loader may enter in non-capmode even though
	 * our ELF header requests capmode.  The instructions below
	 * should work in both modes.
	 */
#if !defined(__riscv_xcheri)
	modesw.cap
#else
	lla	t0, 1f
	csrr	ct1, pcc
	scaddr	ct1, ct1, t0
	li	t0, 1
	csetflags ct1, ct1, t0
	jr.cap	ct1
#endif
1:
.option pop
#endif

	/* Pick a hart to run the boot process. */
	li	t1, 1
	LL_PTR	PTR(t0), hart_lottery
	amoadd.w t0, t1, 0(PTR(t0))

	/*
	 * We must jump to mpentry in the non-BSP case because the offset is
	 * too large to fit in a 12-bit branch immediate.
	 */
	beqz	t0, 1f
	j	mpentry
1:
	/* Store the boot hart */
	LL_PTR	PTR(t0), boot_hart
	sw	a0, 0(PTR(t0))

	/*
	 * Stash the DTB pointer in the callee-saved register s4, and zero s3
	 * to indicate that we have no loader metadata.
	 */
	mv	s4, a1
	mv	s3, zero
	j	pagetables

/*
 * Main entry point. This routine is marked as the ELF entry, and is where
 * loader(8) will enter the kernel. Arguments are as follows:
 *  - a0 = modulep
 *  - a1 = ???
 *
 * It is expected that only a single CPU will enter here.
 */
	.globl _start
_start:
	/* Set the global pointer */
#ifdef __CHERI_PURE_CAPABILITY__
	cmv	cgp, cnull
#else
.option push
.option norelax
	lla	gp, __global_pointer$
.option pop
#endif

	/*
	 * Stash modulep in the callee-saved register s3, and zero s4 to
	 * indicate that we have no DTB pointer. It is already included in the
	 * loader(8) metadata.
	 */
#ifdef __CHERI_PURE_CAPABILITY__
	cmv	cs3, ca0    
#else	
	mv	s3, a0
#endif
	mv	s4, zero

	/*
	 * Set up page tables: Our goal is to enable virtual memory, doing the
	 * minimum amount of work in assembly; just what is required to
	 * bootstrap. We will construct the real page tables in C code, in
	 * pmap_bootstrap().
	 *
	 * Here we map a 1GB region starting at KERNBASE using 2MB superpages,
	 * starting from the first 2MB physical page into which the kernel was
	 * loaded.
	 *
	 * We also use an L1 entry to create a 1GB identity map (1:1 PA->VA).
	 * This is useful for two reasons:
	 *  - handling the DTB pointer passed from SBI firmware (physical addr)
	 *  - simpler construction of pagetables in pmap_bootstrap()
	 *
	 * Implementations are required to provide Sv39 mode, so we use that
	 * here and will conditionally enable Sv48 (or higher) later.
	 *
	 * We arrive here with:
	 *  s3 - modulep or zero
	 *  s4 - zero or dtbp
	 */
pagetables:
	/* Get the kernel's load address (kernstart) in s9 */
#ifdef __CHERI_PURE_CAPABILITY__
	llc	cra, get_physmem
	jalr	cra
#else
	jal	get_physmem
#endif

	/* Get PTE attribute bits in s8 */
#ifdef __CHERI_PURE_CAPABILITY__
	llc	cra, get_pte_fixup_bits
	jalr	cra
#else
	jal	get_pte_fixup_bits
#endif

	/* Construct 1GB Identity Map (1:1 PA->VA) */
	LL_PTR	PTR(s1), bootstrap_pt_l1

	srli	s2, s9, L1_SHIFT	/* kernstart >> L1_SHIFT */
	andi	a5, s2, Ln_ADDR_MASK	/* & Ln_ADDR_MASK */
	li	t4, (PTE_KERN)
	or	t4, t4, s8		/* t4 |= pte bits */
	slli	s2, s2, PTE_PPN2_S	/* (s2 << PTE_PPN2_S) */
	or	t6, t4, s2

	/* Store L1 PTE entry to position */
	li	a6, PTE_SIZE
	mulw	a5, a5, a6		/* calculate L1 slot */
	ADD_PTR	PTR(t0), PTR(s1), a5
	sd	t6, (PTR(t0))		/* Store new PTE */

	/* Construct the virtual address space at KERNBASE */

	/* Add L1 entry for kernel */
	LL_PTR	PTR(s1), bootstrap_pt_l1
	LL_PTR	PTR(s2), bootstrap_pt_l2	/* Link to next level PN */
	srli	s2, s2, PAGE_SHIFT

	li	a5, KERNBASE
	srli	a5, a5, L1_SHIFT	/* >> L1_SHIFT */
	andi	a5, a5, Ln_ADDR_MASK	/* & Ln_ADDR_MASK */
	li	t4, PTE_V
	slli	t5, s2, PTE_PPN0_S	/* (s2 << PTE_PPN0_S) */
	or	t6, t4, t5

	/* Store L1 PTE entry to position */
	li	a6, PTE_SIZE
	mulw	a5, a5, a6
	ADD_PTR	PTR(t0), PTR(s1), a5
	sd	t6, (PTR(t0))

	/* Level 2 superpages (512 x 2MiB) */
	LL_PTR	PTR(s1), bootstrap_pt_l2
	srli	t4, s9, L2_SHIFT	/* Div physmem base by 2 MiB */
	li	t2, Ln_ENTRIES		/* Build 512 entries */
	add	t3, t4, t2
	li	t0, (PTE_KERN_CAP | PTE_X)
	or	t0, t0, s8		/* t0 |= pte bits */
1:
	slli	t2, t4, PTE_PPN1_S	/* << PTE_PPN1_S */
	or	t5, t0, t2
	sd	t5, (PTR(s1))		/* Store PTE entry to position */
	ADDI_PTR PTR(s1), PTR(s1), PTE_SIZE

	addi	t4, t4, 1
	bltu	t4, t3, 1b

	/* Page tables END */

	/*
	 * Set the supervisor trap vector temporarily. Enabling virtual memory
	 * may generate a page fault. We simply wish to continue onwards, so
	 * have the trap deliver us to 'va'.
	 */
	li	t1, KERNBASE
	sub	t1, t1, s9
	LL_PTR	PTR(t0), va
	ADD_PTR PTR(t0), PTR(t0), t1
	set_stvec	PTR(t0)

	/* Set page tables base register */
	LL_PTR	PTR(s2), bootstrap_pt_l1
	srli	s2, s2, PAGE_SHIFT
	li	t0, SATP_MODE_SV39
	or	s2, s2, t0
	sfence.vma
	csrw	satp, s2

	// Enter the kenrnel VA space
	LL_PTR PTR(t0), va
	li	t1, KERNBASE
	sub	t1, t1, s9
	ADD_PTR	PTR(t0), PTR(t0), t1
	jr	PTR(t0)

	.align 2
va:
	/* Set the global pointer again, this time with the virtual address. */
#ifdef __CHERI_PURE_CAPABILITY__
	/* CHERI-RISC-V purecap doesn't currently use cgp. */
#else
.option push
.option norelax
	lla	gp, __global_pointer$
.option pop
#endif

#ifdef __CHERI_PURE_CAPABILITY__
	/* Create a reduced PCC. */
	li	t0, KERNBASE
	llc	ct1, _C_LABEL(_end)
	sub	t2, t1, t0
	scaddr	ct1, ct1, t0
	scbndsr	ct1, ct1, t2
	llc	ct0, 1f
	scaddr	ct1, ct1, t0
	jr	ct1
1:
#endif

	/* Set the trap vector to the real handler. */
	set_exception_handler

	/* Ensure sscratch is zero */
#if __has_feature(capabilities)
	cmv	ct0, cnull
	csrw	sscratchc, ct0
#ifdef __riscv_xcheri
	/* Ensure stdc is null and thus not used */
	csrw	stdc, ct0
#endif
#else
	li	t0, 0
	csrw	sscratch, t0
#endif

#ifdef __CHERI_PURE_CAPABILITY__
	/* Initialize stack pointer */
	llc	cs2, initstack
	llc	ct0, initstack_end
	sub	t0, t0, s2
	scbndsr	cs2, cs2, t0
	li	t1, CHERI_PERMS_KERNEL_DATA
	acperm	cs2, cs2, t1
	cadd	csp, cs2, t0

	/* Allocate space for thread0 PCB and riscv_bootparams */
	caddi	csp, csp, -(PCB_SIZE + RISCV_BOOTPARAMS_SIZE) & ~STACKALIGNBYTES

	/* Clear BSS */
	llc	cs0, _C_LABEL(__bss_start)
	llc	cs1, _C_LABEL(_end)
1:
	sd	zero, 0(cs0)
	caddi	cs0, cs0, 8
	bltu	s0, s1, 1b

	/* Save omnipotent DDC and clear kernel's DDC. */
	csrr	cs0, ddc
	cmv	ct0, cnull
	csrw	ddc, ct0

	/* Initialize cap relocs. */
	li	t0, CHERI_PERMS_KERNEL_DATA
	acperm	ca0, cs0, t0
	llc	cra, _C_LABEL(init_cap_relocs)
	li	t0, CHERI_PERMS_KERNEL_CODE
	acperm	ca1, cra, t0
	jalr	cra

	/* Initialize capabilities. */
	cmv	ca0, cs0
	lgc	cra, _C_LABEL(cheri_init_capabilities)
	jalr	cra

	/* Fill riscv_bootparams */
	sd	s9, RISCV_BOOTPARAMS_KERN_PHYS(csp)

	sc	cs2, RISCV_BOOTPARAMS_KERN_STACK(csp)
	sd	s4, RISCV_BOOTPARAMS_DTBP_PHYS(csp)
	sc	cs3, RISCV_BOOTPARAMS_MODULEP(csp)

	/* Discard omnipotent cs0. */
	cmv	cs0, cnull

	/* Clear other capabilities no longer needed. */
	cmv	cs1, cnull
	cmv	cs2, cnull
	cmv	cs3, cnull

	li	t0, RISCV_BOOTPARAMS_SIZE
	scbndsr	ca0, csp, t0
	lgc	cra, _C_LABEL(initriscv)
	jalr	cra			/* Off we go */
	lgc	cra, _C_LABEL(mi_startup)
	jalr	cra
#else
	/* Initialize stack pointer */
	la	sp, initstack_end

	/* Clear frame pointer */
	mv	s0, zero

	/* Allocate space for thread0 PCB and riscv_bootparams */
	addi	sp, sp, -(PCB_SIZE + RISCV_BOOTPARAMS_SIZE) & ~STACKALIGNBYTES

	/* Clear BSS */
	la	t0, _C_LABEL(__bss_start)
	la	t1, _C_LABEL(_end)
1:
	sd	zero, 0(t0)
	addi	t0, t0, 8
	bltu	t0, t1, 1b

#if __has_feature(capabilities)
	/* Initialize capabilities. */
	csrr	ca0, ddc
	call	_C_LABEL(cheri_init_capabilities)
#endif

	/* Fill riscv_bootparams */
	sd	s9, RISCV_BOOTPARAMS_KERN_PHYS(sp)

	la	t0, initstack
	sd	t0, RISCV_BOOTPARAMS_KERN_STACK(sp)
	sd	s4, RISCV_BOOTPARAMS_DTBP_PHYS(sp)
	sd	s3, RISCV_BOOTPARAMS_MODULEP(sp)

	mv	a0, sp
	call	_C_LABEL(initriscv)	/* Off we go */
	call	_C_LABEL(mi_startup)
#endif

	/* We should never reach here, but if so just hang. */
2:
	wfi
	j	2b

/*
 * Get the physical address the kernel is loaded to. Returned in s9.
 */
get_physmem:
	LL_PTR	PTR(t0), virt_map	/* physical address of virt_map */
	ld	t1, 0(PTR(t0))	/* virtual address of virt_map */
	sub	t1, t1, t0	/* calculate phys->virt delta */
	li	t2, KERNBASE
	sub	s9, t2, t1	/* s9 = physmem base */
	ret

/*
 * T-HEAD CPUs implement an alternate scheme for PTE attributes that is
 * incompatible with the RISC-V PTE specification (see the definitions in
 * pte.h). Worse, it defines a non-zero value for "main" memory, and this must
 * be set in order to proceed with our new page tables.
 *
 * Therefore, we are forced to check the CPU identity here, which is both
 * inconvenient and fragile.
 *
 * Return the required attribute bits in s8. For sane implementations this is
 * zero.
 */
get_pte_fixup_bits:
	mv	s8, zero
	SBI_CALL(SBI_EXT_ID_BASE, SBI_BASE_GET_MVENDORID)
	li	t0, MVENDORID_THEAD
	xor	t0, t0, a1
	bnez	t0, 1f		/* branch if a1 != t0 */
	li	s8, PTE_THEAD_MA_NONE
1:
	ret

	.align  4
initstack:
	.space  (PAGE_SIZE * KSTACK_PAGES)
initstack_end:

/*
 * Static space for the bootstrap page tables. Unused after pmap_bootstrap().
 */
	.data
	.balign	PAGE_SIZE
	.type	bootstrap_pt_l1, @object
bootstrap_pt_l1:
	.space	PAGE_SIZE
	.size	bootstrap_pt_l1, . - bootstrap_pt_l1
	.type	bootstrap_pt_l2, @object
bootstrap_pt_l2:
	.space	PAGE_SIZE
	.size	bootstrap_pt_l2, . - bootstrap_pt_l2

	.align 3
virt_map:
	.quad   virt_map
hart_lottery:
	.space	4

#ifndef SMP
ENTRY(mpentry)
1:
	wfi
	j	1b
END(mpentry)
#else
/*
 * mpentry(unsigned long)
 *
 * Called by a core when it is being brought online.
 */
ENTRY(mpentry)
	/*
	 * Calculate the offset to __riscv_boot_ap
	 * for the current core, cpuid is in a0.
	 */
	li	t1, 4
	mulw	t1, t1, a0
	/* Get the pointer */

	LL_PTR	PTR(t0), __riscv_boot_ap
	ADD_PTR	PTR(t0), PTR(t0), t1

1:
	/* Wait the kernel to be ready */
	lw	t1, 0(PTR(t0))
	beqz	t1, 1b

	/* Setup stack pointer */
	LL_PTR	PTR(t0), bootstack
	LD_PTR	PTR(sp), 0(PTR(t0))

	/* Get the kernel's load address */
	LL_PTR	PTR(ra), get_physmem
	jalr	PTR(ra)

	/* Setup supervisor trap vector */
	LL_PTR	PTR(t0), mpva
	li	t1, KERNBASE
	sub	t1, t1, s9
	ADD_PTR	PTR(t0), PTR(t0), t1
	set_stvec	PTR(t0)

	/* Set page tables base register */
	LL_PTR	PTR(t2), kernel_pmap_store
	ld	s2, PM_SATP(PTR(t2))
	sfence.vma
	csrw	satp, s2

	.align 2
mpva:
	/* Set the global pointer again, this time with the virtual address. */
#ifdef __CHERI_PURE_CAPABILITY__
	/* CHERI-RISC-V purecap doesn't currently use cgp. */
	cmv	cgp, cnull
#else
.option push
.option norelax
	lla	gp, __global_pointer$
.option pop
#endif

#ifdef __CHERI_PURE_CAPABILITY__
	/* Create a reduced PCC. */
	li	t0, KERNBASE
	llc	ct1, _C_LABEL(_end)
	sub	t2, t1, t0
	scaddr	ct1, ct1, t0
	scbndsr	ct1, ct1, t2
	llc	ct0, 1f
	scaddr	ct1, ct1, t0
	jr	ct1
1:
#endif

	/* Set the trap vector to the real handler. */
	set_exception_handler

	/* Ensure sscratch is zero */
#if __has_feature(capabilities)
	cmv	ct0, cnull
	csrw	sscratchc, ct0
#ifdef __riscv_xcheri
	/* Ensure stdc is null and thus not used */
	csrw	stdc, ct0
#endif
#else
	li	t0, 0
	csrw	sscratch, t0
#endif

#ifdef __CHERI_PURE_CAPABILITY__
	lgc	cra, init_secondary
	jalr	cra
#else
	call	init_secondary
#endif
END(mpentry)
#endif

/*-
 * CHERI CHANGES START
 * {
 *   "updated": 20230509,
 *   "target_type": "kernel",
 *   "changes_purecap": [
 *     "support",
 *     "pointer_as_integer"
 *   ]
 * }
 * CHERI CHANGES END
 */
