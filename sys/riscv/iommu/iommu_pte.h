/*-
 * Copyright (c) 2014 Andrew Turner
 * Copyright (c) 2015-2021 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * Portions of this software were developed by SRI International and the
 * University of Cambridge Computer Laboratory under DARPA/AFRL contract
 * FA8750-10-C-0237 ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Portions of this software were developed by the University of Cambridge
 * Computer Laboratory as part of the CTSRD Project, with support from the
 * UK Higher Education Innovation Fund (HEIF).
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

#ifndef _IOMMU_PTE_H_
#define	_IOMMU_PTE_H_

/* Level 0 table, 512GiB per entry */
#define	IOMMU_L0_SHIFT		39

/* Level 1 table, 1GiB per entry */
#define	IOMMU_L1_SHIFT		30
#define	IOMMU_L1_SIZE 		(1 << IOMMU_L1_SHIFT)
#define	IOMMU_L1_OFFSET 	(IOMMU_L1_SIZE - 1)

/* Level 2 table, 2MiB per entry */
#define	IOMMU_L2_SHIFT		21
#define	IOMMU_L2_SIZE 		(1 << IOMMU_L2_SHIFT)
#define	IOMMU_L2_OFFSET 	(IOMMU_L2_SIZE - 1)

/* Level 3 table, 4KiB per entry */
#define	IOMMU_L3_SHIFT		12
#define	IOMMU_L3_SIZE 		(1 << IOMMU_L3_SHIFT)
#define	IOMMU_L3_OFFSET 	(IOMMU_L3_SIZE - 1)

#define	IOMMU_Ln_ENTRIES_SHIFT	9
#define	IOMMU_Ln_ENTRIES	(1 << IOMMU_Ln_ENTRIES_SHIFT)
#define	IOMMU_Ln_ADDR_MASK	(IOMMU_Ln_ENTRIES - 1)

#define	iommu_l1_index(va)	(((va) >> IOMMU_L1_SHIFT) & IOMMU_Ln_ADDR_MASK)
#define	iommu_l2_index(va)	(((va) >> IOMMU_L2_SHIFT) & IOMMU_Ln_ADDR_MASK)
#define	iommu_l3_index(va)	(((va) >> IOMMU_L3_SHIFT) & IOMMU_Ln_ADDR_MASK)

#endif /* !_IOMMU_PTE_H_ */
