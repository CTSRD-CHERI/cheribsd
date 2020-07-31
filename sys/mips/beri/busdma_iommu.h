/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Ruslan Bukin <br@bsdpad.com>
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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

#ifndef _MIPS_BERI_BUSDMA_IOMMU_H_
#define _MIPS_BERI_BUSDMA_IOMMU_H_

#include <sys/proc.h>
#include <sys/vmem.h>

#ifdef FDT
#include <dev/fdt/fdt_common.h>
#include <dev/ofw/openfirm.h>
#endif

#include <vm/vm.h>
#include <vm/pmap.h>

struct busdma_iommu {
	struct pmap p;
	vmem_t *vmem;		/* VA space */
	device_t dev;		/* IOMMU device */
};

int busdma_iommu_init(struct busdma_iommu *xio);
int busdma_iommu_release(struct busdma_iommu *xio);
void busdma_iommu_remove_entry(struct busdma_iommu *xio, vm_offset_t va);
void busdma_iommu_add_entry(struct busdma_iommu *xio, vm_offset_t *va,
    vm_paddr_t pa, vm_size_t size, vm_prot_t prot);

#endif /* !_MIPS_BERI_BUSDMA_IOMMU_H_ */
