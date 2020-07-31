/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Ruslan Bukin <br@bsdpad.com>
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_platform.h"
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>

#include <machine/bus.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>
#include <vm/vm_page.h>

#ifdef FDT
#include <dev/fdt/fdt_common.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#endif

#include <mips/beri/busdma_iommu.h>
#include "iommu_if.h"
#include "busdma_iommu_if.h"

#define	FDT_REG_CELLS	4

static int
busdma_handle_mem_node(vmem_t *vmem, phandle_t memory)
{
	pcell_t reg[FDT_REG_CELLS * FDT_MEM_REGIONS];
	pcell_t *regp;
	int addr_cells, size_cells;
	int i, reg_len, ret, tuple_size, tuples;
	u_long mem_start, mem_size;

	if ((ret = fdt_addrsize_cells(OF_parent(memory), &addr_cells,
	    &size_cells)) != 0)
		return (ret);

	if (addr_cells > 2)
		return (ERANGE);

	tuple_size = sizeof(pcell_t) * (addr_cells + size_cells);
	reg_len = OF_getproplen(memory, "reg");
	if (reg_len <= 0 || reg_len > sizeof(reg))
		return (ERANGE);

	if (OF_getprop(memory, "reg", reg, reg_len) <= 0)
		return (ENXIO);

	tuples = reg_len / tuple_size;
	regp = (pcell_t *)&reg;
	for (i = 0; i < tuples; i++) {
		ret = fdt_data_to_res(regp, addr_cells, size_cells,
		    &mem_start, &mem_size);
		if (ret != 0)
			return (ret);

		vmem_add(vmem, mem_start, mem_size, 0);
		regp += addr_cells + size_cells;
	}

	return (0);
}

void
busdma_iommu_remove_entry(struct busdma_iommu *xio, vm_offset_t va)
{

	va &= ~(PAGE_SIZE - 1);
	pmap_remove(&xio->p, va, va + PAGE_SIZE);

	BUSDMA_IOMMU_REMOVE(xio->dev, &xio->p, va);

	vmem_free(xio->vmem, va, PAGE_SIZE);
}

static void
busdma_iommu_enter(struct busdma_iommu *xio, vm_offset_t va,
    vm_paddr_t pa, vm_size_t size, vm_prot_t prot)
{
	vm_page_t m;
	pmap_t p;

	p = &xio->p;

	KASSERT((size & PAGE_MASK) == 0,
	    ("%s: device mapping not page-sized", __func__));

	for (; size > 0; size -= PAGE_SIZE) {
		m = PHYS_TO_VM_PAGE(pa);
		pmap_enter(p, va, m, prot, prot | PMAP_ENTER_WIRED, 0);

		BUSDMA_IOMMU_ENTER(xio->dev, p, va, pa);

		va += PAGE_SIZE;
		pa += PAGE_SIZE;
	}
}

void
busdma_iommu_add_entry(struct busdma_iommu *xio, vm_offset_t *va,
    vm_paddr_t pa, vm_size_t size, vm_prot_t prot)
{
	vm_offset_t addr;

	size = roundup2(size, PAGE_SIZE * 2);

	if (vmem_alloc(xio->vmem, size,
	    M_FIRSTFIT | M_NOWAIT, &addr)) {
		panic("Could not allocate virtual address.\n");
	}

	addr |= pa & (PAGE_SIZE - 1);

	if (va)
		*va = addr;

	busdma_iommu_enter(xio, addr, pa, size, prot);
}

int
busdma_iommu_init(struct busdma_iommu *xio)
{
#ifdef FDT
	phandle_t mem_node, node;
	pcell_t mem_handle;
#endif

	printf("%s\n", __func__);

	pmap_pinit(&xio->p);

#ifdef FDT
	node = ofw_bus_get_node(xio->dev);
	if (!OF_hasprop(node, "va-region"))
		return (ENXIO);

	if (OF_getencprop(node, "va-region", (void *)&mem_handle,
	    sizeof(mem_handle)) <= 0)
		return (ENXIO);
#endif

	xio->vmem = vmem_create("busdma vmem", 0, 0, PAGE_SIZE,
	    PAGE_SIZE, M_FIRSTFIT | M_WAITOK);
	if (xio->vmem == NULL)
		return (ENXIO);

#ifdef FDT
	mem_node = OF_node_from_xref(mem_handle);
	if (busdma_handle_mem_node(xio->vmem, mem_node) != 0) {
		vmem_destroy(xio->vmem);
		return (ENXIO);
	}
#endif

	BUSDMA_IOMMU_INIT(xio->dev, &xio->p);

	return (0);
}

int
busdma_iommu_release(struct busdma_iommu *xio)
{

	pmap_release(&xio->p);

	vmem_destroy(xio->vmem);

	BUSDMA_IOMMU_RELEASE(xio->dev, &xio->p);

	return (0);
}
