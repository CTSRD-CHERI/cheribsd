/*-
 * Copyright (c) 2022 The FreeBSD Foundation
 *
 * This software was developed by Andrew Turner under sponsorship from
 * the FreeBSD Foundation.
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
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
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

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include <libfdt.h>

#include "bhyverun.h"

#define	SET_PROP_U32(prop, idx, val)	\
    ((uint32_t *)(prop))[(idx)] = cpu_to_fdt32(val)
#define	SET_PROP_U64(prop, idx, val)	\
    ((uint64_t *)(prop))[(idx)] = cpu_to_fdt64(val)

/* Start of mem + 1M */
#define	FDT_BASE	0x100100000
#define	FDT_SIZE	(64 * 1024)

#define	GIC_SPI			0
#define	GIC_PPI			1
#define	IRQ_TYPE_LEVEL_HIGH	4
#define	IRQ_TYPE_LEVEL_LOW	8

/* XXX: Ask for this info */
#define	MEM_START	0x100000000
#define	MEM_LEN		0x40000000

static uint32_t next_phandle = 1;

static uint32_t
assign_phandle(void *fdt)
{
	uint32_t phandle;

	phandle = next_phandle;
	next_phandle++;
	fdt_property_u32(fdt, "phandle", phandle);

	return (phandle);
}

static void
set_single_reg(void *fdt, uint64_t start, uint64_t len)
{
	void *reg;

	fdt_property_placeholder(fdt, "reg", 2 * sizeof(uint64_t), &reg);
	SET_PROP_U64(reg, 0, start);
	SET_PROP_U64(reg, 1, len);
}

static void
add_gic(void *fdt, uint32_t *phandle)
{
	void *prop;

	fdt_begin_node(fdt, "interrupt-controller@2f000000");
	*phandle = assign_phandle(fdt);
	fdt_property_string(fdt, "compatible", "arm,gic-v3");
	fdt_property(fdt, "interrupt-controller", NULL, 0);
	/* XXX: Needed given the root #address-cells? */
	fdt_property_u32(fdt, "#address-cells", 2);
	fdt_property_u32(fdt, "#interrupt-cells", 3);
	fdt_property_placeholder(fdt, "reg", 4 * sizeof(uint64_t), &prop);
	/* GICD */
	SET_PROP_U64(prop, 0, 0x2f000000);
	SET_PROP_U64(prop, 1, 0x10000);
	/* GICR */
	SET_PROP_U64(prop, 2, 0x2f100000);
	SET_PROP_U64(prop, 3, 0x200000);

	fdt_property_placeholder(fdt, "mbi-ranges", 2 * sizeof(uint32_t),
	    &prop);
	SET_PROP_U32(prop, 0, 256);
	SET_PROP_U32(prop, 1, 64);

	fdt_end_node(fdt);
}

static void
add_timer(void *fdt, uint32_t gic_phandle)
{
	void *interrupts;
	uint32_t irqs[] = { 13, 14, 11 };

	fdt_begin_node(fdt, "timer");
	fdt_property_string(fdt, "compatible", "arm,armv8-timer");
	fdt_property_u32(fdt, "interrupt-parent", gic_phandle);
	fdt_property_placeholder(fdt, "interrupts", 9 * sizeof(uint32_t),
	    &interrupts);
	for (int i = 0; i < nitems(irqs); i++) {
		SET_PROP_U32(interrupts, i * 3 + 0, GIC_PPI);
		SET_PROP_U32(interrupts, i * 3 + 1, irqs[i]);
		SET_PROP_U32(interrupts, i * 3 + 2, IRQ_TYPE_LEVEL_LOW);
	}
	fdt_end_node(fdt);
}

static void
add_uart(void *fdt)
{
	void *prop;
	uint32_t clk_phandle;

	fdt_begin_node(fdt, "uart-clock");
	fdt_property_string(fdt, "compatible", "fixed-clock");
	fdt_property_string(fdt, "clock-output-names", "clk24mhz");
	fdt_property_u32(fdt, "#clock-cells", 0);
	fdt_property_u32(fdt, "clock-frequency", 24000000);
	clk_phandle = assign_phandle(fdt);
	fdt_end_node(fdt);

	fdt_begin_node(fdt, "serial@10000");
#define	UART_COMPAT	"arm,pl011\0arm,primecell"
	fdt_property(fdt, "compatible", UART_COMPAT, sizeof(UART_COMPAT));
#undef UART_COMPAT
	set_single_reg(fdt, 0x10000, 0x1000);
	fdt_property_placeholder(fdt, "clocks", 2 * sizeof(uint32_t), &prop);
	SET_PROP_U32(prop, 0, clk_phandle);
	SET_PROP_U32(prop, 1, clk_phandle);
#define	UART_CLK_NAMES	"uartclk\0apb_pclk"
	fdt_property(fdt, "clock-names", UART_CLK_NAMES,
	    sizeof(UART_CLK_NAMES));
#undef UART_CLK_NAMES
	
	fdt_end_node(fdt);
}

static void
add_pcie(void *fdt, uint32_t gic_phandle)
{
	void *prop;

	fdt_begin_node(fdt, "pcie@1f0000000");
	fdt_property_string(fdt, "compatible", "pci-host-ecam-generic");
	fdt_property_u32(fdt, "#address-cells", 3);
	fdt_property_u32(fdt, "#size-cells", 2);
	fdt_property_string(fdt, "device_type", "pci");
	fdt_property_u64(fdt, "bus-range", (0ul << 32) | 1);
	set_single_reg(fdt, 0xe0000000, 0x10000000);
	fdt_property_placeholder(fdt, "ranges",
	    2 * 7 * sizeof(uint32_t), &prop);
	SET_PROP_U32(prop, 0, 0x01000000);

	SET_PROP_U32(prop, 1, 0);
	SET_PROP_U32(prop, 2, 0xdf000000);

	SET_PROP_U32(prop, 3, 0);
	SET_PROP_U32(prop, 4, 0xdf000000);

	SET_PROP_U32(prop, 5, 0);
	SET_PROP_U32(prop, 6, 0x01000000);


	SET_PROP_U32(prop, 7, 0x02000000);

	SET_PROP_U32(prop, 8, 0);
	SET_PROP_U32(prop, 9, 0xa0000000);

	SET_PROP_U32(prop, 10, 0);
	SET_PROP_U32(prop, 11, 0xa0000000);

	SET_PROP_U32(prop, 12, 0);
	SET_PROP_U32(prop, 13, 0x3f000000);
	
	fdt_property_placeholder(fdt, "msi-map", 4 * sizeof(uint32_t), &prop);
	SET_PROP_U32(prop, 0, 0);
	SET_PROP_U32(prop, 1, gic_phandle);
	SET_PROP_U32(prop, 2, 0);
	SET_PROP_U32(prop, 3, 0x10000);
	fdt_property_u32(fdt, "msi-parent", gic_phandle);

	fdt_property_u32(fdt, "#interrupt-cells", 1);
	fdt_property_u32(fdt, "interrupt-parent", gic_phandle);
	fdt_property_placeholder(fdt, "interrupt-map-mask",
	    4 * sizeof(uint32_t), &prop);
	SET_PROP_U32(prop, 0, 0);
	SET_PROP_U32(prop, 1, 0);
	SET_PROP_U32(prop, 2, 0);
	SET_PROP_U32(prop, 3, 7);
	fdt_property_placeholder(fdt, "interrupt-map",
	    10 * sizeof(uint32_t), &prop);
	SET_PROP_U32(prop, 0, 0);
	SET_PROP_U32(prop, 1, 0);
	SET_PROP_U32(prop, 2, 0);
	SET_PROP_U32(prop, 3, 1);
	SET_PROP_U32(prop, 4, gic_phandle);
	SET_PROP_U32(prop, 5, 0);
	SET_PROP_U32(prop, 5, 0);
	SET_PROP_U32(prop, 5, GIC_SPI);
	SET_PROP_U32(prop, 5, 1);
	SET_PROP_U32(prop, 5, IRQ_TYPE_LEVEL_HIGH);

	fdt_end_node(fdt);
}

static void
add_cpu(void *fdt, int cpuid)
{
	char node_name[16];

	snprintf(node_name, sizeof(node_name), "cpu@%d", cpuid);

	fdt_begin_node(fdt, node_name);
	fdt_property_string(fdt, "device_type", "cpu");
	fdt_property_string(fdt, "compatible", "arm,armv8");
	fdt_property_u64(fdt, "reg", cpuid);
	fdt_property_string(fdt, "enable-method", "psci");
	fdt_end_node(fdt);
}

static void
add_cpus(void *fdt, int ncpu)
{
	int cpuid;

	fdt_begin_node(fdt, "cpus");
	/* XXX: Needed given the root #address-cells? */
	fdt_property_u32(fdt, "#address-cells", 2);
	fdt_property_u32(fdt, "#size-cells", 0);

	for (cpuid = 0; cpuid < ncpu; cpuid++) {
		add_cpu(fdt, cpuid);
	}
	fdt_end_node(fdt);
}

int fdt_build(struct vmctx *ctx, int ncpu);
int
fdt_build(struct vmctx *ctx, int ncpu)
{
	void *fdt;
	uint32_t gic_phandle;

	fdt = paddr_guest2host(ctx, FDT_BASE, FDT_SIZE);
	if (fdt == NULL)
		return (EFAULT);

	printf("dtb base %lx\n", FDT_BASE);

	fdt_create(fdt, FDT_SIZE);

	/* Add the memory reserve map (needed even if none is reserved) */
	fdt_finish_reservemap(fdt);

	/* Create the root node */
	fdt_begin_node(fdt, "");

	fdt_property_string(fdt, "compatible", "freebsd,bhyve");
	fdt_property_u32(fdt, "#address-cells", 2);
	fdt_property_u32(fdt, "#size-cells", 2);

	fdt_begin_node(fdt, "chosen");
	fdt_property_string(fdt, "stdout-path", "serial0:115200n8");
	fdt_end_node(fdt);

	fdt_begin_node(fdt, "memory@100000000");
	fdt_property_string(fdt, "device_type", "memory");
	set_single_reg(fdt, MEM_START, MEM_LEN);
	fdt_end_node(fdt);

	add_cpus(fdt, ncpu);

	fdt_begin_node(fdt, "psci");
	fdt_property_string(fdt, "compatible", "arm,psci-1.0");
	fdt_property_string(fdt, "method", "hvc");
	fdt_end_node(fdt);

	add_gic(fdt, &gic_phandle);
	fdt_property_u32(fdt, "interrupt-parent", gic_phandle);

	add_timer(fdt, gic_phandle);

	add_uart(fdt);

	add_pcie(fdt, gic_phandle);

	fdt_begin_node(fdt, "aliases");
	fdt_property_string(fdt, "serial0", "/serial@10000");
	fdt_end_node(fdt);

	fdt_end_node(fdt);

	fdt_finish(fdt);

	return (0);
}
