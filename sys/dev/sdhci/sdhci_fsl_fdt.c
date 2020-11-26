/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2020 Alstom Group.
 * Copyright (c) 2020 Semihalf.
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

/* eSDHC controller driver for NXP QorIQ Layerscape SoCs. */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/rman.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>

#include <machine/bus.h>
#include <machine/resource.h>

#include <dev/extres/clk/clk.h>
#include <dev/mmc/bridge.h>
#include <dev/mmc/mmcbrvar.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#include <dev/sdhci/sdhci.h>
#include <dev/sdhci/sdhci_fdt_gpio.h>

#include "mmcbr_if.h"
#include "sdhci_if.h"

#define	RD4	(sc->read)
#define	WR4	(sc->write)

#define	SDHCI_FSL_PRES_STATE		0x24
#define	SDHCI_FSL_PRES_SDSTB		(1 << 3)
#define	SDHCI_FSL_PRES_COMPAT_MASK	0x000f0f07

#define	SDHCI_FSL_PROT_CTRL		0x28
#define	SDHCI_FSL_PROT_CTRL_WIDTH_1BIT	(0 << 1)
#define	SDHCI_FSL_PROT_CTRL_WIDTH_4BIT	(1 << 1)
#define	SDHCI_FSL_PROT_CTRL_WIDTH_8BIT	(2 << 1)
#define	SDHCI_FSL_PROT_CTRL_WIDTH_MASK	(3 << 1)
#define	SDHCI_FSL_PROT_CTRL_BYTE_SWAP	(0 << 4)
#define	SDHCI_FSL_PROT_CTRL_BYTE_NATIVE	(2 << 4)
#define	SDHCI_FSL_PROT_CTRL_BYTE_MASK	(3 << 4)
#define	SDHCI_FSL_PROT_CTRL_DMA_MASK	(3 << 8)

#define	SDHCI_FSL_SYS_CTRL		0x2c
#define	SDHCI_FSL_CLK_IPGEN		(1 << 0)
#define	SDHCI_FSL_CLK_SDCLKEN		(1 << 3)
#define	SDHCI_FSL_CLK_DIVIDER_MASK	0x000000f0
#define	SDHCI_FSL_CLK_DIVIDER_SHIFT	4
#define	SDHCI_FSL_CLK_PRESCALE_MASK	0x0000ff00
#define	SDHCI_FSL_CLK_PRESCALE_SHIFT	8

#define	SDHCI_FSL_WTMK_LVL		0x44
#define	SDHCI_FSL_WTMK_RD_512B		(0 << 0)
#define	SDHCI_FSL_WTMK_WR_512B		(0 << 15)

#define	SDHCI_FSL_HOST_VERSION		0xfc
#define	SDHCI_FSL_CAPABILITIES2		0x114

#define	SDHCI_FSL_ESDHC_CTRL		0x40c
#define	SDHCI_FSL_ESDHC_CTRL_SNOOP	(1 << 6)
#define	SDHCI_FSL_ESDHC_CTRL_CLK_DIV2	(1 << 19)

struct sdhci_fsl_fdt_softc {
	device_t				dev;
	const struct sdhci_fsl_fdt_soc_data	*soc_data;
	struct resource				*mem_res;
	struct resource				*irq_res;
	void					*irq_cookie;
	uint32_t				baseclk_hz;
	struct sdhci_fdt_gpio			*gpio;
	struct sdhci_slot			slot;
	bool					slot_init_done;
	uint32_t				cmd_and_mode;
	uint16_t				sdclk_bits;

	uint32_t (* read)(struct sdhci_fsl_fdt_softc *, bus_size_t);
	void (* write)(struct sdhci_fsl_fdt_softc *, bus_size_t, uint32_t);
};

struct sdhci_fsl_fdt_soc_data {
	int quirks;
};

static const struct sdhci_fsl_fdt_soc_data sdhci_fsl_fdt_ls1046a_soc_data = {
	.quirks = SDHCI_QUIRK_DONT_SET_HISPD_BIT | SDHCI_QUIRK_BROKEN_AUTO_STOP
};

static const struct sdhci_fsl_fdt_soc_data sdhci_fsl_fdt_gen_data = {
	.quirks = 0,
};

static const struct ofw_compat_data sdhci_fsl_fdt_compat_data[] = {
	{"fsl,ls1046a-esdhc",	(uintptr_t)&sdhci_fsl_fdt_ls1046a_soc_data},
	{"fsl,esdhc",		(uintptr_t)&sdhci_fsl_fdt_gen_data},
	{NULL,			0}
};

static uint32_t
read_be(struct sdhci_fsl_fdt_softc *sc, bus_size_t off)
{

	return (be32toh(bus_read_4(sc->mem_res, off)));
}

static void
write_be(struct sdhci_fsl_fdt_softc *sc, bus_size_t off, uint32_t val)
{

	bus_write_4(sc->mem_res, off, htobe32(val));
}

static uint32_t
read_le(struct sdhci_fsl_fdt_softc *sc, bus_size_t off)
{

	return (bus_read_4(sc->mem_res, off));
}

static void
write_le(struct sdhci_fsl_fdt_softc *sc, bus_size_t off, uint32_t val)
{

	bus_write_4(sc->mem_res, off, val);
}


static uint16_t
sdhci_fsl_fdt_get_clock(struct sdhci_fsl_fdt_softc *sc)
{
	uint16_t val;

	val = sc->sdclk_bits | SDHCI_CLOCK_INT_EN;
	if (RD4(sc, SDHCI_FSL_PRES_STATE) & SDHCI_FSL_PRES_SDSTB)
		val |= SDHCI_CLOCK_INT_STABLE;
	if (RD4(sc, SDHCI_FSL_SYS_CTRL) & SDHCI_FSL_CLK_SDCLKEN)
		val |= SDHCI_CLOCK_CARD_EN;

	return (val);
}

static void
fsl_sdhc_fdt_set_clock(struct sdhci_fsl_fdt_softc *sc, uint16_t val)
{
	uint32_t div, freq, prescale, val32;

	sc->sdclk_bits = val & SDHCI_DIVIDERS_MASK;
	val32 = RD4(sc, SDHCI_CLOCK_CONTROL);

	if ((val & SDHCI_CLOCK_CARD_EN) == 0) {
		WR4(sc, SDHCI_CLOCK_CONTROL, val32 & ~SDHCI_FSL_CLK_SDCLKEN);
		return;
	}

	div = ((val >> SDHCI_DIVIDER_SHIFT) & SDHCI_DIVIDER_MASK) |
	    ((val >> SDHCI_DIVIDER_HI_SHIFT) & SDHCI_DIVIDER_HI_MASK) <<
	    SDHCI_DIVIDER_MASK_LEN;
	if (div == 0)
		freq = sc->baseclk_hz;
	else
		freq = sc->baseclk_hz / (2 * div);

	for (prescale = 2; freq < sc->baseclk_hz / (prescale * 16); )
		prescale <<= 1;
	for (div = 1; freq < sc->baseclk_hz / (prescale * div); )
		++div;

#ifdef DEBUG
	device_printf(sc->dev,
	    "Desired SD/MMC freq: %d, actual: %d; base %d prescale %d divisor %d\n",
	    freq, sc->baseclk_hz / (prescale * div),
	    sc->baseclk_hz, prescale, div);
#endif

	prescale >>= 1;
	div -= 1;

	val32 &= ~(SDHCI_FSL_CLK_DIVIDER_MASK | SDHCI_FSL_CLK_PRESCALE_MASK);
	val32 |= div << SDHCI_FSL_CLK_DIVIDER_SHIFT;
	val32 |= prescale << SDHCI_FSL_CLK_PRESCALE_SHIFT;
	val32 |= SDHCI_FSL_CLK_IPGEN | SDHCI_FSL_CLK_SDCLKEN;
	WR4(sc, SDHCI_CLOCK_CONTROL, val32);
}

static uint8_t
sdhci_fsl_fdt_read_1(device_t dev, struct sdhci_slot *slot, bus_size_t off)
{
	struct sdhci_fsl_fdt_softc *sc;
	uint32_t wrk32, val32;

	sc = device_get_softc(dev);

	switch (off) {
	case SDHCI_HOST_CONTROL:
		wrk32 = RD4(sc, SDHCI_FSL_PROT_CTRL);
		val32 = wrk32 & (SDHCI_CTRL_LED | SDHCI_CTRL_CARD_DET |
		    SDHCI_CTRL_FORCE_CARD);
		if (wrk32 & SDHCI_FSL_PROT_CTRL_WIDTH_4BIT)
			val32 |= SDHCI_CTRL_4BITBUS;
		else if (wrk32 & SDHCI_FSL_PROT_CTRL_WIDTH_8BIT)
			val32 |= SDHCI_CTRL_8BITBUS;
		return (val32);
	case SDHCI_POWER_CONTROL:
		return (SDHCI_POWER_ON | SDHCI_POWER_300);
	default:
		break;
	}

	return ((RD4(sc, off & ~3) >> (off & 3) * 8) & UINT8_MAX);
}

static uint16_t
sdhci_fsl_fdt_read_2(device_t dev, struct sdhci_slot *slot, bus_size_t off)
{
	struct sdhci_fsl_fdt_softc *sc;
	uint32_t val32;

	sc = device_get_softc(dev);

	switch (off) {
	case SDHCI_CLOCK_CONTROL:
		return (sdhci_fsl_fdt_get_clock(sc));
	case SDHCI_HOST_VERSION:
		return (RD4(sc, SDHCI_FSL_HOST_VERSION) & UINT16_MAX);
	case SDHCI_TRANSFER_MODE:
		return (sc->cmd_and_mode & UINT16_MAX);
	case SDHCI_COMMAND_FLAGS:
		return (sc->cmd_and_mode >> 16);
	case SDHCI_SLOT_INT_STATUS:
	/*
	 * eSDHC hardware manages only a single slot.
	 * Synthesize a slot interrupt status register for slot 1 below.
	 */
		val32 = RD4(sc, SDHCI_INT_STATUS);
		val32 &= RD4(sc, SDHCI_SIGNAL_ENABLE);
		return (!!val32);
	default:
		return ((RD4(sc, off & ~3) >> (off & 3) * 8) & UINT16_MAX);
	}
}

static uint32_t
sdhci_fsl_fdt_read_4(device_t dev, struct sdhci_slot *slot, bus_size_t off)
{
	struct sdhci_fsl_fdt_softc *sc;
	uint32_t wrk32, val32;

	sc = device_get_softc(dev);

	if (off == SDHCI_BUFFER)
		return (bus_read_4(sc->mem_res, off));
	if (off == SDHCI_CAPABILITIES2)
		off = SDHCI_FSL_CAPABILITIES2;

	val32 = RD4(sc, off);

	switch (off) {
	case SDHCI_CAPABILITIES:
		val32 &= ~(SDHCI_CAN_DO_SUSPEND | SDHCI_CAN_VDD_180);
		break;
	case SDHCI_PRESENT_STATE:
		wrk32 = val32;
		val32 &= SDHCI_FSL_PRES_COMPAT_MASK;
		val32 |= (wrk32 >> 4) & SDHCI_STATE_DAT_MASK;
		val32 |= (wrk32 << 1) & SDHCI_STATE_CMD;
		break;
	default:
		break;
	}

	return (val32);
}

static void
sdhci_fsl_fdt_read_multi_4(device_t dev, struct sdhci_slot *slot, bus_size_t off,
    uint32_t *data, bus_size_t count)
{
	struct sdhci_fsl_fdt_softc *sc;

	sc = device_get_softc(dev);
	bus_read_multi_4(sc->mem_res, off, data, count);
}

static void
sdhci_fsl_fdt_write_1(device_t dev, struct sdhci_slot *slot, bus_size_t off,
    uint8_t val)
{
	struct sdhci_fsl_fdt_softc *sc;
	uint32_t val32;

	sc = device_get_softc(dev);

	switch (off) {
	case SDHCI_HOST_CONTROL:
		val32 = RD4(sc, SDHCI_FSL_PROT_CTRL);
		val32 &= ~SDHCI_FSL_PROT_CTRL_WIDTH_MASK;
		val32 |= (val & SDHCI_CTRL_LED);

		if (val & SDHCI_CTRL_8BITBUS)
			val32 |= SDHCI_FSL_PROT_CTRL_WIDTH_8BIT;
		else
			/* Bus width is 1-bit when this flag is not set. */
			val32 |= (val & SDHCI_CTRL_4BITBUS);
		/* Enable SDMA by masking out this field. */
		val32 &= ~SDHCI_FSL_PROT_CTRL_DMA_MASK;
		val32 &= ~(SDHCI_CTRL_CARD_DET | SDHCI_CTRL_FORCE_CARD);
		val32 |= (val & (SDHCI_CTRL_CARD_DET |
		    SDHCI_CTRL_FORCE_CARD));
		WR4(sc, SDHCI_FSL_PROT_CTRL, val32);
		return;
	case SDHCI_POWER_CONTROL:
		return;
	case SDHCI_SOFTWARE_RESET:
		val &= ~SDHCI_RESET_ALL;
	/* FALLTHROUGH. */
	default:
		val32 = RD4(sc, off & ~3);
		val32 &= ~(UINT8_MAX << (off & 3) * 8);
		val32 |= (val << (off & 3) * 8);
		WR4(sc, off & ~3, val32);
		return;
	}
}

static void
sdhci_fsl_fdt_write_2(device_t dev, struct sdhci_slot *slot, bus_size_t off,
    uint16_t val)
{
	struct sdhci_fsl_fdt_softc *sc;
	uint32_t val32;

	sc = device_get_softc(dev);

	switch (off) {
	case SDHCI_CLOCK_CONTROL:
		fsl_sdhc_fdt_set_clock(sc, val);
		return;
	/*
	 * eSDHC hardware combines command and mode into a single
	 * register. Cache it here, so that command isn't written
	 * until after mode.
	 */
	case SDHCI_TRANSFER_MODE:
		sc->cmd_and_mode = val;
		return;
	case SDHCI_COMMAND_FLAGS:
		sc->cmd_and_mode =
		    (sc->cmd_and_mode & UINT16_MAX) | (val << 16);
		WR4(sc, SDHCI_TRANSFER_MODE, sc->cmd_and_mode);
		sc->cmd_and_mode = 0;
		return;
	default:
		val32 = RD4(sc, off & ~3);
		val32 &= ~(UINT16_MAX << (off & 3) * 8);
		val32 |= ((val & UINT16_MAX) << (off & 3) * 8);
		WR4(sc, off & ~3, val32);
		return;
	}
}

static void
sdhci_fsl_fdt_write_4(device_t dev, struct sdhci_slot *slot, bus_size_t off,
    uint32_t val)
{
	struct sdhci_fsl_fdt_softc *sc;

	sc = device_get_softc(dev);

	switch (off) {
	case SDHCI_BUFFER:
		bus_write_4(sc->mem_res, off, val);
		return;
	/*
	 * eSDHC hardware lacks support for the SDMA buffer boundary
	 * feature and instead generates SDHCI_INT_DMA_END interrupts
	 * after each completed DMA data transfer.
	 * Since this duplicates the SDHCI_INT_DATA_END functionality,
	 * mask out the unneeded SDHCI_INT_DMA_END interrupt.
	 */
	case SDHCI_INT_ENABLE:
	case SDHCI_SIGNAL_ENABLE:
		val &= ~SDHCI_INT_DMA_END;
	/* FALLTHROUGH. */
	default:
		WR4(sc, off, val);
		return;
	}
}

static void
sdhci_fsl_fdt_write_multi_4(device_t dev, struct sdhci_slot *slot,
    bus_size_t off, uint32_t *data, bus_size_t count)
{
	struct sdhci_fsl_fdt_softc *sc;

	sc = device_get_softc(dev);
	bus_write_multi_4(sc->mem_res, off, data, count);
}

static void
sdhci_fsl_fdt_irq(void *arg)
{
	struct sdhci_fsl_fdt_softc *sc;

	sc = arg;
	sdhci_generic_intr(&sc->slot);
	return;
}

static int
sdhci_fsl_fdt_get_ro(device_t bus, device_t child)
{
	struct sdhci_fsl_fdt_softc *sc;

	sc = device_get_softc(bus);
	return (sdhci_fdt_gpio_get_readonly(sc->gpio));
}

static bool
sdhci_fsl_fdt_get_card_present(device_t dev, struct sdhci_slot *slot)
{
	struct sdhci_fsl_fdt_softc *sc;

	sc = device_get_softc(dev);
	return (sdhci_fdt_gpio_get_present(sc->gpio));
}

static int
sdhci_fsl_fdt_attach(device_t dev)
{
	struct sdhci_fsl_fdt_softc *sc;
	uint32_t val, buf_order;
	uintptr_t ocd_data;
	uint64_t clk_hz;
	phandle_t node;
	int rid, ret;
	clk_t clk;

	node = ofw_bus_get_node(dev);
	sc = device_get_softc(dev);
	ocd_data = ofw_bus_search_compatible(dev,
	    sdhci_fsl_fdt_compat_data)->ocd_data;
	sc->soc_data = (struct sdhci_fsl_fdt_soc_data *)ocd_data;
	sc->dev = dev;
	sc->slot.quirks = sc->soc_data->quirks;

	rid = 0;
	sc->mem_res = bus_alloc_resource_any(dev, SYS_RES_MEMORY, &rid,
	    RF_ACTIVE);
	if (sc->mem_res == NULL) {
		device_printf(dev,
		    "Could not allocate resources for controller\n");
		return (ENOMEM);
	}

	rid = 0;
	sc->irq_res = bus_alloc_resource_any(dev, SYS_RES_IRQ, &rid,
	    RF_ACTIVE);
	if (sc->irq_res == NULL) {
		device_printf(dev,
		    "Could not allocate irq resources for controller\n");
		ret = ENOMEM;
		goto err_free_mem;
	}

	ret = bus_setup_intr(dev, sc->irq_res, INTR_TYPE_BIO | INTR_MPSAFE,
	    NULL, sdhci_fsl_fdt_irq, sc, &sc->irq_cookie);
	if (ret != 0) {
		device_printf(dev, "Could not setup IRQ handler\n");
		goto err_free_irq_res;
	}

	ret = clk_get_by_ofw_index(dev, node, 0, &clk);
	if (ret != 0) {
		device_printf(dev, "Parent clock not found\n");
		goto err_free_irq;
	}

	ret = clk_get_freq(clk, &clk_hz);
	if (ret != 0) {
		device_printf(dev,
		    "Could not get parent clock frequency\n");
		goto err_free_irq;
	}

	sc->baseclk_hz = clk_hz / 2;

	/* Figure out eSDHC block endianness before we touch any HW regs. */
	if (OF_hasprop(node, "little-endian")) {
		sc->read = read_le;
		sc->write = write_le;
		buf_order = SDHCI_FSL_PROT_CTRL_BYTE_NATIVE;
	} else {
		sc->read = read_be;
		sc->write = write_be;
		buf_order = SDHCI_FSL_PROT_CTRL_BYTE_SWAP;
	}

	/*
	 * Setting this register affects byte order in SDHCI_BUFFER only.
	 * If the eSDHC block is connected over a big-endian bus, the data
	 * read from/written to the buffer will be already byte swapped.
	 * In such a case, setting SDHCI_FSL_PROT_CTRL_BYTE_SWAP will convert
	 * the byte order again, resulting in a native byte order.
	 * The read/write callbacks accommodate for this behavior.
	 */
	val = RD4(sc, SDHCI_FSL_PROT_CTRL);
	val &= ~SDHCI_FSL_PROT_CTRL_BYTE_MASK;
	WR4(sc, SDHCI_FSL_PROT_CTRL, val | buf_order);

	/*
	 * Gate the SD clock and set its source to peripheral clock / 2.
	 * The frequency in baseclk_hz is set to match this.
	 */
	val = RD4(sc, SDHCI_CLOCK_CONTROL);
	WR4(sc, SDHCI_CLOCK_CONTROL, val & ~SDHCI_FSL_CLK_SDCLKEN);
	val = RD4(sc, SDHCI_FSL_ESDHC_CTRL);
	WR4(sc, SDHCI_FSL_ESDHC_CTRL, val | SDHCI_FSL_ESDHC_CTRL_CLK_DIV2);
	sc->slot.max_clk = sc->baseclk_hz;
	sc->gpio = sdhci_fdt_gpio_setup(dev, &sc->slot);

	/*
	 * Set the buffer watermark level to 128 words (512 bytes) for both
	 * read and write. The hardware has a restriction that when the read or
	 * write ready status is asserted, that means you can read exactly the
	 * number of words set in the watermark register before you have to
	 * re-check the status and potentially wait for more data. The main
	 * sdhci driver provides no hook for doing status checking on less than
	 * a full block boundary, so we set the watermark level to be a full
	 * block. Reads and writes where the block size is less than the
	 * watermark size will work correctly too, no need to change the
	 * watermark for different size blocks. However, 128 is the maximum
	 * allowed for the watermark, so PIO is limitted to 512 byte blocks.
	 */
	WR4(sc, SDHCI_FSL_WTMK_LVL, SDHCI_FSL_WTMK_WR_512B |
	    SDHCI_FSL_WTMK_RD_512B);

	ret = sdhci_init_slot(dev, &sc->slot, 0);
	if (ret != 0)
		goto err_free_gpio;
	sc->slot_init_done = true;
	sdhci_start_slot(&sc->slot);

	return (bus_generic_attach(dev));

err_free_gpio:
	sdhci_fdt_gpio_teardown(sc->gpio);
err_free_irq:
	bus_teardown_intr(dev, sc->irq_res, sc->irq_cookie);
err_free_irq_res:
	bus_free_resource(dev, SYS_RES_IRQ, sc->irq_res);
err_free_mem:
	bus_free_resource(dev, SYS_RES_MEMORY, sc->mem_res);
	return (ret);
}

static int
sdhci_fsl_fdt_detach(device_t dev)
{
	struct sdhci_fsl_fdt_softc *sc;

	sc = device_get_softc(dev);
	if (sc->slot_init_done)
		sdhci_cleanup_slot(&sc->slot);
	if (sc->gpio != NULL)
		sdhci_fdt_gpio_teardown(sc->gpio);
	if (sc->irq_cookie != NULL)
		bus_teardown_intr(dev, sc->irq_res, sc->irq_cookie);
	if (sc->irq_res != NULL)
		bus_free_resource(dev, SYS_RES_IRQ, sc->irq_res);
	if (sc->mem_res != NULL)
		bus_free_resource(dev, SYS_RES_MEMORY, sc->mem_res);
	return (0);
}

static int
sdhci_fsl_fdt_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (!ofw_bus_search_compatible(dev,
	   sdhci_fsl_fdt_compat_data)->ocd_data)
		return (ENXIO);

	device_set_desc(dev, "NXP QorIQ Layerscape eSDHC controller");
	return (BUS_PROBE_DEFAULT);
}

static int
sdhci_fsl_fdt_read_ivar(device_t bus, device_t child, int which,
    uintptr_t *result)
{
	struct sdhci_slot *slot = device_get_ivars(child);

	if (which == MMCBR_IVAR_MAX_DATA && (slot->opt & SDHCI_HAVE_DMA)) {
		/*
		 * In the absence of SDMA buffer boundary functionality,
		 * limit the maximum data length per read/write command
		 * to bounce buffer size.
		 */
		*result = howmany(slot->sdma_bbufsz, 512);
		return (0);
	}
	return (sdhci_generic_read_ivar(bus, child, which, result));
}

static const device_method_t sdhci_fsl_fdt_methods[] = {
	/* Device interface. */
	DEVMETHOD(device_probe,			sdhci_fsl_fdt_probe),
	DEVMETHOD(device_attach,		sdhci_fsl_fdt_attach),
	DEVMETHOD(device_detach,		sdhci_fsl_fdt_detach),

	/* Bus interface. */
	DEVMETHOD(bus_read_ivar,		sdhci_fsl_fdt_read_ivar),
	DEVMETHOD(bus_write_ivar,		sdhci_generic_write_ivar),

	/* MMC bridge interface. */
	DEVMETHOD(mmcbr_update_ios,		sdhci_generic_update_ios),
	DEVMETHOD(mmcbr_request,		sdhci_generic_request),
	DEVMETHOD(mmcbr_get_ro,			sdhci_fsl_fdt_get_ro),
	DEVMETHOD(mmcbr_acquire_host,		sdhci_generic_acquire_host),
	DEVMETHOD(mmcbr_release_host,		sdhci_generic_release_host),

	/* SDHCI accessors. */
	DEVMETHOD(sdhci_read_1,			sdhci_fsl_fdt_read_1),
	DEVMETHOD(sdhci_read_2,			sdhci_fsl_fdt_read_2),
	DEVMETHOD(sdhci_read_4,			sdhci_fsl_fdt_read_4),
	DEVMETHOD(sdhci_read_multi_4,		sdhci_fsl_fdt_read_multi_4),
	DEVMETHOD(sdhci_write_1,		sdhci_fsl_fdt_write_1),
	DEVMETHOD(sdhci_write_2,		sdhci_fsl_fdt_write_2),
	DEVMETHOD(sdhci_write_4,		sdhci_fsl_fdt_write_4),
	DEVMETHOD(sdhci_write_multi_4,		sdhci_fsl_fdt_write_multi_4),
	DEVMETHOD(sdhci_get_card_present,	sdhci_fsl_fdt_get_card_present),
	DEVMETHOD_END
};

static devclass_t sdhci_fsl_fdt_devclass;
static driver_t sdhci_fsl_fdt_driver = {
	"sdhci_fsl_fdt",
	sdhci_fsl_fdt_methods,
	sizeof(struct sdhci_fsl_fdt_softc),
};

DRIVER_MODULE(sdhci_fsl_fdt, simplebus, sdhci_fsl_fdt_driver,
    sdhci_fsl_fdt_devclass, NULL, NULL);
SDHCI_DEPEND(sdhci_fsl_fdt);

#ifndef MMCCAM
MMC_DECLARE_BRIDGE(sdhci_fsl_fdt);
#endif
