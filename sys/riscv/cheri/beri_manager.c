/*-
 * Copyright (c) 2021 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/malloc.h>
#include <sys/rman.h>
#include <sys/timeet.h>
#include <sys/timetc.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/endian.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>

#include <dev/ofw/openfirm.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>
#include <dev/ofw/ofw_subr.h>

#include <machine/bus.h>
#include <machine/cpu.h>
#include <machine/intr.h>
#include <machine/sbi.h>
#include <machine/vmparam.h>

struct beri_cmd {
	int test;
};

#define	BM_RESET	_IOWR('X', 1, struct beri_cmd)
#define	BM_RELEASE	_IOWR('X', 2, struct beri_cmd)

struct berimgr_softc {
	struct resource		*res[3];
	struct cdev		*mgr_cdev;
	device_t		dev;
	bus_space_tag_t		bst_data;
	bus_space_handle_t	bsh_data;
	uint32_t		offs;
	uint32_t		state;
#define	STATE_RESET	0
#define	STATE_LOADED	1
#define	STATE_RUNNING	2
};

static struct resource_spec berimgr_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ -1, 0 }
};

struct spin_entry {
	uint64_t entry_addr;
	uint64_t a0;
	uint32_t rsvd1;
	uint32_t pir;
	uint64_t rsvd2;
};

#define	BERIPIC1_CFG			0xff7f808000
#define	BERIPIC1_IP_READ		0xff7f80a000
#define	BERIPIC1_IP_SET			0xff7f80a080
#define	BERIPIC1_IP_CLEAR		0xff7f80a100
#define	MIPS_XKPHYS_UNCACHED_BASE	0x9000000000000000ULL
#define	SOFT_IRQ_N			16

void mpentry(u_long hartid);

static void
dm_reset(struct berimgr_softc *sc)
{
#if 0
	uint64_t addr;

	printf("%s: sending IPI to CPU1\n", __func__);

	addr = BERIPIC1_IP_SET | MIPS_XKPHYS_UNCACHED_BASE;
	*(volatile uint64_t *)(addr) = (1 << SOFT_IRQ_N);

	mips_barrier();

	mips_sync();
	mips_sync();
	mips_sync();
#endif
	printf("%s\n", __func__);

	sc->offs = 0;
}

extern vm_offset_t __dm_boot[1];

static int
dm_release(struct berimgr_softc *sc)
{
	uint64_t addr;

	if (sc->offs == 0) {
		/* Nothing loaded */
		return (ENXIO);
	}

	addr = PHYS_TO_DMAP(0xf8000000);
	cpu_dcache_wb_range((vm_offset_t)addr, sc->offs);
	(void) addr;

#if 0
	/* Start secondary core. */
	int error;
	vm_paddr_t start_addr;
	start_addr = pmap_kextract((vm_offset_t)mpentry);
	if (PCPU_GET(hart) == 0)
		error = sbi_hsm_hart_start(1, start_addr, 0);
	else
		error = sbi_hsm_hart_start(0, start_addr, 0);

	printf("%s: cur hart %d error %d\n", __func__, PCPU_GET(hart), error);
#else
	printf("%s: cheribsd hart %d cpuid %d\n", __func__,
	    PCPU_GET(hart), PCPU_GET(cpuid));
#endif

	DELAY(100000);
	DELAY(100000);
	DELAY(100000);
	DELAY(100000);
	DELAY(100000);

	u_long mask;
	void *dtbp;

	dtbp = ofw_fdtp();

	/* Note DM starts at 0xf8000000. */

	__dm_boot[0] = (vm_offset_t)pmap_kextract((vm_offset_t)dtbp);
	if (PCPU_GET(hart) == 0)
		mask = 1 << 1;
	else
		mask = 1 << 0;
	sbi_send_ipi(&mask);
	printf("%s: cpu released, mask %lx, dtbp %lx\n", __func__, mask,
	    __dm_boot[0]);

	return (0);
}

static int
beri_open(struct cdev *dev, int flags __unused,
    int fmt __unused, struct thread *td __unused)
{
#if 0
	struct berimgr_softc *sc;

	sc = dev->si_drv1;
#endif
	return (0);
}

static int
beri_close(struct cdev *dev, int flags __unused,
    int fmt __unused, struct thread *td __unused)
{
#if 0
	struct berimgr_softc *sc;

	sc = dev->si_drv1;
#endif
	return (0);
}

static int
beri_write(struct cdev *dev, struct uio *uio, int ioflag)
{
	struct berimgr_softc *sc;
	uint32_t buffer;

	sc = dev->si_drv1;

	if (sc->state != STATE_RESET)
		return (-1);

	while (uio->uio_resid > 0) {
		uiomove(&buffer, 4, uio);
		bus_space_write_4(sc->bst_data, sc->bsh_data,
		    sc->offs, buffer);
		sc->offs += 4;
	}

#if 0
	printf("%s: done\n", __func__);
#endif

	return (0);
}

static int
beri_ioctl(struct cdev *dev, u_long cmd, caddr_t addr, int flags,
    struct thread *td)
{
	struct berimgr_softc *sc;

	sc = dev->si_drv1;

	switch (cmd) {
	case BM_RESET:
		dm_reset(sc);
		sc->state = STATE_RESET;
		break;
	case BM_RELEASE:
		if (dm_release(sc) == 0)
			sc->state = STATE_RUNNING;
		break;
	default:
		break;
	};

	return (0);
}

static struct cdevsw beri_cdevsw = {
	.d_version =	D_VERSION,
	.d_open =	beri_open,
	.d_close =	beri_close,
	.d_write =	beri_write,
	.d_ioctl =	beri_ioctl,
	.d_name =	"BERI Manager",
};

static int
berimgr_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (!ofw_bus_is_compatible(dev, "beri,mgr"))
		return (ENXIO);

	device_set_desc(dev, "BERI Manager");

	return (BUS_PROBE_DEFAULT);
}

static int
berimgr_attach(device_t dev)
{
	struct berimgr_softc *sc;

	sc = device_get_softc(dev);
	sc->dev = dev;

	if (bus_alloc_resources(dev, berimgr_spec, sc->res)) {
		device_printf(dev, "could not allocate resources\n");
		return (ENXIO);
	}

	/* Memory interface */
	sc->bst_data = rman_get_bustag(sc->res[0]);
	sc->bsh_data = rman_get_bushandle(sc->res[0]);

	sc->mgr_cdev = make_dev(&beri_cdevsw, 0, UID_ROOT, GID_WHEEL,
	    0600, "beri%d", device_get_unit(sc->dev));
	if (sc->mgr_cdev == NULL) {
		device_printf(dev, "Failed to create character device.\n");
		return (ENXIO);
	}

	sc->mgr_cdev->si_drv1 = sc;
	sc->offs = 0;
	sc->state = STATE_RESET;

	return (0);
}

static device_method_t berimgr_methods[] = {
	DEVMETHOD(device_probe,		berimgr_probe),
	DEVMETHOD(device_attach,	berimgr_attach),
	{ 0, 0 }
};

static driver_t berimgr_driver = {
	"berimgr",
	berimgr_methods,
	sizeof(struct berimgr_softc),
};

/* static devclass_t berimgr_devclass; */

DRIVER_MODULE(berimgr, simplebus, berimgr_driver, 0, 0);
