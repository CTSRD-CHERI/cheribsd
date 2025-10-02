/*-
 * Copyright (c) 2025 Ruslan Bukin <br@bsdpad.com>
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/rman.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <machine/bus.h>
#include <machine/sbi.h>

#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <sys/hwc.h>
#include <dev/hwc/hwc_context.h>
#include <dev/hwc/hwc_backend.h>

#if 0
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

static struct ofw_compat_data compat_data[] = {
	{ "riscv,pmu",			1 },
	{ NULL,				0 }
};

struct pmu_softc {
	device_t dev;
};

static int
pmu_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_search_compatible(dev, compat_data)->ocd_data == 0)
		return (ENXIO);

	device_set_desc(dev, "RISC-V Performance Monitoring Unit (PMU)");

	return (BUS_PROBE_DEFAULT);
}

static int
pmu_backend_init(struct hwc_context *ctx)
{

	dprintf("%s\n", __func__);

	return (0);
}

static int
pmu_backend_deinit(struct hwc_context *ctx)
{

	dprintf("%s\n", __func__);

	return (0);
}

static int
pmu_backend_configure(struct hwc_context *ctx, struct hwc_configure *hc)
{
	struct sbi_ret ret;
	uint32_t reg;

	dprintf("%s: event_id %d counter_id %d\n", __func__, hc->event_id,
	    hc->counter_id);

#if 1
	/* Raw counter example usage. */
	ret = SBI_CALL5(SBI_EXT_ID_PMU, SBI_PMU_COUNTER_CONFIG_MATCHING, 0,
	    (1 << hc->counter_id), hc->flags, 0x20000, hc->event_id);
#else
	ret = SBI_CALL5(SBI_EXT_ID_PMU, SBI_PMU_COUNTER_CONFIG_MATCHING, 0,
	    (1 << hc->counter_id), hc->flags, hc->event_id, 0);
#endif

	dprintf("%s: config match ev_id %d counter_id %d, err %ld val %ld\n",
	    __func__, hc->event_id, hc->counter_id, ret.error, ret.value);

	/* Enable user access. */
	if (ret.error == 0) {
		reg = csr_read(scounteren);
		reg |= (1 << hc->counter_id);
		csr_write(scounteren, reg);
	}

	return (ret.error);
}

static int
pmu_backend_start(struct hwc_context *ctx, struct hwc_start *hs)
{
	struct sbi_ret ret;

	ret = SBI_CALL4(SBI_EXT_ID_PMU, SBI_PMU_COUNTER_START, 0,
	    hs->counter_mask, hs->flags, hs->data);

	dprintf("start counters err %ld num %ld\n", ret.error, ret.value);

	return (ret.error);
}

static int
pmu_backend_stop(struct hwc_context *ctx, struct hwc_stop *hs)
{
	struct sbi_ret ret;

	ret = SBI_CALL3(SBI_EXT_ID_PMU, SBI_PMU_COUNTER_STOP, 0,
	    hs->counter_mask, hs->flags);

	dprintf("stop counters err %ld num %ld\n", ret.error, ret.value);

	return (ret.error);
}

static struct hwc_backend_ops pmu_ops = {
	.hwc_backend_init = pmu_backend_init,
	.hwc_backend_deinit = pmu_backend_deinit,
	.hwc_backend_configure = pmu_backend_configure,
	.hwc_backend_start = pmu_backend_start,
	.hwc_backend_stop = pmu_backend_stop,
#if 0
	.hwc_backend_enable = pmu_backend_enable,
	.hwc_backend_disable = pmu_backend_disable,
	.hwc_backend_read = pmu_backend_read,
	.hwc_backend_dump = pmu_backend_dump,
#endif
};

static struct hwc_backend pmu_backend = {
	.ops = &pmu_ops,
	.name = "pmu",
};

static int
pmu_attach(device_t dev)
{
	struct pmu_softc *sc;
	int error;

	sc = device_get_softc(dev);
	sc->dev = dev;

	error = hwc_backend_register(&pmu_backend);
	if (error) {
		device_printf(dev, "Could not register in HWC\n");
		return (error);
	}

	return (0);
}

static device_method_t pmu_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		pmu_probe),
	DEVMETHOD(device_attach,	pmu_attach),
	DEVMETHOD_END
};

static driver_t pmu_driver = {
	"pmu",
	pmu_methods,
	sizeof(struct pmu_softc)
};

DRIVER_MODULE(pmu, simplebus, pmu_driver, 0, 0);
MODULE_DEPEND(pmu, hwc, 1, 1, 1);
MODULE_VERSION(pmu, 1);
