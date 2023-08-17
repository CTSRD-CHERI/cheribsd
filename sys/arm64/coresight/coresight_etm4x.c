/*-
 * Copyright (c) 2018-2023 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
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
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/rman.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <machine/bus.h>

#include <arm64/coresight/coresight.h>
#include <arm64/coresight/coresight_etm4x.h>

#include <dev/hwt/hwt_context.h>

#include "coresight_if.h"

#define	ETM_DEBUG
#undef ETM_DEBUG
   
#ifdef ETM_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

/*
 * Typical trace flow:
 *
 * CPU0 -> ETM0 -> funnel1 -> funnel0 -> ETF -> replicator -> ETR -> DRAM
 * CPU1 -> ETM1 -> funnel1 -^
 * CPU2 -> ETM2 -> funnel1 -^
 * CPU3 -> ETM3 -> funnel1 -^
 */

static struct resource_spec etm_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ -1, 0 }
};

static int
etm_configure_etmv4(device_t dev, struct etmv4_config *config)
{
	struct etm_softc *sc;
	int cpu;
	int i;

	sc = device_get_softc(dev);

	cpu = PCPU_GET(cpuid);

	dprintf("%s_%d\n", __func__, device_get_unit(dev));

	bus_write_4(sc->res, TRCCONFIGR, config->cfg);
	bus_write_4(sc->res, TRCEVENTCTL0R, config->eventctrl0);
	bus_write_4(sc->res, TRCEVENTCTL1R, config->eventctrl1);
	bus_write_4(sc->res, TRCSTALLCTLR, config->stall_ctrl);
	bus_write_4(sc->res, TRCTSCTLR, config->ts_ctrl);
	bus_write_4(sc->res, TRCSYNCPR, config->syncfreq);
	bus_write_4(sc->res, TRCVICTLR, config->vinst_ctrl);
	bus_write_4(sc->res, TRCPROCSELR, cpu); /* Not sure if this is needed.*/

	/* Address-range filtering. */
	for (i = 0; i < ETM_MAX_SINGLE_ADDR_CMP; i++) {
		bus_write_8(sc->res, TRCACVR(i), config->addr_val[i]);
		bus_write_8(sc->res, TRCACATR(i), config->addr_acc[i]);
	}
	bus_write_4(sc->res, TRCVIIECTLR, config->viiectlr);

	bus_write_4(sc->res, TRCVDARCCTLR, 0);
	bus_write_4(sc->res, TRCSSCSR(0), 0);
	bus_write_4(sc->res, TRCVISSCTLR, config->vissctlr);
	bus_write_4(sc->res, TRCVDCTLR, 0);
	bus_write_4(sc->res, TRCVDSACCTLR, 0);

#if 0
        uint32_t                mode;
        uint32_t                pe_sel;
        uint32_t                cfg;
        uint32_t                eventctrl0;
        uint32_t                eventctrl1;
        uint32_t                stall_ctrl;
        uint32_t                ts_ctrl;
        uint32_t                syncfreq;
        uint32_t                ccctlr;
        uint32_t                bb_ctrl;
        uint32_t                vinst_ctrl;
        uint32_t                viiectlr;
        uint32_t                vissctlr;
        uint32_t                vipcssctlr;
        uint8_t                 seq_idx;
        uint32_t                seq_ctrl[ETM_MAX_SEQ_STATES];
        uint32_t                seq_rst;
        uint32_t                seq_state;
        uint8_t                 cntr_idx;
        uint32_t                cntrldvr[ETMv4_MAX_CNTR];
        uint32_t                cntr_ctrl[ETMv4_MAX_CNTR];
        uint32_t                cntr_val[ETMv4_MAX_CNTR];
        uint8_t                 res_idx;
        uint32_t                res_ctrl[ETM_MAX_RES_SEL];
        uint8_t                 ss_idx;
        uint32_t                ss_ctrl[ETM_MAX_SS_CMP];
        uint32_t                ss_status[ETM_MAX_SS_CMP];
        uint32_t                ss_pe_cmp[ETM_MAX_SS_CMP];
        uint8_t                 addr_idx;
        uint64_t                addr_val[ETM_MAX_SINGLE_ADDR_CMP];
        uint64_t                addr_acc[ETM_MAX_SINGLE_ADDR_CMP];
        uint8_t                 addr_type[ETM_MAX_SINGLE_ADDR_CMP];
        uint8_t                 ctxid_idx;
        uint64_t                ctxid_pid[ETMv4_MAX_CTXID_CMP];
        uint32_t                ctxid_mask0;
        uint32_t                ctxid_mask1;
        uint8_t                 vmid_idx;
        uint64_t                vmid_val[ETM_MAX_VMID_CMP];
        uint32_t                vmid_mask0;
        uint32_t                vmid_mask1;
        uint32_t                ext_inp; 
        uint8_t                 s_ex_level;
#endif

	return (0);
}

static int
etm_configure_etmv4_default(device_t dev, struct coresight_pipeline *pipeline)
{
	struct etm_softc *sc;
	uint32_t reg;
	int i;

	dprintf("%s%d\n", __func__, device_get_unit(dev));

	sc = device_get_softc(dev);

	/* Configure ETM */

	/*
	 * Enable the return stack, global timestamping,
	 * Context ID, and Virtual context identifier tracing.
	 */
	reg = TRCCONFIGR_RS | TRCCONFIGR_TS;
	reg |= TRCCONFIGR_CID | TRCCONFIGR_VMID;
	reg |= TRCCONFIGR_INSTP0_LDRSTR;
	reg |= TRCCONFIGR_COND_ALL;
	bus_write_4(sc->res, TRCCONFIGR, reg);
	dprintf("%s: TRCCONFIGR is %x\n", __func__, reg);

	/* Disable all event tracing. */
	bus_write_4(sc->res, TRCEVENTCTL0R, 0);
	bus_write_4(sc->res, TRCEVENTCTL1R, 0);

	/* Disable stalling, if implemented. */
	bus_write_4(sc->res, TRCSTALLCTLR, 0);

	/* Enable trace synchronization every 4096 bytes of trace. */
	bus_write_4(sc->res, TRCSYNCPR, TRCSYNCPR_4K);

	dprintf("%s: IDR0 is %x\n", __func__, bus_read_4(sc->res, TRCIDR(0)));
	dprintf("%s: IDR1 is %x\n", __func__, bus_read_4(sc->res, TRCIDR(1)));
	dprintf("%s: IDR2 is %x\n", __func__, bus_read_4(sc->res, TRCIDR(2)));
	dprintf("%s: IDR8 is %x\n", __func__, bus_read_4(sc->res, TRCIDR(8)));

	/*
	 * Disable the timestamp event. The trace unit still generates
	 * timestamps due to other reasons such as trace synchronization.
	 */
	bus_write_4(sc->res, TRCTSCTLR, 0);

	/*
	 * Enable ViewInst to trace everything, with the start/stop
	 * logic started.
	 */
	reg = TRCVICTLR_SSSTATUS;

	/* The number of the single resource used to activate the event. */
	reg |= (1 << EVENT_SEL_S);

	if (pipeline->excp_level > 2)
		return (-1);

	reg |= TRCVICTLR_EXLEVEL_NS_M;
	reg &= ~TRCVICTLR_EXLEVEL_NS(pipeline->excp_level);
	reg |= TRCVICTLR_EXLEVEL_S_M;
	reg &= ~TRCVICTLR_EXLEVEL_S(pipeline->excp_level);
	bus_write_4(sc->res, TRCVICTLR, reg);

	for (i = 0; i < pipeline->naddr * 2; i++) {
		dprintf("configure range %d, address %lx\n",
		    i, pipeline->addr[i]);
		bus_write_8(sc->res, TRCACVR(i), pipeline->addr[i]);

		reg = 0;
		/* Secure state */
		reg |= TRCACATR_EXLEVEL_S_M;
		reg &= ~TRCACATR_EXLEVEL_S(pipeline->excp_level);
		/* Non-secure state */
		reg |= TRCACATR_EXLEVEL_NS_M;
		reg &= ~TRCACATR_EXLEVEL_NS(pipeline->excp_level);
		bus_write_4(sc->res, TRCACATR(i), reg);

		/* Address range is included */
		reg = bus_read_4(sc->res, TRCVIIECTLR);
		reg |= (1 << (TRCVIIECTLR_INCLUDE_S + i / 2));
		bus_write_4(sc->res, TRCVIIECTLR, reg);
	}

	/* No address filtering for ViewData. */
	bus_write_4(sc->res, TRCVDARCCTLR, 0);

	/* Clear the STATUS bit to zero */
	bus_write_4(sc->res, TRCSSCSR(0), 0);

	if (pipeline->naddr == 0) {
		/* No address range filtering for ViewInst. */
		bus_write_4(sc->res, TRCVIIECTLR, 0);
	}

	/* No start or stop points for ViewInst. */
	bus_write_4(sc->res, TRCVISSCTLR, 0);

	/* Disable ViewData */
	bus_write_4(sc->res, TRCVDCTLR, 0);

	/* No address filtering for ViewData. */
	bus_write_4(sc->res, TRCVDSACCTLR, 0);

	return (0);
}

static int
etm_configure(device_t dev, struct endpoint *endp,
    struct coresight_pipeline *pipeline, struct hwt_context *ctx)
{
	struct etmv4_config *config;
	int error;

	dprintf("%s%d\n", __func__, device_get_unit(dev));

	if (ctx->config &&
	    ctx->config_size == sizeof(struct etmv4_config) &&
	    ctx->config_version == 1) {
		config = (struct etmv4_config *)ctx->config;
		error = etm_configure_etmv4(dev, config);
	} else
		error = etm_configure_etmv4_default(dev, pipeline);

	return (error);
}

static int
etm_init(device_t dev)
{
	struct etm_softc *sc;
	uint32_t reg __unused;

	sc = device_get_softc(dev);

	dprintf("%s%d\n", __func__, device_get_unit(dev));

	/* Unlocking Coresight */
	bus_write_4(sc->res, CORESIGHT_LAR, CORESIGHT_UNLOCK);

	/* Unlocking ETM */
	bus_write_4(sc->res, TRCOSLAR, 0);

	reg = bus_read_4(sc->res, TRCIDR(1));
	dprintf("ETM Version: %d.%d\n",
	    (reg & TRCIDR1_TRCARCHMAJ_M) >> TRCIDR1_TRCARCHMAJ_S,
	    (reg & TRCIDR1_TRCARCHMIN_M) >> TRCIDR1_TRCARCHMIN_S);

	return (0);
}

static int
etm_enable(device_t dev, struct endpoint *endp,
    struct coresight_pipeline *pipeline)
{
	struct etm_softc *sc;
	uint32_t reg;

	sc = device_get_softc(dev);

	dprintf("%s%d\n", __func__, device_get_unit(dev));

	/* Set a value for the trace ID */
	bus_write_4(sc->res, TRCTRACEIDR, pipeline->etm.trace_id);

	/* Enable the trace unit */
	reg = bus_read_4(sc->res, TRCPRGCTLR);
	reg |= TRCPRGCTLR_EN;
	bus_write_4(sc->res, TRCPRGCTLR, reg);

	/* Wait for an IDLE bit to be LOW */

	/* TODO: add timeout */
	do {
		reg = bus_read_4(sc->res, TRCSTATR);
	} while (reg & TRCSTATR_IDLE);

	if ((bus_read_4(sc->res, TRCPRGCTLR) & TRCPRGCTLR_EN) == 0) {
		printf("%s: etm is not enabled\n", __func__);
		return (ENXIO);
	}

	return (0);
}

static void
etm_disable(device_t dev, struct endpoint *endp,
    struct coresight_pipeline *pipeline)
{
	struct etm_softc *sc;
	uint32_t reg;

	sc = device_get_softc(dev);

	dprintf("%s%d\n", __func__, device_get_unit(dev));

	/* Disable the trace unit */
	reg = bus_read_4(sc->res, TRCPRGCTLR);
	reg &= ~TRCPRGCTLR_EN;
	bus_write_4(sc->res, TRCPRGCTLR, reg);

	/* Wait for an IDLE bit */
	do {
		reg = bus_read_4(sc->res, TRCSTATR);
	} while ((reg & TRCSTATR_IDLE) == 0);
}

int
etm_attach(device_t dev)
{
	struct coresight_desc desc;
	struct etm_softc *sc;
	char name[16];
	int i;

	sc = device_get_softc(dev);

	if (bus_alloc_resources(dev, etm_spec, &sc->res) != 0) {
		device_printf(dev, "cannot allocate resources for device\n");
		return (ENXIO);
	}

	desc.pdata = sc->pdata;
	desc.dev = dev;
	desc.dev_type = CORESIGHT_ETMV4;
	coresight_register(&desc);

	for (i = 0; i < 14; i++) {
		snprintf(name, 16, "idr%d", i);
		sc->id_regs[i] = bus_read_4(sc->res, TRCIDR(i));
		SYSCTL_ADD_INT(device_get_sysctl_ctx(dev),
		    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
		    OID_AUTO, name, CTLFLAG_RD,
		    &sc->id_regs[i], 0, "id register");
	}

	return (0);
}

int
etm_detach(device_t dev)
{
	struct etm_softc *sc;
	int error;

	sc = device_get_softc(dev);
 
	error = coresight_unregister(dev);
	if (error)
		return (error);

	bus_release_resources(dev, etm_spec, &sc->res);

	return (0);
}

static device_method_t etm_methods[] = {
	/* Coresight interface */
	DEVMETHOD(coresight_init,	etm_init),
	DEVMETHOD(coresight_configure,	etm_configure),
	DEVMETHOD(coresight_enable,	etm_enable),
	DEVMETHOD(coresight_disable,	etm_disable),
	DEVMETHOD_END
};

DEFINE_CLASS_0(coresight_etm4x, coresight_etm4x_driver, etm_methods,
    sizeof(struct etm_softc));
