/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2016 Nicole Graziano <nicole@nextbsd.org>
 * All rights reserved.
 * Copyright (c) 2021 Rubicon Communications, LLC (Netgate)
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

#include "if_igc.h"
#include <sys/sbuf.h>
#include <machine/_inttypes.h>

#ifdef RSS
#include <net/rss_config.h>
#include <netinet/in_rss.h>
#endif

/*********************************************************************
 *  PCI Device ID Table
 *
 *  Used by probe to select devices to load on
 *  Last entry must be all 0s
 *
 *  { Vendor ID, Device ID, String }
 *********************************************************************/

static pci_vendor_info_t igc_vendor_info_array[] =
{
	/* Intel(R) PRO/1000 Network Connection - igc */
	PVID(0x8086, IGC_DEV_ID_I225_LM, "Intel(R) Ethernet Controller I225-LM"),
	PVID(0x8086, IGC_DEV_ID_I225_V, "Intel(R) Ethernet Controller I225-V"),
	PVID(0x8086, IGC_DEV_ID_I225_K, "Intel(R) Ethernet Controller I225-K"),
	PVID(0x8086, IGC_DEV_ID_I225_I, "Intel(R) Ethernet Controller I225-I"),
	PVID(0x8086, IGC_DEV_ID_I220_V, "Intel(R) Ethernet Controller I220-V"),
	PVID(0x8086, IGC_DEV_ID_I225_K2, "Intel(R) Ethernet Controller I225-K(2)"),
	PVID(0x8086, IGC_DEV_ID_I225_LMVP, "Intel(R) Ethernet Controller I225-LMvP(2)"),
	PVID(0x8086, IGC_DEV_ID_I226_K, "Intel(R) Ethernet Controller I226-K"),
	PVID(0x8086, IGC_DEV_ID_I225_IT, "Intel(R) Ethernet Controller I225-IT(2)"),
	PVID(0x8086, IGC_DEV_ID_I226_LM, "Intel(R) Ethernet Controller I226-LM"),
	PVID(0x8086, IGC_DEV_ID_I226_V, "Intel(R) Ethernet Controller I226-V"),
	PVID(0x8086, IGC_DEV_ID_I226_IT, "Intel(R) Ethernet Controller I226-IT"),
	PVID(0x8086, IGC_DEV_ID_I221_V, "Intel(R) Ethernet Controller I221-V"),
	PVID(0x8086, IGC_DEV_ID_I226_BLANK_NVM, "Intel(R) Ethernet Controller I226(blankNVM)"),
	PVID(0x8086, IGC_DEV_ID_I225_BLANK_NVM, "Intel(R) Ethernet Controller I225(blankNVM)"),
	/* required last entry */
	PVID_END
};

/*********************************************************************
 *  Function prototypes
 *********************************************************************/
static void	*igc_register(device_t dev);
static int	igc_if_attach_pre(if_ctx_t ctx);
static int	igc_if_attach_post(if_ctx_t ctx);
static int	igc_if_detach(if_ctx_t ctx);
static int	igc_if_shutdown(if_ctx_t ctx);
static int	igc_if_suspend(if_ctx_t ctx);
static int	igc_if_resume(if_ctx_t ctx);

static int	igc_if_tx_queues_alloc(if_ctx_t ctx, caddr_t *vaddrs, uint64_t *paddrs, int ntxqs, int ntxqsets);
static int	igc_if_rx_queues_alloc(if_ctx_t ctx, caddr_t *vaddrs, uint64_t *paddrs, int nrxqs, int nrxqsets);
static void	igc_if_queues_free(if_ctx_t ctx);

static uint64_t	igc_if_get_counter(if_ctx_t, ift_counter);
static void	igc_if_init(if_ctx_t ctx);
static void	igc_if_stop(if_ctx_t ctx);
static void	igc_if_media_status(if_ctx_t, struct ifmediareq *);
static int	igc_if_media_change(if_ctx_t ctx);
static int	igc_if_mtu_set(if_ctx_t ctx, uint32_t mtu);
static void	igc_if_timer(if_ctx_t ctx, uint16_t qid);
static void	igc_if_vlan_register(if_ctx_t ctx, u16 vtag);
static void	igc_if_vlan_unregister(if_ctx_t ctx, u16 vtag);
static void	igc_if_watchdog_reset(if_ctx_t ctx);
static bool	igc_if_needs_restart(if_ctx_t ctx, enum iflib_restart_event event);

static void	igc_identify_hardware(if_ctx_t ctx);
static int	igc_allocate_pci_resources(if_ctx_t ctx);
static void	igc_free_pci_resources(if_ctx_t ctx);
static void	igc_reset(if_ctx_t ctx);
static int	igc_setup_interface(if_ctx_t ctx);
static int	igc_setup_msix(if_ctx_t ctx);

static void	igc_initialize_transmit_unit(if_ctx_t ctx);
static void	igc_initialize_receive_unit(if_ctx_t ctx);

static void	igc_if_intr_enable(if_ctx_t ctx);
static void	igc_if_intr_disable(if_ctx_t ctx);
static int	igc_if_rx_queue_intr_enable(if_ctx_t ctx, uint16_t rxqid);
static int	igc_if_tx_queue_intr_enable(if_ctx_t ctx, uint16_t txqid);
static void	igc_if_multi_set(if_ctx_t ctx);
static void	igc_if_update_admin_status(if_ctx_t ctx);
static void	igc_if_debug(if_ctx_t ctx);
static void	igc_update_stats_counters(struct igc_adapter *);
static void	igc_add_hw_stats(struct igc_adapter *adapter);
static int	igc_if_set_promisc(if_ctx_t ctx, int flags);
static void	igc_setup_vlan_hw_support(struct igc_adapter *);
static int	igc_sysctl_nvm_info(SYSCTL_HANDLER_ARGS);
static void	igc_print_nvm_info(struct igc_adapter *);
static int	igc_sysctl_debug_info(SYSCTL_HANDLER_ARGS);
static int	igc_get_rs(SYSCTL_HANDLER_ARGS);
static void	igc_print_debug_info(struct igc_adapter *);
static int 	igc_is_valid_ether_addr(u8 *);
static int	igc_sysctl_int_delay(SYSCTL_HANDLER_ARGS);
static void	igc_add_int_delay_sysctl(struct igc_adapter *, const char *,
		    const char *, struct igc_int_delay_info *, int, int);
/* Management and WOL Support */
static void	igc_get_hw_control(struct igc_adapter *);
static void	igc_release_hw_control(struct igc_adapter *);
static void	igc_get_wakeup(if_ctx_t ctx);
static void	igc_enable_wakeup(if_ctx_t ctx);

int		igc_intr(void *arg);

/* MSI-X handlers */
static int	igc_if_msix_intr_assign(if_ctx_t, int);
static int	igc_msix_link(void *);
static void	igc_handle_link(void *context);

static int	igc_set_flowcntl(SYSCTL_HANDLER_ARGS);
static int	igc_sysctl_eee(SYSCTL_HANDLER_ARGS);

static int	igc_get_regs(SYSCTL_HANDLER_ARGS);

static void	igc_configure_queues(struct igc_adapter *adapter);


/*********************************************************************
 *  FreeBSD Device Interface Entry Points
 *********************************************************************/
static device_method_t igc_methods[] = {
	/* Device interface */
	DEVMETHOD(device_register, igc_register),
	DEVMETHOD(device_probe, iflib_device_probe),
	DEVMETHOD(device_attach, iflib_device_attach),
	DEVMETHOD(device_detach, iflib_device_detach),
	DEVMETHOD(device_shutdown, iflib_device_shutdown),
	DEVMETHOD(device_suspend, iflib_device_suspend),
	DEVMETHOD(device_resume, iflib_device_resume),
	DEVMETHOD_END
};

static driver_t igc_driver = {
	"igc", igc_methods, sizeof(struct igc_adapter),
};

static devclass_t igc_devclass;
DRIVER_MODULE(igc, pci, igc_driver, igc_devclass, 0, 0);

MODULE_DEPEND(igc, pci, 1, 1, 1);
MODULE_DEPEND(igc, ether, 1, 1, 1);
MODULE_DEPEND(igc, iflib, 1, 1, 1);

IFLIB_PNP_INFO(pci, igc, igc_vendor_info_array);

static device_method_t igc_if_methods[] = {
	DEVMETHOD(ifdi_attach_pre, igc_if_attach_pre),
	DEVMETHOD(ifdi_attach_post, igc_if_attach_post),
	DEVMETHOD(ifdi_detach, igc_if_detach),
	DEVMETHOD(ifdi_shutdown, igc_if_shutdown),
	DEVMETHOD(ifdi_suspend, igc_if_suspend),
	DEVMETHOD(ifdi_resume, igc_if_resume),
	DEVMETHOD(ifdi_init, igc_if_init),
	DEVMETHOD(ifdi_stop, igc_if_stop),
	DEVMETHOD(ifdi_msix_intr_assign, igc_if_msix_intr_assign),
	DEVMETHOD(ifdi_intr_enable, igc_if_intr_enable),
	DEVMETHOD(ifdi_intr_disable, igc_if_intr_disable),
	DEVMETHOD(ifdi_tx_queues_alloc, igc_if_tx_queues_alloc),
	DEVMETHOD(ifdi_rx_queues_alloc, igc_if_rx_queues_alloc),
	DEVMETHOD(ifdi_queues_free, igc_if_queues_free),
	DEVMETHOD(ifdi_update_admin_status, igc_if_update_admin_status),
	DEVMETHOD(ifdi_multi_set, igc_if_multi_set),
	DEVMETHOD(ifdi_media_status, igc_if_media_status),
	DEVMETHOD(ifdi_media_change, igc_if_media_change),
	DEVMETHOD(ifdi_mtu_set, igc_if_mtu_set),
	DEVMETHOD(ifdi_promisc_set, igc_if_set_promisc),
	DEVMETHOD(ifdi_timer, igc_if_timer),
	DEVMETHOD(ifdi_watchdog_reset, igc_if_watchdog_reset),
	DEVMETHOD(ifdi_vlan_register, igc_if_vlan_register),
	DEVMETHOD(ifdi_vlan_unregister, igc_if_vlan_unregister),
	DEVMETHOD(ifdi_get_counter, igc_if_get_counter),
	DEVMETHOD(ifdi_rx_queue_intr_enable, igc_if_rx_queue_intr_enable),
	DEVMETHOD(ifdi_tx_queue_intr_enable, igc_if_tx_queue_intr_enable),
	DEVMETHOD(ifdi_debug, igc_if_debug),
	DEVMETHOD(ifdi_needs_restart, igc_if_needs_restart),
	DEVMETHOD_END
};

static driver_t igc_if_driver = {
	"igc_if", igc_if_methods, sizeof(struct igc_adapter)
};

/*********************************************************************
 *  Tunable default values.
 *********************************************************************/

#define IGC_TICKS_TO_USECS(ticks)	((1024 * (ticks) + 500) / 1000)
#define IGC_USECS_TO_TICKS(usecs)	((1000 * (usecs) + 512) / 1024)

#define MAX_INTS_PER_SEC	8000
#define DEFAULT_ITR		(1000000000/(MAX_INTS_PER_SEC * 256))

/* Allow common code without TSO */
#ifndef CSUM_TSO
#define CSUM_TSO	0
#endif

static SYSCTL_NODE(_hw, OID_AUTO, igc, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "igc driver parameters");

static int igc_disable_crc_stripping = 0;
SYSCTL_INT(_hw_igc, OID_AUTO, disable_crc_stripping, CTLFLAG_RDTUN,
    &igc_disable_crc_stripping, 0, "Disable CRC Stripping");

static int igc_tx_int_delay_dflt = IGC_TICKS_TO_USECS(IGC_TIDV_VAL);
static int igc_rx_int_delay_dflt = IGC_TICKS_TO_USECS(IGC_RDTR_VAL);
SYSCTL_INT(_hw_igc, OID_AUTO, tx_int_delay, CTLFLAG_RDTUN, &igc_tx_int_delay_dflt,
    0, "Default transmit interrupt delay in usecs");
SYSCTL_INT(_hw_igc, OID_AUTO, rx_int_delay, CTLFLAG_RDTUN, &igc_rx_int_delay_dflt,
    0, "Default receive interrupt delay in usecs");

static int igc_tx_abs_int_delay_dflt = IGC_TICKS_TO_USECS(IGC_TADV_VAL);
static int igc_rx_abs_int_delay_dflt = IGC_TICKS_TO_USECS(IGC_RADV_VAL);
SYSCTL_INT(_hw_igc, OID_AUTO, tx_abs_int_delay, CTLFLAG_RDTUN,
    &igc_tx_abs_int_delay_dflt, 0,
    "Default transmit interrupt delay limit in usecs");
SYSCTL_INT(_hw_igc, OID_AUTO, rx_abs_int_delay, CTLFLAG_RDTUN,
    &igc_rx_abs_int_delay_dflt, 0,
    "Default receive interrupt delay limit in usecs");

static int igc_smart_pwr_down = false;
SYSCTL_INT(_hw_igc, OID_AUTO, smart_pwr_down, CTLFLAG_RDTUN, &igc_smart_pwr_down,
    0, "Set to true to leave smart power down enabled on newer adapters");

/* Controls whether promiscuous also shows bad packets */
static int igc_debug_sbp = true;
SYSCTL_INT(_hw_igc, OID_AUTO, sbp, CTLFLAG_RDTUN, &igc_debug_sbp, 0,
    "Show bad packets in promiscuous mode");

/* How many packets rxeof tries to clean at a time */
static int igc_rx_process_limit = 100;
SYSCTL_INT(_hw_igc, OID_AUTO, rx_process_limit, CTLFLAG_RDTUN,
    &igc_rx_process_limit, 0,
    "Maximum number of received packets to process "
    "at a time, -1 means unlimited");

/* Energy efficient ethernet - default to OFF */
static int igc_eee_setting = 1;
SYSCTL_INT(_hw_igc, OID_AUTO, eee_setting, CTLFLAG_RDTUN, &igc_eee_setting, 0,
    "Enable Energy Efficient Ethernet");

/*
** Tuneable Interrupt rate
*/
static int igc_max_interrupt_rate = 8000;
SYSCTL_INT(_hw_igc, OID_AUTO, max_interrupt_rate, CTLFLAG_RDTUN,
    &igc_max_interrupt_rate, 0, "Maximum interrupts per second");

extern struct if_txrx igc_txrx;

static struct if_shared_ctx igc_sctx_init = {
	.isc_magic = IFLIB_MAGIC,
	.isc_q_align = PAGE_SIZE,
	.isc_tx_maxsize = IGC_TSO_SIZE + sizeof(struct ether_vlan_header),
	.isc_tx_maxsegsize = PAGE_SIZE,
	.isc_tso_maxsize = IGC_TSO_SIZE + sizeof(struct ether_vlan_header),
	.isc_tso_maxsegsize = IGC_TSO_SEG_SIZE,
	.isc_rx_maxsize = MAX_JUMBO_FRAME_SIZE,
	.isc_rx_nsegments = 1,
	.isc_rx_maxsegsize = MJUM9BYTES,
	.isc_nfl = 1,
	.isc_nrxqs = 1,
	.isc_ntxqs = 1,
	.isc_admin_intrcnt = 1,
	.isc_vendor_info = igc_vendor_info_array,
	.isc_driver_version = "1",
	.isc_driver = &igc_if_driver,
	.isc_flags = IFLIB_NEED_SCRATCH | IFLIB_TSO_INIT_IP | IFLIB_NEED_ZERO_CSUM,

	.isc_nrxd_min = {IGC_MIN_RXD},
	.isc_ntxd_min = {IGC_MIN_TXD},
	.isc_nrxd_max = {IGC_MAX_RXD},
	.isc_ntxd_max = {IGC_MAX_TXD},
	.isc_nrxd_default = {IGC_DEFAULT_RXD},
	.isc_ntxd_default = {IGC_DEFAULT_TXD},
};

/*****************************************************************
 *
 * Dump Registers
 *
 ****************************************************************/
#define IGC_REGS_LEN 739

static int igc_get_regs(SYSCTL_HANDLER_ARGS)
{
	struct igc_adapter *adapter = (struct igc_adapter *)arg1;
	struct igc_hw *hw = &adapter->hw;
	struct sbuf *sb;
	u32 *regs_buff;
	int rc;

	regs_buff = malloc(sizeof(u32) * IGC_REGS_LEN, M_DEVBUF, M_WAITOK);
	memset(regs_buff, 0, IGC_REGS_LEN * sizeof(u32));

	rc = sysctl_wire_old_buffer(req, 0);
	MPASS(rc == 0);
	if (rc != 0) {
		free(regs_buff, M_DEVBUF);
		return (rc);
	}

	sb = sbuf_new_for_sysctl(NULL, NULL, 32*400, req);
	MPASS(sb != NULL);
	if (sb == NULL) {
		free(regs_buff, M_DEVBUF);
		return (ENOMEM);
	}

	/* General Registers */
	regs_buff[0] = IGC_READ_REG(hw, IGC_CTRL);
	regs_buff[1] = IGC_READ_REG(hw, IGC_STATUS);
	regs_buff[2] = IGC_READ_REG(hw, IGC_CTRL_EXT);
	regs_buff[3] = IGC_READ_REG(hw, IGC_ICR);
	regs_buff[4] = IGC_READ_REG(hw, IGC_RCTL);
	regs_buff[5] = IGC_READ_REG(hw, IGC_RDLEN(0));
	regs_buff[6] = IGC_READ_REG(hw, IGC_RDH(0));
	regs_buff[7] = IGC_READ_REG(hw, IGC_RDT(0));
	regs_buff[8] = IGC_READ_REG(hw, IGC_RXDCTL(0));
	regs_buff[9] = IGC_READ_REG(hw, IGC_RDBAL(0));
	regs_buff[10] = IGC_READ_REG(hw, IGC_RDBAH(0));
	regs_buff[11] = IGC_READ_REG(hw, IGC_TCTL);
	regs_buff[12] = IGC_READ_REG(hw, IGC_TDBAL(0));
	regs_buff[13] = IGC_READ_REG(hw, IGC_TDBAH(0));
	regs_buff[14] = IGC_READ_REG(hw, IGC_TDLEN(0));
	regs_buff[15] = IGC_READ_REG(hw, IGC_TDH(0));
	regs_buff[16] = IGC_READ_REG(hw, IGC_TDT(0));
	regs_buff[17] = IGC_READ_REG(hw, IGC_TXDCTL(0));

	sbuf_printf(sb, "General Registers\n");
	sbuf_printf(sb, "\tCTRL\t %08x\n", regs_buff[0]);
	sbuf_printf(sb, "\tSTATUS\t %08x\n", regs_buff[1]);
	sbuf_printf(sb, "\tCTRL_EXIT\t %08x\n\n", regs_buff[2]);

	sbuf_printf(sb, "Interrupt Registers\n");
	sbuf_printf(sb, "\tICR\t %08x\n\n", regs_buff[3]);

	sbuf_printf(sb, "RX Registers\n");
	sbuf_printf(sb, "\tRCTL\t %08x\n", regs_buff[4]);
	sbuf_printf(sb, "\tRDLEN\t %08x\n", regs_buff[5]);
	sbuf_printf(sb, "\tRDH\t %08x\n", regs_buff[6]);
	sbuf_printf(sb, "\tRDT\t %08x\n", regs_buff[7]);
	sbuf_printf(sb, "\tRXDCTL\t %08x\n", regs_buff[8]);
	sbuf_printf(sb, "\tRDBAL\t %08x\n", regs_buff[9]);
	sbuf_printf(sb, "\tRDBAH\t %08x\n\n", regs_buff[10]);

	sbuf_printf(sb, "TX Registers\n");
	sbuf_printf(sb, "\tTCTL\t %08x\n", regs_buff[11]);
	sbuf_printf(sb, "\tTDBAL\t %08x\n", regs_buff[12]);
	sbuf_printf(sb, "\tTDBAH\t %08x\n", regs_buff[13]);
	sbuf_printf(sb, "\tTDLEN\t %08x\n", regs_buff[14]);
	sbuf_printf(sb, "\tTDH\t %08x\n", regs_buff[15]);
	sbuf_printf(sb, "\tTDT\t %08x\n", regs_buff[16]);
	sbuf_printf(sb, "\tTXDCTL\t %08x\n", regs_buff[17]);
	sbuf_printf(sb, "\tTDFH\t %08x\n", regs_buff[18]);
	sbuf_printf(sb, "\tTDFT\t %08x\n", regs_buff[19]);
	sbuf_printf(sb, "\tTDFHS\t %08x\n", regs_buff[20]);
	sbuf_printf(sb, "\tTDFPC\t %08x\n\n", regs_buff[21]);

	free(regs_buff, M_DEVBUF);

#ifdef DUMP_DESCS
	{
		if_softc_ctx_t scctx = adapter->shared;
		struct rx_ring *rxr = &rx_que->rxr;
		struct tx_ring *txr = &tx_que->txr;
		int ntxd = scctx->isc_ntxd[0];
		int nrxd = scctx->isc_nrxd[0];
		int j;

	for (j = 0; j < nrxd; j++) {
		u32 staterr = le32toh(rxr->rx_base[j].wb.upper.status_error);
		u32 length =  le32toh(rxr->rx_base[j].wb.upper.length);
		sbuf_printf(sb, "\tReceive Descriptor Address %d: %08" PRIx64 "  Error:%d  Length:%d\n", j, rxr->rx_base[j].read.buffer_addr, staterr, length);
	}

	for (j = 0; j < min(ntxd, 256); j++) {
		unsigned int *ptr = (unsigned int *)&txr->tx_base[j];

		sbuf_printf(sb, "\tTXD[%03d] [0]: %08x [1]: %08x [2]: %08x [3]: %08x  eop: %d DD=%d\n",
			    j, ptr[0], ptr[1], ptr[2], ptr[3], buf->eop,
			    buf->eop != -1 ? txr->tx_base[buf->eop].upper.fields.status & IGC_TXD_STAT_DD : 0);

	}
	}
#endif

	rc = sbuf_finish(sb);
	sbuf_delete(sb);
	return(rc);
}

static void *
igc_register(device_t dev)
{
	return (&igc_sctx_init);
}

static int
igc_set_num_queues(if_ctx_t ctx)
{
	int maxqueues;

	maxqueues = 4;

	return (maxqueues);
}

#define	IGC_CAPS							\
    IFCAP_HWCSUM | IFCAP_VLAN_MTU | IFCAP_VLAN_HWTAGGING |		\
    IFCAP_VLAN_HWCSUM | IFCAP_WOL | IFCAP_VLAN_HWFILTER | IFCAP_TSO4 |	\
    IFCAP_LRO | IFCAP_VLAN_HWTSO | IFCAP_JUMBO_MTU | IFCAP_HWCSUM_IPV6 |\
    IFCAP_TSO6

/*********************************************************************
 *  Device initialization routine
 *
 *  The attach entry point is called when the driver is being loaded.
 *  This routine identifies the type of hardware, allocates all resources
 *  and initializes the hardware.
 *
 *  return 0 on success, positive on failure
 *********************************************************************/
static int
igc_if_attach_pre(if_ctx_t ctx)
{
	struct igc_adapter *adapter;
	if_softc_ctx_t scctx;
	device_t dev;
	struct igc_hw *hw;
	int error = 0;

	INIT_DEBUGOUT("igc_if_attach_pre: begin");
	dev = iflib_get_dev(ctx);
	adapter = iflib_get_softc(ctx);

	adapter->ctx = adapter->osdep.ctx = ctx;
	adapter->dev = adapter->osdep.dev = dev;
	scctx = adapter->shared = iflib_get_softc_ctx(ctx);
	adapter->media = iflib_get_media(ctx);
	hw = &adapter->hw;

	adapter->tx_process_limit = scctx->isc_ntxd[0];

	/* SYSCTL stuff */
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "nvm", CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_NEEDGIANT,
	    adapter, 0, igc_sysctl_nvm_info, "I", "NVM Information");

	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "debug", CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_NEEDGIANT,
	    adapter, 0, igc_sysctl_debug_info, "I", "Debug Information");

	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "fc", CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_NEEDGIANT,
	    adapter, 0, igc_set_flowcntl, "I", "Flow Control");

	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "reg_dump",
	    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_NEEDGIANT, adapter, 0,
	    igc_get_regs, "A", "Dump Registers");

	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "rs_dump",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_NEEDGIANT, adapter, 0,
	    igc_get_rs, "I", "Dump RS indexes");

	/* Determine hardware and mac info */
	igc_identify_hardware(ctx);

	scctx->isc_tx_nsegments = IGC_MAX_SCATTER;
	scctx->isc_nrxqsets_max = scctx->isc_ntxqsets_max = igc_set_num_queues(ctx);
	if (bootverbose)
		device_printf(dev, "attach_pre capping queues at %d\n",
		    scctx->isc_ntxqsets_max);

	scctx->isc_txqsizes[0] = roundup2(scctx->isc_ntxd[0] * sizeof(union igc_adv_tx_desc), IGC_DBA_ALIGN);
	scctx->isc_rxqsizes[0] = roundup2(scctx->isc_nrxd[0] * sizeof(union igc_adv_rx_desc), IGC_DBA_ALIGN);
	scctx->isc_txd_size[0] = sizeof(union igc_adv_tx_desc);
	scctx->isc_rxd_size[0] = sizeof(union igc_adv_rx_desc);
	scctx->isc_txrx = &igc_txrx;
	scctx->isc_tx_tso_segments_max = IGC_MAX_SCATTER;
	scctx->isc_tx_tso_size_max = IGC_TSO_SIZE;
	scctx->isc_tx_tso_segsize_max = IGC_TSO_SEG_SIZE;
	scctx->isc_capabilities = scctx->isc_capenable = IGC_CAPS;
	scctx->isc_tx_csum_flags = CSUM_TCP | CSUM_UDP | CSUM_TSO |
		CSUM_IP6_TCP | CSUM_IP6_UDP | CSUM_SCTP | CSUM_IP6_SCTP;

	/*
	** Some new devices, as with ixgbe, now may
	** use a different BAR, so we need to keep
	** track of which is used.
	*/
	scctx->isc_msix_bar = PCIR_BAR(IGC_MSIX_BAR);
	if (pci_read_config(dev, scctx->isc_msix_bar, 4) == 0)
		scctx->isc_msix_bar += 4;

	/* Setup PCI resources */
	if (igc_allocate_pci_resources(ctx)) {
		device_printf(dev, "Allocation of PCI resources failed\n");
		error = ENXIO;
		goto err_pci;
	}

	/* Do Shared Code initialization */
	error = igc_setup_init_funcs(hw, true);
	if (error) {
		device_printf(dev, "Setup of Shared code failed, error %d\n",
		    error);
		error = ENXIO;
		goto err_pci;
	}

	igc_setup_msix(ctx);
	igc_get_bus_info(hw);

	/* Set up some sysctls for the tunable interrupt delays */
	igc_add_int_delay_sysctl(adapter, "rx_int_delay",
	    "receive interrupt delay in usecs", &adapter->rx_int_delay,
	    IGC_REGISTER(hw, IGC_RDTR), igc_rx_int_delay_dflt);
	igc_add_int_delay_sysctl(adapter, "tx_int_delay",
	    "transmit interrupt delay in usecs", &adapter->tx_int_delay,
	    IGC_REGISTER(hw, IGC_TIDV), igc_tx_int_delay_dflt);
	igc_add_int_delay_sysctl(adapter, "rx_abs_int_delay",
	    "receive interrupt delay limit in usecs",
	    &adapter->rx_abs_int_delay,
	    IGC_REGISTER(hw, IGC_RADV),
	    igc_rx_abs_int_delay_dflt);
	igc_add_int_delay_sysctl(adapter, "tx_abs_int_delay",
	    "transmit interrupt delay limit in usecs",
	    &adapter->tx_abs_int_delay,
	    IGC_REGISTER(hw, IGC_TADV),
	    igc_tx_abs_int_delay_dflt);
	igc_add_int_delay_sysctl(adapter, "itr",
	    "interrupt delay limit in usecs/4",
	    &adapter->tx_itr,
	    IGC_REGISTER(hw, IGC_ITR),
	    DEFAULT_ITR);

	hw->mac.autoneg = DO_AUTO_NEG;
	hw->phy.autoneg_wait_to_complete = false;
	hw->phy.autoneg_advertised = AUTONEG_ADV_DEFAULT;

	/* Copper options */
	if (hw->phy.media_type == igc_media_type_copper) {
		hw->phy.mdix = AUTO_ALL_MODES;
	}

	/*
	 * Set the frame limits assuming
	 * standard ethernet sized frames.
	 */
	scctx->isc_max_frame_size = adapter->hw.mac.max_frame_size =
	    ETHERMTU + ETHER_HDR_LEN + ETHERNET_FCS_SIZE;

	/* Allocate multicast array memory. */
	adapter->mta = malloc(sizeof(u8) * ETHER_ADDR_LEN *
	    MAX_NUM_MULTICAST_ADDRESSES, M_DEVBUF, M_NOWAIT);
	if (adapter->mta == NULL) {
		device_printf(dev, "Can not allocate multicast setup array\n");
		error = ENOMEM;
		goto err_late;
	}

	/* Check SOL/IDER usage */
	if (igc_check_reset_block(hw))
		device_printf(dev, "PHY reset is blocked"
			      " due to SOL/IDER session.\n");

	/* Sysctl for setting Energy Efficient Ethernet */
	adapter->hw.dev_spec._i225.eee_disable = igc_eee_setting;
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev)),
	    OID_AUTO, "eee_control",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_NEEDGIANT,
	    adapter, 0, igc_sysctl_eee, "I",
	    "Disable Energy Efficient Ethernet");

	/*
	** Start from a known state, this is
	** important in reading the nvm and
	** mac from that.
	*/
	igc_reset_hw(hw);

	/* Make sure we have a good EEPROM before we read from it */
	if (igc_validate_nvm_checksum(hw) < 0) {
		/*
		** Some PCI-E parts fail the first check due to
		** the link being in sleep state, call it again,
		** if it fails a second time its a real issue.
		*/
		if (igc_validate_nvm_checksum(hw) < 0) {
			device_printf(dev,
			    "The EEPROM Checksum Is Not Valid\n");
			error = EIO;
			goto err_late;
		}
	}

	/* Copy the permanent MAC address out of the EEPROM */
	if (igc_read_mac_addr(hw) < 0) {
		device_printf(dev, "EEPROM read error while reading MAC"
			      " address\n");
		error = EIO;
		goto err_late;
	}

	if (!igc_is_valid_ether_addr(hw->mac.addr)) {
		device_printf(dev, "Invalid MAC address\n");
		error = EIO;
		goto err_late;
	}

	/*
	 * Get Wake-on-Lan and Management info for later use
	 */
	igc_get_wakeup(ctx);

	/* Enable only WOL MAGIC by default */
	scctx->isc_capenable &= ~IFCAP_WOL;
	if (adapter->wol != 0)
		scctx->isc_capenable |= IFCAP_WOL_MAGIC;

	iflib_set_mac(ctx, hw->mac.addr);

	return (0);

err_late:
	igc_release_hw_control(adapter);
err_pci:
	igc_free_pci_resources(ctx);
	free(adapter->mta, M_DEVBUF);

	return (error);
}

static int
igc_if_attach_post(if_ctx_t ctx)
{
	struct igc_adapter *adapter = iflib_get_softc(ctx);
	struct igc_hw *hw = &adapter->hw;
	int error = 0;

	/* Setup OS specific network interface */
	error = igc_setup_interface(ctx);
	if (error != 0) {
		goto err_late;
	}

	igc_reset(ctx);

	/* Initialize statistics */
	igc_update_stats_counters(adapter);
	hw->mac.get_link_status = true;
	igc_if_update_admin_status(ctx);
	igc_add_hw_stats(adapter);

	/* the driver can now take control from firmware */
	igc_get_hw_control(adapter);

	INIT_DEBUGOUT("igc_if_attach_post: end");

	return (error);

err_late:
	igc_release_hw_control(adapter);
	igc_free_pci_resources(ctx);
	igc_if_queues_free(ctx);
	free(adapter->mta, M_DEVBUF);

	return (error);
}

/*********************************************************************
 *  Device removal routine
 *
 *  The detach entry point is called when the driver is being removed.
 *  This routine stops the adapter and deallocates all the resources
 *  that were allocated for driver operation.
 *
 *  return 0 on success, positive on failure
 *********************************************************************/
static int
igc_if_detach(if_ctx_t ctx)
{
	struct igc_adapter	*adapter = iflib_get_softc(ctx);

	INIT_DEBUGOUT("igc_if_detach: begin");

	igc_phy_hw_reset(&adapter->hw);

	igc_release_hw_control(adapter);
	igc_free_pci_resources(ctx);

	return (0);
}

/*********************************************************************
 *
 *  Shutdown entry point
 *
 **********************************************************************/

static int
igc_if_shutdown(if_ctx_t ctx)
{
	return igc_if_suspend(ctx);
}

/*
 * Suspend/resume device methods.
 */
static int
igc_if_suspend(if_ctx_t ctx)
{
	struct igc_adapter *adapter = iflib_get_softc(ctx);

	igc_release_hw_control(adapter);
	igc_enable_wakeup(ctx);
	return (0);
}

static int
igc_if_resume(if_ctx_t ctx)
{
	igc_if_init(ctx);

	return(0);
}

static int
igc_if_mtu_set(if_ctx_t ctx, uint32_t mtu)
{
	int max_frame_size;
	struct igc_adapter *adapter = iflib_get_softc(ctx);
	if_softc_ctx_t scctx = iflib_get_softc_ctx(ctx);

	 IOCTL_DEBUGOUT("ioctl rcv'd: SIOCSIFMTU (Set Interface MTU)");

	 /* 9K Jumbo Frame size */
	 max_frame_size = 9234;

	if (mtu > max_frame_size - ETHER_HDR_LEN - ETHER_CRC_LEN) {
		return (EINVAL);
	}

	scctx->isc_max_frame_size = adapter->hw.mac.max_frame_size =
	    mtu + ETHER_HDR_LEN + ETHER_CRC_LEN;
	return (0);
}

/*********************************************************************
 *  Init entry point
 *
 *  This routine is used in two ways. It is used by the stack as
 *  init entry point in network interface structure. It is also used
 *  by the driver as a hw/sw initialization routine to get to a
 *  consistent state.
 *
 **********************************************************************/
static void
igc_if_init(if_ctx_t ctx)
{
	struct igc_adapter *adapter = iflib_get_softc(ctx);
	if_softc_ctx_t scctx = adapter->shared;
	struct ifnet *ifp = iflib_get_ifp(ctx);
	struct igc_tx_queue *tx_que;
	int i;

	INIT_DEBUGOUT("igc_if_init: begin");

	/* Get the latest mac address, User can use a LAA */
	bcopy(if_getlladdr(ifp), adapter->hw.mac.addr,
	    ETHER_ADDR_LEN);

	/* Put the address into the Receive Address Array */
	igc_rar_set(&adapter->hw, adapter->hw.mac.addr, 0);

	/* Initialize the hardware */
	igc_reset(ctx);
	igc_if_update_admin_status(ctx);

	for (i = 0, tx_que = adapter->tx_queues; i < adapter->tx_num_queues; i++, tx_que++) {
		struct tx_ring *txr = &tx_que->txr;

		txr->tx_rs_cidx = txr->tx_rs_pidx;

		/* Initialize the last processed descriptor to be the end of
		 * the ring, rather than the start, so that we avoid an
		 * off-by-one error when calculating how many descriptors are
		 * done in the credits_update function.
		 */
		txr->tx_cidx_processed = scctx->isc_ntxd[0] - 1;
	}

	/* Setup VLAN support, basic and offload if available */
	IGC_WRITE_REG(&adapter->hw, IGC_VET, ETHERTYPE_VLAN);

	/* Prepare transmit descriptors and buffers */
	igc_initialize_transmit_unit(ctx);

	/* Setup Multicast table */
	igc_if_multi_set(ctx);

	adapter->rx_mbuf_sz = iflib_get_rx_mbuf_sz(ctx);
	igc_initialize_receive_unit(ctx);

	/* Use real VLAN Filter support? */
	if (if_getcapenable(ifp) & IFCAP_VLAN_HWTAGGING) {
		if (if_getcapenable(ifp) & IFCAP_VLAN_HWFILTER)
			/* Use real VLAN Filter support */
			igc_setup_vlan_hw_support(adapter);
		else {
			u32 ctrl;
			ctrl = IGC_READ_REG(&adapter->hw, IGC_CTRL);
			ctrl |= IGC_CTRL_VME;
			IGC_WRITE_REG(&adapter->hw, IGC_CTRL, ctrl);
		}
	}

	/* Don't lose promiscuous settings */
	igc_if_set_promisc(ctx, IFF_PROMISC);
	igc_clear_hw_cntrs_base_generic(&adapter->hw);

	if (adapter->intr_type == IFLIB_INTR_MSIX) /* Set up queue routing */
		igc_configure_queues(adapter);

	/* this clears any pending interrupts */
	IGC_READ_REG(&adapter->hw, IGC_ICR);
	IGC_WRITE_REG(&adapter->hw, IGC_ICS, IGC_ICS_LSC);

	/* the driver can now take control from firmware */
	igc_get_hw_control(adapter);

	/* Set Energy Efficient Ethernet */
	igc_set_eee_i225(&adapter->hw, true, true, true);
}

/*********************************************************************
 *
 *  Fast Legacy/MSI Combined Interrupt Service routine
 *
 *********************************************************************/
int
igc_intr(void *arg)
{
	struct igc_adapter *adapter = arg;
	if_ctx_t ctx = adapter->ctx;
	u32 reg_icr;

	reg_icr = IGC_READ_REG(&adapter->hw, IGC_ICR);

	/* Hot eject? */
	if (reg_icr == 0xffffffff)
		return FILTER_STRAY;

	/* Definitely not our interrupt. */
	if (reg_icr == 0x0)
		return FILTER_STRAY;

	if ((reg_icr & IGC_ICR_INT_ASSERTED) == 0)
		return FILTER_STRAY;

	/*
	 * Only MSI-X interrupts have one-shot behavior by taking advantage
	 * of the EIAC register.  Thus, explicitly disable interrupts.  This
	 * also works around the MSI message reordering errata on certain
	 * systems.
	 */
	IFDI_INTR_DISABLE(ctx);

	/* Link status change */
	if (reg_icr & (IGC_ICR_RXSEQ | IGC_ICR_LSC))
		igc_handle_link(ctx);

	if (reg_icr & IGC_ICR_RXO)
		adapter->rx_overruns++;

	return (FILTER_SCHEDULE_THREAD);
}

static int
igc_if_rx_queue_intr_enable(if_ctx_t ctx, uint16_t rxqid)
{
	struct igc_adapter *adapter = iflib_get_softc(ctx);
	struct igc_rx_queue *rxq = &adapter->rx_queues[rxqid];

	IGC_WRITE_REG(&adapter->hw, IGC_EIMS, rxq->eims);
	return (0);
}

static int
igc_if_tx_queue_intr_enable(if_ctx_t ctx, uint16_t txqid)
{
	struct igc_adapter *adapter = iflib_get_softc(ctx);
	struct igc_tx_queue *txq = &adapter->tx_queues[txqid];

	IGC_WRITE_REG(&adapter->hw, IGC_EIMS, txq->eims);
	return (0);
}

/*********************************************************************
 *
 *  MSI-X RX Interrupt Service routine
 *
 **********************************************************************/
static int
igc_msix_que(void *arg)
{
	struct igc_rx_queue *que = arg;

	++que->irqs;

	return (FILTER_SCHEDULE_THREAD);
}

/*********************************************************************
 *
 *  MSI-X Link Fast Interrupt Service routine
 *
 **********************************************************************/
static int
igc_msix_link(void *arg)
{
	struct igc_adapter *adapter = arg;
	u32 reg_icr;

	++adapter->link_irq;
	MPASS(adapter->hw.back != NULL);
	reg_icr = IGC_READ_REG(&adapter->hw, IGC_ICR);

	if (reg_icr & IGC_ICR_RXO)
		adapter->rx_overruns++;

	if (reg_icr & (IGC_ICR_RXSEQ | IGC_ICR_LSC)) {
		igc_handle_link(adapter->ctx);
	}

	IGC_WRITE_REG(&adapter->hw, IGC_IMS, IGC_IMS_LSC);
	IGC_WRITE_REG(&adapter->hw, IGC_EIMS, adapter->link_mask);

	return (FILTER_HANDLED);
}

static void
igc_handle_link(void *context)
{
	if_ctx_t ctx = context;
	struct igc_adapter *adapter = iflib_get_softc(ctx);

	adapter->hw.mac.get_link_status = true;
	iflib_admin_intr_deferred(ctx);
}

/*********************************************************************
 *
 *  Media Ioctl callback
 *
 *  This routine is called whenever the user queries the status of
 *  the interface using ifconfig.
 *
 **********************************************************************/
static void
igc_if_media_status(if_ctx_t ctx, struct ifmediareq *ifmr)
{
	struct igc_adapter *adapter = iflib_get_softc(ctx);

	INIT_DEBUGOUT("igc_if_media_status: begin");

	iflib_admin_intr_deferred(ctx);

	ifmr->ifm_status = IFM_AVALID;
	ifmr->ifm_active = IFM_ETHER;

	if (!adapter->link_active) {
		return;
	}

	ifmr->ifm_status |= IFM_ACTIVE;

	switch (adapter->link_speed) {
	case 10:
		ifmr->ifm_active |= IFM_10_T;
		break;
	case 100:
		ifmr->ifm_active |= IFM_100_TX;
                break;
	case 1000:
		ifmr->ifm_active |= IFM_1000_T;
		break;
	case 2500:
                ifmr->ifm_active |= IFM_2500_T;
                break;
	}

	if (adapter->link_duplex == FULL_DUPLEX)
		ifmr->ifm_active |= IFM_FDX;
	else
		ifmr->ifm_active |= IFM_HDX;
}

/*********************************************************************
 *
 *  Media Ioctl callback
 *
 *  This routine is called when the user changes speed/duplex using
 *  media/mediopt option with ifconfig.
 *
 **********************************************************************/
static int
igc_if_media_change(if_ctx_t ctx)
{
	struct igc_adapter *adapter = iflib_get_softc(ctx);
	struct ifmedia *ifm = iflib_get_media(ctx);

	INIT_DEBUGOUT("igc_if_media_change: begin");

	if (IFM_TYPE(ifm->ifm_media) != IFM_ETHER)
		return (EINVAL);

	adapter->hw.mac.autoneg = DO_AUTO_NEG;

	switch (IFM_SUBTYPE(ifm->ifm_media)) {
	case IFM_AUTO:
		adapter->hw.phy.autoneg_advertised = AUTONEG_ADV_DEFAULT;
		break;
        case IFM_2500_T:
                adapter->hw.phy.autoneg_advertised = ADVERTISE_2500_FULL;
                break;
	case IFM_1000_T:
		adapter->hw.phy.autoneg_advertised = ADVERTISE_1000_FULL;
		break;
	case IFM_100_TX:
		if ((ifm->ifm_media & IFM_GMASK) == IFM_HDX)
			adapter->hw.phy.autoneg_advertised = ADVERTISE_100_HALF;
		else
			adapter->hw.phy.autoneg_advertised = ADVERTISE_100_FULL;
		break;
	case IFM_10_T:
		if ((ifm->ifm_media & IFM_GMASK) == IFM_HDX)
			adapter->hw.phy.autoneg_advertised = ADVERTISE_10_HALF;
		else
			adapter->hw.phy.autoneg_advertised = ADVERTISE_10_FULL;
		break;
	default:
		device_printf(adapter->dev, "Unsupported media type\n");
	}

	igc_if_init(ctx);

	return (0);
}

static int
igc_if_set_promisc(if_ctx_t ctx, int flags)
{
	struct igc_adapter *adapter = iflib_get_softc(ctx);
	struct ifnet *ifp = iflib_get_ifp(ctx);
	u32 reg_rctl;
	int mcnt = 0;

	reg_rctl = IGC_READ_REG(&adapter->hw, IGC_RCTL);
	reg_rctl &= ~(IGC_RCTL_SBP | IGC_RCTL_UPE);
	if (flags & IFF_ALLMULTI)
		mcnt = MAX_NUM_MULTICAST_ADDRESSES;
	else
		mcnt = min(if_llmaddr_count(ifp), MAX_NUM_MULTICAST_ADDRESSES);

	/* Don't disable if in MAX groups */
	if (mcnt < MAX_NUM_MULTICAST_ADDRESSES)
		reg_rctl &=  (~IGC_RCTL_MPE);
	IGC_WRITE_REG(&adapter->hw, IGC_RCTL, reg_rctl);

	if (flags & IFF_PROMISC) {
		reg_rctl |= (IGC_RCTL_UPE | IGC_RCTL_MPE);
		/* Turn this on if you want to see bad packets */
		if (igc_debug_sbp)
			reg_rctl |= IGC_RCTL_SBP;
		IGC_WRITE_REG(&adapter->hw, IGC_RCTL, reg_rctl);
	} else if (flags & IFF_ALLMULTI) {
		reg_rctl |= IGC_RCTL_MPE;
		reg_rctl &= ~IGC_RCTL_UPE;
		IGC_WRITE_REG(&adapter->hw, IGC_RCTL, reg_rctl);
	}
	return (0);
}

static u_int
igc_copy_maddr(void *arg, struct sockaddr_dl *sdl, u_int idx)
{
	u8 *mta = arg;

	if (idx == MAX_NUM_MULTICAST_ADDRESSES)
		return (0);

	bcopy(LLADDR(sdl), &mta[idx * ETHER_ADDR_LEN], ETHER_ADDR_LEN);

	return (1);
}

/*********************************************************************
 *  Multicast Update
 *
 *  This routine is called whenever multicast address list is updated.
 *
 **********************************************************************/

static void
igc_if_multi_set(if_ctx_t ctx)
{
	struct igc_adapter *adapter = iflib_get_softc(ctx);
	struct ifnet *ifp = iflib_get_ifp(ctx);
	u8  *mta; /* Multicast array memory */
	u32 reg_rctl = 0;
	int mcnt = 0;

	IOCTL_DEBUGOUT("igc_set_multi: begin");

	mta = adapter->mta;
	bzero(mta, sizeof(u8) * ETHER_ADDR_LEN * MAX_NUM_MULTICAST_ADDRESSES);

	mcnt = if_foreach_llmaddr(ifp, igc_copy_maddr, mta);

	reg_rctl = IGC_READ_REG(&adapter->hw, IGC_RCTL);

	if (if_getflags(ifp) & IFF_PROMISC) {
		reg_rctl |= (IGC_RCTL_UPE | IGC_RCTL_MPE);
		/* Turn this on if you want to see bad packets */
		if (igc_debug_sbp)
			reg_rctl |= IGC_RCTL_SBP;
	} else if (mcnt >= MAX_NUM_MULTICAST_ADDRESSES ||
	      if_getflags(ifp) & IFF_ALLMULTI) {
                reg_rctl |= IGC_RCTL_MPE;
		reg_rctl &= ~IGC_RCTL_UPE;
        } else
		reg_rctl &= ~(IGC_RCTL_UPE | IGC_RCTL_MPE);

	if (mcnt < MAX_NUM_MULTICAST_ADDRESSES)
		igc_update_mc_addr_list(&adapter->hw, mta, mcnt);

	IGC_WRITE_REG(&adapter->hw, IGC_RCTL, reg_rctl);
}

/*********************************************************************
 *  Timer routine
 *
 *  This routine schedules igc_if_update_admin_status() to check for
 *  link status and to gather statistics as well as to perform some
 *  controller-specific hardware patting.
 *
 **********************************************************************/
static void
igc_if_timer(if_ctx_t ctx, uint16_t qid)
{

	if (qid != 0)
		return;

	iflib_admin_intr_deferred(ctx);
}

static void
igc_if_update_admin_status(if_ctx_t ctx)
{
	struct igc_adapter *adapter = iflib_get_softc(ctx);
	struct igc_hw *hw = &adapter->hw;
	device_t dev = iflib_get_dev(ctx);
	u32 link_check, thstat, ctrl;

	link_check = thstat = ctrl = 0;
	/* Get the cached link value or read phy for real */
	switch (hw->phy.media_type) {
	case igc_media_type_copper:
		if (hw->mac.get_link_status == true) {
			/* Do the work to read phy */
			igc_check_for_link(hw);
			link_check = !hw->mac.get_link_status;
		} else
			link_check = true;
		break;
	case igc_media_type_unknown:
		igc_check_for_link(hw);
		link_check = !hw->mac.get_link_status;
		/* FALLTHROUGH */
	default:
		break;
	}

	/* Now check for a transition */
	if (link_check && (adapter->link_active == 0)) {
		igc_get_speed_and_duplex(hw, &adapter->link_speed,
		    &adapter->link_duplex);
		if (bootverbose)
			device_printf(dev, "Link is up %d Mbps %s\n",
			    adapter->link_speed,
			    ((adapter->link_duplex == FULL_DUPLEX) ?
			    "Full Duplex" : "Half Duplex"));
		adapter->link_active = 1;
		iflib_link_state_change(ctx, LINK_STATE_UP,
		    IF_Mbps(adapter->link_speed));
	} else if (!link_check && (adapter->link_active == 1)) {
		adapter->link_speed = 0;
		adapter->link_duplex = 0;
		adapter->link_active = 0;
		iflib_link_state_change(ctx, LINK_STATE_DOWN, 0);
	}
	igc_update_stats_counters(adapter);
}

static void
igc_if_watchdog_reset(if_ctx_t ctx)
{
	struct igc_adapter *adapter = iflib_get_softc(ctx);

	/*
	 * Just count the event; iflib(4) will already trigger a
	 * sufficient reset of the controller.
	 */
	adapter->watchdog_events++;
}

/*********************************************************************
 *
 *  This routine disables all traffic on the adapter by issuing a
 *  global reset on the MAC.
 *
 **********************************************************************/
static void
igc_if_stop(if_ctx_t ctx)
{
	struct igc_adapter *adapter = iflib_get_softc(ctx);

	INIT_DEBUGOUT("igc_if_stop: begin");

	igc_reset_hw(&adapter->hw);
	IGC_WRITE_REG(&adapter->hw, IGC_WUC, 0);
}

/*********************************************************************
 *
 *  Determine hardware revision.
 *
 **********************************************************************/
static void
igc_identify_hardware(if_ctx_t ctx)
{
	device_t dev = iflib_get_dev(ctx);
	struct igc_adapter *adapter = iflib_get_softc(ctx);

	/* Make sure our PCI config space has the necessary stuff set */
	adapter->hw.bus.pci_cmd_word = pci_read_config(dev, PCIR_COMMAND, 2);

	/* Save off the information about this board */
	adapter->hw.vendor_id = pci_get_vendor(dev);
	adapter->hw.device_id = pci_get_device(dev);
	adapter->hw.revision_id = pci_read_config(dev, PCIR_REVID, 1);
	adapter->hw.subsystem_vendor_id =
	    pci_read_config(dev, PCIR_SUBVEND_0, 2);
	adapter->hw.subsystem_device_id =
	    pci_read_config(dev, PCIR_SUBDEV_0, 2);

	/* Do Shared Code Init and Setup */
	if (igc_set_mac_type(&adapter->hw)) {
		device_printf(dev, "Setup init failure\n");
		return;
	}
}

static int
igc_allocate_pci_resources(if_ctx_t ctx)
{
	struct igc_adapter *adapter = iflib_get_softc(ctx);
	device_t dev = iflib_get_dev(ctx);
	int rid;

	rid = PCIR_BAR(0);
	adapter->memory = bus_alloc_resource_any(dev, SYS_RES_MEMORY,
	    &rid, RF_ACTIVE);
	if (adapter->memory == NULL) {
		device_printf(dev, "Unable to allocate bus resource: memory\n");
		return (ENXIO);
	}
	adapter->osdep.mem_bus_space_tag = rman_get_bustag(adapter->memory);
	adapter->osdep.mem_bus_space_handle =
	    rman_get_bushandle(adapter->memory);
	adapter->hw.hw_addr = (u8 *)&adapter->osdep.mem_bus_space_handle;

	adapter->hw.back = &adapter->osdep;

	return (0);
}

/*********************************************************************
 *
 *  Set up the MSI-X Interrupt handlers
 *
 **********************************************************************/
static int
igc_if_msix_intr_assign(if_ctx_t ctx, int msix)
{
	struct igc_adapter *adapter = iflib_get_softc(ctx);
	struct igc_rx_queue *rx_que = adapter->rx_queues;
	struct igc_tx_queue *tx_que = adapter->tx_queues;
	int error, rid, i, vector = 0, rx_vectors;
	char buf[16];

	/* First set up ring resources */
	for (i = 0; i < adapter->rx_num_queues; i++, rx_que++, vector++) {
		rid = vector + 1;
		snprintf(buf, sizeof(buf), "rxq%d", i);
		error = iflib_irq_alloc_generic(ctx, &rx_que->que_irq, rid, IFLIB_INTR_RXTX, igc_msix_que, rx_que, rx_que->me, buf);
		if (error) {
			device_printf(iflib_get_dev(ctx), "Failed to allocate que int %d err: %d", i, error);
			adapter->rx_num_queues = i + 1;
			goto fail;
		}

		rx_que->msix =  vector;

		/*
		 * Set the bit to enable interrupt
		 * in IGC_IMS -- bits 20 and 21
		 * are for RX0 and RX1, note this has
		 * NOTHING to do with the MSI-X vector
		 */
		rx_que->eims = 1 << vector;
	}
	rx_vectors = vector;

	vector = 0;
	for (i = 0; i < adapter->tx_num_queues; i++, tx_que++, vector++) {
		snprintf(buf, sizeof(buf), "txq%d", i);
		tx_que = &adapter->tx_queues[i];
		iflib_softirq_alloc_generic(ctx,
		    &adapter->rx_queues[i % adapter->rx_num_queues].que_irq,
		    IFLIB_INTR_TX, tx_que, tx_que->me, buf);

		tx_que->msix = (vector % adapter->rx_num_queues);

		/*
		 * Set the bit to enable interrupt
		 * in IGC_IMS -- bits 22 and 23
		 * are for TX0 and TX1, note this has
		 * NOTHING to do with the MSI-X vector
		 */
		tx_que->eims = 1 << i;
	}

	/* Link interrupt */
	rid = rx_vectors + 1;
	error = iflib_irq_alloc_generic(ctx, &adapter->irq, rid, IFLIB_INTR_ADMIN, igc_msix_link, adapter, 0, "aq");

	if (error) {
		device_printf(iflib_get_dev(ctx), "Failed to register admin handler");
		goto fail;
	}
	adapter->linkvec = rx_vectors;
	return (0);
fail:
	iflib_irq_free(ctx, &adapter->irq);
	rx_que = adapter->rx_queues;
	for (int i = 0; i < adapter->rx_num_queues; i++, rx_que++)
		iflib_irq_free(ctx, &rx_que->que_irq);
	return (error);
}

static void
igc_configure_queues(struct igc_adapter *adapter)
{
	struct igc_hw *hw = &adapter->hw;
	struct igc_rx_queue *rx_que;
	struct igc_tx_queue *tx_que;
	u32 ivar = 0, newitr = 0;

	/* First turn on RSS capability */
	IGC_WRITE_REG(hw, IGC_GPIE,
	    IGC_GPIE_MSIX_MODE | IGC_GPIE_EIAME | IGC_GPIE_PBA |
	    IGC_GPIE_NSICR);

	/* Turn on MSI-X */
	/* RX entries */
	for (int i = 0; i < adapter->rx_num_queues; i++) {
		u32 index = i >> 1;
		ivar = IGC_READ_REG_ARRAY(hw, IGC_IVAR0, index);
		rx_que = &adapter->rx_queues[i];
		if (i & 1) {
			ivar &= 0xFF00FFFF;
			ivar |= (rx_que->msix | IGC_IVAR_VALID) << 16;
		} else {
			ivar &= 0xFFFFFF00;
			ivar |= rx_que->msix | IGC_IVAR_VALID;
		}
		IGC_WRITE_REG_ARRAY(hw, IGC_IVAR0, index, ivar);
	}
	/* TX entries */
	for (int i = 0; i < adapter->tx_num_queues; i++) {
		u32 index = i >> 1;
		ivar = IGC_READ_REG_ARRAY(hw, IGC_IVAR0, index);
		tx_que = &adapter->tx_queues[i];
		if (i & 1) {
			ivar &= 0x00FFFFFF;
			ivar |= (tx_que->msix | IGC_IVAR_VALID) << 24;
		} else {
			ivar &= 0xFFFF00FF;
			ivar |= (tx_que->msix | IGC_IVAR_VALID) << 8;
		}
		IGC_WRITE_REG_ARRAY(hw, IGC_IVAR0, index, ivar);
		adapter->que_mask |= tx_que->eims;
	}

	/* And for the link interrupt */
	ivar = (adapter->linkvec | IGC_IVAR_VALID) << 8;
	adapter->link_mask = 1 << adapter->linkvec;
	IGC_WRITE_REG(hw, IGC_IVAR_MISC, ivar);

	/* Set the starting interrupt rate */
	if (igc_max_interrupt_rate > 0)
		newitr = (4000000 / igc_max_interrupt_rate) & 0x7FFC;

	newitr |= IGC_EITR_CNT_IGNR;

	for (int i = 0; i < adapter->rx_num_queues; i++) {
		rx_que = &adapter->rx_queues[i];
		IGC_WRITE_REG(hw, IGC_EITR(rx_que->msix), newitr);
	}

	return;
}

static void
igc_free_pci_resources(if_ctx_t ctx)
{
	struct igc_adapter *adapter = iflib_get_softc(ctx);
	struct igc_rx_queue *que = adapter->rx_queues;
	device_t dev = iflib_get_dev(ctx);

	/* Release all MSI-X queue resources */
	if (adapter->intr_type == IFLIB_INTR_MSIX)
		iflib_irq_free(ctx, &adapter->irq);

	for (int i = 0; i < adapter->rx_num_queues; i++, que++) {
		iflib_irq_free(ctx, &que->que_irq);
	}

	if (adapter->memory != NULL) {
		bus_release_resource(dev, SYS_RES_MEMORY,
		    rman_get_rid(adapter->memory), adapter->memory);
		adapter->memory = NULL;
	}

	if (adapter->flash != NULL) {
		bus_release_resource(dev, SYS_RES_MEMORY,
		    rman_get_rid(adapter->flash), adapter->flash);
		adapter->flash = NULL;
	}

	if (adapter->ioport != NULL) {
		bus_release_resource(dev, SYS_RES_IOPORT,
		    rman_get_rid(adapter->ioport), adapter->ioport);
		adapter->ioport = NULL;
	}
}

/* Set up MSI or MSI-X */
static int
igc_setup_msix(if_ctx_t ctx)
{
	return (0);
}

/*********************************************************************
 *
 *  Initialize the DMA Coalescing feature
 *
 **********************************************************************/
static void
igc_init_dmac(struct igc_adapter *adapter, u32 pba)
{
	device_t	dev = adapter->dev;
	struct igc_hw *hw = &adapter->hw;
	u32 		dmac, reg = ~IGC_DMACR_DMAC_EN;
	u16		hwm;
	u16		max_frame_size;
	int		status;

	max_frame_size = adapter->shared->isc_max_frame_size;

	if (adapter->dmac == 0) { /* Disabling it */
		IGC_WRITE_REG(hw, IGC_DMACR, reg);
		return;
	} else
		device_printf(dev, "DMA Coalescing enabled\n");

	/* Set starting threshold */
	IGC_WRITE_REG(hw, IGC_DMCTXTH, 0);

	hwm = 64 * pba - max_frame_size / 16;
	if (hwm < 64 * (pba - 6))
		hwm = 64 * (pba - 6);
	reg = IGC_READ_REG(hw, IGC_FCRTC);
	reg &= ~IGC_FCRTC_RTH_COAL_MASK;
	reg |= ((hwm << IGC_FCRTC_RTH_COAL_SHIFT)
		& IGC_FCRTC_RTH_COAL_MASK);
	IGC_WRITE_REG(hw, IGC_FCRTC, reg);

	dmac = pba - max_frame_size / 512;
	if (dmac < pba - 10)
		dmac = pba - 10;
	reg = IGC_READ_REG(hw, IGC_DMACR);
	reg &= ~IGC_DMACR_DMACTHR_MASK;
	reg |= ((dmac << IGC_DMACR_DMACTHR_SHIFT)
		& IGC_DMACR_DMACTHR_MASK);

	/* transition to L0x or L1 if available..*/
	reg |= (IGC_DMACR_DMAC_EN | IGC_DMACR_DMAC_LX_MASK);

	/* Check if status is 2.5Gb backplane connection
	 * before configuration of watchdog timer, which is
	 * in msec values in 12.8usec intervals
	 * watchdog timer= msec values in 32usec intervals
	 * for non 2.5Gb connection
	 */
	status = IGC_READ_REG(hw, IGC_STATUS);
	if ((status & IGC_STATUS_2P5_SKU) &&
	    (!(status & IGC_STATUS_2P5_SKU_OVER)))
		reg |= ((adapter->dmac * 5) >> 6);
	else
		reg |= (adapter->dmac >> 5);

	IGC_WRITE_REG(hw, IGC_DMACR, reg);

	IGC_WRITE_REG(hw, IGC_DMCRTRH, 0);

	/* Set the interval before transition */
	reg = IGC_READ_REG(hw, IGC_DMCTLX);
	reg |= IGC_DMCTLX_DCFLUSH_DIS;

	/*
	** in 2.5Gb connection, TTLX unit is 0.4 usec
	** which is 0x4*2 = 0xA. But delay is still 4 usec
	*/
	status = IGC_READ_REG(hw, IGC_STATUS);
	if ((status & IGC_STATUS_2P5_SKU) &&
	    (!(status & IGC_STATUS_2P5_SKU_OVER)))
		reg |= 0xA;
	else
		reg |= 0x4;

	IGC_WRITE_REG(hw, IGC_DMCTLX, reg);

	/* free space in tx packet buffer to wake from DMA coal */
	IGC_WRITE_REG(hw, IGC_DMCTXTH, (IGC_TXPBSIZE -
	    (2 * max_frame_size)) >> 6);

	/* make low power state decision controlled by DMA coal */
	reg = IGC_READ_REG(hw, IGC_PCIEMISC);
	reg &= ~IGC_PCIEMISC_LX_DECISION;
	IGC_WRITE_REG(hw, IGC_PCIEMISC, reg);
}

/*********************************************************************
 *
 *  Initialize the hardware to a configuration as specified by the
 *  adapter structure.
 *
 **********************************************************************/
static void
igc_reset(if_ctx_t ctx)
{
	device_t dev = iflib_get_dev(ctx);
	struct igc_adapter *adapter = iflib_get_softc(ctx);
	struct igc_hw *hw = &adapter->hw;
	u16 rx_buffer_size;
	u32 pba;

	INIT_DEBUGOUT("igc_reset: begin");
	/* Let the firmware know the OS is in control */
	igc_get_hw_control(adapter);

	/*
	 * Packet Buffer Allocation (PBA)
	 * Writing PBA sets the receive portion of the buffer
	 * the remainder is used for the transmit buffer.
	 */
	pba = IGC_PBA_34K;

	INIT_DEBUGOUT1("igc_reset: pba=%dK",pba);

	/*
	 * These parameters control the automatic generation (Tx) and
	 * response (Rx) to Ethernet PAUSE frames.
	 * - High water mark should allow for at least two frames to be
	 *   received after sending an XOFF.
	 * - Low water mark works best when it is very near the high water mark.
	 *   This allows the receiver to restart by sending XON when it has
	 *   drained a bit. Here we use an arbitrary value of 1500 which will
	 *   restart after one full frame is pulled from the buffer. There
	 *   could be several smaller frames in the buffer and if so they will
	 *   not trigger the XON until their total number reduces the buffer
	 *   by 1500.
	 * - The pause time is fairly large at 1000 x 512ns = 512 usec.
	 */
	rx_buffer_size = (pba & 0xffff) << 10;
	hw->fc.high_water = rx_buffer_size -
	    roundup2(adapter->hw.mac.max_frame_size, 1024);
	/* 16-byte granularity */
	hw->fc.low_water = hw->fc.high_water - 16;

	if (adapter->fc) /* locally set flow control value? */
		hw->fc.requested_mode = adapter->fc;
	else
		hw->fc.requested_mode = igc_fc_full;

	hw->fc.pause_time = IGC_FC_PAUSE_TIME;

	hw->fc.send_xon = true;

	/* Issue a global reset */
	igc_reset_hw(hw);
	IGC_WRITE_REG(hw, IGC_WUC, 0);

	/* and a re-init */
	if (igc_init_hw(hw) < 0) {
		device_printf(dev, "Hardware Initialization Failed\n");
		return;
	}

	/* Setup DMA Coalescing */
	igc_init_dmac(adapter, pba);

	IGC_WRITE_REG(hw, IGC_VET, ETHERTYPE_VLAN);
	igc_get_phy_info(hw);
	igc_check_for_link(hw);
}

/*
 * Initialise the RSS mapping for NICs that support multiple transmit/
 * receive rings.
 */

#define RSSKEYLEN 10
static void
igc_initialize_rss_mapping(struct igc_adapter *adapter)
{
	struct igc_hw *hw = &adapter->hw;
	int i;
	int queue_id;
	u32 reta;
	u32 rss_key[RSSKEYLEN], mrqc, shift = 0;

	/*
	 * The redirection table controls which destination
	 * queue each bucket redirects traffic to.
	 * Each DWORD represents four queues, with the LSB
	 * being the first queue in the DWORD.
	 *
	 * This just allocates buckets to queues using round-robin
	 * allocation.
	 *
	 * NOTE: It Just Happens to line up with the default
	 * RSS allocation method.
	 */

	/* Warning FM follows */
	reta = 0;
	for (i = 0; i < 128; i++) {
#ifdef RSS
		queue_id = rss_get_indirection_to_bucket(i);
		/*
		 * If we have more queues than buckets, we'll
		 * end up mapping buckets to a subset of the
		 * queues.
		 *
		 * If we have more buckets than queues, we'll
		 * end up instead assigning multiple buckets
		 * to queues.
		 *
		 * Both are suboptimal, but we need to handle
		 * the case so we don't go out of bounds
		 * indexing arrays and such.
		 */
		queue_id = queue_id % adapter->rx_num_queues;
#else
		queue_id = (i % adapter->rx_num_queues);
#endif
		/* Adjust if required */
		queue_id = queue_id << shift;

		/*
		 * The low 8 bits are for hash value (n+0);
		 * The next 8 bits are for hash value (n+1), etc.
		 */
		reta = reta >> 8;
		reta = reta | ( ((uint32_t) queue_id) << 24);
		if ((i & 3) == 3) {
			IGC_WRITE_REG(hw, IGC_RETA(i >> 2), reta);
			reta = 0;
		}
	}

	/* Now fill in hash table */

	/*
	 * MRQC: Multiple Receive Queues Command
	 * Set queuing to RSS control, number depends on the device.
	 */
	mrqc = IGC_MRQC_ENABLE_RSS_4Q;

#ifdef RSS
	/* XXX ew typecasting */
	rss_getkey((uint8_t *) &rss_key);
#else
	arc4rand(&rss_key, sizeof(rss_key), 0);
#endif
	for (i = 0; i < RSSKEYLEN; i++)
		IGC_WRITE_REG_ARRAY(hw, IGC_RSSRK(0), i, rss_key[i]);

	/*
	 * Configure the RSS fields to hash upon.
	 */
	mrqc |= (IGC_MRQC_RSS_FIELD_IPV4 |
	    IGC_MRQC_RSS_FIELD_IPV4_TCP);
	mrqc |= (IGC_MRQC_RSS_FIELD_IPV6 |
	    IGC_MRQC_RSS_FIELD_IPV6_TCP);
	mrqc |=( IGC_MRQC_RSS_FIELD_IPV4_UDP |
	    IGC_MRQC_RSS_FIELD_IPV6_UDP);
	mrqc |=( IGC_MRQC_RSS_FIELD_IPV6_UDP_EX |
	    IGC_MRQC_RSS_FIELD_IPV6_TCP_EX);

	IGC_WRITE_REG(hw, IGC_MRQC, mrqc);
}

/*********************************************************************
 *
 *  Setup networking device structure and register interface media.
 *
 **********************************************************************/
static int
igc_setup_interface(if_ctx_t ctx)
{
	struct ifnet *ifp = iflib_get_ifp(ctx);
	struct igc_adapter *adapter = iflib_get_softc(ctx);
	if_softc_ctx_t scctx = adapter->shared;

	INIT_DEBUGOUT("igc_setup_interface: begin");

	/* Single Queue */
	if (adapter->tx_num_queues == 1) {
		if_setsendqlen(ifp, scctx->isc_ntxd[0] - 1);
		if_setsendqready(ifp);
	}

	/*
	 * Specify the media types supported by this adapter and register
	 * callbacks to update media and link information
	 */
	ifmedia_add(adapter->media, IFM_ETHER | IFM_10_T, 0, NULL);
	ifmedia_add(adapter->media, IFM_ETHER | IFM_10_T | IFM_FDX, 0, NULL);
	ifmedia_add(adapter->media, IFM_ETHER | IFM_100_TX, 0, NULL);
	ifmedia_add(adapter->media, IFM_ETHER | IFM_100_TX | IFM_FDX, 0, NULL);
	ifmedia_add(adapter->media, IFM_ETHER | IFM_1000_T | IFM_FDX, 0, NULL);
	ifmedia_add(adapter->media, IFM_ETHER | IFM_1000_T, 0, NULL);
	ifmedia_add(adapter->media, IFM_ETHER | IFM_2500_T, 0, NULL);

	ifmedia_add(adapter->media, IFM_ETHER | IFM_AUTO, 0, NULL);
	ifmedia_set(adapter->media, IFM_ETHER | IFM_AUTO);
	return (0);
}

static int
igc_if_tx_queues_alloc(if_ctx_t ctx, caddr_t *vaddrs, uint64_t *paddrs, int ntxqs, int ntxqsets)
{
	struct igc_adapter *adapter = iflib_get_softc(ctx);
	if_softc_ctx_t scctx = adapter->shared;
	int error = IGC_SUCCESS;
	struct igc_tx_queue *que;
	int i, j;

	MPASS(adapter->tx_num_queues > 0);
	MPASS(adapter->tx_num_queues == ntxqsets);

	/* First allocate the top level queue structs */
	if (!(adapter->tx_queues =
	    (struct igc_tx_queue *) malloc(sizeof(struct igc_tx_queue) *
	    adapter->tx_num_queues, M_DEVBUF, M_NOWAIT | M_ZERO))) {
		device_printf(iflib_get_dev(ctx), "Unable to allocate queue memory\n");
		return(ENOMEM);
	}

	for (i = 0, que = adapter->tx_queues; i < adapter->tx_num_queues; i++, que++) {
		/* Set up some basics */

		struct tx_ring *txr = &que->txr;
		txr->adapter = que->adapter = adapter;
		que->me = txr->me =  i;

		/* Allocate report status array */
		if (!(txr->tx_rsq = (qidx_t *) malloc(sizeof(qidx_t) * scctx->isc_ntxd[0], M_DEVBUF, M_NOWAIT | M_ZERO))) {
			device_printf(iflib_get_dev(ctx), "failed to allocate rs_idxs memory\n");
			error = ENOMEM;
			goto fail;
		}
		for (j = 0; j < scctx->isc_ntxd[0]; j++)
			txr->tx_rsq[j] = QIDX_INVALID;
		/* get the virtual and physical address of the hardware queues */
		txr->tx_base = (struct igc_tx_desc *)vaddrs[i*ntxqs];
		txr->tx_paddr = paddrs[i*ntxqs];
	}

	if (bootverbose)
		device_printf(iflib_get_dev(ctx),
		    "allocated for %d tx_queues\n", adapter->tx_num_queues);
	return (0);
fail:
	igc_if_queues_free(ctx);
	return (error);
}

static int
igc_if_rx_queues_alloc(if_ctx_t ctx, caddr_t *vaddrs, uint64_t *paddrs, int nrxqs, int nrxqsets)
{
	struct igc_adapter *adapter = iflib_get_softc(ctx);
	int error = IGC_SUCCESS;
	struct igc_rx_queue *que;
	int i;

	MPASS(adapter->rx_num_queues > 0);
	MPASS(adapter->rx_num_queues == nrxqsets);

	/* First allocate the top level queue structs */
	if (!(adapter->rx_queues =
	    (struct igc_rx_queue *) malloc(sizeof(struct igc_rx_queue) *
	    adapter->rx_num_queues, M_DEVBUF, M_NOWAIT | M_ZERO))) {
		device_printf(iflib_get_dev(ctx), "Unable to allocate queue memory\n");
		error = ENOMEM;
		goto fail;
	}

	for (i = 0, que = adapter->rx_queues; i < nrxqsets; i++, que++) {
		/* Set up some basics */
		struct rx_ring *rxr = &que->rxr;
		rxr->adapter = que->adapter = adapter;
		rxr->que = que;
		que->me = rxr->me =  i;

		/* get the virtual and physical address of the hardware queues */
		rxr->rx_base = (union igc_rx_desc_extended *)vaddrs[i*nrxqs];
		rxr->rx_paddr = paddrs[i*nrxqs];
	}
 
	if (bootverbose)
		device_printf(iflib_get_dev(ctx),
		    "allocated for %d rx_queues\n", adapter->rx_num_queues);

	return (0);
fail:
	igc_if_queues_free(ctx);
	return (error);
}

static void
igc_if_queues_free(if_ctx_t ctx)
{
	struct igc_adapter *adapter = iflib_get_softc(ctx);
	struct igc_tx_queue *tx_que = adapter->tx_queues;
	struct igc_rx_queue *rx_que = adapter->rx_queues;

	if (tx_que != NULL) {
		for (int i = 0; i < adapter->tx_num_queues; i++, tx_que++) {
			struct tx_ring *txr = &tx_que->txr;
			if (txr->tx_rsq == NULL)
				break;

			free(txr->tx_rsq, M_DEVBUF);
			txr->tx_rsq = NULL;
		}
		free(adapter->tx_queues, M_DEVBUF);
		adapter->tx_queues = NULL;
	}

	if (rx_que != NULL) {
		free(adapter->rx_queues, M_DEVBUF);
		adapter->rx_queues = NULL;
	}

	igc_release_hw_control(adapter);

	if (adapter->mta != NULL) {
		free(adapter->mta, M_DEVBUF);
	}
}

/*********************************************************************
 *
 *  Enable transmit unit.
 *
 **********************************************************************/
static void
igc_initialize_transmit_unit(if_ctx_t ctx)
{
	struct igc_adapter *adapter = iflib_get_softc(ctx);
	if_softc_ctx_t scctx = adapter->shared;
	struct igc_tx_queue *que;
	struct tx_ring	*txr;
	struct igc_hw	*hw = &adapter->hw;
	u32 tctl, txdctl = 0;

	INIT_DEBUGOUT("igc_initialize_transmit_unit: begin");

	for (int i = 0; i < adapter->tx_num_queues; i++, txr++) {
		u64 bus_addr;
		caddr_t offp, endp;

		que = &adapter->tx_queues[i];
		txr = &que->txr;
		bus_addr = txr->tx_paddr;

		/* Clear checksum offload context. */
		offp = (caddr_t)&txr->csum_flags;
		endp = (caddr_t)(txr + 1);
		bzero(offp, endp - offp);

		/* Base and Len of TX Ring */
		IGC_WRITE_REG(hw, IGC_TDLEN(i),
		    scctx->isc_ntxd[0] * sizeof(struct igc_tx_desc));
		IGC_WRITE_REG(hw, IGC_TDBAH(i),
		    (u32)(bus_addr >> 32));
		IGC_WRITE_REG(hw, IGC_TDBAL(i),
		    (u32)bus_addr);
		/* Init the HEAD/TAIL indices */
		IGC_WRITE_REG(hw, IGC_TDT(i), 0);
		IGC_WRITE_REG(hw, IGC_TDH(i), 0);

		HW_DEBUGOUT2("Base = %x, Length = %x\n",
		    IGC_READ_REG(&adapter->hw, IGC_TDBAL(i)),
		    IGC_READ_REG(&adapter->hw, IGC_TDLEN(i)));

		txdctl = 0; /* clear txdctl */
		txdctl |= 0x1f; /* PTHRESH */
		txdctl |= 1 << 8; /* HTHRESH */
		txdctl |= 1 << 16;/* WTHRESH */
		txdctl |= 1 << 22; /* Reserved bit 22 must always be 1 */
		txdctl |= IGC_TXDCTL_GRAN;
		txdctl |= 1 << 25; /* LWTHRESH */

		IGC_WRITE_REG(hw, IGC_TXDCTL(i), txdctl);
	}

	/* Program the Transmit Control Register */
	tctl = IGC_READ_REG(&adapter->hw, IGC_TCTL);
	tctl &= ~IGC_TCTL_CT;
	tctl |= (IGC_TCTL_PSP | IGC_TCTL_RTLC | IGC_TCTL_EN |
		   (IGC_COLLISION_THRESHOLD << IGC_CT_SHIFT));

	/* This write will effectively turn on the transmit unit. */
	IGC_WRITE_REG(&adapter->hw, IGC_TCTL, tctl);
}

/*********************************************************************
 *
 *  Enable receive unit.
 *
 **********************************************************************/

static void
igc_initialize_receive_unit(if_ctx_t ctx)
{
	struct igc_adapter *adapter = iflib_get_softc(ctx);
	if_softc_ctx_t scctx = adapter->shared;
	struct ifnet *ifp = iflib_get_ifp(ctx);
	struct igc_hw	*hw = &adapter->hw;
	struct igc_rx_queue *que;
	int i;
	u32 psize, rctl, rxcsum, srrctl = 0;

	INIT_DEBUGOUT("igc_initialize_receive_units: begin");

	/*
	 * Make sure receives are disabled while setting
	 * up the descriptor ring
	 */
	rctl = IGC_READ_REG(hw, IGC_RCTL);
	IGC_WRITE_REG(hw, IGC_RCTL, rctl & ~IGC_RCTL_EN);

	/* Setup the Receive Control Register */
	rctl &= ~(3 << IGC_RCTL_MO_SHIFT);
	rctl |= IGC_RCTL_EN | IGC_RCTL_BAM |
	    IGC_RCTL_LBM_NO | IGC_RCTL_RDMTS_HALF |
	    (hw->mac.mc_filter_type << IGC_RCTL_MO_SHIFT);

	/* Do not store bad packets */
	rctl &= ~IGC_RCTL_SBP;

	/* Enable Long Packet receive */
	if (if_getmtu(ifp) > ETHERMTU)
		rctl |= IGC_RCTL_LPE;
	else
		rctl &= ~IGC_RCTL_LPE;

	/* Strip the CRC */
	if (!igc_disable_crc_stripping)
		rctl |= IGC_RCTL_SECRC;

	/*
	 * Set the interrupt throttling rate. Value is calculated
	 * as DEFAULT_ITR = 1/(MAX_INTS_PER_SEC * 256ns)
	 */
	IGC_WRITE_REG(hw, IGC_ITR, DEFAULT_ITR);

	rxcsum = IGC_READ_REG(hw, IGC_RXCSUM);
	if (if_getcapenable(ifp) & IFCAP_RXCSUM) {
		rxcsum |= IGC_RXCSUM_CRCOFL;
		if (adapter->tx_num_queues > 1)
			rxcsum |= IGC_RXCSUM_PCSD;
		else
			rxcsum |= IGC_RXCSUM_IPPCSE;
	} else {
		if (adapter->tx_num_queues > 1)
			rxcsum |= IGC_RXCSUM_PCSD;
		else
			rxcsum &= ~IGC_RXCSUM_TUOFL;
	}
	IGC_WRITE_REG(hw, IGC_RXCSUM, rxcsum);

	if (adapter->rx_num_queues > 1)
		igc_initialize_rss_mapping(adapter);

	if (if_getmtu(ifp) > ETHERMTU) {
		/* Set maximum packet len */
		if (adapter->rx_mbuf_sz <= 4096) {
			srrctl |= 4096 >> IGC_SRRCTL_BSIZEPKT_SHIFT;
			rctl |= IGC_RCTL_SZ_4096 | IGC_RCTL_BSEX;
		} else if (adapter->rx_mbuf_sz > 4096) {
			srrctl |= 8192 >> IGC_SRRCTL_BSIZEPKT_SHIFT;
			rctl |= IGC_RCTL_SZ_8192 | IGC_RCTL_BSEX;
		}
		psize = scctx->isc_max_frame_size;
		/* are we on a vlan? */
		if (ifp->if_vlantrunk != NULL)
			psize += VLAN_TAG_SIZE;
		IGC_WRITE_REG(&adapter->hw, IGC_RLPML, psize);
	} else {
		srrctl |= 2048 >> IGC_SRRCTL_BSIZEPKT_SHIFT;
		rctl |= IGC_RCTL_SZ_2048;
	}

	/*
	 * If TX flow control is disabled and there's >1 queue defined,
	 * enable DROP.
	 *
	 * This drops frames rather than hanging the RX MAC for all queues.
	 */
	if ((adapter->rx_num_queues > 1) &&
	    (adapter->fc == igc_fc_none ||
	     adapter->fc == igc_fc_rx_pause)) {
		srrctl |= IGC_SRRCTL_DROP_EN;
	}

	/* Setup the Base and Length of the Rx Descriptor Rings */
	for (i = 0, que = adapter->rx_queues; i < adapter->rx_num_queues; i++, que++) {
		struct rx_ring *rxr = &que->rxr;
		u64 bus_addr = rxr->rx_paddr;
		u32 rxdctl;

#ifdef notyet
		/* Configure for header split? -- ignore for now */
		rxr->hdr_split = igc_header_split;
#else
		srrctl |= IGC_SRRCTL_DESCTYPE_ADV_ONEBUF;
#endif

		IGC_WRITE_REG(hw, IGC_RDLEN(i),
			      scctx->isc_nrxd[0] * sizeof(struct igc_rx_desc));
		IGC_WRITE_REG(hw, IGC_RDBAH(i),
			      (uint32_t)(bus_addr >> 32));
		IGC_WRITE_REG(hw, IGC_RDBAL(i),
			      (uint32_t)bus_addr);
		IGC_WRITE_REG(hw, IGC_SRRCTL(i), srrctl);
		/* Setup the Head and Tail Descriptor Pointers */
		IGC_WRITE_REG(hw, IGC_RDH(i), 0);
		IGC_WRITE_REG(hw, IGC_RDT(i), 0);
		/* Enable this Queue */
		rxdctl = IGC_READ_REG(hw, IGC_RXDCTL(i));
		rxdctl |= IGC_RXDCTL_QUEUE_ENABLE;
		rxdctl &= 0xFFF00000;
		rxdctl |= IGC_RX_PTHRESH;
		rxdctl |= IGC_RX_HTHRESH << 8;
		rxdctl |= IGC_RX_WTHRESH << 16;
		IGC_WRITE_REG(hw, IGC_RXDCTL(i), rxdctl);
	}

	/* Make sure VLAN Filters are off */
	rctl &= ~IGC_RCTL_VFE;

	/* Write out the settings */
	IGC_WRITE_REG(hw, IGC_RCTL, rctl);

	return;
}

static void
igc_if_vlan_register(if_ctx_t ctx, u16 vtag)
{
	struct igc_adapter *adapter = iflib_get_softc(ctx);
	u32 index, bit;

	index = (vtag >> 5) & 0x7F;
	bit = vtag & 0x1F;
	adapter->shadow_vfta[index] |= (1 << bit);
	++adapter->num_vlans;
}

static void
igc_if_vlan_unregister(if_ctx_t ctx, u16 vtag)
{
	struct igc_adapter *adapter = iflib_get_softc(ctx);
	u32 index, bit;

	index = (vtag >> 5) & 0x7F;
	bit = vtag & 0x1F;
	adapter->shadow_vfta[index] &= ~(1 << bit);
	--adapter->num_vlans;
}

static void
igc_setup_vlan_hw_support(struct igc_adapter *adapter)
{
	struct igc_hw *hw = &adapter->hw;
	u32 reg;

	/*
	 * We get here thru init_locked, meaning
	 * a soft reset, this has already cleared
	 * the VFTA and other state, so if there
	 * have been no vlan's registered do nothing.
	 */
	if (adapter->num_vlans == 0)
		return;

	/*
	 * A soft reset zero's out the VFTA, so
	 * we need to repopulate it now.
	 */
	for (int i = 0; i < IGC_VFTA_SIZE; i++)
		if (adapter->shadow_vfta[i] != 0)
			IGC_WRITE_REG_ARRAY(hw, IGC_VFTA,
			    i, adapter->shadow_vfta[i]);

	reg = IGC_READ_REG(hw, IGC_CTRL);
	reg |= IGC_CTRL_VME;
	IGC_WRITE_REG(hw, IGC_CTRL, reg);

	/* Enable the Filter Table */
	reg = IGC_READ_REG(hw, IGC_RCTL);
	reg &= ~IGC_RCTL_CFIEN;
	reg |= IGC_RCTL_VFE;
	IGC_WRITE_REG(hw, IGC_RCTL, reg);
}

static void
igc_if_intr_enable(if_ctx_t ctx)
{
	struct igc_adapter *adapter = iflib_get_softc(ctx);
	struct igc_hw *hw = &adapter->hw;
	u32 mask;

	if (__predict_true(adapter->intr_type == IFLIB_INTR_MSIX)) {
		mask = (adapter->que_mask | adapter->link_mask);
		IGC_WRITE_REG(hw, IGC_EIAC, mask);
		IGC_WRITE_REG(hw, IGC_EIAM, mask);
		IGC_WRITE_REG(hw, IGC_EIMS, mask);
		IGC_WRITE_REG(hw, IGC_IMS, IGC_IMS_LSC);
	} else
		IGC_WRITE_REG(hw, IGC_IMS, IMS_ENABLE_MASK);
	IGC_WRITE_FLUSH(hw);
}

static void
igc_if_intr_disable(if_ctx_t ctx)
{
	struct igc_adapter *adapter = iflib_get_softc(ctx);
	struct igc_hw *hw = &adapter->hw;

	if (__predict_true(adapter->intr_type == IFLIB_INTR_MSIX)) {
		IGC_WRITE_REG(hw, IGC_EIMC, 0xffffffff);
		IGC_WRITE_REG(hw, IGC_EIAC, 0);
	}
	IGC_WRITE_REG(hw, IGC_IMC, 0xffffffff);
	IGC_WRITE_FLUSH(hw);
}

/*
 * igc_get_hw_control sets the {CTRL_EXT|FWSM}:DRV_LOAD bit.
 * For ASF and Pass Through versions of f/w this means
 * that the driver is loaded. For AMT version type f/w
 * this means that the network i/f is open.
 */
static void
igc_get_hw_control(struct igc_adapter *adapter)
{
	u32 ctrl_ext;

	if (adapter->vf_ifp)
		return;

	ctrl_ext = IGC_READ_REG(&adapter->hw, IGC_CTRL_EXT);
	IGC_WRITE_REG(&adapter->hw, IGC_CTRL_EXT,
	    ctrl_ext | IGC_CTRL_EXT_DRV_LOAD);
}

/*
 * igc_release_hw_control resets {CTRL_EXT|FWSM}:DRV_LOAD bit.
 * For ASF and Pass Through versions of f/w this means that
 * the driver is no longer loaded. For AMT versions of the
 * f/w this means that the network i/f is closed.
 */
static void
igc_release_hw_control(struct igc_adapter *adapter)
{
	u32 ctrl_ext;

	ctrl_ext = IGC_READ_REG(&adapter->hw, IGC_CTRL_EXT);
	IGC_WRITE_REG(&adapter->hw, IGC_CTRL_EXT,
	    ctrl_ext & ~IGC_CTRL_EXT_DRV_LOAD);
	return;
}

static int
igc_is_valid_ether_addr(u8 *addr)
{
	char zero_addr[6] = { 0, 0, 0, 0, 0, 0 };

	if ((addr[0] & 1) || (!bcmp(addr, zero_addr, ETHER_ADDR_LEN))) {
		return (false);
	}

	return (true);
}

/*
** Parse the interface capabilities with regard
** to both system management and wake-on-lan for
** later use.
*/
static void
igc_get_wakeup(if_ctx_t ctx)
{
	struct igc_adapter *adapter = iflib_get_softc(ctx);
	u16 eeprom_data = 0, apme_mask;

	apme_mask = IGC_WUC_APME;
	eeprom_data = IGC_READ_REG(&adapter->hw, IGC_WUC);

	if (eeprom_data & apme_mask)
		adapter->wol = IGC_WUFC_LNKC;
}


/*
 * Enable PCI Wake On Lan capability
 */
static void
igc_enable_wakeup(if_ctx_t ctx)
{
	struct igc_adapter *adapter = iflib_get_softc(ctx);
	device_t dev = iflib_get_dev(ctx);
	if_t ifp = iflib_get_ifp(ctx);
	int error = 0;
	u32 pmc, ctrl, rctl;
	u16 status;

	if (pci_find_cap(dev, PCIY_PMG, &pmc) != 0)
		return;

	/*
	 * Determine type of Wakeup: note that wol
	 * is set with all bits on by default.
	 */
	if ((if_getcapenable(ifp) & IFCAP_WOL_MAGIC) == 0)
		adapter->wol &= ~IGC_WUFC_MAG;

	if ((if_getcapenable(ifp) & IFCAP_WOL_UCAST) == 0)
		adapter->wol &= ~IGC_WUFC_EX;

	if ((if_getcapenable(ifp) & IFCAP_WOL_MCAST) == 0)
		adapter->wol &= ~IGC_WUFC_MC;
	else {
		rctl = IGC_READ_REG(&adapter->hw, IGC_RCTL);
		rctl |= IGC_RCTL_MPE;
		IGC_WRITE_REG(&adapter->hw, IGC_RCTL, rctl);
	}

	if (!(adapter->wol & (IGC_WUFC_EX | IGC_WUFC_MAG | IGC_WUFC_MC)))
		goto pme;

	/* Advertise the wakeup capability */
	ctrl = IGC_READ_REG(&adapter->hw, IGC_CTRL);
	ctrl |= IGC_CTRL_ADVD3WUC;
	IGC_WRITE_REG(&adapter->hw, IGC_CTRL, ctrl);

	/* Enable wakeup by the MAC */
	IGC_WRITE_REG(&adapter->hw, IGC_WUC, IGC_WUC_PME_EN);
	IGC_WRITE_REG(&adapter->hw, IGC_WUFC, adapter->wol);

pme:
	status = pci_read_config(dev, pmc + PCIR_POWER_STATUS, 2);
	status &= ~(PCIM_PSTAT_PME | PCIM_PSTAT_PMEENABLE);
	if (!error && (if_getcapenable(ifp) & IFCAP_WOL))
		status |= PCIM_PSTAT_PME | PCIM_PSTAT_PMEENABLE;
	pci_write_config(dev, pmc + PCIR_POWER_STATUS, status, 2);

	return;
}

/**********************************************************************
 *
 *  Update the board statistics counters.
 *
 **********************************************************************/
static void
igc_update_stats_counters(struct igc_adapter *adapter)
{
	u64 prev_xoffrxc = adapter->stats.xoffrxc;

	adapter->stats.crcerrs += IGC_READ_REG(&adapter->hw, IGC_CRCERRS);
	adapter->stats.mpc += IGC_READ_REG(&adapter->hw, IGC_MPC);
	adapter->stats.scc += IGC_READ_REG(&adapter->hw, IGC_SCC);
	adapter->stats.ecol += IGC_READ_REG(&adapter->hw, IGC_ECOL);

	adapter->stats.mcc += IGC_READ_REG(&adapter->hw, IGC_MCC);
	adapter->stats.latecol += IGC_READ_REG(&adapter->hw, IGC_LATECOL);
	adapter->stats.colc += IGC_READ_REG(&adapter->hw, IGC_COLC);
	adapter->stats.colc += IGC_READ_REG(&adapter->hw, IGC_RERC);
	adapter->stats.dc += IGC_READ_REG(&adapter->hw, IGC_DC);
	adapter->stats.rlec += IGC_READ_REG(&adapter->hw, IGC_RLEC);
	adapter->stats.xonrxc += IGC_READ_REG(&adapter->hw, IGC_XONRXC);
	adapter->stats.xontxc += IGC_READ_REG(&adapter->hw, IGC_XONTXC);
	adapter->stats.xoffrxc += IGC_READ_REG(&adapter->hw, IGC_XOFFRXC);
	/*
	 * For watchdog management we need to know if we have been
	 * paused during the last interval, so capture that here.
	 */
	if (adapter->stats.xoffrxc != prev_xoffrxc)
		adapter->shared->isc_pause_frames = 1;
	adapter->stats.xofftxc += IGC_READ_REG(&adapter->hw, IGC_XOFFTXC);
	adapter->stats.fcruc += IGC_READ_REG(&adapter->hw, IGC_FCRUC);
	adapter->stats.prc64 += IGC_READ_REG(&adapter->hw, IGC_PRC64);
	adapter->stats.prc127 += IGC_READ_REG(&adapter->hw, IGC_PRC127);
	adapter->stats.prc255 += IGC_READ_REG(&adapter->hw, IGC_PRC255);
	adapter->stats.prc511 += IGC_READ_REG(&adapter->hw, IGC_PRC511);
	adapter->stats.prc1023 += IGC_READ_REG(&adapter->hw, IGC_PRC1023);
	adapter->stats.prc1522 += IGC_READ_REG(&adapter->hw, IGC_PRC1522);
	adapter->stats.tlpic += IGC_READ_REG(&adapter->hw, IGC_TLPIC);
	adapter->stats.rlpic += IGC_READ_REG(&adapter->hw, IGC_RLPIC);
	adapter->stats.gprc += IGC_READ_REG(&adapter->hw, IGC_GPRC);
	adapter->stats.bprc += IGC_READ_REG(&adapter->hw, IGC_BPRC);
	adapter->stats.mprc += IGC_READ_REG(&adapter->hw, IGC_MPRC);
	adapter->stats.gptc += IGC_READ_REG(&adapter->hw, IGC_GPTC);

	/* For the 64-bit byte counters the low dword must be read first. */
	/* Both registers clear on the read of the high dword */

	adapter->stats.gorc += IGC_READ_REG(&adapter->hw, IGC_GORCL) +
	    ((u64)IGC_READ_REG(&adapter->hw, IGC_GORCH) << 32);
	adapter->stats.gotc += IGC_READ_REG(&adapter->hw, IGC_GOTCL) +
	    ((u64)IGC_READ_REG(&adapter->hw, IGC_GOTCH) << 32);

	adapter->stats.rnbc += IGC_READ_REG(&adapter->hw, IGC_RNBC);
	adapter->stats.ruc += IGC_READ_REG(&adapter->hw, IGC_RUC);
	adapter->stats.rfc += IGC_READ_REG(&adapter->hw, IGC_RFC);
	adapter->stats.roc += IGC_READ_REG(&adapter->hw, IGC_ROC);
	adapter->stats.rjc += IGC_READ_REG(&adapter->hw, IGC_RJC);

	adapter->stats.tor += IGC_READ_REG(&adapter->hw, IGC_TORH);
	adapter->stats.tot += IGC_READ_REG(&adapter->hw, IGC_TOTH);

	adapter->stats.tpr += IGC_READ_REG(&adapter->hw, IGC_TPR);
	adapter->stats.tpt += IGC_READ_REG(&adapter->hw, IGC_TPT);
	adapter->stats.ptc64 += IGC_READ_REG(&adapter->hw, IGC_PTC64);
	adapter->stats.ptc127 += IGC_READ_REG(&adapter->hw, IGC_PTC127);
	adapter->stats.ptc255 += IGC_READ_REG(&adapter->hw, IGC_PTC255);
	adapter->stats.ptc511 += IGC_READ_REG(&adapter->hw, IGC_PTC511);
	adapter->stats.ptc1023 += IGC_READ_REG(&adapter->hw, IGC_PTC1023);
	adapter->stats.ptc1522 += IGC_READ_REG(&adapter->hw, IGC_PTC1522);
	adapter->stats.mptc += IGC_READ_REG(&adapter->hw, IGC_MPTC);
	adapter->stats.bptc += IGC_READ_REG(&adapter->hw, IGC_BPTC);

	/* Interrupt Counts */
	adapter->stats.iac += IGC_READ_REG(&adapter->hw, IGC_IAC);
	adapter->stats.rxdmtc += IGC_READ_REG(&adapter->hw, IGC_RXDMTC);

	adapter->stats.algnerrc += IGC_READ_REG(&adapter->hw, IGC_ALGNERRC);
	adapter->stats.tncrs += IGC_READ_REG(&adapter->hw, IGC_TNCRS);
	adapter->stats.htdpmc += IGC_READ_REG(&adapter->hw, IGC_HTDPMC);
	adapter->stats.tsctc += IGC_READ_REG(&adapter->hw, IGC_TSCTC);
}

static uint64_t
igc_if_get_counter(if_ctx_t ctx, ift_counter cnt)
{
	struct igc_adapter *adapter = iflib_get_softc(ctx);
	struct ifnet *ifp = iflib_get_ifp(ctx);

	switch (cnt) {
	case IFCOUNTER_COLLISIONS:
		return (adapter->stats.colc);
	case IFCOUNTER_IERRORS:
		return (adapter->dropped_pkts + adapter->stats.rxerrc +
		    adapter->stats.crcerrs + adapter->stats.algnerrc +
		    adapter->stats.ruc + adapter->stats.roc +
		    adapter->stats.mpc + adapter->stats.htdpmc);
	case IFCOUNTER_OERRORS:
		return (adapter->stats.ecol + adapter->stats.latecol +
		    adapter->watchdog_events);
	default:
		return (if_get_counter_default(ifp, cnt));
	}
}

/* igc_if_needs_restart - Tell iflib when the driver needs to be reinitialized
 * @ctx: iflib context
 * @event: event code to check
 *
 * Defaults to returning true for unknown events.
 *
 * @returns true if iflib needs to reinit the interface
 */
static bool
igc_if_needs_restart(if_ctx_t ctx __unused, enum iflib_restart_event event)
{
	switch (event) {
	case IFLIB_RESTART_VLAN_CONFIG:
	default:
		return (true);
	}
}

/* Export a single 32-bit register via a read-only sysctl. */
static int
igc_sysctl_reg_handler(SYSCTL_HANDLER_ARGS)
{
	struct igc_adapter *adapter;
	u_int val;

	adapter = oidp->oid_arg1;
	val = IGC_READ_REG(&adapter->hw, oidp->oid_arg2);
	return (sysctl_handle_int(oidp, &val, 0, req));
}

/*
 * Add sysctl variables, one per statistic, to the system.
 */
static void
igc_add_hw_stats(struct igc_adapter *adapter)
{
	device_t dev = iflib_get_dev(adapter->ctx);
	struct igc_tx_queue *tx_que = adapter->tx_queues;
	struct igc_rx_queue *rx_que = adapter->rx_queues;

	struct sysctl_ctx_list *ctx = device_get_sysctl_ctx(dev);
	struct sysctl_oid *tree = device_get_sysctl_tree(dev);
	struct sysctl_oid_list *child = SYSCTL_CHILDREN(tree);
	struct igc_hw_stats *stats = &adapter->stats;

	struct sysctl_oid *stat_node, *queue_node, *int_node;
	struct sysctl_oid_list *stat_list, *queue_list, *int_list;

#define QUEUE_NAME_LEN 32
	char namebuf[QUEUE_NAME_LEN];

	/* Driver Statistics */
	SYSCTL_ADD_ULONG(ctx, child, OID_AUTO, "dropped",
			CTLFLAG_RD, &adapter->dropped_pkts,
			"Driver dropped packets");
	SYSCTL_ADD_ULONG(ctx, child, OID_AUTO, "link_irq",
			CTLFLAG_RD, &adapter->link_irq,
			"Link MSI-X IRQ Handled");
	SYSCTL_ADD_ULONG(ctx, child, OID_AUTO, "rx_overruns",
			CTLFLAG_RD, &adapter->rx_overruns,
			"RX overruns");
	SYSCTL_ADD_ULONG(ctx, child, OID_AUTO, "watchdog_timeouts",
			CTLFLAG_RD, &adapter->watchdog_events,
			"Watchdog timeouts");
	SYSCTL_ADD_PROC(ctx, child, OID_AUTO, "device_control",
	    CTLTYPE_UINT | CTLFLAG_RD | CTLFLAG_NEEDGIANT,
	    adapter, IGC_CTRL, igc_sysctl_reg_handler, "IU",
	    "Device Control Register");
	SYSCTL_ADD_PROC(ctx, child, OID_AUTO, "rx_control",
	    CTLTYPE_UINT | CTLFLAG_RD | CTLFLAG_NEEDGIANT,
	    adapter, IGC_RCTL, igc_sysctl_reg_handler, "IU",
	    "Receiver Control Register");
	SYSCTL_ADD_UINT(ctx, child, OID_AUTO, "fc_high_water",
			CTLFLAG_RD, &adapter->hw.fc.high_water, 0,
			"Flow Control High Watermark");
	SYSCTL_ADD_UINT(ctx, child, OID_AUTO, "fc_low_water",
			CTLFLAG_RD, &adapter->hw.fc.low_water, 0,
			"Flow Control Low Watermark");

	for (int i = 0; i < adapter->tx_num_queues; i++, tx_que++) {
		struct tx_ring *txr = &tx_que->txr;
		snprintf(namebuf, QUEUE_NAME_LEN, "queue_tx_%d", i);
		queue_node = SYSCTL_ADD_NODE(ctx, child, OID_AUTO, namebuf,
		    CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, "TX Queue Name");
		queue_list = SYSCTL_CHILDREN(queue_node);

		SYSCTL_ADD_PROC(ctx, queue_list, OID_AUTO, "txd_head",
		    CTLTYPE_UINT | CTLFLAG_RD | CTLFLAG_NEEDGIANT, adapter,
		    IGC_TDH(txr->me), igc_sysctl_reg_handler, "IU",
		    "Transmit Descriptor Head");
		SYSCTL_ADD_PROC(ctx, queue_list, OID_AUTO, "txd_tail",
		    CTLTYPE_UINT | CTLFLAG_RD | CTLFLAG_NEEDGIANT, adapter,
		    IGC_TDT(txr->me), igc_sysctl_reg_handler, "IU",
		    "Transmit Descriptor Tail");
		SYSCTL_ADD_ULONG(ctx, queue_list, OID_AUTO, "tx_irq",
				CTLFLAG_RD, &txr->tx_irq,
				"Queue MSI-X Transmit Interrupts");
	}

	for (int j = 0; j < adapter->rx_num_queues; j++, rx_que++) {
		struct rx_ring *rxr = &rx_que->rxr;
		snprintf(namebuf, QUEUE_NAME_LEN, "queue_rx_%d", j);
		queue_node = SYSCTL_ADD_NODE(ctx, child, OID_AUTO, namebuf,
		    CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, "RX Queue Name");
		queue_list = SYSCTL_CHILDREN(queue_node);

		SYSCTL_ADD_PROC(ctx, queue_list, OID_AUTO, "rxd_head",
		    CTLTYPE_UINT | CTLFLAG_RD | CTLFLAG_NEEDGIANT, adapter,
		    IGC_RDH(rxr->me), igc_sysctl_reg_handler, "IU",
		    "Receive Descriptor Head");
		SYSCTL_ADD_PROC(ctx, queue_list, OID_AUTO, "rxd_tail",
		    CTLTYPE_UINT | CTLFLAG_RD | CTLFLAG_NEEDGIANT, adapter,
		    IGC_RDT(rxr->me), igc_sysctl_reg_handler, "IU",
		    "Receive Descriptor Tail");
		SYSCTL_ADD_ULONG(ctx, queue_list, OID_AUTO, "rx_irq",
				CTLFLAG_RD, &rxr->rx_irq,
				"Queue MSI-X Receive Interrupts");
	}

	/* MAC stats get their own sub node */

	stat_node = SYSCTL_ADD_NODE(ctx, child, OID_AUTO, "mac_stats",
	    CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, "Statistics");
	stat_list = SYSCTL_CHILDREN(stat_node);

	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "excess_coll",
			CTLFLAG_RD, &stats->ecol,
			"Excessive collisions");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "single_coll",
			CTLFLAG_RD, &stats->scc,
			"Single collisions");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "multiple_coll",
			CTLFLAG_RD, &stats->mcc,
			"Multiple collisions");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "late_coll",
			CTLFLAG_RD, &stats->latecol,
			"Late collisions");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "collision_count",
			CTLFLAG_RD, &stats->colc,
			"Collision Count");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "symbol_errors",
			CTLFLAG_RD, &adapter->stats.symerrs,
			"Symbol Errors");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "sequence_errors",
			CTLFLAG_RD, &adapter->stats.sec,
			"Sequence Errors");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "defer_count",
			CTLFLAG_RD, &adapter->stats.dc,
			"Defer Count");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "missed_packets",
			CTLFLAG_RD, &adapter->stats.mpc,
			"Missed Packets");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "recv_no_buff",
			CTLFLAG_RD, &adapter->stats.rnbc,
			"Receive No Buffers");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "recv_undersize",
			CTLFLAG_RD, &adapter->stats.ruc,
			"Receive Undersize");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "recv_fragmented",
			CTLFLAG_RD, &adapter->stats.rfc,
			"Fragmented Packets Received ");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "recv_oversize",
			CTLFLAG_RD, &adapter->stats.roc,
			"Oversized Packets Received");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "recv_jabber",
			CTLFLAG_RD, &adapter->stats.rjc,
			"Recevied Jabber");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "recv_errs",
			CTLFLAG_RD, &adapter->stats.rxerrc,
			"Receive Errors");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "crc_errs",
			CTLFLAG_RD, &adapter->stats.crcerrs,
			"CRC errors");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "alignment_errs",
			CTLFLAG_RD, &adapter->stats.algnerrc,
			"Alignment Errors");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "xon_recvd",
			CTLFLAG_RD, &adapter->stats.xonrxc,
			"XON Received");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "xon_txd",
			CTLFLAG_RD, &adapter->stats.xontxc,
			"XON Transmitted");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "xoff_recvd",
			CTLFLAG_RD, &adapter->stats.xoffrxc,
			"XOFF Received");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "xoff_txd",
			CTLFLAG_RD, &adapter->stats.xofftxc,
			"XOFF Transmitted");

	/* Packet Reception Stats */
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "total_pkts_recvd",
			CTLFLAG_RD, &adapter->stats.tpr,
			"Total Packets Received ");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "good_pkts_recvd",
			CTLFLAG_RD, &adapter->stats.gprc,
			"Good Packets Received");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "bcast_pkts_recvd",
			CTLFLAG_RD, &adapter->stats.bprc,
			"Broadcast Packets Received");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "mcast_pkts_recvd",
			CTLFLAG_RD, &adapter->stats.mprc,
			"Multicast Packets Received");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "rx_frames_64",
			CTLFLAG_RD, &adapter->stats.prc64,
			"64 byte frames received ");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "rx_frames_65_127",
			CTLFLAG_RD, &adapter->stats.prc127,
			"65-127 byte frames received");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "rx_frames_128_255",
			CTLFLAG_RD, &adapter->stats.prc255,
			"128-255 byte frames received");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "rx_frames_256_511",
			CTLFLAG_RD, &adapter->stats.prc511,
			"256-511 byte frames received");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "rx_frames_512_1023",
			CTLFLAG_RD, &adapter->stats.prc1023,
			"512-1023 byte frames received");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "rx_frames_1024_1522",
			CTLFLAG_RD, &adapter->stats.prc1522,
			"1023-1522 byte frames received");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "good_octets_recvd",
			CTLFLAG_RD, &adapter->stats.gorc,
			"Good Octets Received");

	/* Packet Transmission Stats */
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "good_octets_txd",
			CTLFLAG_RD, &adapter->stats.gotc,
			"Good Octets Transmitted");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "total_pkts_txd",
			CTLFLAG_RD, &adapter->stats.tpt,
			"Total Packets Transmitted");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "good_pkts_txd",
			CTLFLAG_RD, &adapter->stats.gptc,
			"Good Packets Transmitted");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "bcast_pkts_txd",
			CTLFLAG_RD, &adapter->stats.bptc,
			"Broadcast Packets Transmitted");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "mcast_pkts_txd",
			CTLFLAG_RD, &adapter->stats.mptc,
			"Multicast Packets Transmitted");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "tx_frames_64",
			CTLFLAG_RD, &adapter->stats.ptc64,
			"64 byte frames transmitted ");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "tx_frames_65_127",
			CTLFLAG_RD, &adapter->stats.ptc127,
			"65-127 byte frames transmitted");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "tx_frames_128_255",
			CTLFLAG_RD, &adapter->stats.ptc255,
			"128-255 byte frames transmitted");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "tx_frames_256_511",
			CTLFLAG_RD, &adapter->stats.ptc511,
			"256-511 byte frames transmitted");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "tx_frames_512_1023",
			CTLFLAG_RD, &adapter->stats.ptc1023,
			"512-1023 byte frames transmitted");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "tx_frames_1024_1522",
			CTLFLAG_RD, &adapter->stats.ptc1522,
			"1024-1522 byte frames transmitted");
	SYSCTL_ADD_UQUAD(ctx, stat_list, OID_AUTO, "tso_txd",
			CTLFLAG_RD, &adapter->stats.tsctc,
			"TSO Contexts Transmitted");

	/* Interrupt Stats */

	int_node = SYSCTL_ADD_NODE(ctx, child, OID_AUTO, "interrupts",
	    CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, "Interrupt Statistics");
	int_list = SYSCTL_CHILDREN(int_node);

	SYSCTL_ADD_UQUAD(ctx, int_list, OID_AUTO, "asserts",
			CTLFLAG_RD, &adapter->stats.iac,
			"Interrupt Assertion Count");

	SYSCTL_ADD_UQUAD(ctx, int_list, OID_AUTO, "rx_desc_min_thresh",
			CTLFLAG_RD, &adapter->stats.rxdmtc,
			"Rx Desc Min Thresh Count");
}

/**********************************************************************
 *
 *  This routine provides a way to dump out the adapter eeprom,
 *  often a useful debug/service tool. This only dumps the first
 *  32 words, stuff that matters is in that extent.
 *
 **********************************************************************/
static int
igc_sysctl_nvm_info(SYSCTL_HANDLER_ARGS)
{
	struct igc_adapter *adapter = (struct igc_adapter *)arg1;
	int error;
	int result;

	result = -1;
	error = sysctl_handle_int(oidp, &result, 0, req);

	if (error || !req->newptr)
		return (error);

	/*
	 * This value will cause a hex dump of the
	 * first 32 16-bit words of the EEPROM to
	 * the screen.
	 */
	if (result == 1)
		igc_print_nvm_info(adapter);

	return (error);
}

static void
igc_print_nvm_info(struct igc_adapter *adapter)
{
	u16 eeprom_data;
	int i, j, row = 0;

	/* Its a bit crude, but it gets the job done */
	printf("\nInterface EEPROM Dump:\n");
	printf("Offset\n0x0000  ");
	for (i = 0, j = 0; i < 32; i++, j++) {
		if (j == 8) { /* Make the offset block */
			j = 0; ++row;
			printf("\n0x00%x0  ",row);
		}
		igc_read_nvm(&adapter->hw, i, 1, &eeprom_data);
		printf("%04x ", eeprom_data);
	}
	printf("\n");
}

static int
igc_sysctl_int_delay(SYSCTL_HANDLER_ARGS)
{
	struct igc_int_delay_info *info;
	struct igc_adapter *adapter;
	u32 regval;
	int error, usecs, ticks;

	info = (struct igc_int_delay_info *) arg1;
	usecs = info->value;
	error = sysctl_handle_int(oidp, &usecs, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (usecs < 0 || usecs > IGC_TICKS_TO_USECS(65535))
		return (EINVAL);
	info->value = usecs;
	ticks = IGC_USECS_TO_TICKS(usecs);
	if (info->offset == IGC_ITR)	/* units are 256ns here */
		ticks *= 4;

	adapter = info->adapter;

	regval = IGC_READ_OFFSET(&adapter->hw, info->offset);
	regval = (regval & ~0xffff) | (ticks & 0xffff);
	/* Handle a few special cases. */
	switch (info->offset) {
	case IGC_RDTR:
		break;
	case IGC_TIDV:
		if (ticks == 0) {
			adapter->txd_cmd &= ~IGC_TXD_CMD_IDE;
			/* Don't write 0 into the TIDV register. */
			regval++;
		} else
			adapter->txd_cmd |= IGC_TXD_CMD_IDE;
		break;
	}
	IGC_WRITE_OFFSET(&adapter->hw, info->offset, regval);
	return (0);
}

static void
igc_add_int_delay_sysctl(struct igc_adapter *adapter, const char *name,
	const char *description, struct igc_int_delay_info *info,
	int offset, int value)
{
	info->adapter = adapter;
	info->offset = offset;
	info->value = value;
	SYSCTL_ADD_PROC(device_get_sysctl_ctx(adapter->dev),
	    SYSCTL_CHILDREN(device_get_sysctl_tree(adapter->dev)),
	    OID_AUTO, name, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_NEEDGIANT,
	    info, 0, igc_sysctl_int_delay, "I", description);
}

/*
 * Set flow control using sysctl:
 * Flow control values:
 *      0 - off
 *      1 - rx pause
 *      2 - tx pause
 *      3 - full
 */
static int
igc_set_flowcntl(SYSCTL_HANDLER_ARGS)
{
	int error;
	static int input = 3; /* default is full */
	struct igc_adapter	*adapter = (struct igc_adapter *) arg1;

	error = sysctl_handle_int(oidp, &input, 0, req);

	if ((error) || (req->newptr == NULL))
		return (error);

	if (input == adapter->fc) /* no change? */
		return (error);

	switch (input) {
	case igc_fc_rx_pause:
	case igc_fc_tx_pause:
	case igc_fc_full:
	case igc_fc_none:
		adapter->hw.fc.requested_mode = input;
		adapter->fc = input;
		break;
	default:
		/* Do nothing */
		return (error);
	}

	adapter->hw.fc.current_mode = adapter->hw.fc.requested_mode;
	igc_force_mac_fc(&adapter->hw);
	return (error);
}

/*
 * Manage Energy Efficient Ethernet:
 * Control values:
 *     0/1 - enabled/disabled
 */
static int
igc_sysctl_eee(SYSCTL_HANDLER_ARGS)
{
	struct igc_adapter *adapter = (struct igc_adapter *) arg1;
	int error, value;

	value = adapter->hw.dev_spec._i225.eee_disable;
	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error || req->newptr == NULL)
		return (error);

	adapter->hw.dev_spec._i225.eee_disable = (value != 0);
	igc_if_init(adapter->ctx);

	return (0);
}

static int
igc_sysctl_debug_info(SYSCTL_HANDLER_ARGS)
{
	struct igc_adapter *adapter;
	int error;
	int result;

	result = -1;
	error = sysctl_handle_int(oidp, &result, 0, req);

	if (error || !req->newptr)
		return (error);

	if (result == 1) {
		adapter = (struct igc_adapter *) arg1;
		igc_print_debug_info(adapter);
	}

	return (error);
}

static int
igc_get_rs(SYSCTL_HANDLER_ARGS)
{
	struct igc_adapter *adapter = (struct igc_adapter *) arg1;
	int error;
	int result;

	result = 0;
	error = sysctl_handle_int(oidp, &result, 0, req);

	if (error || !req->newptr || result != 1)
		return (error);
	igc_dump_rs(adapter);

	return (error);
}

static void
igc_if_debug(if_ctx_t ctx)
{
	igc_dump_rs(iflib_get_softc(ctx));
}

/*
 * This routine is meant to be fluid, add whatever is
 * needed for debugging a problem.  -jfv
 */
static void
igc_print_debug_info(struct igc_adapter *adapter)
{
	device_t dev = iflib_get_dev(adapter->ctx);
	struct ifnet *ifp = iflib_get_ifp(adapter->ctx);
	struct tx_ring *txr = &adapter->tx_queues->txr;
	struct rx_ring *rxr = &adapter->rx_queues->rxr;

	if (if_getdrvflags(ifp) & IFF_DRV_RUNNING)
		printf("Interface is RUNNING ");
	else
		printf("Interface is NOT RUNNING\n");

	if (if_getdrvflags(ifp) & IFF_DRV_OACTIVE)
		printf("and INACTIVE\n");
	else
		printf("and ACTIVE\n");

	for (int i = 0; i < adapter->tx_num_queues; i++, txr++) {
		device_printf(dev, "TX Queue %d ------\n", i);
		device_printf(dev, "hw tdh = %d, hw tdt = %d\n",
			IGC_READ_REG(&adapter->hw, IGC_TDH(i)),
			IGC_READ_REG(&adapter->hw, IGC_TDT(i)));

	}
	for (int j=0; j < adapter->rx_num_queues; j++, rxr++) {
		device_printf(dev, "RX Queue %d ------\n", j);
		device_printf(dev, "hw rdh = %d, hw rdt = %d\n",
			IGC_READ_REG(&adapter->hw, IGC_RDH(j)),
			IGC_READ_REG(&adapter->hw, IGC_RDT(j)));
	}
}
