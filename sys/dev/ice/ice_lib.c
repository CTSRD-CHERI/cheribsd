/* SPDX-License-Identifier: BSD-3-Clause */
/*  Copyright (c) 2020, Intel Corporation
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *   1. Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *   3. Neither the name of the Intel Corporation nor the names of its
 *      contributors may be used to endorse or promote products derived from
 *      this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */
/*$FreeBSD$*/

/**
 * @file ice_lib.c
 * @brief Generic device setup and sysctl functions
 *
 * Library of generic device functions not specific to the networking stack.
 *
 * This includes hardware initialization functions, as well as handlers for
 * many of the device sysctls used to probe driver status or tune specific
 * behaviors.
 */

#include "ice_lib.h"
#include "ice_iflib.h"
#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>
#include <machine/resource.h>
#include <net/if_dl.h>
#include <sys/firmware.h>
#include <sys/priv.h>

/**
 * @var M_ICE
 * @brief main ice driver allocation type
 *
 * malloc(9) allocation type used by the majority of memory allocations in the
 * ice driver.
 */
MALLOC_DEFINE(M_ICE, "ice", "Intel(R) 100Gb Network Driver lib allocations");

/*
 * Helper function prototypes
 */
static int ice_get_next_vsi(struct ice_vsi **all_vsi, int size);
static void ice_set_default_vsi_ctx(struct ice_vsi_ctx *ctx);
static void ice_set_rss_vsi_ctx(struct ice_vsi_ctx *ctx, enum ice_vsi_type type);
static int ice_setup_vsi_qmap(struct ice_vsi *vsi, struct ice_vsi_ctx *ctx);
static int ice_setup_tx_ctx(struct ice_tx_queue *txq,
			    struct ice_tlan_ctx *tlan_ctx, u16 pf_q);
static int ice_setup_rx_ctx(struct ice_rx_queue *rxq);
static int ice_is_rxq_ready(struct ice_hw *hw, int pf_q, u32 *reg);
static void ice_free_fltr_list(struct ice_list_head *list);
static int ice_add_mac_to_list(struct ice_vsi *vsi, struct ice_list_head *list,
			       const u8 *addr, enum ice_sw_fwd_act_type action);
static void ice_check_ctrlq_errors(struct ice_softc *sc, const char *qname,
				   struct ice_ctl_q_info *cq);
static void ice_process_link_event(struct ice_softc *sc, struct ice_rq_event_info *e);
static void ice_process_ctrlq_event(struct ice_softc *sc, const char *qname,
				    struct ice_rq_event_info *event);
static void ice_nvm_version_str(struct ice_hw *hw, struct sbuf *buf);
static void ice_active_pkg_version_str(struct ice_hw *hw, struct sbuf *buf);
static void ice_os_pkg_version_str(struct ice_hw *hw, struct sbuf *buf);
static bool ice_filter_is_mcast(struct ice_vsi *vsi, struct ice_fltr_info *info);
static u_int ice_sync_one_mcast_filter(void *p, struct sockaddr_dl *sdl, u_int errors);
static void ice_add_debug_tunables(struct ice_softc *sc);
static void ice_add_debug_sysctls(struct ice_softc *sc);
static void ice_vsi_set_rss_params(struct ice_vsi *vsi);
static void ice_get_default_rss_key(u8 *seed);
static int  ice_set_rss_key(struct ice_vsi *vsi);
static int  ice_set_rss_lut(struct ice_vsi *vsi);
static void ice_set_rss_flow_flds(struct ice_vsi *vsi);
static void ice_clean_vsi_rss_cfg(struct ice_vsi *vsi);
static const char *ice_aq_speed_to_str(struct ice_port_info *pi);
static const char *ice_requested_fec_mode(struct ice_port_info *pi);
static const char *ice_negotiated_fec_mode(struct ice_port_info *pi);
static const char *ice_autoneg_mode(struct ice_port_info *pi);
static const char *ice_flowcontrol_mode(struct ice_port_info *pi);
static void ice_print_bus_link_data(device_t dev, struct ice_hw *hw);
static void ice_set_pci_link_status_data(struct ice_hw *hw, u16 link_status);
static uint8_t ice_pcie_bandwidth_check(struct ice_softc *sc);
static uint64_t ice_pcie_bus_speed_to_rate(enum ice_pcie_bus_speed speed);
static int ice_pcie_lnk_width_to_int(enum ice_pcie_link_width width);
static uint64_t ice_phy_types_to_max_rate(struct ice_port_info *pi);
static void ice_add_sysctls_sw_stats(struct ice_vsi *vsi,
				     struct sysctl_ctx_list *ctx,
				     struct sysctl_oid *parent);
static void ice_setup_vsi_common(struct ice_softc *sc, struct ice_vsi *vsi,
				 enum ice_vsi_type type, int idx,
				 bool dynamic);
static void ice_handle_mib_change_event(struct ice_softc *sc,
				 struct ice_rq_event_info *event);
static void
ice_handle_lan_overflow_event(struct ice_softc *sc,
			      struct ice_rq_event_info *event);
static int ice_add_ethertype_to_list(struct ice_vsi *vsi,
				     struct ice_list_head *list,
				     u16 ethertype, u16 direction,
				     enum ice_sw_fwd_act_type action);
static void ice_add_rx_lldp_filter(struct ice_softc *sc);
static void ice_del_rx_lldp_filter(struct ice_softc *sc);
static u16 ice_aq_phy_types_to_sysctl_speeds(u64 phy_type_low,
					     u64 phy_type_high);
static void
ice_apply_saved_phy_req_to_cfg(struct ice_port_info *pi,
			       struct ice_aqc_get_phy_caps_data *pcaps,
			       struct ice_aqc_set_phy_cfg_data *cfg);
static void
ice_apply_saved_fec_req_to_cfg(struct ice_port_info *pi,
			       struct ice_aqc_get_phy_caps_data *pcaps,
			       struct ice_aqc_set_phy_cfg_data *cfg);
static void
ice_apply_saved_user_req_to_cfg(struct ice_port_info *pi,
				struct ice_aqc_get_phy_caps_data *pcaps,
				struct ice_aqc_set_phy_cfg_data *cfg);
static void
ice_apply_saved_fc_req_to_cfg(struct ice_port_info *pi,
			      struct ice_aqc_set_phy_cfg_data *cfg);
static void
ice_print_ldo_tlv(struct ice_softc *sc,
		  struct ice_link_default_override_tlv *tlv);
static void
ice_sysctl_speeds_to_aq_phy_types(u16 sysctl_speeds, u64 *phy_type_low,
				  u64 *phy_type_high);
static int
ice_intersect_media_types_with_caps(struct ice_softc *sc, u64 *phy_type_low,
				    u64 *phy_type_high);
static int
ice_get_auto_speeds(struct ice_softc *sc, u64 *phy_type_low,
		    u64 *phy_type_high);
static void
ice_apply_supported_speed_filter(u64 *phy_type_low, u64 *phy_type_high);
static enum ice_status
ice_get_phy_types(struct ice_softc *sc, u64 *phy_type_low, u64 *phy_type_high);

static int ice_module_init(void);
static int ice_module_exit(void);

/*
 * package version comparison functions
 */
static bool pkg_ver_empty(struct ice_pkg_ver *pkg_ver, u8 *pkg_name);
static int pkg_ver_compatible(struct ice_pkg_ver *pkg_ver);

/*
 * dynamic sysctl handlers
 */
static int ice_sysctl_show_fw(SYSCTL_HANDLER_ARGS);
static int ice_sysctl_pkg_version(SYSCTL_HANDLER_ARGS);
static int ice_sysctl_os_pkg_version(SYSCTL_HANDLER_ARGS);
static int ice_sysctl_dump_mac_filters(SYSCTL_HANDLER_ARGS);
static int ice_sysctl_dump_vlan_filters(SYSCTL_HANDLER_ARGS);
static int ice_sysctl_dump_ethertype_filters(SYSCTL_HANDLER_ARGS);
static int ice_sysctl_dump_ethertype_mac_filters(SYSCTL_HANDLER_ARGS);
static int ice_sysctl_current_speed(SYSCTL_HANDLER_ARGS);
static int ice_sysctl_request_reset(SYSCTL_HANDLER_ARGS);
static int ice_sysctl_dump_state_flags(SYSCTL_HANDLER_ARGS);
static int ice_sysctl_fec_config(SYSCTL_HANDLER_ARGS);
static int ice_sysctl_fc_config(SYSCTL_HANDLER_ARGS);
static int ice_sysctl_negotiated_fc(SYSCTL_HANDLER_ARGS);
static int ice_sysctl_negotiated_fec(SYSCTL_HANDLER_ARGS);
static int ice_sysctl_phy_type_low(SYSCTL_HANDLER_ARGS);
static int ice_sysctl_phy_type_high(SYSCTL_HANDLER_ARGS);
static int __ice_sysctl_phy_type_handler(SYSCTL_HANDLER_ARGS,
					 bool is_phy_type_high);
static int ice_sysctl_advertise_speed(SYSCTL_HANDLER_ARGS);
static int ice_sysctl_rx_itr(SYSCTL_HANDLER_ARGS);
static int ice_sysctl_tx_itr(SYSCTL_HANDLER_ARGS);
static int ice_sysctl_fw_lldp_agent(SYSCTL_HANDLER_ARGS);
static int ice_sysctl_fw_cur_lldp_persist_status(SYSCTL_HANDLER_ARGS);
static int ice_sysctl_fw_dflt_lldp_persist_status(SYSCTL_HANDLER_ARGS);
static int ice_sysctl_phy_caps(SYSCTL_HANDLER_ARGS, u8 report_mode);
static int ice_sysctl_phy_sw_caps(SYSCTL_HANDLER_ARGS);
static int ice_sysctl_phy_nvm_caps(SYSCTL_HANDLER_ARGS);
static int ice_sysctl_phy_topo_caps(SYSCTL_HANDLER_ARGS);
static int ice_sysctl_phy_link_status(SYSCTL_HANDLER_ARGS);
static int ice_sysctl_read_i2c_diag_data(SYSCTL_HANDLER_ARGS);
static int ice_sysctl_tx_cso_stat(SYSCTL_HANDLER_ARGS);
static int ice_sysctl_rx_cso_stat(SYSCTL_HANDLER_ARGS);
static int ice_sysctl_pba_number(SYSCTL_HANDLER_ARGS);

/**
 * ice_map_bar - Map PCIe BAR memory
 * @dev: the PCIe device
 * @bar: the BAR info structure
 * @bar_num: PCIe BAR number
 *
 * Maps the specified PCIe BAR. Stores the mapping data in struct
 * ice_bar_info.
 */
int
ice_map_bar(device_t dev, struct ice_bar_info *bar, int bar_num)
{
	if (bar->res != NULL) {
		device_printf(dev, "PCI BAR%d already mapped\n", bar_num);
		return (EDOOFUS);
	}

	bar->rid = PCIR_BAR(bar_num);
	bar->res = bus_alloc_resource_any(dev, SYS_RES_MEMORY, &bar->rid,
					  RF_ACTIVE);
	if (!bar->res) {
		device_printf(dev, "PCI BAR%d mapping failed\n", bar_num);
		return (ENXIO);
	}

	bar->tag = rman_get_bustag(bar->res);
	bar->handle = rman_get_bushandle(bar->res);
	bar->size = rman_get_size(bar->res);

	return (0);
}

/**
 * ice_free_bar - Free PCIe BAR memory
 * @dev: the PCIe device
 * @bar: the BAR info structure
 *
 * Frees the specified PCIe BAR, releasing its resources.
 */
void
ice_free_bar(device_t dev, struct ice_bar_info *bar)
{
	if (bar->res != NULL)
		bus_release_resource(dev, SYS_RES_MEMORY, bar->rid, bar->res);
	bar->res = NULL;
}

/**
 * ice_set_ctrlq_len - Configure ctrlq lengths for a device
 * @hw: the device hardware structure
 *
 * Configures the control queues for the given device, setting up the
 * specified lengths, prior to initializing hardware.
 */
void
ice_set_ctrlq_len(struct ice_hw *hw)
{
	hw->adminq.num_rq_entries = ICE_AQ_LEN;
	hw->adminq.num_sq_entries = ICE_AQ_LEN;
	hw->adminq.rq_buf_size = ICE_AQ_MAX_BUF_LEN;
	hw->adminq.sq_buf_size = ICE_AQ_MAX_BUF_LEN;

	hw->mailboxq.num_rq_entries = ICE_MBXQ_LEN;
	hw->mailboxq.num_sq_entries = ICE_MBXQ_LEN;
	hw->mailboxq.rq_buf_size = ICE_MBXQ_MAX_BUF_LEN;
	hw->mailboxq.sq_buf_size = ICE_MBXQ_MAX_BUF_LEN;

}

/**
 * ice_get_next_vsi - Get the next available VSI slot
 * @all_vsi: the VSI list
 * @size: the size of the VSI list
 *
 * Returns the index to the first available VSI slot. Will return size (one
 * past the last index) if there are no slots available.
 */
static int
ice_get_next_vsi(struct ice_vsi **all_vsi, int size)
{
	int i;

	for (i = 0; i < size; i++) {
		if (all_vsi[i] == NULL)
			return i;
	}

	return size;
}

/**
 * ice_setup_vsi_common - Common VSI setup for both dynamic and static VSIs
 * @sc: the device private softc structure
 * @vsi: the VSI to setup
 * @type: the VSI type of the new VSI
 * @idx: the index in the all_vsi array to use
 * @dynamic: whether this VSI memory was dynamically allocated
 *
 * Perform setup for a VSI that is common to both dynamically allocated VSIs
 * and the static PF VSI which is embedded in the softc structure.
 */
static void
ice_setup_vsi_common(struct ice_softc *sc, struct ice_vsi *vsi,
		     enum ice_vsi_type type, int idx, bool dynamic)
{
	/* Store important values in VSI struct */
	vsi->type = type;
	vsi->sc = sc;
	vsi->idx = idx;
	sc->all_vsi[idx] = vsi;
	vsi->dynamic = dynamic;

	/* Setup the VSI tunables now */
	ice_add_vsi_tunables(vsi, sc->vsi_sysctls);
}

/**
 * ice_alloc_vsi - Allocate a dynamic VSI
 * @sc: device softc structure
 * @type: VSI type
 *
 * Allocates a new dynamic VSI structure and inserts it into the VSI list.
 */
struct ice_vsi *
ice_alloc_vsi(struct ice_softc *sc, enum ice_vsi_type type)
{
	struct ice_vsi *vsi;
	int idx;

	/* Find an open index for a new VSI to be allocated. If the returned
	 * index is >= the num_available_vsi then it means no slot is
	 * available.
	 */
	idx = ice_get_next_vsi(sc->all_vsi, sc->num_available_vsi);
	if (idx >= sc->num_available_vsi) {
		device_printf(sc->dev, "No available VSI slots\n");
		return NULL;
	}

	vsi = (struct ice_vsi *)malloc(sizeof(*vsi), M_ICE, M_WAITOK|M_ZERO);
	if (!vsi) {
		device_printf(sc->dev, "Unable to allocate VSI memory\n");
		return NULL;
	}

	ice_setup_vsi_common(sc, vsi, type, idx, true);

	return vsi;
}

/**
 * ice_setup_pf_vsi - Setup the PF VSI
 * @sc: the device private softc
 *
 * Setup the PF VSI structure which is embedded as sc->pf_vsi in the device
 * private softc. Unlike other VSIs, the PF VSI memory is allocated as part of
 * the softc memory, instead of being dynamically allocated at creation.
 */
void
ice_setup_pf_vsi(struct ice_softc *sc)
{
	ice_setup_vsi_common(sc, &sc->pf_vsi, ICE_VSI_PF, 0, false);
}

/**
 * ice_alloc_vsi_qmap
 * @vsi: VSI structure
 * @max_tx_queues: Number of transmit queues to identify
 * @max_rx_queues: Number of receive queues to identify
 *
 * Allocates a max_[t|r]x_queues array of words for the VSI where each
 * word contains the index of the queue it represents.  In here, all
 * words are initialized to an index of ICE_INVALID_RES_IDX, indicating
 * all queues for this VSI are not yet assigned an index and thus,
 * not ready for use.
 *
 * Returns an error code on failure.
 */
int
ice_alloc_vsi_qmap(struct ice_vsi *vsi, const int max_tx_queues,
		   const int max_rx_queues)
{
	struct ice_softc *sc = vsi->sc;
	int i;

	MPASS(max_tx_queues > 0);
	MPASS(max_rx_queues > 0);

	/* Allocate Tx queue mapping memory */
	if (!(vsi->tx_qmap =
	      (u16 *) malloc(sizeof(u16) * max_tx_queues, M_ICE, M_WAITOK))) {
		device_printf(sc->dev, "Unable to allocate Tx qmap memory\n");
		return (ENOMEM);
	}

	/* Allocate Rx queue mapping memory */
	if (!(vsi->rx_qmap =
	      (u16 *) malloc(sizeof(u16) * max_rx_queues, M_ICE, M_WAITOK))) {
		device_printf(sc->dev, "Unable to allocate Rx qmap memory\n");
		goto free_tx_qmap;
	}

	/* Mark every queue map as invalid to start with */
	for (i = 0; i < max_tx_queues; i++) {
		vsi->tx_qmap[i] = ICE_INVALID_RES_IDX;
	}
	for (i = 0; i < max_rx_queues; i++) {
		vsi->rx_qmap[i] = ICE_INVALID_RES_IDX;
	}

	return 0;

free_tx_qmap:
	free(vsi->tx_qmap, M_ICE);
	vsi->tx_qmap = NULL;

	return (ENOMEM);
}

/**
 * ice_free_vsi_qmaps - Free the PF qmaps associated with a VSI
 * @vsi: the VSI private structure
 *
 * Frees the PF qmaps associated with the given VSI. Generally this will be
 * called by ice_release_vsi, but may need to be called during attach cleanup,
 * depending on when the qmaps were allocated.
 */
void
ice_free_vsi_qmaps(struct ice_vsi *vsi)
{
	struct ice_softc *sc = vsi->sc;

	if (vsi->tx_qmap) {
		ice_resmgr_release_map(&sc->tx_qmgr, vsi->tx_qmap,
					   vsi->num_tx_queues);
		free(vsi->tx_qmap, M_ICE);
		vsi->tx_qmap = NULL;
	}

	if (vsi->rx_qmap) {
		ice_resmgr_release_map(&sc->rx_qmgr, vsi->rx_qmap,
					   vsi->num_rx_queues);
		free(vsi->rx_qmap, M_ICE);
		vsi->rx_qmap = NULL;
	}
}

/**
 * ice_set_default_vsi_ctx - Setup default VSI context parameters
 * @ctx: the VSI context to initialize
 *
 * Initialize and prepare a default VSI context for configuring a new VSI.
 */
static void
ice_set_default_vsi_ctx(struct ice_vsi_ctx *ctx)
{
	u32 table = 0;

	memset(&ctx->info, 0, sizeof(ctx->info));
	/* VSI will be allocated from shared pool */
	ctx->alloc_from_pool = true;
	/* Enable source pruning by default */
	ctx->info.sw_flags = ICE_AQ_VSI_SW_FLAG_SRC_PRUNE;
	/* Traffic from VSI can be sent to LAN */
	ctx->info.sw_flags2 = ICE_AQ_VSI_SW_FLAG_LAN_ENA;
	/* Allow all packets untagged/tagged */
	ctx->info.vlan_flags = ((ICE_AQ_VSI_VLAN_MODE_ALL &
				 ICE_AQ_VSI_VLAN_MODE_M) >>
				ICE_AQ_VSI_VLAN_MODE_S);
	/* Show VLAN/UP from packets in Rx descriptors */
	ctx->info.vlan_flags |= ((ICE_AQ_VSI_VLAN_EMOD_STR_BOTH &
				  ICE_AQ_VSI_VLAN_EMOD_M) >>
				 ICE_AQ_VSI_VLAN_EMOD_S);
	/* Have 1:1 UP mapping for both ingress/egress tables */
	table |= ICE_UP_TABLE_TRANSLATE(0, 0);
	table |= ICE_UP_TABLE_TRANSLATE(1, 1);
	table |= ICE_UP_TABLE_TRANSLATE(2, 2);
	table |= ICE_UP_TABLE_TRANSLATE(3, 3);
	table |= ICE_UP_TABLE_TRANSLATE(4, 4);
	table |= ICE_UP_TABLE_TRANSLATE(5, 5);
	table |= ICE_UP_TABLE_TRANSLATE(6, 6);
	table |= ICE_UP_TABLE_TRANSLATE(7, 7);
	ctx->info.ingress_table = CPU_TO_LE32(table);
	ctx->info.egress_table = CPU_TO_LE32(table);
	/* Have 1:1 UP mapping for outer to inner UP table */
	ctx->info.outer_up_table = CPU_TO_LE32(table);
	/* No Outer tag support, so outer_tag_flags remains zero */
}

/**
 * ice_set_rss_vsi_ctx - Setup VSI context parameters for RSS
 * @ctx: the VSI context to configure
 * @type: the VSI type
 *
 * Configures the VSI context for RSS, based on the VSI type.
 */
static void
ice_set_rss_vsi_ctx(struct ice_vsi_ctx *ctx, enum ice_vsi_type type)
{
	u8 lut_type, hash_type;

	switch (type) {
	case ICE_VSI_PF:
		lut_type = ICE_AQ_VSI_Q_OPT_RSS_LUT_PF;
		hash_type = ICE_AQ_VSI_Q_OPT_RSS_TPLZ;
		break;
	case ICE_VSI_VF:
		lut_type = ICE_AQ_VSI_Q_OPT_RSS_LUT_VSI;
		hash_type = ICE_AQ_VSI_Q_OPT_RSS_TPLZ;
		break;
	default:
		/* Other VSI types do not support RSS */
		return;
	}

	ctx->info.q_opt_rss = (((lut_type << ICE_AQ_VSI_Q_OPT_RSS_LUT_S) &
				 ICE_AQ_VSI_Q_OPT_RSS_LUT_M) |
				((hash_type << ICE_AQ_VSI_Q_OPT_RSS_HASH_S) &
				 ICE_AQ_VSI_Q_OPT_RSS_HASH_M));
}

/**
 * ice_setup_vsi_qmap - Setup the queue mapping for a VSI
 * @vsi: the VSI to configure
 * @ctx: the VSI context to configure
 *
 * Configures the context for the given VSI, setting up how the firmware
 * should map the queues for this VSI.
 */
static int
ice_setup_vsi_qmap(struct ice_vsi *vsi, struct ice_vsi_ctx *ctx)
{
	int pow = 0;
	u16 qmap;

	MPASS(vsi->rx_qmap != NULL);

	/* TODO:
	 * Handle multiple Traffic Classes
	 * Handle scattered queues (for VFs)
	 */
	if (vsi->qmap_type != ICE_RESMGR_ALLOC_CONTIGUOUS)
		return (EOPNOTSUPP);

	ctx->info.mapping_flags |= CPU_TO_LE16(ICE_AQ_VSI_Q_MAP_CONTIG);

	ctx->info.q_mapping[0] = CPU_TO_LE16(vsi->rx_qmap[0]);
	ctx->info.q_mapping[1] = CPU_TO_LE16(vsi->num_rx_queues);


	/* Calculate the next power-of-2 of number of queues */
	if (vsi->num_rx_queues)
		pow = flsl(vsi->num_rx_queues - 1);

	/* Assign all the queues to traffic class zero */
	qmap = (pow << ICE_AQ_VSI_TC_Q_NUM_S) & ICE_AQ_VSI_TC_Q_NUM_M;
	ctx->info.tc_mapping[0] = CPU_TO_LE16(qmap);

	return 0;
}

/**
 * ice_initialize_vsi - Initialize a VSI for use
 * @vsi: the vsi to initialize
 *
 * Initialize a VSI over the adminq and prepare it for operation.
 */
int
ice_initialize_vsi(struct ice_vsi *vsi)
{
	struct ice_vsi_ctx ctx = { 0 };
	struct ice_hw *hw = &vsi->sc->hw;
	u16 max_txqs[ICE_MAX_TRAFFIC_CLASS] = { 0 };
	enum ice_status status;
	int err;

	/* For now, we only have code supporting PF VSIs */
	switch (vsi->type) {
	case ICE_VSI_PF:
		ctx.flags = ICE_AQ_VSI_TYPE_PF;
		break;
	default:
		return (ENODEV);
	}

	ice_set_default_vsi_ctx(&ctx);
	ice_set_rss_vsi_ctx(&ctx, vsi->type);

	/* XXX: VSIs of other types may need different port info? */
	ctx.info.sw_id = hw->port_info->sw_id;

	/* Set some RSS parameters based on the VSI type */
	ice_vsi_set_rss_params(vsi);

	/* Initialize the Rx queue mapping for this VSI */
	err = ice_setup_vsi_qmap(vsi, &ctx);
	if (err) {
		return err;
	}

	/* (Re-)add VSI to HW VSI handle list */
	status = ice_add_vsi(hw, vsi->idx, &ctx, NULL);
	if (status != 0) {
		device_printf(vsi->sc->dev,
		    "Add VSI AQ call failed, err %s aq_err %s\n",
		    ice_status_str(status),
		    ice_aq_str(hw->adminq.sq_last_status));
		return (EIO);
	}
	vsi->info = ctx.info;

	/* TODO: DCB traffic class support? */
	max_txqs[0] = vsi->num_tx_queues;

	status = ice_cfg_vsi_lan(hw->port_info, vsi->idx,
			      ICE_DFLT_TRAFFIC_CLASS, max_txqs);
	if (status) {
		device_printf(vsi->sc->dev,
		    "Failed VSI lan queue config, err %s aq_err %s\n",
		    ice_status_str(status),
		    ice_aq_str(hw->adminq.sq_last_status));
		ice_deinit_vsi(vsi);
		return (ENODEV);
	}

	/* Reset VSI stats */
	ice_reset_vsi_stats(vsi);

	return 0;
}

/**
 * ice_deinit_vsi - Tell firmware to release resources for a VSI
 * @vsi: the VSI to release
 *
 * Helper function which requests the firmware to release the hardware
 * resources associated with a given VSI.
 */
void
ice_deinit_vsi(struct ice_vsi *vsi)
{
	struct ice_vsi_ctx ctx = { 0 };
	struct ice_softc *sc = vsi->sc;
	struct ice_hw *hw = &sc->hw;
	enum ice_status status;

	/* Assert that the VSI pointer matches in the list */
	MPASS(vsi == sc->all_vsi[vsi->idx]);

	ctx.info = vsi->info;

	status = ice_rm_vsi_lan_cfg(hw->port_info, vsi->idx);
	if (status) {
		/*
		 * This should only fail if the VSI handle is invalid, or if
		 * any of the nodes have leaf nodes which are still in use.
		 */
		device_printf(sc->dev,
			      "Unable to remove scheduler nodes for VSI %d, err %s\n",
			      vsi->idx, ice_status_str(status));
	}

	/* Tell firmware to release the VSI resources */
	status = ice_free_vsi(hw, vsi->idx, &ctx, false, NULL);
	if (status != 0) {
		device_printf(sc->dev,
		    "Free VSI %u AQ call failed, err %s aq_err %s\n",
		    vsi->idx, ice_status_str(status),
		    ice_aq_str(hw->adminq.sq_last_status));
	}
}

/**
 * ice_release_vsi - Release resources associated with a VSI
 * @vsi: the VSI to release
 *
 * Release software and firmware resources associated with a VSI. Release the
 * queue managers associated with this VSI. Also free the VSI structure memory
 * if the VSI was allocated dynamically using ice_alloc_vsi().
 */
void
ice_release_vsi(struct ice_vsi *vsi)
{
	struct ice_softc *sc = vsi->sc;
	int idx = vsi->idx;

	/* Assert that the VSI pointer matches in the list */
	MPASS(vsi == sc->all_vsi[idx]);

	/* Cleanup RSS configuration */
	if (ice_is_bit_set(sc->feat_en, ICE_FEATURE_RSS))
		ice_clean_vsi_rss_cfg(vsi);

	ice_del_vsi_sysctl_ctx(vsi);

	ice_deinit_vsi(vsi);

	ice_free_vsi_qmaps(vsi);

	if (vsi->dynamic) {
		free(sc->all_vsi[idx], M_ICE);
	}

	sc->all_vsi[idx] = NULL;
}

/**
 * ice_aq_speed_to_rate - Convert AdminQ speed enum to baudrate
 * @pi: port info data
 *
 * Returns the baudrate value for the current link speed of a given port.
 */
uint64_t
ice_aq_speed_to_rate(struct ice_port_info *pi)
{
	switch (pi->phy.link_info.link_speed) {
	case ICE_AQ_LINK_SPEED_100GB:
		return IF_Gbps(100);
	case ICE_AQ_LINK_SPEED_50GB:
		return IF_Gbps(50);
	case ICE_AQ_LINK_SPEED_40GB:
		return IF_Gbps(40);
	case ICE_AQ_LINK_SPEED_25GB:
		return IF_Gbps(25);
	case ICE_AQ_LINK_SPEED_10GB:
		return IF_Gbps(10);
	case ICE_AQ_LINK_SPEED_5GB:
		return IF_Gbps(5);
	case ICE_AQ_LINK_SPEED_2500MB:
		return IF_Mbps(2500);
	case ICE_AQ_LINK_SPEED_1000MB:
		return IF_Mbps(1000);
	case ICE_AQ_LINK_SPEED_100MB:
		return IF_Mbps(100);
	case ICE_AQ_LINK_SPEED_10MB:
		return IF_Mbps(10);
	case ICE_AQ_LINK_SPEED_UNKNOWN:
	default:
		/* return 0 if we don't know the link speed */
		return 0;
	}
}

/**
 * ice_aq_speed_to_str - Convert AdminQ speed enum to string representation
 * @pi: port info data
 *
 * Returns the string representation of the current link speed for a given
 * port.
 */
static const char *
ice_aq_speed_to_str(struct ice_port_info *pi)
{
	switch (pi->phy.link_info.link_speed) {
	case ICE_AQ_LINK_SPEED_100GB:
		return "100 Gbps";
	case ICE_AQ_LINK_SPEED_50GB:
		return "50 Gbps";
	case ICE_AQ_LINK_SPEED_40GB:
		return "40 Gbps";
	case ICE_AQ_LINK_SPEED_25GB:
		return "25 Gbps";
	case ICE_AQ_LINK_SPEED_20GB:
		return "20 Gbps";
	case ICE_AQ_LINK_SPEED_10GB:
		return "10 Gbps";
	case ICE_AQ_LINK_SPEED_5GB:
		return "5 Gbps";
	case ICE_AQ_LINK_SPEED_2500MB:
		return "2.5 Gbps";
	case ICE_AQ_LINK_SPEED_1000MB:
		return "1 Gbps";
	case ICE_AQ_LINK_SPEED_100MB:
		return "100 Mbps";
	case ICE_AQ_LINK_SPEED_10MB:
		return "10 Mbps";
	case ICE_AQ_LINK_SPEED_UNKNOWN:
	default:
		return "Unknown speed";
	}
}

/**
 * ice_get_phy_type_low - Get media associated with phy_type_low
 * @phy_type_low: the low 64bits of phy_type from the AdminQ
 *
 * Given the lower 64bits of the phy_type from the hardware, return the
 * ifm_active bit associated. Return IFM_UNKNOWN when phy_type_low is unknown.
 * Note that only one of ice_get_phy_type_low or ice_get_phy_type_high should
 * be called. If phy_type_low is zero, call ice_phy_type_high.
 */
int
ice_get_phy_type_low(uint64_t phy_type_low)
{
	switch (phy_type_low) {
	case ICE_PHY_TYPE_LOW_100BASE_TX:
		return IFM_100_TX;
	case ICE_PHY_TYPE_LOW_100M_SGMII:
		return IFM_100_SGMII;
	case ICE_PHY_TYPE_LOW_1000BASE_T:
		return IFM_1000_T;
	case ICE_PHY_TYPE_LOW_1000BASE_SX:
		return IFM_1000_SX;
	case ICE_PHY_TYPE_LOW_1000BASE_LX:
		return IFM_1000_LX;
	case ICE_PHY_TYPE_LOW_1000BASE_KX:
		return IFM_1000_KX;
	case ICE_PHY_TYPE_LOW_1G_SGMII:
		return IFM_1000_SGMII;
	case ICE_PHY_TYPE_LOW_2500BASE_T:
		return IFM_2500_T;
	case ICE_PHY_TYPE_LOW_2500BASE_X:
		return IFM_2500_X;
	case ICE_PHY_TYPE_LOW_2500BASE_KX:
		return IFM_2500_KX;
	case ICE_PHY_TYPE_LOW_5GBASE_T:
		return IFM_5000_T;
	case ICE_PHY_TYPE_LOW_5GBASE_KR:
		return IFM_5000_KR;
	case ICE_PHY_TYPE_LOW_10GBASE_T:
		return IFM_10G_T;
	case ICE_PHY_TYPE_LOW_10G_SFI_DA:
		return IFM_10G_TWINAX;
	case ICE_PHY_TYPE_LOW_10GBASE_SR:
		return IFM_10G_SR;
	case ICE_PHY_TYPE_LOW_10GBASE_LR:
		return IFM_10G_LR;
	case ICE_PHY_TYPE_LOW_10GBASE_KR_CR1:
		return IFM_10G_KR;
	case ICE_PHY_TYPE_LOW_10G_SFI_AOC_ACC:
		return IFM_10G_AOC;
	case ICE_PHY_TYPE_LOW_10G_SFI_C2C:
		return IFM_10G_SFI;
	case ICE_PHY_TYPE_LOW_25GBASE_T:
		return IFM_25G_T;
	case ICE_PHY_TYPE_LOW_25GBASE_CR:
		return IFM_25G_CR;
	case ICE_PHY_TYPE_LOW_25GBASE_CR_S:
		return IFM_25G_CR_S;
	case ICE_PHY_TYPE_LOW_25GBASE_CR1:
		return IFM_25G_CR1;
	case ICE_PHY_TYPE_LOW_25GBASE_SR:
		return IFM_25G_SR;
	case ICE_PHY_TYPE_LOW_25GBASE_LR:
		return IFM_25G_LR;
	case ICE_PHY_TYPE_LOW_25GBASE_KR:
		return IFM_25G_KR;
	case ICE_PHY_TYPE_LOW_25GBASE_KR_S:
		return IFM_25G_KR_S;
	case ICE_PHY_TYPE_LOW_25GBASE_KR1:
		return IFM_25G_KR1;
	case ICE_PHY_TYPE_LOW_25G_AUI_AOC_ACC:
		return IFM_25G_AOC;
	case ICE_PHY_TYPE_LOW_25G_AUI_C2C:
		return IFM_25G_AUI;
	case ICE_PHY_TYPE_LOW_40GBASE_CR4:
		return IFM_40G_CR4;
	case ICE_PHY_TYPE_LOW_40GBASE_SR4:
		return IFM_40G_SR4;
	case ICE_PHY_TYPE_LOW_40GBASE_LR4:
		return IFM_40G_LR4;
	case ICE_PHY_TYPE_LOW_40GBASE_KR4:
		return IFM_40G_KR4;
	case ICE_PHY_TYPE_LOW_40G_XLAUI_AOC_ACC:
		return IFM_40G_XLAUI_AC;
	case ICE_PHY_TYPE_LOW_40G_XLAUI:
		return IFM_40G_XLAUI;
	case ICE_PHY_TYPE_LOW_50GBASE_CR2:
		return IFM_50G_CR2;
	case ICE_PHY_TYPE_LOW_50GBASE_SR2:
		return IFM_50G_SR2;
	case ICE_PHY_TYPE_LOW_50GBASE_LR2:
		return IFM_50G_LR2;
	case ICE_PHY_TYPE_LOW_50GBASE_KR2:
		return IFM_50G_KR2;
	case ICE_PHY_TYPE_LOW_50G_LAUI2_AOC_ACC:
		return IFM_50G_LAUI2_AC;
	case ICE_PHY_TYPE_LOW_50G_LAUI2:
		return IFM_50G_LAUI2;
	case ICE_PHY_TYPE_LOW_50G_AUI2_AOC_ACC:
		return IFM_50G_AUI2_AC;
	case ICE_PHY_TYPE_LOW_50G_AUI2:
		return IFM_50G_AUI2;
	case ICE_PHY_TYPE_LOW_50GBASE_CP:
		return IFM_50G_CP;
	case ICE_PHY_TYPE_LOW_50GBASE_SR:
		return IFM_50G_SR;
	case ICE_PHY_TYPE_LOW_50GBASE_FR:
		return IFM_50G_FR;
	case ICE_PHY_TYPE_LOW_50GBASE_LR:
		return IFM_50G_LR;
	case ICE_PHY_TYPE_LOW_50GBASE_KR_PAM4:
		return IFM_50G_KR_PAM4;
	case ICE_PHY_TYPE_LOW_50G_AUI1_AOC_ACC:
		return IFM_50G_AUI1_AC;
	case ICE_PHY_TYPE_LOW_50G_AUI1:
		return IFM_50G_AUI1;
	case ICE_PHY_TYPE_LOW_100GBASE_CR4:
		return IFM_100G_CR4;
	case ICE_PHY_TYPE_LOW_100GBASE_SR4:
		return IFM_100G_SR4;
	case ICE_PHY_TYPE_LOW_100GBASE_LR4:
		return IFM_100G_LR4;
	case ICE_PHY_TYPE_LOW_100GBASE_KR4:
		return IFM_100G_KR4;
	case ICE_PHY_TYPE_LOW_100G_CAUI4_AOC_ACC:
		return IFM_100G_CAUI4_AC;
	case ICE_PHY_TYPE_LOW_100G_CAUI4:
		return IFM_100G_CAUI4;
	case ICE_PHY_TYPE_LOW_100G_AUI4_AOC_ACC:
		return IFM_100G_AUI4_AC;
	case ICE_PHY_TYPE_LOW_100G_AUI4:
		return IFM_100G_AUI4;
	case ICE_PHY_TYPE_LOW_100GBASE_CR_PAM4:
		return IFM_100G_CR_PAM4;
	case ICE_PHY_TYPE_LOW_100GBASE_KR_PAM4:
		return IFM_100G_KR_PAM4;
	case ICE_PHY_TYPE_LOW_100GBASE_CP2:
		return IFM_100G_CP2;
	case ICE_PHY_TYPE_LOW_100GBASE_SR2:
		return IFM_100G_SR2;
	case ICE_PHY_TYPE_LOW_100GBASE_DR:
		return IFM_100G_DR;
	default:
		return IFM_UNKNOWN;
	}
}

/**
 * ice_get_phy_type_high - Get media associated with phy_type_high
 * @phy_type_high: the upper 64bits of phy_type from the AdminQ
 *
 * Given the upper 64bits of the phy_type from the hardware, return the
 * ifm_active bit associated. Return IFM_UNKNOWN on an unknown value. Note
 * that only one of ice_get_phy_type_low or ice_get_phy_type_high should be
 * called. If phy_type_high is zero, call ice_get_phy_type_low.
 */
int
ice_get_phy_type_high(uint64_t phy_type_high)
{
	switch (phy_type_high) {
	case ICE_PHY_TYPE_HIGH_100GBASE_KR2_PAM4:
		return IFM_100G_KR2_PAM4;
	case ICE_PHY_TYPE_HIGH_100G_CAUI2_AOC_ACC:
		return IFM_100G_CAUI2_AC;
	case ICE_PHY_TYPE_HIGH_100G_CAUI2:
		return IFM_100G_CAUI2;
	case ICE_PHY_TYPE_HIGH_100G_AUI2_AOC_ACC:
		return IFM_100G_AUI2_AC;
	case ICE_PHY_TYPE_HIGH_100G_AUI2:
		return IFM_100G_AUI2;
	default:
		return IFM_UNKNOWN;
	}
}

/**
 * ice_phy_types_to_max_rate - Returns port's max supported baudrate
 * @pi: port info struct
 *
 * ice_aq_get_phy_caps() w/ ICE_AQC_REPORT_TOPO_CAP parameter needs to have
 * been called before this function for it to work.
 */
static uint64_t
ice_phy_types_to_max_rate(struct ice_port_info *pi)
{
	uint64_t phy_low = pi->phy.phy_type_low;
	uint64_t phy_high = pi->phy.phy_type_high;
	uint64_t max_rate = 0;
	int bit;

	/*
	 * These are based on the indices used in the BIT() macros for
	 * ICE_PHY_TYPE_LOW_*
	 */
	static const uint64_t phy_rates[] = {
	    IF_Mbps(100),
	    IF_Mbps(100),
	    IF_Gbps(1ULL),
	    IF_Gbps(1ULL),
	    IF_Gbps(1ULL),
	    IF_Gbps(1ULL),
	    IF_Gbps(1ULL),
	    IF_Mbps(2500ULL),
	    IF_Mbps(2500ULL),
	    IF_Mbps(2500ULL),
	    IF_Gbps(5ULL),
	    IF_Gbps(5ULL),
	    IF_Gbps(10ULL),
	    IF_Gbps(10ULL),
	    IF_Gbps(10ULL),
	    IF_Gbps(10ULL),
	    IF_Gbps(10ULL),
	    IF_Gbps(10ULL),
	    IF_Gbps(10ULL),
	    IF_Gbps(25ULL),
	    IF_Gbps(25ULL),
	    IF_Gbps(25ULL),
	    IF_Gbps(25ULL),
	    IF_Gbps(25ULL),
	    IF_Gbps(25ULL),
	    IF_Gbps(25ULL),
	    IF_Gbps(25ULL),
	    IF_Gbps(25ULL),
	    IF_Gbps(25ULL),
	    IF_Gbps(25ULL),
	    IF_Gbps(40ULL),
	    IF_Gbps(40ULL),
	    IF_Gbps(40ULL),
	    IF_Gbps(40ULL),
	    IF_Gbps(40ULL),
	    IF_Gbps(40ULL),
	    IF_Gbps(50ULL),
	    IF_Gbps(50ULL),
	    IF_Gbps(50ULL),
	    IF_Gbps(50ULL),
	    IF_Gbps(50ULL),
	    IF_Gbps(50ULL),
	    IF_Gbps(50ULL),
	    IF_Gbps(50ULL),
	    IF_Gbps(50ULL),
	    IF_Gbps(50ULL),
	    IF_Gbps(50ULL),
	    IF_Gbps(50ULL),
	    IF_Gbps(50ULL),
	    IF_Gbps(50ULL),
	    IF_Gbps(50ULL),
	    IF_Gbps(100ULL),
	    IF_Gbps(100ULL),
	    IF_Gbps(100ULL),
	    IF_Gbps(100ULL),
	    IF_Gbps(100ULL),
	    IF_Gbps(100ULL),
	    IF_Gbps(100ULL),
	    IF_Gbps(100ULL),
	    IF_Gbps(100ULL),
	    IF_Gbps(100ULL),
	    IF_Gbps(100ULL),
	    IF_Gbps(100ULL),
	    IF_Gbps(100ULL),
	    /* These rates are for ICE_PHY_TYPE_HIGH_* */
	    IF_Gbps(100ULL),
	    IF_Gbps(100ULL),
	    IF_Gbps(100ULL),
	    IF_Gbps(100ULL),
	    IF_Gbps(100ULL)
	};

	/* coverity[address_of] */
	for_each_set_bit(bit, &phy_high, 64)
		if ((bit + 64) < (int)ARRAY_SIZE(phy_rates))
			max_rate = uqmax(max_rate, phy_rates[(bit + 64)]);

	/* coverity[address_of] */
	for_each_set_bit(bit, &phy_low, 64)
		max_rate = uqmax(max_rate, phy_rates[bit]);

	return (max_rate);
}

/* The if_media type is split over the original 5 bit media variant field,
 * along with extended types using up extra bits in the options section.
 * We want to convert this split number into a bitmap index, so we reverse the
 * calculation of IFM_X here.
 */
#define IFM_IDX(x) (((x) & IFM_TMASK) | \
		    (((x) & IFM_ETH_XTYPE) >> IFM_ETH_XSHIFT))

/**
 * ice_add_media_types - Add supported media types to the media structure
 * @sc: ice private softc structure
 * @media: ifmedia structure to setup
 *
 * Looks up the supported phy types, and initializes the various media types
 * available.
 *
 * @pre this function must be protected from being called while another thread
 * is accessing the ifmedia types.
 */
enum ice_status
ice_add_media_types(struct ice_softc *sc, struct ifmedia *media)
{
	enum ice_status status;
	uint64_t phy_low, phy_high;
	int bit;

	ASSERT_CFG_LOCKED(sc);

	/* the maximum possible media type index is 511. We probably don't
	 * need most of this space, but this ensures future compatibility when
	 * additional media types are used.
	 */
	ice_declare_bitmap(already_added, 511);

	/* Remove all previous media types */
	ifmedia_removeall(media);

	status = ice_get_phy_types(sc, &phy_low, &phy_high);
	if (status != ICE_SUCCESS) {
		/* Function already prints appropriate error
		 * message
		 */
		return (status);
	}

	/* make sure the added bitmap is zero'd */
	memset(already_added, 0, sizeof(already_added));

	/* coverity[address_of] */
	for_each_set_bit(bit, &phy_low, 64) {
		uint64_t type = BIT_ULL(bit);
		int ostype;

		/* get the OS media type */
		ostype = ice_get_phy_type_low(type);

		/* don't bother adding the unknown type */
		if (ostype == IFM_UNKNOWN)
			continue;

		/* only add each media type to the list once */
		if (ice_is_bit_set(already_added, IFM_IDX(ostype)))
			continue;

		ifmedia_add(media, IFM_ETHER | ostype, 0, NULL);
		ice_set_bit(IFM_IDX(ostype), already_added);
	}

	/* coverity[address_of] */
	for_each_set_bit(bit, &phy_high, 64) {
		uint64_t type = BIT_ULL(bit);
		int ostype;

		/* get the OS media type */
		ostype = ice_get_phy_type_high(type);

		/* don't bother adding the unknown type */
		if (ostype == IFM_UNKNOWN)
			continue;

		/* only add each media type to the list once */
		if (ice_is_bit_set(already_added, IFM_IDX(ostype)))
			continue;

		ifmedia_add(media, IFM_ETHER | ostype, 0, NULL);
		ice_set_bit(IFM_IDX(ostype), already_added);
	}

	/* Use autoselect media by default */
	ifmedia_add(media, IFM_ETHER | IFM_AUTO, 0, NULL);
	ifmedia_set(media, IFM_ETHER | IFM_AUTO);

	return (ICE_SUCCESS);
}

/**
 * ice_configure_rxq_interrupts - Configure HW Rx queues for MSI-X interrupts
 * @vsi: the VSI to configure
 *
 * Called when setting up MSI-X interrupts to configure the Rx hardware queues.
 */
void
ice_configure_rxq_interrupts(struct ice_vsi *vsi)
{
	struct ice_hw *hw = &vsi->sc->hw;
	int i;

	for (i = 0; i < vsi->num_rx_queues; i++) {
		struct ice_rx_queue *rxq = &vsi->rx_queues[i];
		u32 val;

		val = (QINT_RQCTL_CAUSE_ENA_M |
		       (ICE_RX_ITR << QINT_RQCTL_ITR_INDX_S) |
		       (rxq->irqv->me << QINT_RQCTL_MSIX_INDX_S));
		wr32(hw, QINT_RQCTL(vsi->rx_qmap[rxq->me]), val);
	}

	ice_flush(hw);
}

/**
 * ice_configure_txq_interrupts - Configure HW Tx queues for MSI-X interrupts
 * @vsi: the VSI to configure
 *
 * Called when setting up MSI-X interrupts to configure the Tx hardware queues.
 */
void
ice_configure_txq_interrupts(struct ice_vsi *vsi)
{
	struct ice_hw *hw = &vsi->sc->hw;
	int i;

	for (i = 0; i < vsi->num_tx_queues; i++) {
		struct ice_tx_queue *txq = &vsi->tx_queues[i];
		u32 val;

		val = (QINT_TQCTL_CAUSE_ENA_M |
		       (ICE_TX_ITR << QINT_TQCTL_ITR_INDX_S) |
		       (txq->irqv->me << QINT_TQCTL_MSIX_INDX_S));
		wr32(hw, QINT_TQCTL(vsi->tx_qmap[txq->me]), val);
	}

	ice_flush(hw);
}

/**
 * ice_flush_rxq_interrupts - Unconfigure Hw Rx queues MSI-X interrupt cause
 * @vsi: the VSI to configure
 *
 * Unset the CAUSE_ENA flag of the TQCTL register for each queue, then trigger
 * a software interrupt on that cause. This is required as part of the Rx
 * queue disable logic to dissociate the Rx queue from the interrupt.
 *
 * Note: this function must be called prior to disabling Rx queues with
 * ice_control_rx_queues, otherwise the Rx queue may not be disabled properly.
 */
void
ice_flush_rxq_interrupts(struct ice_vsi *vsi)
{
	struct ice_hw *hw = &vsi->sc->hw;
	int i;

	for (i = 0; i < vsi->num_rx_queues; i++) {
		struct ice_rx_queue *rxq = &vsi->rx_queues[i];
		u32 reg, val;

		/* Clear the CAUSE_ENA flag */
		reg = vsi->rx_qmap[rxq->me];
		val = rd32(hw, QINT_RQCTL(reg));
		val &= ~QINT_RQCTL_CAUSE_ENA_M;
		wr32(hw, QINT_RQCTL(reg), val);

		ice_flush(hw);

		/* Trigger a software interrupt to complete interrupt
		 * dissociation.
		 */
		wr32(hw, GLINT_DYN_CTL(rxq->irqv->me),
		     GLINT_DYN_CTL_SWINT_TRIG_M | GLINT_DYN_CTL_INTENA_MSK_M);
	}
}

/**
 * ice_flush_txq_interrupts - Unconfigure Hw Tx queues MSI-X interrupt cause
 * @vsi: the VSI to configure
 *
 * Unset the CAUSE_ENA flag of the TQCTL register for each queue, then trigger
 * a software interrupt on that cause. This is required as part of the Tx
 * queue disable logic to dissociate the Tx queue from the interrupt.
 *
 * Note: this function must be called prior to ice_vsi_disable_tx, otherwise
 * the Tx queue disable may not complete properly.
 */
void
ice_flush_txq_interrupts(struct ice_vsi *vsi)
{
	struct ice_hw *hw = &vsi->sc->hw;
	int i;

	for (i = 0; i < vsi->num_tx_queues; i++) {
		struct ice_tx_queue *txq = &vsi->tx_queues[i];
		u32 reg, val;

		/* Clear the CAUSE_ENA flag */
		reg = vsi->tx_qmap[txq->me];
		val = rd32(hw, QINT_TQCTL(reg));
		val &= ~QINT_TQCTL_CAUSE_ENA_M;
		wr32(hw, QINT_TQCTL(reg), val);

		ice_flush(hw);

		/* Trigger a software interrupt to complete interrupt
		 * dissociation.
		 */
		wr32(hw, GLINT_DYN_CTL(txq->irqv->me),
		     GLINT_DYN_CTL_SWINT_TRIG_M | GLINT_DYN_CTL_INTENA_MSK_M);
	}
}

/**
 * ice_configure_rx_itr - Configure the Rx ITR settings for this VSI
 * @vsi: the VSI to configure
 *
 * Program the hardware ITR registers with the settings for this VSI.
 */
void
ice_configure_rx_itr(struct ice_vsi *vsi)
{
	struct ice_hw *hw = &vsi->sc->hw;
	int i;

	/* TODO: Handle per-queue/per-vector ITR? */

	for (i = 0; i < vsi->num_rx_queues; i++) {
		struct ice_rx_queue *rxq = &vsi->rx_queues[i];

		wr32(hw, GLINT_ITR(ICE_RX_ITR, rxq->irqv->me),
		     ice_itr_to_reg(hw, vsi->rx_itr));
	}

	ice_flush(hw);
}

/**
 * ice_configure_tx_itr - Configure the Tx ITR settings for this VSI
 * @vsi: the VSI to configure
 *
 * Program the hardware ITR registers with the settings for this VSI.
 */
void
ice_configure_tx_itr(struct ice_vsi *vsi)
{
	struct ice_hw *hw = &vsi->sc->hw;
	int i;

	/* TODO: Handle per-queue/per-vector ITR? */

	for (i = 0; i < vsi->num_tx_queues; i++) {
		struct ice_tx_queue *txq = &vsi->tx_queues[i];

		wr32(hw, GLINT_ITR(ICE_TX_ITR, txq->irqv->me),
		     ice_itr_to_reg(hw, vsi->tx_itr));
	}

	ice_flush(hw);
}

/**
 * ice_setup_tx_ctx - Setup an ice_tlan_ctx structure for a queue
 * @txq: the Tx queue to configure
 * @tlan_ctx: the Tx LAN queue context structure to initialize
 * @pf_q: real queue number
 */
static int
ice_setup_tx_ctx(struct ice_tx_queue *txq, struct ice_tlan_ctx *tlan_ctx, u16 pf_q)
{
	struct ice_vsi *vsi = txq->vsi;
	struct ice_softc *sc = vsi->sc;
	struct ice_hw *hw = &sc->hw;

	tlan_ctx->port_num = hw->port_info->lport;

	/* number of descriptors in the queue */
	tlan_ctx->qlen = txq->desc_count;

	/* set the transmit queue base address, defined in 128 byte units */
	tlan_ctx->base = txq->tx_paddr >> 7;

	tlan_ctx->pf_num = hw->pf_id;

	/* For now, we only have code supporting PF VSIs */
	switch (vsi->type) {
	case ICE_VSI_PF:
		tlan_ctx->vmvf_type = ICE_TLAN_CTX_VMVF_TYPE_PF;
		break;
	default:
		return (ENODEV);
	}

	tlan_ctx->src_vsi = ice_get_hw_vsi_num(hw, vsi->idx);

	/* Enable TSO */
	tlan_ctx->tso_ena = 1;
	tlan_ctx->internal_usage_flag = 1;

	tlan_ctx->tso_qnum = pf_q;

	/*
	 * Stick with the older legacy Tx queue interface, instead of the new
	 * advanced queue interface.
	 */
	tlan_ctx->legacy_int = 1;

	/* Descriptor WB mode */
	tlan_ctx->wb_mode = 0;

	return (0);
}

/**
 * ice_cfg_vsi_for_tx - Configure the hardware for Tx
 * @vsi: the VSI to configure
 *
 * Configure the device Tx queues through firmware AdminQ commands. After
 * this, Tx queues will be ready for transmit.
 */
int
ice_cfg_vsi_for_tx(struct ice_vsi *vsi)
{
	struct ice_aqc_add_tx_qgrp qg = { 0 };
	struct ice_hw *hw = &vsi->sc->hw;
	device_t dev = vsi->sc->dev;
	enum ice_status status;
	int i, err;
	u16 pf_q;

	qg.num_txqs = 1;

	for (i = 0; i < vsi->num_tx_queues; i++) {
		struct ice_tlan_ctx tlan_ctx = { 0 };
		struct ice_tx_queue *txq = &vsi->tx_queues[i];

		pf_q = vsi->tx_qmap[txq->me];
		qg.txqs[0].txq_id = htole16(pf_q);

		err = ice_setup_tx_ctx(txq, &tlan_ctx, pf_q);
		if (err)
			return err;

		ice_set_ctx((u8 *)&tlan_ctx, qg.txqs[0].txq_ctx,
			    ice_tlan_ctx_info);

		status = ice_ena_vsi_txq(hw->port_info, vsi->idx, 0,
					 i, 1, &qg, sizeof(qg), NULL);
		if (status) {
			device_printf(dev,
				      "Failed to set LAN Tx queue context, err %s aq_err %s\n",
				      ice_status_str(status), ice_aq_str(hw->adminq.sq_last_status));
			return (ENODEV);
		}

		/* Keep track of the Tx queue TEID */
		if (pf_q == le16toh(qg.txqs[0].txq_id))
			txq->q_teid = le32toh(qg.txqs[0].q_teid);
	}

	return (0);
}

/**
 * ice_setup_rx_ctx - Setup an Rx context structure for a receive queue
 * @rxq: the receive queue to program
 *
 * Setup an Rx queue context structure and program it into the hardware
 * registers. This is a necessary step for enabling the Rx queue.
 *
 * @pre the VSI associated with this queue must have initialized mbuf_sz
 */
static int
ice_setup_rx_ctx(struct ice_rx_queue *rxq)
{
	struct ice_rlan_ctx rlan_ctx = {0};
	struct ice_vsi *vsi = rxq->vsi;
	struct ice_softc *sc = vsi->sc;
	struct ice_hw *hw = &sc->hw;
	enum ice_status status;
	u32 rxdid = ICE_RXDID_FLEX_NIC;
	u32 regval;
	u16 pf_q;

	pf_q = vsi->rx_qmap[rxq->me];

	/* set the receive queue base address, defined in 128 byte units */
	rlan_ctx.base = rxq->rx_paddr >> 7;

	rlan_ctx.qlen = rxq->desc_count;

	rlan_ctx.dbuf = vsi->mbuf_sz >> ICE_RLAN_CTX_DBUF_S;

	/* use 32 byte descriptors */
	rlan_ctx.dsize = 1;

	/* Strip the Ethernet CRC bytes before the packet is posted to the
	 * host memory.
	 */
	rlan_ctx.crcstrip = 1;

	rlan_ctx.l2tsel = 1;

	/* don't do header splitting */
	rlan_ctx.dtype = ICE_RX_DTYPE_NO_SPLIT;
	rlan_ctx.hsplit_0 = ICE_RLAN_RX_HSPLIT_0_NO_SPLIT;
	rlan_ctx.hsplit_1 = ICE_RLAN_RX_HSPLIT_1_NO_SPLIT;

	/* strip VLAN from inner headers */
	rlan_ctx.showiv = 1;

	rlan_ctx.rxmax = min(vsi->max_frame_size,
			     ICE_MAX_RX_SEGS * vsi->mbuf_sz);

	rlan_ctx.lrxqthresh = 1;

	if (vsi->type != ICE_VSI_VF) {
		regval = rd32(hw, QRXFLXP_CNTXT(pf_q));
		regval &= ~QRXFLXP_CNTXT_RXDID_IDX_M;
		regval |= (rxdid << QRXFLXP_CNTXT_RXDID_IDX_S) &
			QRXFLXP_CNTXT_RXDID_IDX_M;

		regval &= ~QRXFLXP_CNTXT_RXDID_PRIO_M;
		regval |= (0x03 << QRXFLXP_CNTXT_RXDID_PRIO_S) &
			QRXFLXP_CNTXT_RXDID_PRIO_M;

		wr32(hw, QRXFLXP_CNTXT(pf_q), regval);
	}

	status = ice_write_rxq_ctx(hw, &rlan_ctx, pf_q);
	if (status) {
		device_printf(sc->dev,
			      "Failed to set LAN Rx queue context, err %s aq_err %s\n",
			      ice_status_str(status), ice_aq_str(hw->adminq.sq_last_status));
		return (EIO);
	}

	wr32(hw, rxq->tail, 0);

	return 0;
}

/**
 * ice_cfg_vsi_for_rx - Configure the hardware for Rx
 * @vsi: the VSI to configure
 *
 * Prepare an Rx context descriptor and configure the device to receive
 * traffic.
 *
 * @pre the VSI must have initialized mbuf_sz
 */
int
ice_cfg_vsi_for_rx(struct ice_vsi *vsi)
{
	int i, err;

	for (i = 0; i < vsi->num_rx_queues; i++) {
		MPASS(vsi->mbuf_sz > 0);
		err = ice_setup_rx_ctx(&vsi->rx_queues[i]);
		if (err)
			return err;
	}

	return (0);
}

/**
 * ice_is_rxq_ready - Check if an Rx queue is ready
 * @hw: ice hw structure
 * @pf_q: absolute PF queue index to check
 * @reg: on successful return, contains qrx_ctrl contents
 *
 * Reads the QRX_CTRL register and verifies if the queue is in a consistent
 * state. That is, QENA_REQ matches QENA_STAT. Used to check before making
 * a request to change the queue, as well as to verify the request has
 * finished. The queue should change status within a few microseconds, so we
 * use a small delay while polling the register.
 *
 * Returns an error code if the queue does not update after a few retries.
 */
static int
ice_is_rxq_ready(struct ice_hw *hw, int pf_q, u32 *reg)
{
	u32 qrx_ctrl, qena_req, qena_stat;
	int i;

	for (i = 0; i < ICE_Q_WAIT_RETRY_LIMIT; i++) {
		qrx_ctrl = rd32(hw, QRX_CTRL(pf_q));
		qena_req = (qrx_ctrl >> QRX_CTRL_QENA_REQ_S) & 1;
		qena_stat = (qrx_ctrl >> QRX_CTRL_QENA_STAT_S) & 1;

		/* if the request and status bits equal, then the queue is
		 * fully disabled or enabled.
		 */
		if (qena_req == qena_stat) {
			*reg = qrx_ctrl;
			return (0);
		}

		/* wait a few microseconds before we check again */
		DELAY(10);
	}

	return (ETIMEDOUT);
}

/**
 * ice_control_rx_queues - Configure hardware to start or stop the Rx queues
 * @vsi: VSI to enable/disable queues
 * @enable: true to enable queues, false to disable
 *
 * Control the Rx queues through the QRX_CTRL register, enabling or disabling
 * them. Wait for the appropriate time to ensure that the queues have actually
 * reached the expected state.
 */
int
ice_control_rx_queues(struct ice_vsi *vsi, bool enable)
{
	struct ice_hw *hw = &vsi->sc->hw;
	device_t dev = vsi->sc->dev;
	u32 qrx_ctrl = 0;
	int i, err;

	/* TODO: amortize waits by changing all queues up front and then
	 * checking their status afterwards. This will become more necessary
	 * when we have a large number of queues.
	 */
	for (i = 0; i < vsi->num_rx_queues; i++) {
		struct ice_rx_queue *rxq = &vsi->rx_queues[i];
		int pf_q = vsi->rx_qmap[rxq->me];

		err = ice_is_rxq_ready(hw, pf_q, &qrx_ctrl);
		if (err) {
			device_printf(dev,
				      "Rx queue %d is not ready\n",
				      pf_q);
			return err;
		}

		/* Skip if the queue is already in correct state */
		if (enable == !!(qrx_ctrl & QRX_CTRL_QENA_STAT_M))
			continue;

		if (enable)
			qrx_ctrl |= QRX_CTRL_QENA_REQ_M;
		else
			qrx_ctrl &= ~QRX_CTRL_QENA_REQ_M;
		wr32(hw, QRX_CTRL(pf_q), qrx_ctrl);

		/* wait for the queue to finalize the request */
		err = ice_is_rxq_ready(hw, pf_q, &qrx_ctrl);
		if (err) {
			device_printf(dev,
				      "Rx queue %d %sable timeout\n",
				      pf_q, (enable ? "en" : "dis"));
			return err;
		}

		/* this should never happen */
		if (enable != !!(qrx_ctrl & QRX_CTRL_QENA_STAT_M)) {
			device_printf(dev,
				      "Rx queue %d invalid state\n",
				      pf_q);
			return (EDOOFUS);
		}
	}

	return (0);
}

/**
 * ice_add_mac_to_list - Add MAC filter to a MAC filter list
 * @vsi: the VSI to forward to
 * @list: list which contains MAC filter entries
 * @addr: the MAC address to be added
 * @action: filter action to perform on match
 *
 * Adds a MAC address filter to the list which will be forwarded to firmware
 * to add a series of MAC address filters.
 *
 * Returns 0 on success, and an error code on failure.
 *
 */
static int
ice_add_mac_to_list(struct ice_vsi *vsi, struct ice_list_head *list,
		    const u8 *addr, enum ice_sw_fwd_act_type action)
{
	struct ice_fltr_list_entry *entry;

	entry = (__typeof(entry))malloc(sizeof(*entry), M_ICE, M_NOWAIT|M_ZERO);
	if (!entry)
		return (ENOMEM);

	entry->fltr_info.flag = ICE_FLTR_TX;
	entry->fltr_info.src_id = ICE_SRC_ID_VSI;
	entry->fltr_info.lkup_type = ICE_SW_LKUP_MAC;
	entry->fltr_info.fltr_act = action;
	entry->fltr_info.vsi_handle = vsi->idx;
	bcopy(addr, entry->fltr_info.l_data.mac.mac_addr, ETHER_ADDR_LEN);

	LIST_ADD(&entry->list_entry, list);

	return 0;
}

/**
 * ice_free_fltr_list - Free memory associated with a MAC address list
 * @list: the list to free
 *
 * Free the memory of each entry associated with the list.
 */
static void
ice_free_fltr_list(struct ice_list_head *list)
{
	struct ice_fltr_list_entry *e, *tmp;

	LIST_FOR_EACH_ENTRY_SAFE(e, tmp, list, ice_fltr_list_entry, list_entry) {
		LIST_DEL(&e->list_entry);
		free(e, M_ICE);
	}
}

/**
 * ice_add_vsi_mac_filter - Add a MAC address filter for a VSI
 * @vsi: the VSI to add the filter for
 * @addr: MAC address to add a filter for
 *
 * Add a MAC address filter for a given VSI. This is a wrapper around
 * ice_add_mac to simplify the interface. First, it only accepts a single
 * address, so we don't have to mess around with the list setup in other
 * functions. Second, it ignores the ICE_ERR_ALREADY_EXIST error, so that
 * callers don't need to worry about attempting to add the same filter twice.
 */
int
ice_add_vsi_mac_filter(struct ice_vsi *vsi, const u8 *addr)
{
	struct ice_list_head mac_addr_list;
	struct ice_hw *hw = &vsi->sc->hw;
	device_t dev = vsi->sc->dev;
	enum ice_status status;
	int err = 0;

	INIT_LIST_HEAD(&mac_addr_list);

	err = ice_add_mac_to_list(vsi, &mac_addr_list, addr, ICE_FWD_TO_VSI);
	if (err)
		goto free_mac_list;

	status = ice_add_mac(hw, &mac_addr_list);
	if (status == ICE_ERR_ALREADY_EXISTS) {
		; /* Don't complain if we try to add a filter that already exists */
	} else if (status) {
		device_printf(dev,
			      "Failed to add a filter for MAC %6D, err %s aq_err %s\n",
			      addr, ":",
			      ice_status_str(status),
			      ice_aq_str(hw->adminq.sq_last_status));
		err = (EIO);
	}

free_mac_list:
	ice_free_fltr_list(&mac_addr_list);
	return err;
}

/**
 * ice_cfg_pf_default_mac_filters - Setup default unicast and broadcast addrs
 * @sc: device softc structure
 *
 * Program the default unicast and broadcast filters for the PF VSI.
 */
int
ice_cfg_pf_default_mac_filters(struct ice_softc *sc)
{
	struct ice_vsi *vsi = &sc->pf_vsi;
	struct ice_hw *hw = &sc->hw;
	int err;

	/* Add the LAN MAC address */
	err = ice_add_vsi_mac_filter(vsi, hw->port_info->mac.lan_addr);
	if (err)
		return err;

	/* Add the broadcast address */
	err = ice_add_vsi_mac_filter(vsi, broadcastaddr);
	if (err)
		return err;

	return (0);
}

/**
 * ice_remove_vsi_mac_filter - Remove a MAC address filter for a VSI
 * @vsi: the VSI to add the filter for
 * @addr: MAC address to remove a filter for
 *
 * Remove a MAC address filter from a given VSI. This is a wrapper around
 * ice_remove_mac to simplify the interface. First, it only accepts a single
 * address, so we don't have to mess around with the list setup in other
 * functions. Second, it ignores the ICE_ERR_DOES_NOT_EXIST error, so that
 * callers don't need to worry about attempting to remove filters which
 * haven't yet been added.
 */
int
ice_remove_vsi_mac_filter(struct ice_vsi *vsi, const u8 *addr)
{
	struct ice_list_head mac_addr_list;
	struct ice_hw *hw = &vsi->sc->hw;
	device_t dev = vsi->sc->dev;
	enum ice_status status;
	int err = 0;

	INIT_LIST_HEAD(&mac_addr_list);

	err = ice_add_mac_to_list(vsi, &mac_addr_list, addr, ICE_FWD_TO_VSI);
	if (err)
		goto free_mac_list;

	status = ice_remove_mac(hw, &mac_addr_list);
	if (status == ICE_ERR_DOES_NOT_EXIST) {
		; /* Don't complain if we try to remove a filter that doesn't exist */
	} else if (status) {
		device_printf(dev,
			      "Failed to remove a filter for MAC %6D, err %s aq_err %s\n",
			      addr, ":",
			      ice_status_str(status),
			      ice_aq_str(hw->adminq.sq_last_status));
		err = (EIO);
	}

free_mac_list:
	ice_free_fltr_list(&mac_addr_list);
	return err;
}

/**
 * ice_rm_pf_default_mac_filters - Remove default unicast and broadcast addrs
 * @sc: device softc structure
 *
 * Remove the default unicast and broadcast filters from the PF VSI.
 */
int
ice_rm_pf_default_mac_filters(struct ice_softc *sc)
{
	struct ice_vsi *vsi = &sc->pf_vsi;
	struct ice_hw *hw = &sc->hw;
	int err;

	/* Remove the LAN MAC address */
	err = ice_remove_vsi_mac_filter(vsi, hw->port_info->mac.lan_addr);
	if (err)
		return err;

	/* Remove the broadcast address */
	err = ice_remove_vsi_mac_filter(vsi, broadcastaddr);
	if (err)
		return (EIO);

	return (0);
}

/**
 * ice_check_ctrlq_errors - Check for and report controlq errors
 * @sc: device private structure
 * @qname: name of the controlq
 * @cq: the controlq to check
 *
 * Check and report controlq errors. Currently all we do is report them to the
 * kernel message log, but we might want to improve this in the future, such
 * as to keep track of statistics.
 */
static void
ice_check_ctrlq_errors(struct ice_softc *sc, const char *qname,
		       struct ice_ctl_q_info *cq)
{
	struct ice_hw *hw = &sc->hw;
	u32 val;

	/* Check for error indications. Note that all the controlqs use the
	 * same register layout, so we use the PF_FW_AxQLEN defines only.
	 */
	val = rd32(hw, cq->rq.len);
	if (val & (PF_FW_ARQLEN_ARQVFE_M | PF_FW_ARQLEN_ARQOVFL_M |
		   PF_FW_ARQLEN_ARQCRIT_M)) {
		if (val & PF_FW_ARQLEN_ARQVFE_M)
			device_printf(sc->dev,
				"%s Receive Queue VF Error detected\n", qname);
		if (val & PF_FW_ARQLEN_ARQOVFL_M)
			device_printf(sc->dev,
				"%s Receive Queue Overflow Error detected\n",
				qname);
		if (val & PF_FW_ARQLEN_ARQCRIT_M)
			device_printf(sc->dev,
				"%s Receive Queue Critical Error detected\n",
				qname);
		val &= ~(PF_FW_ARQLEN_ARQVFE_M | PF_FW_ARQLEN_ARQOVFL_M |
			 PF_FW_ARQLEN_ARQCRIT_M);
		wr32(hw, cq->rq.len, val);
	}

	val = rd32(hw, cq->sq.len);
	if (val & (PF_FW_ATQLEN_ATQVFE_M | PF_FW_ATQLEN_ATQOVFL_M |
		   PF_FW_ATQLEN_ATQCRIT_M)) {
		if (val & PF_FW_ATQLEN_ATQVFE_M)
			device_printf(sc->dev,
				"%s Send Queue VF Error detected\n", qname);
		if (val & PF_FW_ATQLEN_ATQOVFL_M)
			device_printf(sc->dev,
				"%s Send Queue Overflow Error detected\n",
				qname);
		if (val & PF_FW_ATQLEN_ATQCRIT_M)
			device_printf(sc->dev,
				"%s Send Queue Critical Error detected\n",
				qname);
		val &= ~(PF_FW_ATQLEN_ATQVFE_M | PF_FW_ATQLEN_ATQOVFL_M |
			 PF_FW_ATQLEN_ATQCRIT_M);
		wr32(hw, cq->sq.len, val);
	}
}

/**
 * ice_process_link_event - Process a link event indication from firmware
 * @sc: device softc structure
 * @e: the received event data
 *
 * Gets the current link status from hardware, and may print a message if an
 * unqualified is detected.
 */
static void
ice_process_link_event(struct ice_softc *sc,
		       struct ice_rq_event_info __invariant_only *e)
{
	struct ice_port_info *pi = sc->hw.port_info;
	struct ice_hw *hw = &sc->hw;
	device_t dev = sc->dev;
	enum ice_status status;

	/* Sanity check that the data length matches */
	MPASS(le16toh(e->desc.datalen) == sizeof(struct ice_aqc_get_link_status_data));

	/*
	 * Even though the adapter gets link status information inside the
	 * event, it needs to send a Get Link Status AQ command in order
	 * to re-enable link events.
	 */
	pi->phy.get_link_info = true;
	ice_get_link_status(pi, &sc->link_up);

	if (pi->phy.link_info.topo_media_conflict &
	   (ICE_AQ_LINK_TOPO_CONFLICT | ICE_AQ_LINK_MEDIA_CONFLICT |
	    ICE_AQ_LINK_TOPO_CORRUPT))
		device_printf(dev,
		    "Possible mis-configuration of the Ethernet port detected; please use the Intel (R) Ethernet Port Configuration Tool utility to address the issue.\n");

	if ((pi->phy.link_info.link_info & ICE_AQ_MEDIA_AVAILABLE) &&
	    !(pi->phy.link_info.link_info & ICE_AQ_LINK_UP) &&
	    !(pi->phy.link_info.an_info & ICE_AQ_QUALIFIED_MODULE))
		device_printf(dev,
		    "Link is disabled on this device because an unsupported module type was detected! Refer to the Intel (R) Ethernet Adapters and Devices User Guide for a list of supported modules.\n");

	if (!(pi->phy.link_info.link_info & ICE_AQ_MEDIA_AVAILABLE)) {
		if (!ice_testandset_state(&sc->state, ICE_STATE_NO_MEDIA)) {
			status = ice_aq_set_link_restart_an(pi, false, NULL);
			if (status != ICE_SUCCESS)
				device_printf(dev,
				    "%s: ice_aq_set_link_restart_an: status %s, aq_err %s\n",
				    __func__, ice_status_str(status),
				    ice_aq_str(hw->adminq.sq_last_status));
		}
	}
	/* ICE_STATE_NO_MEDIA is cleared when polling task detects media */

	/* Indicate that link status must be reported again */
	ice_clear_state(&sc->state, ICE_STATE_LINK_STATUS_REPORTED);

	/* OS link info is updated elsewhere */
}

/**
 * ice_process_ctrlq_event - Respond to a controlq event
 * @sc: device private structure
 * @qname: the name for this controlq
 * @event: the event to process
 *
 * Perform actions in response to various controlq event notifications.
 */
static void
ice_process_ctrlq_event(struct ice_softc *sc, const char *qname,
			struct ice_rq_event_info *event)
{
	u16 opcode;

	opcode = le16toh(event->desc.opcode);

	switch (opcode) {
	case ice_aqc_opc_get_link_status:
		ice_process_link_event(sc, event);
		break;
	case ice_mbx_opc_send_msg_to_pf:
		/* TODO: handle IOV event */
		break;
	case ice_aqc_opc_lldp_set_mib_change:
		ice_handle_mib_change_event(sc, event);
		break;
	case ice_aqc_opc_event_lan_overflow:
		ice_handle_lan_overflow_event(sc, event);
		break;
	default:
		device_printf(sc->dev,
			      "%s Receive Queue unhandled event 0x%04x ignored\n",
			      qname, opcode);
	}
}

/**
 * ice_process_ctrlq - helper function to process controlq rings
 * @sc: device private structure
 * @q_type: specific control queue type
 * @pending: return parameter to track remaining events
 *
 * Process controlq events for a given control queue type. Returns zero on
 * success, and an error code on failure. If successful, pending is the number
 * of remaining events left in the queue.
 */
int
ice_process_ctrlq(struct ice_softc *sc, enum ice_ctl_q q_type, u16 *pending)
{
	struct ice_rq_event_info event = { { 0 } };
	struct ice_hw *hw = &sc->hw;
	struct ice_ctl_q_info *cq;
	enum ice_status status;
	const char *qname;
	int loop = 0;

	switch (q_type) {
	case ICE_CTL_Q_ADMIN:
		cq = &hw->adminq;
		qname = "Admin";
		break;
	case ICE_CTL_Q_MAILBOX:
		cq = &hw->mailboxq;
		qname = "Mailbox";
		break;
	default:
		device_printf(sc->dev,
			      "Unknown control queue type 0x%x\n",
			      q_type);
		return 0;
	}

	ice_check_ctrlq_errors(sc, qname, cq);

	/*
	 * Control queue processing happens during the admin task which may be
	 * holding a non-sleepable lock, so we *must* use M_NOWAIT here.
	 */
	event.buf_len = cq->rq_buf_size;
	event.msg_buf = (u8 *)malloc(event.buf_len, M_ICE, M_ZERO | M_NOWAIT);
	if (!event.msg_buf) {
		device_printf(sc->dev,
			      "Unable to allocate memory for %s Receive Queue event\n",
			      qname);
		return (ENOMEM);
	}

	do {
		status = ice_clean_rq_elem(hw, cq, &event, pending);
		if (status == ICE_ERR_AQ_NO_WORK)
			break;
		if (status) {
			if (q_type == ICE_CTL_Q_ADMIN)
				device_printf(sc->dev,
					      "%s Receive Queue event error %s aq_err %s\n",
					      qname, ice_status_str(status),
					      ice_aq_str(cq->rq_last_status));
			else
				device_printf(sc->dev,
					      "%s Receive Queue event error %s cq_err %d\n",
					      qname, ice_status_str(status), cq->rq_last_status);
			free(event.msg_buf, M_ICE);
			return (EIO);
		}
		/* XXX should we separate this handler by controlq type? */
		ice_process_ctrlq_event(sc, qname, &event);
	} while (*pending && (++loop < ICE_CTRLQ_WORK_LIMIT));

	free(event.msg_buf, M_ICE);

	return 0;
}

/**
 * pkg_ver_empty - Check if a package version is empty
 * @pkg_ver: the package version to check
 * @pkg_name: the package name to check
 *
 * Checks if the package version structure is empty. We consider a package
 * version as empty if none of the versions are non-zero and the name string
 * is null as well.
 *
 * This is used to check if the package version was initialized by the driver,
 * as we do not expect an actual DDP package file to have a zero'd version and
 * name.
 *
 * @returns true if the package version is valid, or false otherwise.
 */
static bool
pkg_ver_empty(struct ice_pkg_ver *pkg_ver, u8 *pkg_name)
{
	return (pkg_name[0] == '\0' &&
		pkg_ver->major == 0 &&
		pkg_ver->minor == 0 &&
		pkg_ver->update == 0 &&
		pkg_ver->draft == 0);
}

/**
 * pkg_ver_compatible - Check if the package version is compatible
 * @pkg_ver: the package version to check
 *
 * Compares the package version number to the driver's expected major/minor
 * version. Returns an integer indicating whether the version is older, newer,
 * or compatible with the driver.
 *
 * @returns 0 if the package version is compatible, -1 if the package version
 * is older, and 1 if the package version is newer than the driver version.
 */
static int
pkg_ver_compatible(struct ice_pkg_ver *pkg_ver)
{
	if (pkg_ver->major > ICE_PKG_SUPP_VER_MAJ)
		return (1); /* newer */
	else if ((pkg_ver->major == ICE_PKG_SUPP_VER_MAJ) &&
		 (pkg_ver->minor > ICE_PKG_SUPP_VER_MNR))
		return (1); /* newer */
	else if ((pkg_ver->major == ICE_PKG_SUPP_VER_MAJ) &&
		 (pkg_ver->minor == ICE_PKG_SUPP_VER_MNR))
		return (0); /* compatible */
	else
		return (-1); /* older */
}

/**
 * ice_os_pkg_version_str - Format OS package version info into a sbuf
 * @hw: device hw structure
 * @buf: string buffer to store name/version string
 *
 * Formats the name and version of the OS DDP package as found in the ice_ddp
 * module into a string.
 *
 * @remark This will almost always be the same as the active package, but
 * could be different in some cases. Use ice_active_pkg_version_str to get the
 * version of the active DDP package.
 */
static void
ice_os_pkg_version_str(struct ice_hw *hw, struct sbuf *buf)
{
	char name_buf[ICE_PKG_NAME_SIZE];

	/* If the OS DDP package info is empty, use "None" */
	if (pkg_ver_empty(&hw->pkg_ver, hw->pkg_name)) {
		sbuf_printf(buf, "None");
		return;
	}

	/*
	 * This should already be null-terminated, but since this is a raw
	 * value from an external source, strlcpy() into a new buffer to
	 * make sure.
	 */
	bzero(name_buf, sizeof(name_buf));
	strlcpy(name_buf, (char *)hw->pkg_name, ICE_PKG_NAME_SIZE);

	sbuf_printf(buf, "%s version %u.%u.%u.%u",
	    name_buf,
	    hw->pkg_ver.major,
	    hw->pkg_ver.minor,
	    hw->pkg_ver.update,
	    hw->pkg_ver.draft);
}

/**
 * ice_active_pkg_version_str - Format active package version info into a sbuf
 * @hw: device hw structure
 * @buf: string buffer to store name/version string
 *
 * Formats the name and version of the active DDP package info into a string
 * buffer for use.
 */
static void
ice_active_pkg_version_str(struct ice_hw *hw, struct sbuf *buf)
{
	char name_buf[ICE_PKG_NAME_SIZE];

	/* If the active DDP package info is empty, use "None" */
	if (pkg_ver_empty(&hw->active_pkg_ver, hw->active_pkg_name)) {
		sbuf_printf(buf, "None");
		return;
	}

	/*
	 * This should already be null-terminated, but since this is a raw
	 * value from an external source, strlcpy() into a new buffer to
	 * make sure.
	 */
	bzero(name_buf, sizeof(name_buf));
	strlcpy(name_buf, (char *)hw->active_pkg_name, ICE_PKG_NAME_SIZE);

	sbuf_printf(buf, "%s version %u.%u.%u.%u",
	    name_buf,
	    hw->active_pkg_ver.major,
	    hw->active_pkg_ver.minor,
	    hw->active_pkg_ver.update,
	    hw->active_pkg_ver.draft);

	if (hw->active_track_id != 0)
		sbuf_printf(buf, ", track id 0x%08x", hw->active_track_id);
}

/**
 * ice_nvm_version_str - Format the NVM version information into a sbuf
 * @hw: device hw structure
 * @buf: string buffer to store version string
 *
 * Formats the NVM information including firmware version, API version, NVM
 * version, the EETRACK id, and OEM specific version information into a string
 * buffer.
 */
static void
ice_nvm_version_str(struct ice_hw *hw, struct sbuf *buf)
{
	struct ice_nvm_info *nvm = &hw->nvm;
	struct ice_orom_info *orom = &nvm->orom;
	struct ice_netlist_ver_info *netlist_ver = &hw->netlist_ver;

	/* Note that the netlist versions are stored in packed Binary Coded
	 * Decimal format. The use of '%x' will correctly display these as
	 * decimal numbers. This works because every 4 bits will be displayed
	 * as a hexadecimal digit, and the BCD format will only use the values
	 * 0-9.
	 */
	sbuf_printf(buf,
		    "fw %u.%u.%u api %u.%u nvm %x.%02x etid %08x netlist %x.%x.%x-%x.%x.%x.%04x oem %u.%u.%u",
		    hw->fw_maj_ver, hw->fw_min_ver, hw->fw_patch,
		    hw->api_maj_ver, hw->api_min_ver,
		    nvm->major_ver, nvm->minor_ver, nvm->eetrack,
		    netlist_ver->major, netlist_ver->minor,
		    netlist_ver->type >> 16, netlist_ver->type & 0xFFFF,
		    netlist_ver->rev, netlist_ver->cust_ver, netlist_ver->hash,
		    orom->major, orom->build, orom->patch);
}

/**
 * ice_print_nvm_version - Print the NVM info to the kernel message log
 * @sc: the device softc structure
 *
 * Format and print an NVM version string using ice_nvm_version_str().
 */
void
ice_print_nvm_version(struct ice_softc *sc)
{
	struct ice_hw *hw = &sc->hw;
	device_t dev = sc->dev;
	struct sbuf *sbuf;

	sbuf = sbuf_new_auto();
	ice_nvm_version_str(hw, sbuf);
	sbuf_finish(sbuf);
	device_printf(dev, "%s\n", sbuf_data(sbuf));
	sbuf_delete(sbuf);
}

/**
 * ice_update_vsi_hw_stats - Update VSI-specific ethernet statistics counters
 * @vsi: the VSI to be updated
 *
 * Reads hardware stats and updates the ice_vsi_hw_stats tracking structure with
 * the updated values.
 */
void
ice_update_vsi_hw_stats(struct ice_vsi *vsi)
{
	struct ice_eth_stats *prev_es, *cur_es;
	struct ice_hw *hw = &vsi->sc->hw;
	u16 vsi_num;

	if (!ice_is_vsi_valid(hw, vsi->idx))
		return;

	vsi_num = ice_get_hw_vsi_num(hw, vsi->idx); /* HW absolute index of a VSI */
	prev_es = &vsi->hw_stats.prev;
	cur_es = &vsi->hw_stats.cur;

#define ICE_VSI_STAT40(name, location) \
	ice_stat_update40(hw, name ## L(vsi_num), \
			  vsi->hw_stats.offsets_loaded, \
			  &prev_es->location, &cur_es->location)

#define ICE_VSI_STAT32(name, location) \
	ice_stat_update32(hw, name(vsi_num), \
			  vsi->hw_stats.offsets_loaded, \
			  &prev_es->location, &cur_es->location)

	ICE_VSI_STAT40(GLV_GORC, rx_bytes);
	ICE_VSI_STAT40(GLV_UPRC, rx_unicast);
	ICE_VSI_STAT40(GLV_MPRC, rx_multicast);
	ICE_VSI_STAT40(GLV_BPRC, rx_broadcast);
	ICE_VSI_STAT32(GLV_RDPC, rx_discards);
	ICE_VSI_STAT40(GLV_GOTC, tx_bytes);
	ICE_VSI_STAT40(GLV_UPTC, tx_unicast);
	ICE_VSI_STAT40(GLV_MPTC, tx_multicast);
	ICE_VSI_STAT40(GLV_BPTC, tx_broadcast);
	ICE_VSI_STAT32(GLV_TEPC, tx_errors);

	ice_stat_update_repc(hw, vsi->idx, vsi->hw_stats.offsets_loaded,
			     cur_es);

#undef ICE_VSI_STAT40
#undef ICE_VSI_STAT32

	vsi->hw_stats.offsets_loaded = true;
}

/**
 * ice_reset_vsi_stats - Reset VSI statistics counters
 * @vsi: VSI structure
 *
 * Resets the software tracking counters for the VSI statistics, and indicate
 * that the offsets haven't been loaded. This is intended to be called
 * post-reset so that VSI statistics count from zero again.
 */
void
ice_reset_vsi_stats(struct ice_vsi *vsi)
{
	/* Reset HW stats */
	memset(&vsi->hw_stats.prev, 0, sizeof(vsi->hw_stats.prev));
	memset(&vsi->hw_stats.cur, 0, sizeof(vsi->hw_stats.cur));
	vsi->hw_stats.offsets_loaded = false;
}

/**
 * ice_update_pf_stats - Update port stats counters
 * @sc: device private softc structure
 *
 * Reads hardware statistics registers and updates the software tracking
 * structure with new values.
 */
void
ice_update_pf_stats(struct ice_softc *sc)
{
	struct ice_hw_port_stats *prev_ps, *cur_ps;
	struct ice_hw *hw = &sc->hw;
	u8 lport;

	MPASS(hw->port_info);

	prev_ps = &sc->stats.prev;
	cur_ps = &sc->stats.cur;
	lport = hw->port_info->lport;

#define ICE_PF_STAT40(name, location) \
	ice_stat_update40(hw, name ## L(lport), \
			  sc->stats.offsets_loaded, \
			  &prev_ps->location, &cur_ps->location)

#define ICE_PF_STAT32(name, location) \
	ice_stat_update32(hw, name(lport), \
			  sc->stats.offsets_loaded, \
			  &prev_ps->location, &cur_ps->location)

	ICE_PF_STAT40(GLPRT_GORC, eth.rx_bytes);
	ICE_PF_STAT40(GLPRT_UPRC, eth.rx_unicast);
	ICE_PF_STAT40(GLPRT_MPRC, eth.rx_multicast);
	ICE_PF_STAT40(GLPRT_BPRC, eth.rx_broadcast);
	ICE_PF_STAT40(GLPRT_GOTC, eth.tx_bytes);
	ICE_PF_STAT40(GLPRT_UPTC, eth.tx_unicast);
	ICE_PF_STAT40(GLPRT_MPTC, eth.tx_multicast);
	ICE_PF_STAT40(GLPRT_BPTC, eth.tx_broadcast);

	ICE_PF_STAT32(GLPRT_TDOLD, tx_dropped_link_down);
	ICE_PF_STAT40(GLPRT_PRC64, rx_size_64);
	ICE_PF_STAT40(GLPRT_PRC127, rx_size_127);
	ICE_PF_STAT40(GLPRT_PRC255, rx_size_255);
	ICE_PF_STAT40(GLPRT_PRC511, rx_size_511);
	ICE_PF_STAT40(GLPRT_PRC1023, rx_size_1023);
	ICE_PF_STAT40(GLPRT_PRC1522, rx_size_1522);
	ICE_PF_STAT40(GLPRT_PRC9522, rx_size_big);
	ICE_PF_STAT40(GLPRT_PTC64, tx_size_64);
	ICE_PF_STAT40(GLPRT_PTC127, tx_size_127);
	ICE_PF_STAT40(GLPRT_PTC255, tx_size_255);
	ICE_PF_STAT40(GLPRT_PTC511, tx_size_511);
	ICE_PF_STAT40(GLPRT_PTC1023, tx_size_1023);
	ICE_PF_STAT40(GLPRT_PTC1522, tx_size_1522);
	ICE_PF_STAT40(GLPRT_PTC9522, tx_size_big);

	ICE_PF_STAT32(GLPRT_LXONRXC, link_xon_rx);
	ICE_PF_STAT32(GLPRT_LXOFFRXC, link_xoff_rx);
	ICE_PF_STAT32(GLPRT_LXONTXC, link_xon_tx);
	ICE_PF_STAT32(GLPRT_LXOFFTXC, link_xoff_tx);
	ICE_PF_STAT32(GLPRT_CRCERRS, crc_errors);
	ICE_PF_STAT32(GLPRT_ILLERRC, illegal_bytes);
	ICE_PF_STAT32(GLPRT_MLFC, mac_local_faults);
	ICE_PF_STAT32(GLPRT_MRFC, mac_remote_faults);
	ICE_PF_STAT32(GLPRT_RLEC, rx_len_errors);
	ICE_PF_STAT32(GLPRT_RUC, rx_undersize);
	ICE_PF_STAT32(GLPRT_RFC, rx_fragments);
	ICE_PF_STAT32(GLPRT_ROC, rx_oversize);
	ICE_PF_STAT32(GLPRT_RJC, rx_jabber);

#undef ICE_PF_STAT40
#undef ICE_PF_STAT32

	sc->stats.offsets_loaded = true;
}

/**
 * ice_reset_pf_stats - Reset port stats counters
 * @sc: Device private softc structure
 *
 * Reset software tracking values for statistics to zero, and indicate that
 * offsets haven't been loaded. Intended to be called after a device reset so
 * that statistics count from zero again.
 */
void
ice_reset_pf_stats(struct ice_softc *sc)
{
	memset(&sc->stats.prev, 0, sizeof(sc->stats.prev));
	memset(&sc->stats.cur, 0, sizeof(sc->stats.cur));
	sc->stats.offsets_loaded = false;
}

/**
 * ice_sysctl_show_fw - sysctl callback to show firmware information
 * @oidp: sysctl oid structure
 * @arg1: pointer to private data structure
 * @arg2: unused
 * @req: sysctl request pointer
 *
 * Callback for the fw_version sysctl, to display the current firmware
 * information found at hardware init time.
 */
static int
ice_sysctl_show_fw(SYSCTL_HANDLER_ARGS)
{
	struct ice_softc *sc = (struct ice_softc *)arg1;
	struct ice_hw *hw = &sc->hw;
	struct sbuf *sbuf;

	UNREFERENCED_PARAMETER(oidp);
	UNREFERENCED_PARAMETER(arg2);

	if (ice_driver_is_detaching(sc))
		return (ESHUTDOWN);

	sbuf = sbuf_new_for_sysctl(NULL, NULL, 128, req);
	ice_nvm_version_str(hw, sbuf);
	sbuf_finish(sbuf);
	sbuf_delete(sbuf);

	return (0);
}

/**
 * ice_sysctl_pba_number - sysctl callback to show PBA number
 * @oidp: sysctl oid structure
 * @arg1: pointer to private data structure
 * @arg2: unused
 * @req: sysctl request pointer
 *
 * Callback for the pba_number sysctl, used to read the Product Board Assembly
 * number for this device.
 */
static int
ice_sysctl_pba_number(SYSCTL_HANDLER_ARGS)
{
	struct ice_softc *sc = (struct ice_softc *)arg1;
	struct ice_hw *hw = &sc->hw;
	device_t dev = sc->dev;
	u8 pba_string[32] = "";
	enum ice_status status;

	UNREFERENCED_PARAMETER(arg2);

	if (ice_driver_is_detaching(sc))
		return (ESHUTDOWN);

	status = ice_read_pba_string(hw, pba_string, sizeof(pba_string));
	if (status) {
		device_printf(dev,
		    "%s: failed to read PBA string from NVM; status %s, aq_err %s\n",
		    __func__, ice_status_str(status),
		    ice_aq_str(hw->adminq.sq_last_status));
		return (EIO);
	}

	return sysctl_handle_string(oidp, pba_string, sizeof(pba_string), req);
}

/**
 * ice_sysctl_pkg_version - sysctl to show the active package version info
 * @oidp: sysctl oid structure
 * @arg1: pointer to private data structure
 * @arg2: unused
 * @req: sysctl request pointer
 *
 * Callback for the pkg_version sysctl, to display the active DDP package name
 * and version information.
 */
static int
ice_sysctl_pkg_version(SYSCTL_HANDLER_ARGS)
{
	struct ice_softc *sc = (struct ice_softc *)arg1;
	struct ice_hw *hw = &sc->hw;
	struct sbuf *sbuf;

	UNREFERENCED_PARAMETER(oidp);
	UNREFERENCED_PARAMETER(arg2);

	if (ice_driver_is_detaching(sc))
		return (ESHUTDOWN);

	sbuf = sbuf_new_for_sysctl(NULL, NULL, 128, req);
	ice_active_pkg_version_str(hw, sbuf);
	sbuf_finish(sbuf);
	sbuf_delete(sbuf);

	return (0);
}

/**
 * ice_sysctl_os_pkg_version - sysctl to show the OS package version info
 * @oidp: sysctl oid structure
 * @arg1: pointer to private data structure
 * @arg2: unused
 * @req: sysctl request pointer
 *
 * Callback for the pkg_version sysctl, to display the OS DDP package name and
 * version info found in the ice_ddp module.
 */
static int
ice_sysctl_os_pkg_version(SYSCTL_HANDLER_ARGS)
{
	struct ice_softc *sc = (struct ice_softc *)arg1;
	struct ice_hw *hw = &sc->hw;
	struct sbuf *sbuf;

	UNREFERENCED_PARAMETER(oidp);
	UNREFERENCED_PARAMETER(arg2);

	if (ice_driver_is_detaching(sc))
		return (ESHUTDOWN);

	sbuf = sbuf_new_for_sysctl(NULL, NULL, 128, req);
	ice_os_pkg_version_str(hw, sbuf);
	sbuf_finish(sbuf);
	sbuf_delete(sbuf);

	return (0);
}

/**
 * ice_sysctl_current_speed - sysctl callback to show current link speed
 * @oidp: sysctl oid structure
 * @arg1: pointer to private data structure
 * @arg2: unused
 * @req: sysctl request pointer
 *
 * Callback for the current_speed sysctl, to display the string representing
 * the current link speed.
 */
static int
ice_sysctl_current_speed(SYSCTL_HANDLER_ARGS)
{
	struct ice_softc *sc = (struct ice_softc *)arg1;
	struct ice_hw *hw = &sc->hw;
	struct sbuf *sbuf;

	UNREFERENCED_PARAMETER(oidp);
	UNREFERENCED_PARAMETER(arg2);

	if (ice_driver_is_detaching(sc))
		return (ESHUTDOWN);

	sbuf = sbuf_new_for_sysctl(NULL, NULL, 10, req);
	sbuf_printf(sbuf, "%s", ice_aq_speed_to_str(hw->port_info));
	sbuf_finish(sbuf);
	sbuf_delete(sbuf);

	return (0);
}

/**
 * @var phy_link_speeds
 * @brief PHY link speed conversion array
 *
 * Array of link speeds to convert ICE_PHY_TYPE_LOW and ICE_PHY_TYPE_HIGH into
 * link speeds used by the link speed sysctls.
 *
 * @remark these are based on the indices used in the BIT() macros for the
 * ICE_PHY_TYPE_LOW_* and ICE_PHY_TYPE_HIGH_* definitions.
 */
static const uint16_t phy_link_speeds[] = {
    ICE_AQ_LINK_SPEED_100MB,
    ICE_AQ_LINK_SPEED_100MB,
    ICE_AQ_LINK_SPEED_1000MB,
    ICE_AQ_LINK_SPEED_1000MB,
    ICE_AQ_LINK_SPEED_1000MB,
    ICE_AQ_LINK_SPEED_1000MB,
    ICE_AQ_LINK_SPEED_1000MB,
    ICE_AQ_LINK_SPEED_2500MB,
    ICE_AQ_LINK_SPEED_2500MB,
    ICE_AQ_LINK_SPEED_2500MB,
    ICE_AQ_LINK_SPEED_5GB,
    ICE_AQ_LINK_SPEED_5GB,
    ICE_AQ_LINK_SPEED_10GB,
    ICE_AQ_LINK_SPEED_10GB,
    ICE_AQ_LINK_SPEED_10GB,
    ICE_AQ_LINK_SPEED_10GB,
    ICE_AQ_LINK_SPEED_10GB,
    ICE_AQ_LINK_SPEED_10GB,
    ICE_AQ_LINK_SPEED_10GB,
    ICE_AQ_LINK_SPEED_25GB,
    ICE_AQ_LINK_SPEED_25GB,
    ICE_AQ_LINK_SPEED_25GB,
    ICE_AQ_LINK_SPEED_25GB,
    ICE_AQ_LINK_SPEED_25GB,
    ICE_AQ_LINK_SPEED_25GB,
    ICE_AQ_LINK_SPEED_25GB,
    ICE_AQ_LINK_SPEED_25GB,
    ICE_AQ_LINK_SPEED_25GB,
    ICE_AQ_LINK_SPEED_25GB,
    ICE_AQ_LINK_SPEED_25GB,
    ICE_AQ_LINK_SPEED_40GB,
    ICE_AQ_LINK_SPEED_40GB,
    ICE_AQ_LINK_SPEED_40GB,
    ICE_AQ_LINK_SPEED_40GB,
    ICE_AQ_LINK_SPEED_40GB,
    ICE_AQ_LINK_SPEED_40GB,
    ICE_AQ_LINK_SPEED_50GB,
    ICE_AQ_LINK_SPEED_50GB,
    ICE_AQ_LINK_SPEED_50GB,
    ICE_AQ_LINK_SPEED_50GB,
    ICE_AQ_LINK_SPEED_50GB,
    ICE_AQ_LINK_SPEED_50GB,
    ICE_AQ_LINK_SPEED_50GB,
    ICE_AQ_LINK_SPEED_50GB,
    ICE_AQ_LINK_SPEED_50GB,
    ICE_AQ_LINK_SPEED_50GB,
    ICE_AQ_LINK_SPEED_50GB,
    ICE_AQ_LINK_SPEED_50GB,
    ICE_AQ_LINK_SPEED_50GB,
    ICE_AQ_LINK_SPEED_50GB,
    ICE_AQ_LINK_SPEED_50GB,
    ICE_AQ_LINK_SPEED_100GB,
    ICE_AQ_LINK_SPEED_100GB,
    ICE_AQ_LINK_SPEED_100GB,
    ICE_AQ_LINK_SPEED_100GB,
    ICE_AQ_LINK_SPEED_100GB,
    ICE_AQ_LINK_SPEED_100GB,
    ICE_AQ_LINK_SPEED_100GB,
    ICE_AQ_LINK_SPEED_100GB,
    ICE_AQ_LINK_SPEED_100GB,
    ICE_AQ_LINK_SPEED_100GB,
    ICE_AQ_LINK_SPEED_100GB,
    ICE_AQ_LINK_SPEED_100GB,
    ICE_AQ_LINK_SPEED_100GB,
    /* These rates are for ICE_PHY_TYPE_HIGH_* */
    ICE_AQ_LINK_SPEED_100GB,
    ICE_AQ_LINK_SPEED_100GB,
    ICE_AQ_LINK_SPEED_100GB,
    ICE_AQ_LINK_SPEED_100GB,
    ICE_AQ_LINK_SPEED_100GB
};

#define ICE_SYSCTL_HELP_ADVERTISE_SPEED		\
"\nControl advertised link speed."		\
"\nFlags:"					\
"\n\t   0x0 - Auto"				\
"\n\t   0x1 - 10 Mb"				\
"\n\t   0x2 - 100 Mb"				\
"\n\t   0x4 - 1G"				\
"\n\t   0x8 - 2.5G"				\
"\n\t  0x10 - 5G"				\
"\n\t  0x20 - 10G"				\
"\n\t  0x40 - 20G"				\
"\n\t  0x80 - 25G"				\
"\n\t 0x100 - 40G"				\
"\n\t 0x200 - 50G"				\
"\n\t 0x400 - 100G"				\
"\n\t0x8000 - Unknown"				\
"\n\t"						\
"\nUse \"sysctl -x\" to view flags properly."

#define ICE_PHYS_100MB			\
    (ICE_PHY_TYPE_LOW_100BASE_TX |	\
     ICE_PHY_TYPE_LOW_100M_SGMII)
#define ICE_PHYS_1000MB			\
    (ICE_PHY_TYPE_LOW_1000BASE_T |	\
     ICE_PHY_TYPE_LOW_1000BASE_SX |	\
     ICE_PHY_TYPE_LOW_1000BASE_LX |	\
     ICE_PHY_TYPE_LOW_1000BASE_KX |	\
     ICE_PHY_TYPE_LOW_1G_SGMII)
#define ICE_PHYS_2500MB			\
    (ICE_PHY_TYPE_LOW_2500BASE_T |	\
     ICE_PHY_TYPE_LOW_2500BASE_X |	\
     ICE_PHY_TYPE_LOW_2500BASE_KX)
#define ICE_PHYS_5GB			\
    (ICE_PHY_TYPE_LOW_5GBASE_T |	\
     ICE_PHY_TYPE_LOW_5GBASE_KR)
#define ICE_PHYS_10GB			\
    (ICE_PHY_TYPE_LOW_10GBASE_T |	\
     ICE_PHY_TYPE_LOW_10G_SFI_DA |	\
     ICE_PHY_TYPE_LOW_10GBASE_SR |	\
     ICE_PHY_TYPE_LOW_10GBASE_LR |	\
     ICE_PHY_TYPE_LOW_10GBASE_KR_CR1 |	\
     ICE_PHY_TYPE_LOW_10G_SFI_AOC_ACC |	\
     ICE_PHY_TYPE_LOW_10G_SFI_C2C)
#define ICE_PHYS_25GB			\
    (ICE_PHY_TYPE_LOW_25GBASE_T |	\
     ICE_PHY_TYPE_LOW_25GBASE_CR |	\
     ICE_PHY_TYPE_LOW_25GBASE_CR_S |	\
     ICE_PHY_TYPE_LOW_25GBASE_CR1 |	\
     ICE_PHY_TYPE_LOW_25GBASE_SR |	\
     ICE_PHY_TYPE_LOW_25GBASE_LR |	\
     ICE_PHY_TYPE_LOW_25GBASE_KR |	\
     ICE_PHY_TYPE_LOW_25GBASE_KR_S |	\
     ICE_PHY_TYPE_LOW_25GBASE_KR1 |	\
     ICE_PHY_TYPE_LOW_25G_AUI_AOC_ACC |	\
     ICE_PHY_TYPE_LOW_25G_AUI_C2C)
#define ICE_PHYS_40GB			\
    (ICE_PHY_TYPE_LOW_40GBASE_CR4 |	\
     ICE_PHY_TYPE_LOW_40GBASE_SR4 |	\
     ICE_PHY_TYPE_LOW_40GBASE_LR4 |	\
     ICE_PHY_TYPE_LOW_40GBASE_KR4 |	\
     ICE_PHY_TYPE_LOW_40G_XLAUI_AOC_ACC | \
     ICE_PHY_TYPE_LOW_40G_XLAUI)
#define ICE_PHYS_50GB			\
    (ICE_PHY_TYPE_LOW_50GBASE_CR2 |	\
     ICE_PHY_TYPE_LOW_50GBASE_SR2 |	\
     ICE_PHY_TYPE_LOW_50GBASE_LR2 |	\
     ICE_PHY_TYPE_LOW_50GBASE_KR2 |	\
     ICE_PHY_TYPE_LOW_50G_LAUI2_AOC_ACC | \
     ICE_PHY_TYPE_LOW_50G_LAUI2 |	\
     ICE_PHY_TYPE_LOW_50G_AUI2_AOC_ACC | \
     ICE_PHY_TYPE_LOW_50G_AUI2 |	\
     ICE_PHY_TYPE_LOW_50GBASE_CP |	\
     ICE_PHY_TYPE_LOW_50GBASE_SR |	\
     ICE_PHY_TYPE_LOW_50GBASE_FR |	\
     ICE_PHY_TYPE_LOW_50GBASE_LR |	\
     ICE_PHY_TYPE_LOW_50GBASE_KR_PAM4 |	\
     ICE_PHY_TYPE_LOW_50G_AUI1_AOC_ACC | \
     ICE_PHY_TYPE_LOW_50G_AUI1)
#define ICE_PHYS_100GB_LOW		\
    (ICE_PHY_TYPE_LOW_100GBASE_CR4 |	\
     ICE_PHY_TYPE_LOW_100GBASE_SR4 |	\
     ICE_PHY_TYPE_LOW_100GBASE_LR4 |	\
     ICE_PHY_TYPE_LOW_100GBASE_KR4 |	\
     ICE_PHY_TYPE_LOW_100G_CAUI4_AOC_ACC | \
     ICE_PHY_TYPE_LOW_100G_CAUI4 |	\
     ICE_PHY_TYPE_LOW_100G_AUI4_AOC_ACC | \
     ICE_PHY_TYPE_LOW_100G_AUI4 |	\
     ICE_PHY_TYPE_LOW_100GBASE_CR_PAM4 | \
     ICE_PHY_TYPE_LOW_100GBASE_KR_PAM4 | \
     ICE_PHY_TYPE_LOW_100GBASE_CP2 |	\
     ICE_PHY_TYPE_LOW_100GBASE_SR2 |	\
     ICE_PHY_TYPE_LOW_100GBASE_DR)
#define ICE_PHYS_100GB_HIGH		\
    (ICE_PHY_TYPE_HIGH_100GBASE_KR2_PAM4 | \
     ICE_PHY_TYPE_HIGH_100G_CAUI2_AOC_ACC | \
     ICE_PHY_TYPE_HIGH_100G_CAUI2 |	\
     ICE_PHY_TYPE_HIGH_100G_AUI2_AOC_ACC | \
     ICE_PHY_TYPE_HIGH_100G_AUI2)

/**
 * ice_aq_phy_types_to_sysctl_speeds - Convert the PHY Types to speeds
 * @phy_type_low: lower 64-bit PHY Type bitmask
 * @phy_type_high: upper 64-bit PHY Type bitmask
 *
 * Convert the PHY Type fields from Get PHY Abilities and Set PHY Config into
 * link speed flags. If phy_type_high has an unknown PHY type, then the return
 * value will include the "ICE_AQ_LINK_SPEED_UNKNOWN" flag as well.
 */
static u16
ice_aq_phy_types_to_sysctl_speeds(u64 phy_type_low, u64 phy_type_high)
{
	u16 sysctl_speeds = 0;
	int bit;

	/* coverity[address_of] */
	for_each_set_bit(bit, &phy_type_low, 64)
		sysctl_speeds |= phy_link_speeds[bit];

	/* coverity[address_of] */
	for_each_set_bit(bit, &phy_type_high, 64) {
		if ((bit + 64) < (int)ARRAY_SIZE(phy_link_speeds))
			sysctl_speeds |= phy_link_speeds[bit + 64];
		else
			sysctl_speeds |= ICE_AQ_LINK_SPEED_UNKNOWN;
	}

	return (sysctl_speeds);
}

/**
 * ice_sysctl_speeds_to_aq_phy_types - Convert sysctl speed flags to AQ PHY flags
 * @sysctl_speeds: 16-bit sysctl speeds or AQ_LINK_SPEED flags
 * @phy_type_low: output parameter for lower AQ PHY flags
 * @phy_type_high: output parameter for higher AQ PHY flags
 *
 * Converts the given link speed flags into AQ PHY type flag sets appropriate
 * for use in a Set PHY Config command.
 */
static void
ice_sysctl_speeds_to_aq_phy_types(u16 sysctl_speeds, u64 *phy_type_low,
				  u64 *phy_type_high)
{
	*phy_type_low = 0, *phy_type_high = 0;

	if (sysctl_speeds & ICE_AQ_LINK_SPEED_100MB)
		*phy_type_low |= ICE_PHYS_100MB;
	if (sysctl_speeds & ICE_AQ_LINK_SPEED_1000MB)
		*phy_type_low |= ICE_PHYS_1000MB;
	if (sysctl_speeds & ICE_AQ_LINK_SPEED_2500MB)
		*phy_type_low |= ICE_PHYS_2500MB;
	if (sysctl_speeds & ICE_AQ_LINK_SPEED_5GB)
		*phy_type_low |= ICE_PHYS_5GB;
	if (sysctl_speeds & ICE_AQ_LINK_SPEED_10GB)
		*phy_type_low |= ICE_PHYS_10GB;
	if (sysctl_speeds & ICE_AQ_LINK_SPEED_25GB)
		*phy_type_low |= ICE_PHYS_25GB;
	if (sysctl_speeds & ICE_AQ_LINK_SPEED_40GB)
		*phy_type_low |= ICE_PHYS_40GB;
	if (sysctl_speeds & ICE_AQ_LINK_SPEED_50GB)
		*phy_type_low |= ICE_PHYS_50GB;
	if (sysctl_speeds & ICE_AQ_LINK_SPEED_100GB) {
		*phy_type_low |= ICE_PHYS_100GB_LOW;
		*phy_type_high |= ICE_PHYS_100GB_HIGH;
	}
}

/**
 * ice_intersect_media_types_with_caps - Restrict input AQ PHY flags
 * @sc: driver private structure
 * @phy_type_low: input/output flag set for low PHY types
 * @phy_type_high: input/output flag set for high PHY types
 *
 * Intersects the input PHY flags with PHY flags retrieved from the adapter to
 * ensure the flags are compatible.
 *
 * @returns 0 on success, EIO if an AQ command fails, or EINVAL if input PHY
 * types have no intersection with TOPO_CAPS and the adapter is in non-lenient
 * mode
 */
static int
ice_intersect_media_types_with_caps(struct ice_softc *sc, u64 *phy_type_low,
				    u64 *phy_type_high)
{
	device_t dev = sc->dev;
	enum ice_status status;

	u64 new_phy_low, new_phy_high;

	status = ice_get_phy_types(sc, &new_phy_low, &new_phy_high);
	if (status != ICE_SUCCESS) {
		/* Function already prints appropriate error message */
		return (EIO);
	}

	ice_apply_supported_speed_filter(&new_phy_low, &new_phy_high);

	new_phy_low &= *phy_type_low;
	new_phy_high &= *phy_type_high;

	if (new_phy_low == 0 && new_phy_high == 0) {
		device_printf(dev,
		    "The selected speed is not supported by the current media. Please select a link speed that is supported by the current media.\n");
		return (EINVAL);
	}

	/* Overwrite input phy_type values and return */
	*phy_type_low = new_phy_low;
	*phy_type_high = new_phy_high;

	return (0);
}

/**
 * ice_get_auto_speeds - Get PHY type flags for "auto" speed
 * @sc: driver private structure
 * @phy_type_low: output low PHY type flags
 * @phy_type_high: output high PHY type flags
 *
 * Retrieves a suitable set of PHY type flags to use for an "auto" speed
 * setting by either using the NVM default overrides for speed, or retrieving
 * a default from the adapter using Get PHY capabilities in TOPO_CAPS mode.
 *
 * @returns 0 on success or EIO on AQ command failure
 */
static int
ice_get_auto_speeds(struct ice_softc *sc, u64 *phy_type_low,
		    u64 *phy_type_high)
{
	struct ice_aqc_get_phy_caps_data pcaps = { 0 };
	struct ice_hw *hw = &sc->hw;
	struct ice_port_info *pi = hw->port_info;
	device_t dev = sc->dev;
	enum ice_status status;

	if (ice_is_bit_set(sc->feat_en, ICE_FEATURE_DEFAULT_OVERRIDE)) {
		/* copy over speed settings from LDO TLV */
		*phy_type_low = CPU_TO_LE64(sc->ldo_tlv.phy_type_low);
		*phy_type_high = CPU_TO_LE64(sc->ldo_tlv.phy_type_high);
	} else {
		status = ice_aq_get_phy_caps(pi, false, ICE_AQC_REPORT_TOPO_CAP,
					     &pcaps, NULL);
		if (status != ICE_SUCCESS) {
			device_printf(dev,
			    "%s: ice_aq_get_phy_caps (TOPO_CAP) failed; status %s, aq_err %s\n",
			    __func__, ice_status_str(status),
			    ice_aq_str(hw->adminq.sq_last_status));
			return (EIO);
		}

		*phy_type_low = le64toh(pcaps.phy_type_low);
		*phy_type_high = le64toh(pcaps.phy_type_high);
	}

	return (0);
}

/**
 * ice_sysctl_advertise_speed - Display/change link speeds supported by port
 * @oidp: sysctl oid structure
 * @arg1: pointer to private data structure
 * @arg2: unused
 * @req: sysctl request pointer
 *
 * On read: Displays the currently supported speeds
 * On write: Sets the device's supported speeds
 * Valid input flags: see ICE_SYSCTL_HELP_ADVERTISE_SPEED
 */
static int
ice_sysctl_advertise_speed(SYSCTL_HANDLER_ARGS)
{
	struct ice_softc *sc = (struct ice_softc *)arg1;
	struct ice_aqc_get_phy_caps_data pcaps = { 0 };
	struct ice_aqc_set_phy_cfg_data cfg = { 0 };
	struct ice_hw *hw = &sc->hw;
	struct ice_port_info *pi = hw->port_info;
	device_t dev = sc->dev;
	enum ice_status status;
	u64 phy_low, phy_high;
	u16 sysctl_speeds = 0;
	int error = 0;

	UNREFERENCED_PARAMETER(arg2);

	if (ice_driver_is_detaching(sc))
		return (ESHUTDOWN);

	/* Get the current speeds from the adapter's "active" configuration. */
	status = ice_aq_get_phy_caps(pi, false, ICE_AQC_REPORT_SW_CFG,
				     &pcaps, NULL);
	if (status != ICE_SUCCESS) {
		device_printf(dev,
		    "%s: ice_aq_get_phy_caps (SW_CFG) failed; status %s, aq_err %s\n",
		    __func__, ice_status_str(status),
		    ice_aq_str(hw->adminq.sq_last_status));
		return (EIO);
	}

	phy_low = le64toh(pcaps.phy_type_low);
	phy_high = le64toh(pcaps.phy_type_high);
	sysctl_speeds = ice_aq_phy_types_to_sysctl_speeds(phy_low, phy_high);

	error = sysctl_handle_16(oidp, &sysctl_speeds, 0, req);
	if ((error) || (req->newptr == NULL))
		return (error);

	if (sysctl_speeds > 0x7FF) {
		device_printf(dev,
			      "%s: \"%u\" is outside of the range of acceptable values.\n",
			      __func__, sysctl_speeds);
		return (EINVAL);
	}

	/* 0 is treated as "Auto"; the driver will handle selecting the correct speeds,
	 * or apply an override if one is specified in the NVM.
	 */
	if (sysctl_speeds == 0) {
		error = ice_get_auto_speeds(sc, &phy_low, &phy_high);
		if (error)
			/* Function already prints appropriate error message */
			return (error);
	} else {
		ice_sysctl_speeds_to_aq_phy_types(sysctl_speeds, &phy_low, &phy_high);
		error = ice_intersect_media_types_with_caps(sc, &phy_low, &phy_high);
		if (error)
			/* Function already prints appropriate error message */
			return (error);
	}
	sysctl_speeds = ice_aq_phy_types_to_sysctl_speeds(phy_low, phy_high);

	/* Cache new user setting for speeds */
	pi->phy.curr_user_speed_req = sysctl_speeds;

	/* Setup new PHY config with new input PHY types */
	ice_copy_phy_caps_to_cfg(pi, &pcaps, &cfg);

	cfg.phy_type_low = phy_low;
	cfg.phy_type_high = phy_high;
	cfg.caps |= ICE_AQ_PHY_ENA_AUTO_LINK_UPDT;

	status = ice_aq_set_phy_cfg(hw, pi, &cfg, NULL);
	if (status != ICE_SUCCESS) {
		/* Don't indicate failure if there's no media in the port -- the sysctl
		 * handler has saved the value and will apply it when media is inserted.
		 */
		if (status == ICE_ERR_AQ_ERROR &&
		    hw->adminq.sq_last_status == ICE_AQ_RC_EBUSY) {
			device_printf(dev,
			    "%s: Setting will be applied when media is inserted\n", __func__);
			return (0);
		} else {
			device_printf(dev,
			    "%s: ice_aq_set_phy_cfg failed; status %s, aq_err %s\n",
			    __func__, ice_status_str(status),
			    ice_aq_str(hw->adminq.sq_last_status));
			return (EIO);
		}
	}

	return (0);
}

#define ICE_SYSCTL_HELP_FEC_CONFIG			\
"\nDisplay or set the port's requested FEC mode."	\
"\n\tauto - " ICE_FEC_STRING_AUTO			\
"\n\tfc - " ICE_FEC_STRING_BASER			\
"\n\trs - " ICE_FEC_STRING_RS				\
"\n\tnone - " ICE_FEC_STRING_NONE			\
"\nEither of the left or right strings above can be used to set the requested mode."

/**
 * ice_sysctl_fec_config - Display/change the configured FEC mode
 * @oidp: sysctl oid structure
 * @arg1: pointer to private data structure
 * @arg2: unused
 * @req: sysctl request pointer
 *
 * On read: Displays the configured FEC mode
 * On write: Sets the device's FEC mode to the input string, if it's valid.
 * Valid input strings: see ICE_SYSCTL_HELP_FEC_CONFIG
 */
static int
ice_sysctl_fec_config(SYSCTL_HANDLER_ARGS)
{
	struct ice_softc *sc = (struct ice_softc *)arg1;
	struct ice_port_info *pi = sc->hw.port_info;
	struct ice_aqc_get_phy_caps_data pcaps = { 0 };
	struct ice_aqc_set_phy_cfg_data cfg = { 0 };
	struct ice_hw *hw = &sc->hw;
	enum ice_fec_mode new_mode;
	enum ice_status status;
	device_t dev = sc->dev;
	char req_fec[32];
	int error = 0;

	UNREFERENCED_PARAMETER(arg2);

	if (ice_driver_is_detaching(sc))
		return (ESHUTDOWN);

	bzero(req_fec, sizeof(req_fec));
	strlcpy(req_fec, ice_requested_fec_mode(pi), sizeof(req_fec));

	error = sysctl_handle_string(oidp, req_fec, sizeof(req_fec), req);
	if ((error) || (req->newptr == NULL))
		return (error);

	if (strcmp(req_fec, "auto") == 0 ||
	    strcmp(req_fec, ice_fec_str(ICE_FEC_AUTO)) == 0) {
		new_mode = ICE_FEC_AUTO;
	} else if (strcmp(req_fec, "fc") == 0 ||
	    strcmp(req_fec, ice_fec_str(ICE_FEC_BASER)) == 0) {
		new_mode = ICE_FEC_BASER;
	} else if (strcmp(req_fec, "rs") == 0 ||
	    strcmp(req_fec, ice_fec_str(ICE_FEC_RS)) == 0) {
		new_mode = ICE_FEC_RS;
	} else if (strcmp(req_fec, "none") == 0 ||
	    strcmp(req_fec, ice_fec_str(ICE_FEC_NONE)) == 0) {
		new_mode = ICE_FEC_NONE;
	} else {
		device_printf(dev,
		    "%s: \"%s\" is not a valid FEC mode\n",
		    __func__, req_fec);
		return (EINVAL);
	}

	/* Cache user FEC mode for later link ups */
	pi->phy.curr_user_fec_req = new_mode;

	status = ice_aq_get_phy_caps(pi, false, ICE_AQC_REPORT_SW_CFG,
				     &pcaps, NULL);
	if (status != ICE_SUCCESS) {
		device_printf(dev,
		    "%s: ice_aq_get_phy_caps failed (SW_CFG); status %s, aq_err %s\n",
		    __func__, ice_status_str(status),
		    ice_aq_str(hw->adminq.sq_last_status));
		return (EIO);
	}

	ice_copy_phy_caps_to_cfg(pi, &pcaps, &cfg);

	/* Get link_fec_opt/AUTO_FEC mode from TOPO caps for base for new FEC mode */
	memset(&pcaps, 0, sizeof(pcaps));
	status = ice_aq_get_phy_caps(pi, false, ICE_AQC_REPORT_TOPO_CAP,
				     &pcaps, NULL);
	if (status != ICE_SUCCESS) {
		device_printf(dev,
		    "%s: ice_aq_get_phy_caps failed (TOPO_CAP); status %s, aq_err %s\n",
		    __func__, ice_status_str(status),
		    ice_aq_str(hw->adminq.sq_last_status));
		return (EIO);
	}

	/* Configure new FEC options using TOPO caps */
	cfg.link_fec_opt = pcaps.link_fec_options;
	cfg.caps &= ~ICE_AQ_PHY_ENA_AUTO_FEC;
	if (pcaps.caps & ICE_AQC_PHY_EN_AUTO_FEC)
		cfg.caps |= ICE_AQ_PHY_ENA_AUTO_FEC;

	if (ice_is_bit_set(sc->feat_en, ICE_FEATURE_DEFAULT_OVERRIDE) &&
	    new_mode == ICE_FEC_AUTO) {
		/* copy over FEC settings from LDO TLV */
		cfg.link_fec_opt = sc->ldo_tlv.fec_options;
	} else {
		ice_cfg_phy_fec(pi, &cfg, new_mode);

		/* Check if the new mode is valid, and exit with an error if not */
		if (cfg.link_fec_opt &&
		    !(cfg.link_fec_opt & pcaps.link_fec_options)) {
			device_printf(dev,
			    "%s: The requested FEC mode, %s, is not supported by current media\n",
			    __func__, ice_fec_str(new_mode));
			return (ENOTSUP);
		}
	}

	cfg.caps |= ICE_AQ_PHY_ENA_AUTO_LINK_UPDT;
	status = ice_aq_set_phy_cfg(hw, pi, &cfg, NULL);
	if (status != ICE_SUCCESS) {
		/* Don't indicate failure if there's no media in the port -- the sysctl
		 * handler has saved the value and will apply it when media is inserted.
		 */
		if (status == ICE_ERR_AQ_ERROR &&
		    hw->adminq.sq_last_status == ICE_AQ_RC_EBUSY) {
			device_printf(dev,
			    "%s: Setting will be applied when media is inserted\n", __func__);
			return (0);
		} else {
			device_printf(dev,
			    "%s: ice_aq_set_phy_cfg failed; status %s, aq_err %s\n",
			    __func__, ice_status_str(status),
			    ice_aq_str(hw->adminq.sq_last_status));
			return (EIO);
		}
	}

	return (0);
}

/**
 * ice_sysctl_negotiated_fec - Display the negotiated FEC mode on the link
 * @oidp: sysctl oid structure
 * @arg1: pointer to private data structure
 * @arg2: unused
 * @req: sysctl request pointer
 *
 * On read: Displays the negotiated FEC mode, in a string
 */
static int
ice_sysctl_negotiated_fec(SYSCTL_HANDLER_ARGS)
{
	struct ice_softc *sc = (struct ice_softc *)arg1;
	struct ice_hw *hw = &sc->hw;
	char neg_fec[32];
	int error;

	UNREFERENCED_PARAMETER(arg2);

	if (ice_driver_is_detaching(sc))
		return (ESHUTDOWN);

	/* Copy const string into a buffer to drop const qualifier */
	bzero(neg_fec, sizeof(neg_fec));
	strlcpy(neg_fec, ice_negotiated_fec_mode(hw->port_info), sizeof(neg_fec));

	error = sysctl_handle_string(oidp, neg_fec, 0, req);
	if (req->newptr != NULL)
		return (EPERM);

	return (error);
}

#define ICE_SYSCTL_HELP_FC_CONFIG				\
"\nDisplay or set the port's advertised flow control mode.\n"	\
"\t0 - " ICE_FC_STRING_NONE					\
"\n\t1 - " ICE_FC_STRING_RX					\
"\n\t2 - " ICE_FC_STRING_TX					\
"\n\t3 - " ICE_FC_STRING_FULL					\
"\nEither the numbers or the strings above can be used to set the advertised mode."

/**
 * ice_sysctl_fc_config - Display/change the advertised flow control mode
 * @oidp: sysctl oid structure
 * @arg1: pointer to private data structure
 * @arg2: unused
 * @req: sysctl request pointer
 *
 * On read: Displays the configured flow control mode
 * On write: Sets the device's flow control mode to the input, if it's valid.
 * Valid input strings: see ICE_SYSCTL_HELP_FC_CONFIG
 */
static int
ice_sysctl_fc_config(SYSCTL_HANDLER_ARGS)
{
	struct ice_softc *sc = (struct ice_softc *)arg1;
	struct ice_port_info *pi = sc->hw.port_info;
	struct ice_aqc_get_phy_caps_data pcaps = { 0 };
	enum ice_fc_mode old_mode, new_mode;
	struct ice_hw *hw = &sc->hw;
	device_t dev = sc->dev;
	enum ice_status status;
	int error = 0, fc_num;
	bool mode_set = false;
	struct sbuf buf;
	char *fc_str_end;
	char fc_str[32];
	u8 aq_failures;

	UNREFERENCED_PARAMETER(arg2);

	if (ice_driver_is_detaching(sc))
		return (ESHUTDOWN);

	status = ice_aq_get_phy_caps(pi, false, ICE_AQC_REPORT_SW_CFG,
				     &pcaps, NULL);
	if (status != ICE_SUCCESS) {
		device_printf(dev,
		    "%s: ice_aq_get_phy_caps failed; status %s, aq_err %s\n",
		    __func__, ice_status_str(status),
		    ice_aq_str(hw->adminq.sq_last_status));
		return (EIO);
	}

	/* Convert HW response format to SW enum value */
	if ((pcaps.caps & ICE_AQC_PHY_EN_TX_LINK_PAUSE) &&
	    (pcaps.caps & ICE_AQC_PHY_EN_RX_LINK_PAUSE))
		old_mode = ICE_FC_FULL;
	else if (pcaps.caps & ICE_AQC_PHY_EN_TX_LINK_PAUSE)
		old_mode = ICE_FC_TX_PAUSE;
	else if (pcaps.caps & ICE_AQC_PHY_EN_RX_LINK_PAUSE)
		old_mode = ICE_FC_RX_PAUSE;
	else
		old_mode = ICE_FC_NONE;

	/* Create "old" string for output */
	bzero(fc_str, sizeof(fc_str));
	sbuf_new_for_sysctl(&buf, fc_str, sizeof(fc_str), req);
	sbuf_printf(&buf, "%d<%s>", old_mode, ice_fc_str(old_mode));
	sbuf_finish(&buf);
	sbuf_delete(&buf);

	error = sysctl_handle_string(oidp, fc_str, sizeof(fc_str), req);
	if ((error) || (req->newptr == NULL))
		return (error);

	/* Try to parse input as a string, first */
	if (strcasecmp(ice_fc_str(ICE_FC_FULL), fc_str) == 0) {
		new_mode = ICE_FC_FULL;
		mode_set = true;
	}
	else if (strcasecmp(ice_fc_str(ICE_FC_TX_PAUSE), fc_str) == 0) {
		new_mode = ICE_FC_TX_PAUSE;
		mode_set = true;
	}
	else if (strcasecmp(ice_fc_str(ICE_FC_RX_PAUSE), fc_str) == 0) {
		new_mode = ICE_FC_RX_PAUSE;
		mode_set = true;
	}
	else if (strcasecmp(ice_fc_str(ICE_FC_NONE), fc_str) == 0) {
		new_mode = ICE_FC_NONE;
		mode_set = true;
	}

	/*
	 * Then check if it's an integer, for compatibility with the method
	 * used in older drivers.
	 */
	if (!mode_set) {
		fc_num = strtol(fc_str, &fc_str_end, 0);
		if (fc_str_end == fc_str)
			fc_num = -1;
		switch (fc_num) {
		case 3:
			new_mode = ICE_FC_FULL;
			break;
		case 2:
			new_mode = ICE_FC_TX_PAUSE;
			break;
		case 1:
			new_mode = ICE_FC_RX_PAUSE;
			break;
		case 0:
			new_mode = ICE_FC_NONE;
			break;
		default:
			device_printf(dev,
			    "%s: \"%s\" is not a valid flow control mode\n",
			    __func__, fc_str);
			return (EINVAL);
		}
	}

	/* Finally, set the flow control mode in FW */
	hw->port_info->fc.req_mode = new_mode;
	status = ice_set_fc(pi, &aq_failures, true);
	if (status != ICE_SUCCESS) {
		/* Don't indicate failure if there's no media in the port -- the sysctl
		 * handler has saved the value and will apply it when media is inserted.
		 */
		if (aq_failures == ICE_SET_FC_AQ_FAIL_SET &&
		    hw->adminq.sq_last_status == ICE_AQ_RC_EBUSY) {
			device_printf(dev,
			    "%s: Setting will be applied when media is inserted\n", __func__);
			return (0);
		} else {
			device_printf(dev,
			    "%s: ice_set_fc AQ failure = %d\n", __func__, aq_failures);
			return (EIO);
		}
	}

	return (0);
}

/**
 * ice_sysctl_negotiated_fc - Display currently negotiated FC mode
 * @oidp: sysctl oid structure
 * @arg1: pointer to private data structure
 * @arg2: unused
 * @req: sysctl request pointer
 *
 * On read: Displays the currently negotiated flow control settings.
 *
 * If link is not established, this will report ICE_FC_NONE, as no flow
 * control is negotiated while link is down.
 */
static int
ice_sysctl_negotiated_fc(SYSCTL_HANDLER_ARGS)
{
	struct ice_softc *sc = (struct ice_softc *)arg1;
	struct ice_port_info *pi = sc->hw.port_info;
	const char *negotiated_fc;

	UNREFERENCED_PARAMETER(arg2);

	if (ice_driver_is_detaching(sc))
		return (ESHUTDOWN);

	negotiated_fc = ice_flowcontrol_mode(pi);

	return sysctl_handle_string(oidp, __DECONST(char *, negotiated_fc), 0, req);
}

/**
 * __ice_sysctl_phy_type_handler - Display/change supported PHY types/speeds
 * @oidp: sysctl oid structure
 * @arg1: pointer to private data structure
 * @arg2: unused
 * @req: sysctl request pointer
 * @is_phy_type_high: if true, handle the high PHY type instead of the low PHY type
 *
 * Private handler for phy_type_high and phy_type_low sysctls.
 */
static int
__ice_sysctl_phy_type_handler(SYSCTL_HANDLER_ARGS, bool is_phy_type_high)
{
	struct ice_softc *sc = (struct ice_softc *)arg1;
	struct ice_aqc_get_phy_caps_data pcaps = { 0 };
	struct ice_aqc_set_phy_cfg_data cfg = { 0 };
	struct ice_hw *hw = &sc->hw;
	device_t dev = sc->dev;
	enum ice_status status;
	uint64_t types;
	int error = 0;

	UNREFERENCED_PARAMETER(arg2);

	if (ice_driver_is_detaching(sc))
		return (ESHUTDOWN);

	status = ice_aq_get_phy_caps(hw->port_info, false, ICE_AQC_REPORT_SW_CFG,
				     &pcaps, NULL);
	if (status != ICE_SUCCESS) {
		device_printf(dev,
		    "%s: ice_aq_get_phy_caps failed; status %s, aq_err %s\n",
		    __func__, ice_status_str(status),
		    ice_aq_str(hw->adminq.sq_last_status));
		return (EIO);
	}

	if (is_phy_type_high)
		types = pcaps.phy_type_high;
	else
		types = pcaps.phy_type_low;

	error = sysctl_handle_64(oidp, &types, sizeof(types), req);
	if ((error) || (req->newptr == NULL))
		return (error);

	ice_copy_phy_caps_to_cfg(hw->port_info, &pcaps, &cfg);

	if (is_phy_type_high)
		cfg.phy_type_high = types & hw->port_info->phy.phy_type_high;
	else
		cfg.phy_type_low = types & hw->port_info->phy.phy_type_low;
	cfg.caps |= ICE_AQ_PHY_ENA_AUTO_LINK_UPDT;

	status = ice_aq_set_phy_cfg(hw, hw->port_info, &cfg, NULL);
	if (status != ICE_SUCCESS) {
		device_printf(dev,
		    "%s: ice_aq_set_phy_cfg failed; status %s, aq_err %s\n",
		    __func__, ice_status_str(status),
		    ice_aq_str(hw->adminq.sq_last_status));
		return (EIO);
	}

	return (0);

}

/**
 * ice_sysctl_phy_type_low - Display/change supported lower PHY types/speeds
 * @oidp: sysctl oid structure
 * @arg1: pointer to private data structure
 * @arg2: unused
 * @req: sysctl request pointer
 *
 * On read: Displays the currently supported lower PHY types
 * On write: Sets the device's supported low PHY types
 */
static int
ice_sysctl_phy_type_low(SYSCTL_HANDLER_ARGS)
{
	return __ice_sysctl_phy_type_handler(oidp, arg1, arg2, req, false);
}

/**
 * ice_sysctl_phy_type_high - Display/change supported higher PHY types/speeds
 * @oidp: sysctl oid structure
 * @arg1: pointer to private data structure
 * @arg2: unused
 * @req: sysctl request pointer
 *
 * On read: Displays the currently supported higher PHY types
 * On write: Sets the device's supported high PHY types
 */
static int
ice_sysctl_phy_type_high(SYSCTL_HANDLER_ARGS)
{
	return __ice_sysctl_phy_type_handler(oidp, arg1, arg2, req, true);
}

/**
 * ice_sysctl_phy_caps - Display response from Get PHY abililties
 * @oidp: sysctl oid structure
 * @arg1: pointer to private data structure
 * @arg2: unused
 * @req: sysctl request pointer
 * @report_mode: the mode to report
 *
 * On read: Display the response from Get PHY abillities with the given report
 * mode.
 */
static int
ice_sysctl_phy_caps(SYSCTL_HANDLER_ARGS, u8 report_mode)
{
	struct ice_softc *sc = (struct ice_softc *)arg1;
	struct ice_aqc_get_phy_caps_data pcaps = { 0 };
	struct ice_hw *hw = &sc->hw;
	struct ice_port_info *pi = hw->port_info;
	device_t dev = sc->dev;
	enum ice_status status;
	int error;

	UNREFERENCED_PARAMETER(arg2);

	error = priv_check(curthread, PRIV_DRIVER);
	if (error)
		return (error);

	if (ice_driver_is_detaching(sc))
		return (ESHUTDOWN);

	status = ice_aq_get_phy_caps(pi, true, report_mode, &pcaps, NULL);
	if (status != ICE_SUCCESS) {
		device_printf(dev,
		    "%s: ice_aq_get_phy_caps failed; status %s, aq_err %s\n",
		    __func__, ice_status_str(status),
		    ice_aq_str(hw->adminq.sq_last_status));
		return (EIO);
	}

	error = sysctl_handle_opaque(oidp, &pcaps, sizeof(pcaps), req);
	if (req->newptr != NULL)
		return (EPERM);

	return (error);
}

/**
 * ice_sysctl_phy_sw_caps - Display response from Get PHY abililties
 * @oidp: sysctl oid structure
 * @arg1: pointer to private data structure
 * @arg2: unused
 * @req: sysctl request pointer
 *
 * On read: Display the response from Get PHY abillities reporting the last
 * software configuration.
 */
static int
ice_sysctl_phy_sw_caps(SYSCTL_HANDLER_ARGS)
{
	return ice_sysctl_phy_caps(oidp, arg1, arg2, req,
				   ICE_AQC_REPORT_SW_CFG);
}

/**
 * ice_sysctl_phy_nvm_caps - Display response from Get PHY abililties
 * @oidp: sysctl oid structure
 * @arg1: pointer to private data structure
 * @arg2: unused
 * @req: sysctl request pointer
 *
 * On read: Display the response from Get PHY abillities reporting the NVM
 * configuration.
 */
static int
ice_sysctl_phy_nvm_caps(SYSCTL_HANDLER_ARGS)
{
	return ice_sysctl_phy_caps(oidp, arg1, arg2, req,
				   ICE_AQC_REPORT_NVM_CAP);
}

/**
 * ice_sysctl_phy_topo_caps - Display response from Get PHY abililties
 * @oidp: sysctl oid structure
 * @arg1: pointer to private data structure
 * @arg2: unused
 * @req: sysctl request pointer
 *
 * On read: Display the response from Get PHY abillities reporting the
 * topology configuration.
 */
static int
ice_sysctl_phy_topo_caps(SYSCTL_HANDLER_ARGS)
{
	return ice_sysctl_phy_caps(oidp, arg1, arg2, req,
				   ICE_AQC_REPORT_TOPO_CAP);
}

/**
 * ice_sysctl_phy_link_status - Display response from Get Link Status
 * @oidp: sysctl oid structure
 * @arg1: pointer to private data structure
 * @arg2: unused
 * @req: sysctl request pointer
 *
 * On read: Display the response from firmware for the Get Link Status
 * request.
 */
static int
ice_sysctl_phy_link_status(SYSCTL_HANDLER_ARGS)
{
	struct ice_aqc_get_link_status_data link_data = { 0 };
	struct ice_softc *sc = (struct ice_softc *)arg1;
	struct ice_hw *hw = &sc->hw;
	struct ice_port_info *pi = hw->port_info;
	struct ice_aqc_get_link_status *resp;
	struct ice_aq_desc desc;
	device_t dev = sc->dev;
	enum ice_status status;
	int error;

	UNREFERENCED_PARAMETER(arg2);

	/*
	 * Ensure that only contexts with driver privilege are allowed to
	 * access this information
	 */
	error = priv_check(curthread, PRIV_DRIVER);
	if (error)
		return (error);

	if (ice_driver_is_detaching(sc))
		return (ESHUTDOWN);

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_get_link_status);
	resp = &desc.params.get_link_status;
	resp->lport_num = pi->lport;

	status = ice_aq_send_cmd(hw, &desc, &link_data, sizeof(link_data), NULL);
	if (status != ICE_SUCCESS) {
		device_printf(dev,
		    "%s: ice_aq_send_cmd failed; status %s, aq_err %s\n",
		    __func__, ice_status_str(status),
		    ice_aq_str(hw->adminq.sq_last_status));
		return (EIO);
	}

	error = sysctl_handle_opaque(oidp, &link_data, sizeof(link_data), req);
	if (req->newptr != NULL)
		return (EPERM);

	return (error);
}

/**
 * ice_sysctl_fw_cur_lldp_persist_status - Display current FW LLDP status
 * @oidp: sysctl oid structure
 * @arg1: pointer to private softc structure
 * @arg2: unused
 * @req: sysctl request pointer
 *
 * On read: Displays current persistent LLDP status.
 */
static int
ice_sysctl_fw_cur_lldp_persist_status(SYSCTL_HANDLER_ARGS)
{
	struct ice_softc *sc = (struct ice_softc *)arg1;
	struct ice_hw *hw = &sc->hw;
	device_t dev = sc->dev;
	enum ice_status status;
	struct sbuf *sbuf;
	u32 lldp_state;

	UNREFERENCED_PARAMETER(arg2);
	UNREFERENCED_PARAMETER(oidp);

	if (ice_driver_is_detaching(sc))
		return (ESHUTDOWN);

	status = ice_get_cur_lldp_persist_status(hw, &lldp_state);
	if (status) {
		device_printf(dev,
		    "Could not acquire current LLDP persistence status, err %s aq_err %s\n",
		    ice_status_str(status), ice_aq_str(hw->adminq.sq_last_status));
		return (EIO);
	}

	sbuf = sbuf_new_for_sysctl(NULL, NULL, 128, req);
	sbuf_printf(sbuf, "%s", ice_fw_lldp_status(lldp_state));
	sbuf_finish(sbuf);
	sbuf_delete(sbuf);

	return (0);
}

/**
 * ice_sysctl_fw_dflt_lldp_persist_status - Display default FW LLDP status
 * @oidp: sysctl oid structure
 * @arg1: pointer to private softc structure
 * @arg2: unused
 * @req: sysctl request pointer
 *
 * On read: Displays default persistent LLDP status.
 */
static int
ice_sysctl_fw_dflt_lldp_persist_status(SYSCTL_HANDLER_ARGS)
{
	struct ice_softc *sc = (struct ice_softc *)arg1;
	struct ice_hw *hw = &sc->hw;
	device_t dev = sc->dev;
	enum ice_status status;
	struct sbuf *sbuf;
	u32 lldp_state;

	UNREFERENCED_PARAMETER(arg2);
	UNREFERENCED_PARAMETER(oidp);

	if (ice_driver_is_detaching(sc))
		return (ESHUTDOWN);

	status = ice_get_dflt_lldp_persist_status(hw, &lldp_state);
	if (status) {
		device_printf(dev,
		    "Could not acquire default LLDP persistence status, err %s aq_err %s\n",
		    ice_status_str(status), ice_aq_str(hw->adminq.sq_last_status));
		return (EIO);
	}

	sbuf = sbuf_new_for_sysctl(NULL, NULL, 128, req);
	sbuf_printf(sbuf, "%s", ice_fw_lldp_status(lldp_state));
	sbuf_finish(sbuf);
	sbuf_delete(sbuf);

	return (0);
}

#define ICE_SYSCTL_HELP_FW_LLDP_AGENT	\
"\nDisplay or change FW LLDP agent state:" \
"\n\t0 - disabled"			\
"\n\t1 - enabled"

/**
 * ice_sysctl_fw_lldp_agent - Display or change the FW LLDP agent status
 * @oidp: sysctl oid structure
 * @arg1: pointer to private softc structure
 * @arg2: unused
 * @req: sysctl request pointer
 *
 * On read: Displays whether the FW LLDP agent is running
 * On write: Persistently enables or disables the FW LLDP agent
 */
static int
ice_sysctl_fw_lldp_agent(SYSCTL_HANDLER_ARGS)
{
	struct ice_softc *sc = (struct ice_softc *)arg1;
	struct ice_hw *hw = &sc->hw;
	device_t dev = sc->dev;
	enum ice_status status;
	int error = 0;
	u32 old_state;
	u8 fw_lldp_enabled;
	bool retried_start_lldp = false;

	UNREFERENCED_PARAMETER(arg2);

	if (ice_driver_is_detaching(sc))
		return (ESHUTDOWN);

	status = ice_get_cur_lldp_persist_status(hw, &old_state);
	if (status) {
		device_printf(dev,
		    "Could not acquire current LLDP persistence status, err %s aq_err %s\n",
		    ice_status_str(status), ice_aq_str(hw->adminq.sq_last_status));
		return (EIO);
	}

	if (old_state > ICE_LLDP_ADMINSTATUS_ENA_RXTX) {
		status = ice_get_dflt_lldp_persist_status(hw, &old_state);
		if (status) {
			device_printf(dev,
			    "Could not acquire default LLDP persistence status, err %s aq_err %s\n",
			    ice_status_str(status),
			    ice_aq_str(hw->adminq.sq_last_status));
			return (EIO);
		}
	}
	if (old_state == 0)
		fw_lldp_enabled = false;
	else
		fw_lldp_enabled = true;

	error = sysctl_handle_bool(oidp, &fw_lldp_enabled, 0, req);
	if ((error) || (req->newptr == NULL))
		return (error);

	if (old_state == 0 && fw_lldp_enabled == false)
		return (0);

	if (old_state != 0 && fw_lldp_enabled == true)
		return (0);

	if (fw_lldp_enabled == false) {
		status = ice_aq_stop_lldp(hw, true, true, NULL);
		/* EPERM is returned if the LLDP agent is already shutdown */
		if (status && hw->adminq.sq_last_status != ICE_AQ_RC_EPERM) {
			device_printf(dev,
			    "%s: ice_aq_stop_lldp failed; status %s, aq_err %s\n",
			    __func__, ice_status_str(status),
			    ice_aq_str(hw->adminq.sq_last_status));
			return (EIO);
		}
		ice_aq_set_dcb_parameters(hw, true, NULL);
		hw->port_info->is_sw_lldp = true;
		ice_add_rx_lldp_filter(sc);
	} else {
retry_start_lldp:
		status = ice_aq_start_lldp(hw, true, NULL);
		if (status) {
			switch (hw->adminq.sq_last_status) {
			/* EEXIST is returned if the LLDP agent is already started */
			case ICE_AQ_RC_EEXIST:
				break;
			case ICE_AQ_RC_EAGAIN:
				/* Retry command after a 2 second wait */
				if (retried_start_lldp == false) {
					retried_start_lldp = true;
					pause("slldp", ICE_START_LLDP_RETRY_WAIT);
					goto retry_start_lldp;
				}
				/* Fallthrough */
			default:
				device_printf(dev,
				    "%s: ice_aq_start_lldp failed; status %s, aq_err %s\n",
				    __func__, ice_status_str(status),
				    ice_aq_str(hw->adminq.sq_last_status));
				return (EIO);
			}
		}
		hw->port_info->is_sw_lldp = false;
		ice_del_rx_lldp_filter(sc);
	}

	return (error);
}

/**
 * ice_add_device_sysctls - add device specific dynamic sysctls
 * @sc: device private structure
 *
 * Add per-device dynamic sysctls which show device configuration or enable
 * configuring device functionality. For tunable values which can be set prior
 * to load, see ice_add_device_tunables.
 *
 * This function depends on the sysctl layout setup by ice_add_device_tunables,
 * and likely should be called near the end of the attach process.
 */
void
ice_add_device_sysctls(struct ice_softc *sc)
{
	struct sysctl_oid *hw_node;
	device_t dev = sc->dev;

	struct sysctl_ctx_list *ctx = device_get_sysctl_ctx(dev);
	struct sysctl_oid_list *ctx_list =
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev));

	SYSCTL_ADD_PROC(ctx, ctx_list,
	    OID_AUTO, "fw_version", CTLTYPE_STRING | CTLFLAG_RD,
	    sc, 0, ice_sysctl_show_fw, "A", "Firmware version");

	SYSCTL_ADD_PROC(ctx, ctx_list,
	    OID_AUTO, "pba_number", CTLTYPE_STRING | CTLFLAG_RD,
	    sc, 0, ice_sysctl_pba_number, "A", "Product Board Assembly Number");

	SYSCTL_ADD_PROC(ctx, ctx_list,
	    OID_AUTO, "ddp_version", CTLTYPE_STRING | CTLFLAG_RD,
	    sc, 0, ice_sysctl_pkg_version, "A", "Active DDP package name and version");

	SYSCTL_ADD_PROC(ctx, ctx_list,
	    OID_AUTO, "current_speed", CTLTYPE_STRING | CTLFLAG_RD,
	    sc, 0, ice_sysctl_current_speed, "A", "Current Port Link Speed");

	SYSCTL_ADD_PROC(ctx, ctx_list,
	    OID_AUTO, "requested_fec", CTLTYPE_STRING | CTLFLAG_RW,
	    sc, 0, ice_sysctl_fec_config, "A", ICE_SYSCTL_HELP_FEC_CONFIG);

	SYSCTL_ADD_PROC(ctx, ctx_list,
	    OID_AUTO, "negotiated_fec", CTLTYPE_STRING | CTLFLAG_RD,
	    sc, 0, ice_sysctl_negotiated_fec, "A", "Current Negotiated FEC mode");

	SYSCTL_ADD_PROC(ctx, ctx_list,
	    OID_AUTO, "fc", CTLTYPE_STRING | CTLFLAG_RW,
	    sc, 0, ice_sysctl_fc_config, "A", ICE_SYSCTL_HELP_FC_CONFIG);

	SYSCTL_ADD_PROC(ctx, ctx_list,
	    OID_AUTO, "advertise_speed", CTLTYPE_U16 | CTLFLAG_RW,
	    sc, 0, ice_sysctl_advertise_speed, "SU", ICE_SYSCTL_HELP_ADVERTISE_SPEED);

	SYSCTL_ADD_PROC(ctx, ctx_list,
	    OID_AUTO, "fw_lldp_agent", CTLTYPE_U8 | CTLFLAG_RWTUN,
	    sc, 0, ice_sysctl_fw_lldp_agent, "CU", ICE_SYSCTL_HELP_FW_LLDP_AGENT);

	/* Differentiate software and hardware statistics, by keeping hw stats
	 * in their own node. This isn't in ice_add_device_tunables, because
	 * we won't have any CTLFLAG_TUN sysctls under this node.
	 */
	hw_node = SYSCTL_ADD_NODE(ctx, ctx_list, OID_AUTO, "hw", CTLFLAG_RD,
				  NULL, "Port Hardware Statistics");

	ice_add_sysctls_mac_stats(ctx, hw_node, &sc->stats.cur);

	/* Add the main PF VSI stats now. Other VSIs will add their own stats
	 * during creation
	 */
	ice_add_vsi_sysctls(&sc->pf_vsi);

	/* Add sysctls related to debugging the device driver. This includes
	 * sysctls which display additional internal driver state for use in
	 * understanding what is happening within the driver.
	 */
	ice_add_debug_sysctls(sc);
}

/**
 * @enum hmc_error_type
 * @brief enumeration of HMC errors
 *
 * Enumeration defining the possible HMC errors that might occur.
 */
enum hmc_error_type {
	HMC_ERR_PMF_INVALID = 0,
	HMC_ERR_VF_IDX_INVALID = 1,
	HMC_ERR_VF_PARENT_PF_INVALID = 2,
	/* 3 is reserved */
	HMC_ERR_INDEX_TOO_BIG = 4,
	HMC_ERR_ADDRESS_TOO_LARGE = 5,
	HMC_ERR_SEGMENT_DESC_INVALID = 6,
	HMC_ERR_SEGMENT_DESC_TOO_SMALL = 7,
	HMC_ERR_PAGE_DESC_INVALID = 8,
	HMC_ERR_UNSUPPORTED_REQUEST_COMPLETION = 9,
	/* 10 is reserved */
	HMC_ERR_INVALID_OBJECT_TYPE = 11,
	/* 12 is reserved */
};

/**
 * ice_log_hmc_error - Log an HMC error message
 * @hw: device hw structure
 * @dev: the device to pass to device_printf()
 *
 * Log a message when an HMC error interrupt is triggered.
 */
void
ice_log_hmc_error(struct ice_hw *hw, device_t dev)
{
	u32 info, data;
	u8 index, errtype, objtype;
	bool isvf;

	info = rd32(hw, PFHMC_ERRORINFO);
	data = rd32(hw, PFHMC_ERRORDATA);

	index = (u8)(info & PFHMC_ERRORINFO_PMF_INDEX_M);
	errtype = (u8)((info & PFHMC_ERRORINFO_HMC_ERROR_TYPE_M) >>
		       PFHMC_ERRORINFO_HMC_ERROR_TYPE_S);
	objtype = (u8)((info & PFHMC_ERRORINFO_HMC_OBJECT_TYPE_M) >>
		       PFHMC_ERRORINFO_HMC_OBJECT_TYPE_S);

	isvf = info & PFHMC_ERRORINFO_PMF_ISVF_M;

	device_printf(dev, "%s HMC Error detected on PMF index %d:\n",
		      isvf ? "VF" : "PF", index);

	device_printf(dev, "error type %d, object type %d, data 0x%08x\n",
		      errtype, objtype, data);

	switch (errtype) {
	case HMC_ERR_PMF_INVALID:
		device_printf(dev, "Private Memory Function is not valid\n");
		break;
	case HMC_ERR_VF_IDX_INVALID:
		device_printf(dev, "Invalid Private Memory Function index for PE enabled VF\n");
		break;
	case HMC_ERR_VF_PARENT_PF_INVALID:
		device_printf(dev, "Invalid parent PF for PE enabled VF\n");
		break;
	case HMC_ERR_INDEX_TOO_BIG:
		device_printf(dev, "Object index too big\n");
		break;
	case HMC_ERR_ADDRESS_TOO_LARGE:
		device_printf(dev, "Address extends beyond segment descriptor limit\n");
		break;
	case HMC_ERR_SEGMENT_DESC_INVALID:
		device_printf(dev, "Segment descriptor is invalid\n");
		break;
	case HMC_ERR_SEGMENT_DESC_TOO_SMALL:
		device_printf(dev, "Segment descriptor is too small\n");
		break;
	case HMC_ERR_PAGE_DESC_INVALID:
		device_printf(dev, "Page descriptor is invalid\n");
		break;
	case HMC_ERR_UNSUPPORTED_REQUEST_COMPLETION:
		device_printf(dev, "Unsupported Request completion received from PCIe\n");
		break;
	case HMC_ERR_INVALID_OBJECT_TYPE:
		device_printf(dev, "Invalid object type\n");
		break;
	default:
		device_printf(dev, "Unknown HMC error\n");
	}

	/* Clear the error indication */
	wr32(hw, PFHMC_ERRORINFO, 0);
}

/**
 * @struct ice_sysctl_info
 * @brief sysctl information
 *
 * Structure used to simplify the process of defining the many similar
 * statistics sysctls.
 */
struct ice_sysctl_info {
	u64		*stat;
	const char	*name;
	const char	*description;
};

/**
 * ice_add_sysctls_eth_stats - Add sysctls for ethernet statistics
 * @ctx: sysctl ctx to use
 * @parent: the parent node to add sysctls under
 * @stats: the ethernet stats structure to source values from
 *
 * Adds statistics sysctls for the ethernet statistics of the MAC or a VSI.
 * Will add them under the parent node specified.
 *
 * Note that rx_discards and tx_errors are only meaningful for VSIs and not
 * the global MAC/PF statistics, so they are not included here.
 */
void
ice_add_sysctls_eth_stats(struct sysctl_ctx_list *ctx,
			  struct sysctl_oid *parent,
			  struct ice_eth_stats *stats)
{
	const struct ice_sysctl_info ctls[] = {
		/* Rx Stats */
		{ &stats->rx_bytes, "good_octets_rcvd", "Good Octets Received" },
		{ &stats->rx_unicast, "ucast_pkts_rcvd", "Unicast Packets Received" },
		{ &stats->rx_multicast, "mcast_pkts_rcvd", "Multicast Packets Received" },
		{ &stats->rx_broadcast, "bcast_pkts_rcvd", "Broadcast Packets Received" },
		/* Tx Stats */
		{ &stats->tx_bytes, "good_octets_txd", "Good Octets Transmitted" },
		{ &stats->tx_unicast, "ucast_pkts_txd", "Unicast Packets Transmitted" },
		{ &stats->tx_multicast, "mcast_pkts_txd", "Multicast Packets Transmitted" },
		{ &stats->tx_broadcast, "bcast_pkts_txd", "Broadcast Packets Transmitted" },
		/* End */
		{ 0, 0, 0 }
	};

	struct sysctl_oid_list *parent_list = SYSCTL_CHILDREN(parent);

	const struct ice_sysctl_info *entry = ctls;
	while (entry->stat != 0) {
		SYSCTL_ADD_U64(ctx, parent_list, OID_AUTO, entry->name,
			       CTLFLAG_RD | CTLFLAG_STATS, entry->stat, 0,
			       entry->description);
		entry++;
	}
}

/**
 * ice_sysctl_tx_cso_stat - Display Tx checksum offload statistic
 * @oidp: sysctl oid structure
 * @arg1: pointer to private data structure
 * @arg2: Tx CSO stat to read
 * @req: sysctl request pointer
 *
 * On read: Sums the per-queue Tx CSO stat and displays it.
 */
static int
ice_sysctl_tx_cso_stat(SYSCTL_HANDLER_ARGS)
{
	struct ice_vsi *vsi = (struct ice_vsi *)arg1;
	enum ice_tx_cso_stat type = (enum ice_tx_cso_stat)arg2;
	u64 stat = 0;
	int i;

	if (ice_driver_is_detaching(vsi->sc))
		return (ESHUTDOWN);

	/* Check that the type is valid */
	if (type >= ICE_CSO_STAT_TX_COUNT)
		return (EDOOFUS);

	/* Sum the stat for each of the Tx queues */
	for (i = 0; i < vsi->num_tx_queues; i++)
		stat += vsi->tx_queues[i].stats.cso[type];

	return sysctl_handle_64(oidp, NULL, stat, req);
}

/**
 * ice_sysctl_rx_cso_stat - Display Rx checksum offload statistic
 * @oidp: sysctl oid structure
 * @arg1: pointer to private data structure
 * @arg2: Rx CSO stat to read
 * @req: sysctl request pointer
 *
 * On read: Sums the per-queue Rx CSO stat and displays it.
 */
static int
ice_sysctl_rx_cso_stat(SYSCTL_HANDLER_ARGS)
{
	struct ice_vsi *vsi = (struct ice_vsi *)arg1;
	enum ice_rx_cso_stat type = (enum ice_rx_cso_stat)arg2;
	u64 stat = 0;
	int i;

	if (ice_driver_is_detaching(vsi->sc))
		return (ESHUTDOWN);

	/* Check that the type is valid */
	if (type >= ICE_CSO_STAT_RX_COUNT)
		return (EDOOFUS);

	/* Sum the stat for each of the Rx queues */
	for (i = 0; i < vsi->num_rx_queues; i++)
		stat += vsi->rx_queues[i].stats.cso[type];

	return sysctl_handle_64(oidp, NULL, stat, req);
}

/**
 * @struct ice_rx_cso_stat_info
 * @brief sysctl information for an Rx checksum offload statistic
 *
 * Structure used to simplify the process of defining the checksum offload
 * statistics.
 */
struct ice_rx_cso_stat_info {
	enum ice_rx_cso_stat	type;
	const char		*name;
	const char		*description;
};

/**
 * @struct ice_tx_cso_stat_info
 * @brief sysctl information for a Tx checksum offload statistic
 *
 * Structure used to simplify the process of defining the checksum offload
 * statistics.
 */
struct ice_tx_cso_stat_info {
	enum ice_tx_cso_stat	type;
	const char		*name;
	const char		*description;
};

/**
 * ice_add_sysctls_sw_stats - Add sysctls for software statistics
 * @vsi: pointer to the VSI to add sysctls for
 * @ctx: sysctl ctx to use
 * @parent: the parent node to add sysctls under
 *
 * Add statistics sysctls for software tracked statistics of a VSI.
 *
 * Currently this only adds checksum offload statistics, but more counters may
 * be added in the future.
 */
static void
ice_add_sysctls_sw_stats(struct ice_vsi *vsi,
			 struct sysctl_ctx_list *ctx,
			 struct sysctl_oid *parent)
{
	struct sysctl_oid *cso_node;
	struct sysctl_oid_list *cso_list;

	/* Tx CSO Stats */
	const struct ice_tx_cso_stat_info tx_ctls[] = {
		{ ICE_CSO_STAT_TX_TCP, "tx_tcp", "Transmit TCP Packets marked for HW checksum" },
		{ ICE_CSO_STAT_TX_UDP, "tx_udp", "Transmit UDP Packets marked for HW checksum" },
		{ ICE_CSO_STAT_TX_SCTP, "tx_sctp", "Transmit SCTP Packets marked for HW checksum" },
		{ ICE_CSO_STAT_TX_IP4, "tx_ip4", "Transmit IPv4 Packets marked for HW checksum" },
		{ ICE_CSO_STAT_TX_IP6, "tx_ip6", "Transmit IPv6 Packets marked for HW checksum" },
		{ ICE_CSO_STAT_TX_L3_ERR, "tx_l3_err", "Transmit packets that driver failed to set L3 HW CSO bits for" },
		{ ICE_CSO_STAT_TX_L4_ERR, "tx_l4_err", "Transmit packets that driver failed to set L4 HW CSO bits for" },
		/* End */
		{ ICE_CSO_STAT_TX_COUNT, 0, 0 }
	};

	/* Rx CSO Stats */
	const struct ice_rx_cso_stat_info rx_ctls[] = {
		{ ICE_CSO_STAT_RX_IP4_ERR, "rx_ip4_err", "Received packets with invalid IPv4 checksum indicated by HW" },
		{ ICE_CSO_STAT_RX_IP6_ERR, "rx_ip6_err", "Received IPv6 packets with extension headers" },
		{ ICE_CSO_STAT_RX_L3_ERR, "rx_l3_err", "Received packets with an unexpected invalid L3 checksum indicated by HW" },
		{ ICE_CSO_STAT_RX_TCP_ERR, "rx_tcp_err", "Received packets with invalid TCP checksum indicated by HW" },
		{ ICE_CSO_STAT_RX_UDP_ERR, "rx_udp_err", "Received packets with invalid UDP checksum indicated by HW" },
		{ ICE_CSO_STAT_RX_SCTP_ERR, "rx_sctp_err", "Received packets with invalid SCTP checksum indicated by HW" },
		{ ICE_CSO_STAT_RX_L4_ERR, "rx_l4_err", "Received packets with an unexpected invalid L4 checksum indicated by HW" },
		/* End */
		{ ICE_CSO_STAT_RX_COUNT, 0, 0 }
	};

	struct sysctl_oid_list *parent_list = SYSCTL_CHILDREN(parent);

	/* Add a node for statistics tracked by software. */
	cso_node = SYSCTL_ADD_NODE(ctx, parent_list, OID_AUTO, "cso", CTLFLAG_RD,
				  NULL, "Checksum offload Statistics");
	cso_list = SYSCTL_CHILDREN(cso_node);

	const struct ice_tx_cso_stat_info *tx_entry = tx_ctls;
	while (tx_entry->name && tx_entry->description) {
		SYSCTL_ADD_PROC(ctx, cso_list, OID_AUTO, tx_entry->name,
				CTLTYPE_U64 | CTLFLAG_RD | CTLFLAG_STATS,
				vsi, tx_entry->type, ice_sysctl_tx_cso_stat, "QU",
				tx_entry->description);
		tx_entry++;
	}

	const struct ice_rx_cso_stat_info *rx_entry = rx_ctls;
	while (rx_entry->name && rx_entry->description) {
		SYSCTL_ADD_PROC(ctx, cso_list, OID_AUTO, rx_entry->name,
				CTLTYPE_U64 | CTLFLAG_RD | CTLFLAG_STATS,
				vsi, rx_entry->type, ice_sysctl_rx_cso_stat, "QU",
				rx_entry->description);
		rx_entry++;
	}
}

/**
 * ice_add_vsi_sysctls - Add sysctls for a VSI
 * @vsi: pointer to VSI structure
 *
 * Add various sysctls for a given VSI.
 */
void
ice_add_vsi_sysctls(struct ice_vsi *vsi)
{
	struct sysctl_ctx_list *ctx = &vsi->ctx;
	struct sysctl_oid *hw_node, *sw_node;
	struct sysctl_oid_list *vsi_list, *hw_list, *sw_list;

	vsi_list = SYSCTL_CHILDREN(vsi->vsi_node);

	/* Keep hw stats in their own node. */
	hw_node = SYSCTL_ADD_NODE(ctx, vsi_list, OID_AUTO, "hw", CTLFLAG_RD,
				  NULL, "VSI Hardware Statistics");
	hw_list = SYSCTL_CHILDREN(hw_node);

	/* Add the ethernet statistics for this VSI */
	ice_add_sysctls_eth_stats(ctx, hw_node, &vsi->hw_stats.cur);

	SYSCTL_ADD_U64(ctx, hw_list, OID_AUTO, "rx_discards",
			CTLFLAG_RD | CTLFLAG_STATS, &vsi->hw_stats.cur.rx_discards,
			0, "Discarded Rx Packets");

	SYSCTL_ADD_U64(ctx, hw_list, OID_AUTO, "rx_errors",
		       CTLFLAG_RD | CTLFLAG_STATS, &vsi->hw_stats.cur.rx_errors,
		       0, "Rx Packets Discarded Due To Error");

	SYSCTL_ADD_U64(ctx, hw_list, OID_AUTO, "rx_no_desc",
		       CTLFLAG_RD | CTLFLAG_STATS, &vsi->hw_stats.cur.rx_no_desc,
		       0, "Rx Packets Discarded Due To Lack Of Descriptors");

	SYSCTL_ADD_U64(ctx, hw_list, OID_AUTO, "tx_errors",
			CTLFLAG_RD | CTLFLAG_STATS, &vsi->hw_stats.cur.tx_errors,
			0, "Tx Packets Discarded Due To Error");

	/* Add a node for statistics tracked by software. */
	sw_node = SYSCTL_ADD_NODE(ctx, vsi_list, OID_AUTO, "sw", CTLFLAG_RD,
				  NULL, "VSI Software Statistics");
	sw_list = SYSCTL_CHILDREN(sw_node);

	ice_add_sysctls_sw_stats(vsi, ctx, sw_node);
}

/**
 * ice_add_sysctls_mac_stats - Add sysctls for global MAC statistics
 * @ctx: the sysctl ctx to use
 * @parent: parent node to add the sysctls under
 * @stats: the hw ports stat structure to pull values from
 *
 * Add global MAC statistics sysctls.
 */
void
ice_add_sysctls_mac_stats(struct sysctl_ctx_list *ctx,
			  struct sysctl_oid *parent,
			  struct ice_hw_port_stats *stats)
{
	struct sysctl_oid *mac_node;
	struct sysctl_oid_list *parent_list, *mac_list;

	parent_list = SYSCTL_CHILDREN(parent);

	mac_node = SYSCTL_ADD_NODE(ctx, parent_list, OID_AUTO, "mac", CTLFLAG_RD,
				   NULL, "Mac Hardware Statistics");
	mac_list = SYSCTL_CHILDREN(mac_node);

	/* add the common ethernet statistics */
	ice_add_sysctls_eth_stats(ctx, mac_node, &stats->eth);

	const struct ice_sysctl_info ctls[] = {
		/* Packet Reception Stats */
		{&stats->rx_size_64, "rx_frames_64", "64 byte frames received"},
		{&stats->rx_size_127, "rx_frames_65_127", "65-127 byte frames received"},
		{&stats->rx_size_255, "rx_frames_128_255", "128-255 byte frames received"},
		{&stats->rx_size_511, "rx_frames_256_511", "256-511 byte frames received"},
		{&stats->rx_size_1023, "rx_frames_512_1023", "512-1023 byte frames received"},
		{&stats->rx_size_1522, "rx_frames_1024_1522", "1024-1522 byte frames received"},
		{&stats->rx_size_big, "rx_frames_big", "1523-9522 byte frames received"},
		{&stats->rx_undersize, "rx_undersize", "Undersized packets received"},
		{&stats->rx_fragments, "rx_fragmented", "Fragmented packets received"},
		{&stats->rx_oversize, "rx_oversized", "Oversized packets received"},
		{&stats->rx_jabber, "rx_jabber", "Received Jabber"},
		{&stats->rx_len_errors, "rx_length_errors", "Receive Length Errors"},
		/* Packet Transmission Stats */
		{&stats->tx_size_64, "tx_frames_64", "64 byte frames transmitted"},
		{&stats->tx_size_127, "tx_frames_65_127", "65-127 byte frames transmitted"},
		{&stats->tx_size_255, "tx_frames_128_255", "128-255 byte frames transmitted"},
		{&stats->tx_size_511, "tx_frames_256_511", "256-511 byte frames transmitted"},
		{&stats->tx_size_1023, "tx_frames_512_1023", "512-1023 byte frames transmitted"},
		{&stats->tx_size_1522, "tx_frames_1024_1522", "1024-1522 byte frames transmitted"},
		{&stats->tx_size_big, "tx_frames_big", "1523-9522 byte frames transmitted"},
		{&stats->tx_dropped_link_down, "tx_dropped", "Tx Dropped Due To Link Down"},
		/* Flow control */
		{&stats->link_xon_tx, "xon_txd", "Link XON transmitted"},
		{&stats->link_xon_rx, "xon_recvd", "Link XON received"},
		{&stats->link_xoff_tx, "xoff_txd", "Link XOFF transmitted"},
		{&stats->link_xoff_rx, "xoff_recvd", "Link XOFF received"},
		/* Other */
		{&stats->crc_errors, "crc_errors", "CRC Errors"},
		{&stats->illegal_bytes, "illegal_bytes", "Illegal Byte Errors"},
		{&stats->mac_local_faults, "local_faults", "MAC Local Faults"},
		{&stats->mac_remote_faults, "remote_faults", "MAC Remote Faults"},
		/* End */
		{ 0, 0, 0 }
	};

	const struct ice_sysctl_info *entry = ctls;
	while (entry->stat != 0) {
		SYSCTL_ADD_U64(ctx, mac_list, OID_AUTO, entry->name,
			CTLFLAG_RD | CTLFLAG_STATS, entry->stat, 0,
			entry->description);
		entry++;
	}
}

/**
 * ice_configure_misc_interrupts - enable 'other' interrupt causes
 * @sc: pointer to device private softc
 *
 * Enable various "other" interrupt causes, and associate them to interrupt 0,
 * which is our administrative interrupt.
 */
void
ice_configure_misc_interrupts(struct ice_softc *sc)
{
	struct ice_hw *hw = &sc->hw;
	u32 val;

	/* Read the OICR register to clear it */
	rd32(hw, PFINT_OICR);

	/* Enable useful "other" interrupt causes */
	val = (PFINT_OICR_ECC_ERR_M |
	       PFINT_OICR_MAL_DETECT_M |
	       PFINT_OICR_GRST_M |
	       PFINT_OICR_PCI_EXCEPTION_M |
	       PFINT_OICR_VFLR_M |
	       PFINT_OICR_HMC_ERR_M |
	       PFINT_OICR_PE_CRITERR_M);

	wr32(hw, PFINT_OICR_ENA, val);

	/* Note that since we're using MSI-X index 0, and ITR index 0, we do
	 * not explicitly program them when writing to the PFINT_*_CTL
	 * registers. Nevertheless, these writes are associating the
	 * interrupts with the ITR 0 vector
	 */

	/* Associate the OICR interrupt with ITR 0, and enable it */
	wr32(hw, PFINT_OICR_CTL, PFINT_OICR_CTL_CAUSE_ENA_M);

	/* Associate the Mailbox interrupt with ITR 0, and enable it */
	wr32(hw, PFINT_MBX_CTL, PFINT_MBX_CTL_CAUSE_ENA_M);

	/* Associate the AdminQ interrupt with ITR 0, and enable it */
	wr32(hw, PFINT_FW_CTL, PFINT_FW_CTL_CAUSE_ENA_M);
}

/**
 * ice_filter_is_mcast - Check if info is a multicast filter
 * @vsi: vsi structure addresses are targeted towards
 * @info: filter info
 *
 * @returns true if the provided info is a multicast filter, and false
 * otherwise.
 */
static bool
ice_filter_is_mcast(struct ice_vsi *vsi, struct ice_fltr_info *info)
{
	const u8 *addr = info->l_data.mac.mac_addr;

	/*
	 * Check if this info matches a multicast filter added by
	 * ice_add_mac_to_list
	 */
	if ((info->flag == ICE_FLTR_TX) &&
	    (info->src_id == ICE_SRC_ID_VSI) &&
	    (info->lkup_type == ICE_SW_LKUP_MAC) &&
	    (info->vsi_handle == vsi->idx) &&
	    ETHER_IS_MULTICAST(addr) && !ETHER_IS_BROADCAST(addr))
		return true;

	return false;
}

/**
 * @struct ice_mcast_sync_data
 * @brief data used by ice_sync_one_mcast_filter function
 *
 * Structure used to store data needed for processing by the
 * ice_sync_one_mcast_filter. This structure contains a linked list of filters
 * to be added, an error indication, and a pointer to the device softc.
 */
struct ice_mcast_sync_data {
	struct ice_list_head add_list;
	struct ice_softc *sc;
	int err;
};

/**
 * ice_sync_one_mcast_filter - Check if we need to program the filter
 * @p: void pointer to algorithm data
 * @sdl: link level socket address
 * @count: unused count value
 *
 * Called by if_foreach_llmaddr to operate on each filter in the ifp filter
 * list. For the given address, search our internal list to see if we have
 * found the filter. If not, add it to our list of filters that need to be
 * programmed.
 *
 * @returns (1) if we've actually setup the filter to be added
 */
static u_int
ice_sync_one_mcast_filter(void *p, struct sockaddr_dl *sdl,
			  u_int __unused count)
{
	struct ice_mcast_sync_data *data = (struct ice_mcast_sync_data *)p;
	struct ice_softc *sc = data->sc;
	struct ice_hw *hw = &sc->hw;
	struct ice_switch_info *sw = hw->switch_info;
	const u8 *sdl_addr = (const u8 *)LLADDR(sdl);
	struct ice_fltr_mgmt_list_entry *itr;
	struct ice_list_head *rules;
	int err;

	rules = &sw->recp_list[ICE_SW_LKUP_MAC].filt_rules;

	/*
	 * If a previous filter already indicated an error, there is no need
	 * for us to finish processing the rest of the filters.
	 */
	if (data->err)
		return (0);

	/* See if this filter has already been programmed */
	LIST_FOR_EACH_ENTRY(itr, rules, ice_fltr_mgmt_list_entry, list_entry) {
		struct ice_fltr_info *info = &itr->fltr_info;
		const u8 *addr = info->l_data.mac.mac_addr;

		/* Only check multicast filters */
		if (!ice_filter_is_mcast(&sc->pf_vsi, info))
			continue;

		/*
		 * If this filter matches, mark the internal filter as
		 * "found", and exit.
		 */
		if (bcmp(addr, sdl_addr, ETHER_ADDR_LEN) == 0) {
			itr->marker = ICE_FLTR_FOUND;
			return (1);
		}
	}

	/*
	 * If we failed to locate the filter in our internal list, we need to
	 * place it into our add list.
	 */
	err = ice_add_mac_to_list(&sc->pf_vsi, &data->add_list, sdl_addr,
				  ICE_FWD_TO_VSI);
	if (err) {
		device_printf(sc->dev,
			      "Failed to place MAC %6D onto add list, err %s\n",
			      sdl_addr, ":", ice_err_str(err));
		data->err = err;

		return (0);
	}

	return (1);
}

/**
 * ice_sync_multicast_filters - Synchronize OS and internal filter list
 * @sc: device private structure
 *
 * Called in response to SIOCDELMULTI to synchronize the operating system
 * multicast address list with the internal list of filters programmed to
 * firmware.
 *
 * Works in one phase to find added and deleted filters using a marker bit on
 * the internal list.
 *
 * First, a loop over the internal list clears the marker bit. Second, for
 * each filter in the ifp list is checked. If we find it in the internal list,
 * the marker bit is set. Otherwise, the filter is added to the add list.
 * Third, a loop over the internal list determines if any filters have not
 * been found. Each of these is added to the delete list. Finally, the add and
 * delete lists are programmed to firmware to update the filters.
 *
 * @returns zero on success or an integer error code on failure.
 */
int
ice_sync_multicast_filters(struct ice_softc *sc)
{
	struct ice_hw *hw = &sc->hw;
	struct ice_switch_info *sw = hw->switch_info;
	struct ice_fltr_mgmt_list_entry *itr;
	struct ice_mcast_sync_data data = {};
	struct ice_list_head *rules, remove_list;
	enum ice_status status;
	int err = 0;

	INIT_LIST_HEAD(&data.add_list);
	INIT_LIST_HEAD(&remove_list);
	data.sc = sc;
	data.err = 0;

	rules = &sw->recp_list[ICE_SW_LKUP_MAC].filt_rules;

	/* Acquire the lock for the entire duration */
	ice_acquire_lock(&sw->recp_list[ICE_SW_LKUP_MAC].filt_rule_lock);

	/* (1) Reset the marker state for all filters */
	LIST_FOR_EACH_ENTRY(itr, rules, ice_fltr_mgmt_list_entry, list_entry)
		itr->marker = ICE_FLTR_NOT_FOUND;

	/* (2) determine which filters need to be added and removed */
	if_foreach_llmaddr(sc->ifp, ice_sync_one_mcast_filter, (void *)&data);
	if (data.err) {
		/* ice_sync_one_mcast_filter already prints an error */
		err = data.err;
		ice_release_lock(&sw->recp_list[ICE_SW_LKUP_MAC].filt_rule_lock);
		goto free_filter_lists;
	}

	LIST_FOR_EACH_ENTRY(itr, rules, ice_fltr_mgmt_list_entry, list_entry) {
		struct ice_fltr_info *info = &itr->fltr_info;
		const u8 *addr = info->l_data.mac.mac_addr;

		/* Only check multicast filters */
		if (!ice_filter_is_mcast(&sc->pf_vsi, info))
			continue;

		/*
		 * If the filter is not marked as found, then it must no
		 * longer be in the ifp address list, so we need to remove it.
		 */
		if (itr->marker == ICE_FLTR_NOT_FOUND) {
			err = ice_add_mac_to_list(&sc->pf_vsi, &remove_list,
						  addr, ICE_FWD_TO_VSI);
			if (err) {
				device_printf(sc->dev,
					      "Failed to place MAC %6D onto remove list, err %s\n",
					      addr, ":", ice_err_str(err));
				ice_release_lock(&sw->recp_list[ICE_SW_LKUP_MAC].filt_rule_lock);
				goto free_filter_lists;
			}
		}
	}

	ice_release_lock(&sw->recp_list[ICE_SW_LKUP_MAC].filt_rule_lock);

	status = ice_add_mac(hw, &data.add_list);
	if (status) {
		device_printf(sc->dev,
			      "Could not add new MAC filters, err %s aq_err %s\n",
			      ice_status_str(status), ice_aq_str(hw->adminq.sq_last_status));
		err = (EIO);
		goto free_filter_lists;
	}

	status = ice_remove_mac(hw, &remove_list);
	if (status) {
		device_printf(sc->dev,
			      "Could not remove old MAC filters, err %s aq_err %s\n",
			      ice_status_str(status), ice_aq_str(hw->adminq.sq_last_status));
		err = (EIO);
		goto free_filter_lists;
	}

free_filter_lists:
	ice_free_fltr_list(&data.add_list);
	ice_free_fltr_list(&remove_list);

	return (err);
}

/**
 * ice_add_vlan_hw_filter - Add a VLAN filter for a given VSI
 * @vsi: The VSI to add the filter for
 * @vid: VLAN to add
 *
 * Programs a HW filter so that the given VSI will receive the specified VLAN.
 */
enum ice_status
ice_add_vlan_hw_filter(struct ice_vsi *vsi, u16 vid)
{
	struct ice_hw *hw = &vsi->sc->hw;
	struct ice_list_head vlan_list;
	struct ice_fltr_list_entry vlan_entry;

	INIT_LIST_HEAD(&vlan_list);
	memset(&vlan_entry, 0, sizeof(vlan_entry));

	vlan_entry.fltr_info.lkup_type = ICE_SW_LKUP_VLAN;
	vlan_entry.fltr_info.fltr_act = ICE_FWD_TO_VSI;
	vlan_entry.fltr_info.flag = ICE_FLTR_TX;
	vlan_entry.fltr_info.src_id = ICE_SRC_ID_VSI;
	vlan_entry.fltr_info.vsi_handle = vsi->idx;
	vlan_entry.fltr_info.l_data.vlan.vlan_id = vid;

	LIST_ADD(&vlan_entry.list_entry, &vlan_list);

	return ice_add_vlan(hw, &vlan_list);
}

/**
 * ice_remove_vlan_hw_filter - Remove a VLAN filter for a given VSI
 * @vsi: The VSI to add the filter for
 * @vid: VLAN to remove
 *
 * Removes a previously programmed HW filter for the specified VSI.
 */
enum ice_status
ice_remove_vlan_hw_filter(struct ice_vsi *vsi, u16 vid)
{
	struct ice_hw *hw = &vsi->sc->hw;
	struct ice_list_head vlan_list;
	struct ice_fltr_list_entry vlan_entry;

	INIT_LIST_HEAD(&vlan_list);
	memset(&vlan_entry, 0, sizeof(vlan_entry));

	vlan_entry.fltr_info.lkup_type = ICE_SW_LKUP_VLAN;
	vlan_entry.fltr_info.fltr_act = ICE_FWD_TO_VSI;
	vlan_entry.fltr_info.flag = ICE_FLTR_TX;
	vlan_entry.fltr_info.src_id = ICE_SRC_ID_VSI;
	vlan_entry.fltr_info.vsi_handle = vsi->idx;
	vlan_entry.fltr_info.l_data.vlan.vlan_id = vid;

	LIST_ADD(&vlan_entry.list_entry, &vlan_list);

	return ice_remove_vlan(hw, &vlan_list);
}

#define ICE_SYSCTL_HELP_RX_ITR			\
"\nControl Rx interrupt throttle rate."		\
"\n\t0-8160 - sets interrupt rate in usecs"	\
"\n\t    -1 - reset the Rx itr to default"

/**
 * ice_sysctl_rx_itr - Display or change the Rx ITR for a VSI
 * @oidp: sysctl oid structure
 * @arg1: pointer to private data structure
 * @arg2: unused
 * @req: sysctl request pointer
 *
 * On read: Displays the current Rx ITR value
 * on write: Sets the Rx ITR value, reconfiguring device if it is up
 */
static int
ice_sysctl_rx_itr(SYSCTL_HANDLER_ARGS)
{
	struct ice_vsi *vsi = (struct ice_vsi *)arg1;
	struct ice_softc *sc = vsi->sc;
	int increment, error = 0;

	UNREFERENCED_PARAMETER(arg2);

	if (ice_driver_is_detaching(sc))
		return (ESHUTDOWN);

	error = sysctl_handle_16(oidp, &vsi->rx_itr, 0, req);
	if ((error) || (req->newptr == NULL))
		return (error);

	if (vsi->rx_itr < 0)
		vsi->rx_itr = ICE_DFLT_RX_ITR;
	if (vsi->rx_itr > ICE_ITR_MAX)
		vsi->rx_itr = ICE_ITR_MAX;

	/* Assume 2usec increment if it hasn't been loaded yet */
	increment = sc->hw.itr_gran ? : 2;

	/* We need to round the value to the hardware's ITR granularity */
	vsi->rx_itr = (vsi->rx_itr / increment ) * increment;

	/* If the driver has finished initializing, then we need to reprogram
	 * the ITR registers now. Otherwise, they will be programmed during
	 * driver initialization.
	 */
	if (ice_test_state(&sc->state, ICE_STATE_DRIVER_INITIALIZED))
		ice_configure_rx_itr(vsi);

	return (0);
}

#define ICE_SYSCTL_HELP_TX_ITR			\
"\nControl Tx interrupt throttle rate."		\
"\n\t0-8160 - sets interrupt rate in usecs"	\
"\n\t    -1 - reset the Tx itr to default"

/**
 * ice_sysctl_tx_itr - Display or change the Tx ITR for a VSI
 * @oidp: sysctl oid structure
 * @arg1: pointer to private data structure
 * @arg2: unused
 * @req: sysctl request pointer
 *
 * On read: Displays the current Tx ITR value
 * on write: Sets the Tx ITR value, reconfiguring device if it is up
 */
static int
ice_sysctl_tx_itr(SYSCTL_HANDLER_ARGS)
{
	struct ice_vsi *vsi = (struct ice_vsi *)arg1;
	struct ice_softc *sc = vsi->sc;
	int increment, error = 0;

	UNREFERENCED_PARAMETER(arg2);

	if (ice_driver_is_detaching(sc))
		return (ESHUTDOWN);

	error = sysctl_handle_16(oidp, &vsi->tx_itr, 0, req);
	if ((error) || (req->newptr == NULL))
		return (error);

	/* Allow configuring a negative value to reset to the default */
	if (vsi->tx_itr < 0)
		vsi->tx_itr = ICE_DFLT_TX_ITR;
	if (vsi->tx_itr > ICE_ITR_MAX)
		vsi->tx_itr = ICE_ITR_MAX;

	/* Assume 2usec increment if it hasn't been loaded yet */
	increment = sc->hw.itr_gran ? : 2;

	/* We need to round the value to the hardware's ITR granularity */
	vsi->tx_itr = (vsi->tx_itr / increment ) * increment;

	/* If the driver has finished initializing, then we need to reprogram
	 * the ITR registers now. Otherwise, they will be programmed during
	 * driver initialization.
	 */
	if (ice_test_state(&sc->state, ICE_STATE_DRIVER_INITIALIZED))
		ice_configure_tx_itr(vsi);

	return (0);
}

/**
 * ice_add_vsi_tunables - Add tunables and nodes for a VSI
 * @vsi: pointer to VSI structure
 * @parent: parent node to add the tunables under
 *
 * Create a sysctl context for the VSI, so that sysctls for the VSI can be
 * dynamically removed upon VSI removal.
 *
 * Add various tunables and set up the basic node structure for the VSI. Must
 * be called *prior* to ice_add_vsi_sysctls. It should be called as soon as
 * possible after the VSI memory is initialized.
 *
 * VSI specific sysctls with CTLFLAG_TUN should be initialized here so that
 * their values can be read from loader.conf prior to their first use in the
 * driver.
 */
void
ice_add_vsi_tunables(struct ice_vsi *vsi, struct sysctl_oid *parent)
{
	struct sysctl_oid_list *vsi_list;
	char vsi_name[32], vsi_desc[32];

	struct sysctl_oid_list *parent_list = SYSCTL_CHILDREN(parent);

	/* Initialize the sysctl context for this VSI */
	sysctl_ctx_init(&vsi->ctx);

	/* Add a node to collect this VSI's statistics together */
	snprintf(vsi_name, sizeof(vsi_name), "%u", vsi->idx);
	snprintf(vsi_desc, sizeof(vsi_desc), "VSI %u", vsi->idx);
	vsi->vsi_node = SYSCTL_ADD_NODE(&vsi->ctx, parent_list, OID_AUTO, vsi_name,
					CTLFLAG_RD, NULL, vsi_desc);
	vsi_list = SYSCTL_CHILDREN(vsi->vsi_node);

	vsi->rx_itr = ICE_DFLT_TX_ITR;
	SYSCTL_ADD_PROC(&vsi->ctx, vsi_list, OID_AUTO, "rx_itr",
			CTLTYPE_S16 | CTLFLAG_RWTUN,
			vsi, 0, ice_sysctl_rx_itr, "S",
			ICE_SYSCTL_HELP_RX_ITR);

	vsi->tx_itr = ICE_DFLT_TX_ITR;
	SYSCTL_ADD_PROC(&vsi->ctx, vsi_list, OID_AUTO, "tx_itr",
			CTLTYPE_S16 | CTLFLAG_RWTUN,
			vsi, 0, ice_sysctl_tx_itr, "S",
			ICE_SYSCTL_HELP_TX_ITR);
}

/**
 * ice_del_vsi_sysctl_ctx - Delete the sysctl context(s) of a VSI
 * @vsi: the VSI to remove contexts for
 *
 * Free the context for the VSI sysctls. This includes the main context, as
 * well as the per-queue sysctls.
 */
void
ice_del_vsi_sysctl_ctx(struct ice_vsi *vsi)
{
	device_t dev = vsi->sc->dev;
	int err;

	if (vsi->vsi_node) {
		err = sysctl_ctx_free(&vsi->ctx);
		if (err)
			device_printf(dev, "failed to free VSI %d sysctl context, err %s\n",
				      vsi->idx, ice_err_str(err));
		vsi->vsi_node = NULL;
	}
}

/**
 * ice_add_device_tunables - Add early tunable sysctls and sysctl nodes
 * @sc: device private structure
 *
 * Add per-device dynamic tunable sysctls, and setup the general sysctl trees
 * for re-use by ice_add_device_sysctls.
 *
 * In order for the sysctl fields to be initialized before use, this function
 * should be called as early as possible during attach activities.
 *
 * Any non-global sysctl marked as CTLFLAG_TUN should likely be initialized
 * here in this function, rather than later in ice_add_device_sysctls.
 *
 * To make things easier, this function is also expected to setup the various
 * sysctl nodes in addition to tunables so that other sysctls which can't be
 * initialized early can hook into the same nodes.
 */
void
ice_add_device_tunables(struct ice_softc *sc)
{
	device_t dev = sc->dev;

	struct sysctl_ctx_list *ctx = device_get_sysctl_ctx(dev);
	struct sysctl_oid_list *ctx_list =
		SYSCTL_CHILDREN(device_get_sysctl_tree(dev));

	/* Add a node to track VSI sysctls. Keep track of the node in the
	 * softc so that we can hook other sysctls into it later. This
	 * includes both the VSI statistics, as well as potentially dynamic
	 * VSIs in the future.
	 */

	sc->vsi_sysctls = SYSCTL_ADD_NODE(ctx, ctx_list, OID_AUTO, "vsi",
					  CTLFLAG_RD, NULL, "VSI Configuration and Statistics");

	/* Add debug tunables */
	ice_add_debug_tunables(sc);
}

/**
 * ice_sysctl_dump_mac_filters - Dump a list of all HW MAC Filters
 * @oidp: sysctl oid structure
 * @arg1: pointer to private data structure
 * @arg2: unused
 * @req: sysctl request pointer
 *
 * Callback for "mac_filters" sysctl to dump the programmed MAC filters.
 */
static int
ice_sysctl_dump_mac_filters(SYSCTL_HANDLER_ARGS)
{
	struct ice_softc *sc = (struct ice_softc *)arg1;
	struct ice_hw *hw = &sc->hw;
	struct ice_switch_info *sw = hw->switch_info;
	struct ice_fltr_mgmt_list_entry *fm_entry;
	struct ice_list_head *rule_head;
	struct ice_lock *rule_lock;
	struct ice_fltr_info *fi;
	struct sbuf *sbuf;
	int ret;

	UNREFERENCED_PARAMETER(oidp);
	UNREFERENCED_PARAMETER(arg2);

	if (ice_driver_is_detaching(sc))
		return (ESHUTDOWN);

	/* Wire the old buffer so we can take a non-sleepable lock */
	ret = sysctl_wire_old_buffer(req, 0);
	if (ret)
		return (ret);

	sbuf = sbuf_new_for_sysctl(NULL, NULL, 128, req);

	rule_lock = &sw->recp_list[ICE_SW_LKUP_MAC].filt_rule_lock;
	rule_head = &sw->recp_list[ICE_SW_LKUP_MAC].filt_rules;

	sbuf_printf(sbuf, "MAC Filter List");

	ice_acquire_lock(rule_lock);

	LIST_FOR_EACH_ENTRY(fm_entry, rule_head, ice_fltr_mgmt_list_entry, list_entry) {
		fi = &fm_entry->fltr_info;

		sbuf_printf(sbuf,
			    "\nmac = %6D, vsi_handle = %3d, fw_act_flag = %5s, lb_en = %1d, lan_en = %1d, fltr_act = %15s, fltr_rule_id = %d",
			    fi->l_data.mac.mac_addr, ":", fi->vsi_handle,
			    ice_fltr_flag_str(fi->flag), fi->lb_en, fi->lan_en,
			    ice_fwd_act_str(fi->fltr_act), fi->fltr_rule_id);

		/* if we have a vsi_list_info, print some information about that */
		if (fm_entry->vsi_list_info) {
			sbuf_printf(sbuf,
				    ", vsi_count = %3d, vsi_list_id = %3d, ref_cnt = %3d",
				    fm_entry->vsi_count,
				    fm_entry->vsi_list_info->vsi_list_id,
				    fm_entry->vsi_list_info->ref_cnt);
		}
	}

	ice_release_lock(rule_lock);

	sbuf_finish(sbuf);
	sbuf_delete(sbuf);

	return (0);
}

/**
 * ice_sysctl_dump_vlan_filters - Dump a list of all HW VLAN Filters
 * @oidp: sysctl oid structure
 * @arg1: pointer to private data structure
 * @arg2: unused
 * @req: sysctl request pointer
 *
 * Callback for "vlan_filters" sysctl to dump the programmed VLAN filters.
 */
static int
ice_sysctl_dump_vlan_filters(SYSCTL_HANDLER_ARGS)
{
	struct ice_softc *sc = (struct ice_softc *)arg1;
	struct ice_hw *hw = &sc->hw;
	struct ice_switch_info *sw = hw->switch_info;
	struct ice_fltr_mgmt_list_entry *fm_entry;
	struct ice_list_head *rule_head;
	struct ice_lock *rule_lock;
	struct ice_fltr_info *fi;
	struct sbuf *sbuf;
	int ret;

	UNREFERENCED_PARAMETER(oidp);
	UNREFERENCED_PARAMETER(arg2);

	if (ice_driver_is_detaching(sc))
		return (ESHUTDOWN);

	/* Wire the old buffer so we can take a non-sleepable lock */
	ret = sysctl_wire_old_buffer(req, 0);
	if (ret)
		return (ret);

	sbuf = sbuf_new_for_sysctl(NULL, NULL, 128, req);

	rule_lock = &sw->recp_list[ICE_SW_LKUP_VLAN].filt_rule_lock;
	rule_head = &sw->recp_list[ICE_SW_LKUP_VLAN].filt_rules;

	sbuf_printf(sbuf, "VLAN Filter List");

	ice_acquire_lock(rule_lock);

	LIST_FOR_EACH_ENTRY(fm_entry, rule_head, ice_fltr_mgmt_list_entry, list_entry) {
		fi = &fm_entry->fltr_info;

		sbuf_printf(sbuf,
			    "\nvlan_id = %4d, vsi_handle = %3d, fw_act_flag = %5s, lb_en = %1d, lan_en = %1d, fltr_act = %15s, fltr_rule_id = %4d",
			    fi->l_data.vlan.vlan_id, fi->vsi_handle,
			    ice_fltr_flag_str(fi->flag), fi->lb_en, fi->lan_en,
			    ice_fwd_act_str(fi->fltr_act), fi->fltr_rule_id);

		/* if we have a vsi_list_info, print some information about that */
		if (fm_entry->vsi_list_info) {
			sbuf_printf(sbuf,
				    ", vsi_count = %3d, vsi_list_id = %3d, ref_cnt = %3d",
				    fm_entry->vsi_count,
				    fm_entry->vsi_list_info->vsi_list_id,
				    fm_entry->vsi_list_info->ref_cnt);
		}
	}

	ice_release_lock(rule_lock);

	sbuf_finish(sbuf);
	sbuf_delete(sbuf);

	return (0);
}

/**
 * ice_sysctl_dump_ethertype_filters - Dump a list of all HW Ethertype filters
 * @oidp: sysctl oid structure
 * @arg1: pointer to private data structure
 * @arg2: unused
 * @req: sysctl request pointer
 *
 * Callback for "ethertype_filters" sysctl to dump the programmed Ethertype
 * filters.
 */
static int
ice_sysctl_dump_ethertype_filters(SYSCTL_HANDLER_ARGS)
{
	struct ice_softc *sc = (struct ice_softc *)arg1;
	struct ice_hw *hw = &sc->hw;
	struct ice_switch_info *sw = hw->switch_info;
	struct ice_fltr_mgmt_list_entry *fm_entry;
	struct ice_list_head *rule_head;
	struct ice_lock *rule_lock;
	struct ice_fltr_info *fi;
	struct sbuf *sbuf;
	int ret;

	UNREFERENCED_PARAMETER(oidp);
	UNREFERENCED_PARAMETER(arg2);

	if (ice_driver_is_detaching(sc))
		return (ESHUTDOWN);

	/* Wire the old buffer so we can take a non-sleepable lock */
	ret = sysctl_wire_old_buffer(req, 0);
	if (ret)
		return (ret);

	sbuf = sbuf_new_for_sysctl(NULL, NULL, 128, req);

	rule_lock = &sw->recp_list[ICE_SW_LKUP_ETHERTYPE].filt_rule_lock;
	rule_head = &sw->recp_list[ICE_SW_LKUP_ETHERTYPE].filt_rules;

	sbuf_printf(sbuf, "Ethertype Filter List");

	ice_acquire_lock(rule_lock);

	LIST_FOR_EACH_ENTRY(fm_entry, rule_head, ice_fltr_mgmt_list_entry, list_entry) {
		fi = &fm_entry->fltr_info;

		sbuf_printf(sbuf,
			    "\nethertype = 0x%04x, vsi_handle = %3d, fw_act_flag = %5s, lb_en = %1d, lan_en = %1d, fltr_act = %15s, fltr_rule_id = %4d",
			fi->l_data.ethertype_mac.ethertype,
			fi->vsi_handle, ice_fltr_flag_str(fi->flag),
			fi->lb_en, fi->lan_en, ice_fwd_act_str(fi->fltr_act),
			fi->fltr_rule_id);

		/* if we have a vsi_list_info, print some information about that */
		if (fm_entry->vsi_list_info) {
			sbuf_printf(sbuf,
				    ", vsi_count = %3d, vsi_list_id = %3d, ref_cnt = %3d",
				    fm_entry->vsi_count,
				    fm_entry->vsi_list_info->vsi_list_id,
				    fm_entry->vsi_list_info->ref_cnt);
		}
	}

	ice_release_lock(rule_lock);

	sbuf_finish(sbuf);
	sbuf_delete(sbuf);

	return (0);
}

/**
 * ice_sysctl_dump_ethertype_mac_filters - Dump a list of all HW Ethertype/MAC filters
 * @oidp: sysctl oid structure
 * @arg1: pointer to private data structure
 * @arg2: unused
 * @req: sysctl request pointer
 *
 * Callback for "ethertype_mac_filters" sysctl to dump the programmed
 * Ethertype/MAC filters.
 */
static int
ice_sysctl_dump_ethertype_mac_filters(SYSCTL_HANDLER_ARGS)
{
	struct ice_softc *sc = (struct ice_softc *)arg1;
	struct ice_hw *hw = &sc->hw;
	struct ice_switch_info *sw = hw->switch_info;
	struct ice_fltr_mgmt_list_entry *fm_entry;
	struct ice_list_head *rule_head;
	struct ice_lock *rule_lock;
	struct ice_fltr_info *fi;
	struct sbuf *sbuf;
	int ret;

	UNREFERENCED_PARAMETER(oidp);
	UNREFERENCED_PARAMETER(arg2);

	if (ice_driver_is_detaching(sc))
		return (ESHUTDOWN);

	/* Wire the old buffer so we can take a non-sleepable lock */
	ret = sysctl_wire_old_buffer(req, 0);
	if (ret)
		return (ret);

	sbuf = sbuf_new_for_sysctl(NULL, NULL, 128, req);

	rule_lock = &sw->recp_list[ICE_SW_LKUP_ETHERTYPE_MAC].filt_rule_lock;
	rule_head = &sw->recp_list[ICE_SW_LKUP_ETHERTYPE_MAC].filt_rules;

	sbuf_printf(sbuf, "Ethertype/MAC Filter List");

	ice_acquire_lock(rule_lock);

	LIST_FOR_EACH_ENTRY(fm_entry, rule_head, ice_fltr_mgmt_list_entry, list_entry) {
		fi = &fm_entry->fltr_info;

		sbuf_printf(sbuf,
			    "\nethertype = 0x%04x, mac = %6D, vsi_handle = %3d, fw_act_flag = %5s, lb_en = %1d, lan_en = %1d, fltr_act = %15s, fltr_rule_id = %4d",
			    fi->l_data.ethertype_mac.ethertype,
			    fi->l_data.ethertype_mac.mac_addr, ":",
			    fi->vsi_handle, ice_fltr_flag_str(fi->flag),
			    fi->lb_en, fi->lan_en, ice_fwd_act_str(fi->fltr_act),
			    fi->fltr_rule_id);

		/* if we have a vsi_list_info, print some information about that */
		if (fm_entry->vsi_list_info) {
			sbuf_printf(sbuf,
				    ", vsi_count = %3d, vsi_list_id = %3d, ref_cnt = %3d",
				    fm_entry->vsi_count,
				    fm_entry->vsi_list_info->vsi_list_id,
				    fm_entry->vsi_list_info->ref_cnt);
		}
	}

	ice_release_lock(rule_lock);

	sbuf_finish(sbuf);
	sbuf_delete(sbuf);

	return (0);
}

/**
 * ice_sysctl_dump_state_flags - Dump device driver state flags
 * @oidp: sysctl oid structure
 * @arg1: pointer to private data structure
 * @arg2: unused
 * @req: sysctl request pointer
 *
 * Callback for "state" sysctl to display currently set driver state flags.
 */
static int
ice_sysctl_dump_state_flags(SYSCTL_HANDLER_ARGS)
{
	struct ice_softc *sc = (struct ice_softc *)arg1;
	struct sbuf *sbuf;
	u32 copied_state;
	unsigned int i;
	bool at_least_one = false;

	UNREFERENCED_PARAMETER(oidp);
	UNREFERENCED_PARAMETER(arg2);

	if (ice_driver_is_detaching(sc))
		return (ESHUTDOWN);

	/* Make a copy of the state to ensure we display coherent values */
	copied_state = atomic_load_acq_32(&sc->state);

	sbuf = sbuf_new_for_sysctl(NULL, NULL, 128, req);

	/* Add the string for each set state to the sbuf */
	for (i = 0; i < 32; i++) {
		if (copied_state & BIT(i)) {
			const char *str = ice_state_to_str((enum ice_state)i);

			at_least_one = true;

			if (str)
				sbuf_printf(sbuf, "\n%s", str);
			else
				sbuf_printf(sbuf, "\nBIT(%u)", i);
		}
	}

	if (!at_least_one)
		sbuf_printf(sbuf, "Nothing set");

	sbuf_finish(sbuf);
	sbuf_delete(sbuf);

	return (0);
}

/**
 * ice_add_debug_tunables - Add tunables helpful for debugging the device driver
 * @sc: device private structure
 *
 * Add sysctl tunable values related to debugging the device driver. For now,
 * this means a tunable to set the debug mask early during driver load.
 *
 * The debug node will be marked CTLFLAG_SKIP unless INVARIANTS is defined, so
 * that in normal kernel builds, these will all be hidden, but on a debug
 * kernel they will be more easily visible.
 */
static void
ice_add_debug_tunables(struct ice_softc *sc)
{
	struct sysctl_oid_list *debug_list;
	device_t dev = sc->dev;

	struct sysctl_ctx_list *ctx = device_get_sysctl_ctx(dev);
	struct sysctl_oid_list *ctx_list =
	    SYSCTL_CHILDREN(device_get_sysctl_tree(dev));

	sc->debug_sysctls = SYSCTL_ADD_NODE(ctx, ctx_list, OID_AUTO, "debug",
					    ICE_CTLFLAG_DEBUG | CTLFLAG_RD,
					    NULL, "Debug Sysctls");
	debug_list = SYSCTL_CHILDREN(sc->debug_sysctls);

	SYSCTL_ADD_U64(ctx, debug_list, OID_AUTO, "debug_mask",
		       CTLFLAG_RW | CTLFLAG_TUN, &sc->hw.debug_mask, 0,
		       "Debug message enable/disable mask");

	/* Load the default value from the global sysctl first */
	sc->enable_tx_fc_filter = ice_enable_tx_fc_filter;

	SYSCTL_ADD_BOOL(ctx, debug_list, OID_AUTO, "enable_tx_fc_filter",
			CTLFLAG_RDTUN, &sc->enable_tx_fc_filter, 0,
			"Drop Ethertype 0x8808 control frames originating from software on this PF");

	/* Load the default value from the global sysctl first */
	sc->enable_tx_lldp_filter = ice_enable_tx_lldp_filter;

	SYSCTL_ADD_BOOL(ctx, debug_list, OID_AUTO, "enable_tx_lldp_filter",
			CTLFLAG_RDTUN, &sc->enable_tx_lldp_filter, 0,
			"Drop Ethertype 0x88cc LLDP frames originating from software on this PF");

}

#define ICE_SYSCTL_HELP_REQUEST_RESET		\
"\nRequest the driver to initiate a reset."	\
"\n\tpfr - Initiate a PF reset"			\
"\n\tcorer - Initiate a CORE reset"		\
"\n\tglobr - Initiate a GLOBAL reset"

/**
 * @var rl_sysctl_ticks
 * @brief timestamp for latest reset request sysctl call
 *
 * Helps rate-limit the call to the sysctl which resets the device
 */
int rl_sysctl_ticks = 0;

/**
 * ice_sysctl_request_reset - Request that the driver initiate a reset
 * @oidp: sysctl oid structure
 * @arg1: pointer to private data structure
 * @arg2: unused
 * @req: sysctl request pointer
 *
 * Callback for "request_reset" sysctl to request that the driver initiate
 * a reset. Expects to be passed one of the following strings
 *
 * "pfr" - Initiate a PF reset
 * "corer" - Initiate a CORE reset
 * "globr" - Initiate a Global reset
 */
static int
ice_sysctl_request_reset(SYSCTL_HANDLER_ARGS)
{
	struct ice_softc *sc = (struct ice_softc *)arg1;
	struct ice_hw *hw = &sc->hw;
	enum ice_status status;
	enum ice_reset_req reset_type = ICE_RESET_INVAL;
	const char *reset_message;
	int error = 0;

	/* Buffer to store the requested reset string. Must contain enough
	 * space to store the largest expected reset string, which currently
	 * means 6 bytes of space.
	 */
	char reset[6] = "";

	UNREFERENCED_PARAMETER(arg2);

	error = priv_check(curthread, PRIV_DRIVER);
	if (error)
		return (error);

	if (ice_driver_is_detaching(sc))
		return (ESHUTDOWN);

	/* Read in the requested reset type. */
	error = sysctl_handle_string(oidp, reset, sizeof(reset), req);
	if ((error) || (req->newptr == NULL))
		return (error);

	if (strcmp(reset, "pfr") == 0) {
		reset_message = "Requesting a PF reset";
		reset_type = ICE_RESET_PFR;
	} else if (strcmp(reset, "corer") == 0) {
		reset_message = "Initiating a CORE reset";
		reset_type = ICE_RESET_CORER;
	} else if (strcmp(reset, "globr") == 0) {
		reset_message = "Initiating a GLOBAL reset";
		reset_type = ICE_RESET_GLOBR;
	} else if (strcmp(reset, "empr") == 0) {
		device_printf(sc->dev, "Triggering an EMP reset via software is not currently supported\n");
		return (EOPNOTSUPP);
	}

	if (reset_type == ICE_RESET_INVAL) {
		device_printf(sc->dev, "%s is not a valid reset request\n", reset);
		return (EINVAL);
	}

	/*
	 * Rate-limit the frequency at which this function is called.
	 * Assuming this is called successfully once, typically,
	 * everything should be handled within the allotted time frame.
	 * However, in the odd setup situations, we've also put in
	 * guards for when the reset has finished, but we're in the
	 * process of rebuilding. And instead of queueing an intent,
	 * simply error out and let the caller retry, if so desired.
	 */
	if (TICKS_2_MSEC(ticks - rl_sysctl_ticks) < 500) {
		device_printf(sc->dev,
		    "Call frequency too high. Operation aborted.\n");
		return (EBUSY);
	}
	rl_sysctl_ticks = ticks;

	if (TICKS_2_MSEC(ticks - sc->rebuild_ticks) < 100) {
		device_printf(sc->dev, "Device rebuilding. Operation aborted.\n");
		return (EBUSY);
	}

	if (rd32(hw, GLGEN_RSTAT) & GLGEN_RSTAT_DEVSTATE_M) {
		device_printf(sc->dev, "Device in reset. Operation aborted.\n");
		return (EBUSY);
	}

	device_printf(sc->dev, "%s\n", reset_message);

	/* Initiate the PF reset during the admin status task */
	if (reset_type == ICE_RESET_PFR) {
		ice_set_state(&sc->state, ICE_STATE_RESET_PFR_REQ);
		return (0);
	}

	/*
	 * Other types of resets including CORE and GLOBAL resets trigger an
	 * interrupt on all PFs. Initiate the reset now. Preparation and
	 * rebuild logic will be handled by the admin status task.
	 */
	status = ice_reset(hw, reset_type);

	/*
	 * Resets can take a long time and we still don't want another call
	 * to this function before we settle down.
	 */
	rl_sysctl_ticks = ticks;

	if (status) {
		device_printf(sc->dev, "failed to initiate device reset, err %s\n",
			      ice_status_str(status));
		ice_set_state(&sc->state, ICE_STATE_RESET_FAILED);
		return (EFAULT);
	}

	return (0);
}

/**
 * ice_add_debug_sysctls - Add sysctls helpful for debugging the device driver
 * @sc: device private structure
 *
 * Add sysctls related to debugging the device driver. Generally these should
 * simply be sysctls which dump internal driver state, to aid in understanding
 * what the driver is doing.
 */
static void
ice_add_debug_sysctls(struct ice_softc *sc)
{
	struct sysctl_oid *sw_node;
	struct sysctl_oid_list *debug_list, *sw_list;
	device_t dev = sc->dev;

	struct sysctl_ctx_list *ctx = device_get_sysctl_ctx(dev);

	debug_list = SYSCTL_CHILDREN(sc->debug_sysctls);

	SYSCTL_ADD_PROC(ctx, debug_list, OID_AUTO, "request_reset",
			CTLTYPE_STRING | CTLFLAG_WR, sc, 0,
			ice_sysctl_request_reset, "A",
			ICE_SYSCTL_HELP_REQUEST_RESET);

	SYSCTL_ADD_U32(ctx, debug_list, OID_AUTO, "pfr_count", CTLFLAG_RD,
		       &sc->soft_stats.pfr_count, 0, "# of PF resets handled");

	SYSCTL_ADD_U32(ctx, debug_list, OID_AUTO, "corer_count", CTLFLAG_RD,
		       &sc->soft_stats.corer_count, 0, "# of CORE resets handled");

	SYSCTL_ADD_U32(ctx, debug_list, OID_AUTO, "globr_count", CTLFLAG_RD,
		       &sc->soft_stats.globr_count, 0, "# of Global resets handled");

	SYSCTL_ADD_U32(ctx, debug_list, OID_AUTO, "empr_count", CTLFLAG_RD,
		       &sc->soft_stats.empr_count, 0, "# of EMP resets handled");

	SYSCTL_ADD_U32(ctx, debug_list, OID_AUTO, "tx_mdd_count", CTLFLAG_RD,
		       &sc->soft_stats.tx_mdd_count, 0, "# of Tx MDD events detected");

	SYSCTL_ADD_U32(ctx, debug_list, OID_AUTO, "rx_mdd_count", CTLFLAG_RD,
		       &sc->soft_stats.rx_mdd_count, 0, "# of Rx MDD events detected");

	SYSCTL_ADD_PROC(ctx, debug_list,
	    OID_AUTO, "state", CTLTYPE_STRING | CTLFLAG_RD,
	    sc, 0, ice_sysctl_dump_state_flags, "A", "Driver State Flags");

	SYSCTL_ADD_PROC(ctx, debug_list,
			OID_AUTO, "phy_type_low", CTLTYPE_U64 | CTLFLAG_RW,
			sc, 0, ice_sysctl_phy_type_low, "QU",
			"PHY type Low from Get PHY Caps/Set PHY Cfg");

	SYSCTL_ADD_PROC(ctx, debug_list,
			OID_AUTO, "phy_type_high", CTLTYPE_U64 | CTLFLAG_RW,
			sc, 0, ice_sysctl_phy_type_high, "QU",
			"PHY type High from Get PHY Caps/Set PHY Cfg");

	SYSCTL_ADD_PROC(ctx, debug_list,
			OID_AUTO, "phy_sw_caps", CTLTYPE_STRUCT | CTLFLAG_RD,
			sc, 0, ice_sysctl_phy_sw_caps, "",
			"Get PHY Capabilities (Software configuration)");

	SYSCTL_ADD_PROC(ctx, debug_list,
			OID_AUTO, "phy_nvm_caps", CTLTYPE_STRUCT | CTLFLAG_RD,
			sc, 0, ice_sysctl_phy_nvm_caps, "",
			"Get PHY Capabilities (NVM configuration)");

	SYSCTL_ADD_PROC(ctx, debug_list,
			OID_AUTO, "phy_topo_caps", CTLTYPE_STRUCT | CTLFLAG_RD,
			sc, 0, ice_sysctl_phy_topo_caps, "",
			"Get PHY Capabilities (Topology configuration)");

	SYSCTL_ADD_PROC(ctx, debug_list,
			OID_AUTO, "phy_link_status", CTLTYPE_STRUCT | CTLFLAG_RD,
			sc, 0, ice_sysctl_phy_link_status, "",
			"Get PHY Link Status");

	SYSCTL_ADD_PROC(ctx, debug_list,
			OID_AUTO, "read_i2c_diag_data", CTLTYPE_STRING | CTLFLAG_RD,
			sc, 0, ice_sysctl_read_i2c_diag_data, "A",
			"Dump selected diagnostic data from FW");

	SYSCTL_ADD_U32(ctx, debug_list, OID_AUTO, "fw_build", CTLFLAG_RD,
			&sc->hw.fw_build, 0, "FW Build ID");

	SYSCTL_ADD_PROC(ctx, debug_list, OID_AUTO, "os_ddp_version", CTLTYPE_STRING | CTLFLAG_RD,
			sc, 0, ice_sysctl_os_pkg_version, "A",
			"DDP package name and version found in ice_ddp");

	SYSCTL_ADD_PROC(ctx, debug_list,
	    OID_AUTO, "cur_lldp_persist_status", CTLTYPE_STRING | CTLFLAG_RD,
	    sc, 0, ice_sysctl_fw_cur_lldp_persist_status, "A", "Current LLDP persistent status");

	SYSCTL_ADD_PROC(ctx, debug_list,
	    OID_AUTO, "dflt_lldp_persist_status", CTLTYPE_STRING | CTLFLAG_RD,
	    sc, 0, ice_sysctl_fw_dflt_lldp_persist_status, "A", "Default LLDP persistent status");

	SYSCTL_ADD_PROC(ctx, debug_list,
	    OID_AUTO, "negotiated_fc", CTLTYPE_STRING | CTLFLAG_RD,
	    sc, 0, ice_sysctl_negotiated_fc, "A", "Current Negotiated Flow Control mode");

	sw_node = SYSCTL_ADD_NODE(ctx, debug_list, OID_AUTO, "switch",
				  CTLFLAG_RD, NULL, "Switch Configuration");
	sw_list = SYSCTL_CHILDREN(sw_node);

	SYSCTL_ADD_PROC(ctx, sw_list,
	    OID_AUTO, "mac_filters", CTLTYPE_STRING | CTLFLAG_RD,
	    sc, 0, ice_sysctl_dump_mac_filters, "A", "MAC Filters");

	SYSCTL_ADD_PROC(ctx, sw_list,
	    OID_AUTO, "vlan_filters", CTLTYPE_STRING | CTLFLAG_RD,
	    sc, 0, ice_sysctl_dump_vlan_filters, "A", "VLAN Filters");

	SYSCTL_ADD_PROC(ctx, sw_list,
	    OID_AUTO, "ethertype_filters", CTLTYPE_STRING | CTLFLAG_RD,
	    sc, 0, ice_sysctl_dump_ethertype_filters, "A", "Ethertype Filters");

	SYSCTL_ADD_PROC(ctx, sw_list,
	    OID_AUTO, "ethertype_mac_filters", CTLTYPE_STRING | CTLFLAG_RD,
	    sc, 0, ice_sysctl_dump_ethertype_mac_filters, "A", "Ethertype/MAC Filters");

}

/**
 * ice_vsi_disable_tx - Disable (unconfigure) Tx queues for a VSI
 * @vsi: the VSI to disable
 *
 * Disables the Tx queues associated with this VSI. Essentially the opposite
 * of ice_cfg_vsi_for_tx.
 */
int
ice_vsi_disable_tx(struct ice_vsi *vsi)
{
	struct ice_softc *sc = vsi->sc;
	struct ice_hw *hw = &sc->hw;
	enum ice_status status;
	u32 *q_teids;
	u16 *q_ids, *q_handles;
	int i, err = 0;

	if (vsi->num_tx_queues > 255)
		return (ENOSYS);

	q_teids = (u32 *)malloc(sizeof(*q_teids) * vsi->num_tx_queues,
				M_ICE, M_NOWAIT|M_ZERO);
	if (!q_teids)
		return (ENOMEM);

	q_ids = (u16 *)malloc(sizeof(*q_ids) * vsi->num_tx_queues,
				M_ICE, M_NOWAIT|M_ZERO);
	if (!q_ids) {
		err = (ENOMEM);
		goto free_q_teids;
	}

	q_handles = (u16 *)malloc(sizeof(*q_handles) * vsi->num_tx_queues,
				M_ICE, M_NOWAIT|M_ZERO);
	if (!q_handles) {
		err = (ENOMEM);
		goto free_q_ids;
	}


	for (i = 0; i < vsi->num_tx_queues; i++) {
		struct ice_tx_queue *txq = &vsi->tx_queues[i];

		q_ids[i] = vsi->tx_qmap[i];
		q_handles[i] = i;
		q_teids[i] = txq->q_teid;
	}

	status = ice_dis_vsi_txq(hw->port_info, vsi->idx, 0, vsi->num_tx_queues,
				 q_handles, q_ids, q_teids, ICE_NO_RESET, 0, NULL);
	if (status == ICE_ERR_DOES_NOT_EXIST) {
		; /* Queues have already been disabled, no need to report this as an error */
	} else if (status == ICE_ERR_RESET_ONGOING) {
		device_printf(sc->dev,
			      "Reset in progress. LAN Tx queues already disabled\n");
	} else if (status) {
		device_printf(sc->dev,
			      "Failed to disable LAN Tx queues: err %s aq_err %s\n",
			      ice_status_str(status), ice_aq_str(hw->adminq.sq_last_status));
		err = (ENODEV);
	}

/* free_q_handles: */
	free(q_handles, M_ICE);
free_q_ids:
	free(q_ids, M_ICE);
free_q_teids:
	free(q_teids, M_ICE);

	return err;
}

/**
 * ice_vsi_set_rss_params - Set the RSS parameters for the VSI
 * @vsi: the VSI to configure
 *
 * Sets the RSS table size and lookup table type for the VSI based on its
 * VSI type.
 */
static void
ice_vsi_set_rss_params(struct ice_vsi *vsi)
{
	struct ice_softc *sc = vsi->sc;
	struct ice_hw_common_caps *cap;

	cap = &sc->hw.func_caps.common_cap;

	switch (vsi->type) {
	case ICE_VSI_PF:
		/* The PF VSI inherits RSS instance of the PF */
		vsi->rss_table_size = cap->rss_table_size;
		vsi->rss_lut_type = ICE_AQC_GSET_RSS_LUT_TABLE_TYPE_PF;
		break;
	case ICE_VSI_VF:
		vsi->rss_table_size = ICE_VSIQF_HLUT_ARRAY_SIZE;
		vsi->rss_lut_type = ICE_AQC_GSET_RSS_LUT_TABLE_TYPE_VSI;
		break;
	default:
		device_printf(sc->dev,
			      "VSI %d: RSS not supported for VSI type %d\n",
			      vsi->idx, vsi->type);
		break;
	}
}

/**
 * ice_vsi_add_txqs_ctx - Create a sysctl context and node to store txq sysctls
 * @vsi: The VSI to add the context for
 *
 * Creates a sysctl context for storing txq sysctls. Additionally creates
 * a node rooted at the given VSI's main sysctl node. This context will be
 * used to store per-txq sysctls which may need to be released during the
 * driver's lifetime.
 */
void
ice_vsi_add_txqs_ctx(struct ice_vsi *vsi)
{
	struct sysctl_oid_list *vsi_list;

	sysctl_ctx_init(&vsi->txqs_ctx);

	vsi_list = SYSCTL_CHILDREN(vsi->vsi_node);

	vsi->txqs_node = SYSCTL_ADD_NODE(&vsi->txqs_ctx, vsi_list, OID_AUTO, "txqs",
					 CTLFLAG_RD, NULL, "Tx Queues");
}

/**
 * ice_vsi_add_rxqs_ctx - Create a sysctl context and node to store rxq sysctls
 * @vsi: The VSI to add the context for
 *
 * Creates a sysctl context for storing rxq sysctls. Additionally creates
 * a node rooted at the given VSI's main sysctl node. This context will be
 * used to store per-rxq sysctls which may need to be released during the
 * driver's lifetime.
 */
void
ice_vsi_add_rxqs_ctx(struct ice_vsi *vsi)
{
	struct sysctl_oid_list *vsi_list;

	sysctl_ctx_init(&vsi->rxqs_ctx);

	vsi_list = SYSCTL_CHILDREN(vsi->vsi_node);

	vsi->rxqs_node = SYSCTL_ADD_NODE(&vsi->rxqs_ctx, vsi_list, OID_AUTO, "rxqs",
					 CTLFLAG_RD, NULL, "Rx Queues");
}

/**
 * ice_vsi_del_txqs_ctx - Delete the Tx queue sysctl context for this VSI
 * @vsi: The VSI to delete from
 *
 * Frees the txq sysctl context created for storing the per-queue Tx sysctls.
 * Must be called prior to freeing the Tx queue memory, in order to avoid
 * having sysctls point at stale memory.
 */
void
ice_vsi_del_txqs_ctx(struct ice_vsi *vsi)
{
	device_t dev = vsi->sc->dev;
	int err;

	if (vsi->txqs_node) {
		err = sysctl_ctx_free(&vsi->txqs_ctx);
		if (err)
			device_printf(dev, "failed to free VSI %d txqs_ctx, err %s\n",
				      vsi->idx, ice_err_str(err));
		vsi->txqs_node = NULL;
	}
}

/**
 * ice_vsi_del_rxqs_ctx - Delete the Rx queue sysctl context for this VSI
 * @vsi: The VSI to delete from
 *
 * Frees the rxq sysctl context created for storing the per-queue Rx sysctls.
 * Must be called prior to freeing the Rx queue memory, in order to avoid
 * having sysctls point at stale memory.
 */
void
ice_vsi_del_rxqs_ctx(struct ice_vsi *vsi)
{
	device_t dev = vsi->sc->dev;
	int err;

	if (vsi->rxqs_node) {
		err = sysctl_ctx_free(&vsi->rxqs_ctx);
		if (err)
			device_printf(dev, "failed to free VSI %d rxqs_ctx, err %s\n",
				      vsi->idx, ice_err_str(err));
		vsi->rxqs_node = NULL;
	}
}

/**
 * ice_add_txq_sysctls - Add per-queue sysctls for a Tx queue
 * @txq: pointer to the Tx queue
 *
* Add per-queue sysctls for a given Tx queue. Can't be called during
* ice_add_vsi_sysctls, since the queue memory has not yet been setup.
 */
void
ice_add_txq_sysctls(struct ice_tx_queue *txq)
{
	struct ice_vsi *vsi = txq->vsi;
	struct sysctl_ctx_list *ctx = &vsi->txqs_ctx;
	struct sysctl_oid_list *txqs_list, *this_txq_list;
	struct sysctl_oid *txq_node;
	char txq_name[32], txq_desc[32];

	const struct ice_sysctl_info ctls[] = {
		{ &txq->stats.tx_packets, "tx_packets", "Queue Packets Transmitted" },
		{ &txq->stats.tx_bytes, "tx_bytes", "Queue Bytes Transmitted" },
		{ &txq->stats.mss_too_small, "mss_too_small", "TSO sends with an MSS less than 64" },
		{ 0, 0, 0 }
	};

	const struct ice_sysctl_info *entry = ctls;

	txqs_list = SYSCTL_CHILDREN(vsi->txqs_node);

	snprintf(txq_name, sizeof(txq_name), "%u", txq->me);
	snprintf(txq_desc, sizeof(txq_desc), "Tx Queue %u", txq->me);
	txq_node = SYSCTL_ADD_NODE(ctx, txqs_list, OID_AUTO, txq_name,
				   CTLFLAG_RD, NULL, txq_desc);
	this_txq_list = SYSCTL_CHILDREN(txq_node);

	/* Add the Tx queue statistics */
	while (entry->stat != 0) {
		SYSCTL_ADD_U64(ctx, this_txq_list, OID_AUTO, entry->name,
			       CTLFLAG_RD | CTLFLAG_STATS, entry->stat, 0,
			       entry->description);
		entry++;
	}
}

/**
 * ice_add_rxq_sysctls - Add per-queue sysctls for an Rx queue
 * @rxq: pointer to the Rx queue
 *
 * Add per-queue sysctls for a given Rx queue. Can't be called during
 * ice_add_vsi_sysctls, since the queue memory has not yet been setup.
 */
void
ice_add_rxq_sysctls(struct ice_rx_queue *rxq)
{
	struct ice_vsi *vsi = rxq->vsi;
	struct sysctl_ctx_list *ctx = &vsi->rxqs_ctx;
	struct sysctl_oid_list *rxqs_list, *this_rxq_list;
	struct sysctl_oid *rxq_node;
	char rxq_name[32], rxq_desc[32];

	const struct ice_sysctl_info ctls[] = {
		{ &rxq->stats.rx_packets, "rx_packets", "Queue Packets Received" },
		{ &rxq->stats.rx_bytes, "rx_bytes", "Queue Bytes Received" },
		{ &rxq->stats.desc_errs, "rx_desc_errs", "Queue Rx Descriptor Errors" },
		{ 0, 0, 0 }
	};

	const struct ice_sysctl_info *entry = ctls;

	rxqs_list = SYSCTL_CHILDREN(vsi->rxqs_node);

	snprintf(rxq_name, sizeof(rxq_name), "%u", rxq->me);
	snprintf(rxq_desc, sizeof(rxq_desc), "Rx Queue %u", rxq->me);
	rxq_node = SYSCTL_ADD_NODE(ctx, rxqs_list, OID_AUTO, rxq_name,
				   CTLFLAG_RD, NULL, rxq_desc);
	this_rxq_list = SYSCTL_CHILDREN(rxq_node);

	/* Add the Rx queue statistics */
	while (entry->stat != 0) {
		SYSCTL_ADD_U64(ctx, this_rxq_list, OID_AUTO, entry->name,
			       CTLFLAG_RD | CTLFLAG_STATS, entry->stat, 0,
			       entry->description);
		entry++;
	}
}

/**
 * ice_get_default_rss_key - Obtain a default RSS key
 * @seed: storage for the RSS key data
 *
 * Copies a pre-generated RSS key into the seed memory. The seed pointer must
 * point to a block of memory that is at least 40 bytes in size.
 *
 * The key isn't randomly generated each time this function is called because
 * that makes the RSS key change every time we reconfigure RSS. This does mean
 * that we're hard coding a possibly 'well known' key. We might want to
 * investigate randomly generating this key once during the first call.
 */
static void
ice_get_default_rss_key(u8 *seed)
{
	const u8 default_seed[ICE_AQC_GET_SET_RSS_KEY_DATA_RSS_KEY_SIZE] = {
		0x39, 0xed, 0xff, 0x4d, 0x43, 0x58, 0x42, 0xc3, 0x5f, 0xb8,
		0xa5, 0x32, 0x95, 0x65, 0x81, 0xcd, 0x36, 0x79, 0x71, 0x97,
		0xde, 0xa4, 0x41, 0x40, 0x6f, 0x27, 0xe9, 0x81, 0x13, 0xa0,
		0x95, 0x93, 0x5b, 0x1e, 0x9d, 0x27, 0x9d, 0x24, 0x84, 0xb5,
	};

	bcopy(default_seed, seed, ICE_AQC_GET_SET_RSS_KEY_DATA_RSS_KEY_SIZE);
}

/**
 * ice_set_rss_key - Configure a given VSI with the default RSS key
 * @vsi: the VSI to configure
 *
 * Program the hardware RSS key. We use rss_getkey to grab the kernel RSS key.
 * If the kernel RSS interface is not available, this will fall back to our
 * pre-generated hash seed from ice_get_default_rss_key().
 */
static int
ice_set_rss_key(struct ice_vsi *vsi)
{
	struct ice_aqc_get_set_rss_keys keydata = { .standard_rss_key = {0} };
	struct ice_softc *sc = vsi->sc;
	struct ice_hw *hw = &sc->hw;
	enum ice_status status;

	/*
	 * If the RSS kernel interface is disabled, this will return the
	 * default RSS key above.
	 */
	rss_getkey(keydata.standard_rss_key);

	status = ice_aq_set_rss_key(hw, vsi->idx, &keydata);
	if (status) {
		device_printf(sc->dev,
			      "ice_aq_set_rss_key status %s, error %s\n",
			      ice_status_str(status), ice_aq_str(hw->adminq.sq_last_status));
		return (EIO);
	}

	return (0);
}

/**
 * ice_set_rss_flow_flds - Program the RSS hash flows after package init
 * @vsi: the VSI to configure
 *
 * If the package file is initialized, the default RSS flows are reset. We
 * need to reprogram the expected hash configuration. We'll use
 * rss_gethashconfig() to determine which flows to enable. If RSS kernel
 * support is not enabled, this macro will fall back to suitable defaults.
 */
static void
ice_set_rss_flow_flds(struct ice_vsi *vsi)
{
	struct ice_softc *sc = vsi->sc;
	struct ice_hw *hw = &sc->hw;
	device_t dev = sc->dev;
	enum ice_status status;
	u_int rss_hash_config;

	rss_hash_config = rss_gethashconfig();

	if (rss_hash_config & RSS_HASHTYPE_RSS_IPV4) {
		status = ice_add_rss_cfg(hw, vsi->idx, ICE_FLOW_HASH_IPV4,
					 ICE_FLOW_SEG_HDR_IPV4);
		if (status)
			device_printf(dev,
				      "ice_add_rss_cfg on VSI %d failed for ipv4 flow, err %s aq_err %s\n",
				      vsi->idx, ice_status_str(status), ice_aq_str(hw->adminq.sq_last_status));
	}
	if (rss_hash_config & RSS_HASHTYPE_RSS_TCP_IPV4) {
		status = ice_add_rss_cfg(hw, vsi->idx, ICE_HASH_TCP_IPV4,
					 ICE_FLOW_SEG_HDR_TCP | ICE_FLOW_SEG_HDR_IPV4);
		if (status)
			device_printf(dev,
				      "ice_add_rss_cfg on VSI %d failed for tcp4 flow, err %s aq_err %s\n",
				      vsi->idx, ice_status_str(status), ice_aq_str(hw->adminq.sq_last_status));
	}
	if (rss_hash_config & RSS_HASHTYPE_RSS_UDP_IPV4) {
		status = ice_add_rss_cfg(hw, vsi->idx, ICE_HASH_UDP_IPV4,
					 ICE_FLOW_SEG_HDR_UDP | ICE_FLOW_SEG_HDR_IPV4);
		if (status)
			device_printf(dev,
				      "ice_add_rss_cfg on VSI %d failed for udp4 flow, err %s aq_err %s\n",
				      vsi->idx, ice_status_str(status), ice_aq_str(hw->adminq.sq_last_status));
	}
	if (rss_hash_config & (RSS_HASHTYPE_RSS_IPV6 | RSS_HASHTYPE_RSS_IPV6_EX)) {
		status = ice_add_rss_cfg(hw, vsi->idx, ICE_FLOW_HASH_IPV6,
					 ICE_FLOW_SEG_HDR_IPV6);
		if (status)
			device_printf(dev,
				      "ice_add_rss_cfg on VSI %d failed for ipv6 flow, err %s aq_err %s\n",
				      vsi->idx, ice_status_str(status), ice_aq_str(hw->adminq.sq_last_status));
	}
	if (rss_hash_config & RSS_HASHTYPE_RSS_TCP_IPV6) {
		status = ice_add_rss_cfg(hw, vsi->idx, ICE_HASH_TCP_IPV6,
					 ICE_FLOW_SEG_HDR_TCP | ICE_FLOW_SEG_HDR_IPV6);
		if (status)
			device_printf(dev,
				      "ice_add_rss_cfg on VSI %d failed for tcp6 flow, err %s aq_err %s\n",
				      vsi->idx, ice_status_str(status), ice_aq_str(hw->adminq.sq_last_status));
	}
	if (rss_hash_config & RSS_HASHTYPE_RSS_UDP_IPV6) {
		status = ice_add_rss_cfg(hw, vsi->idx, ICE_HASH_UDP_IPV6,
					 ICE_FLOW_SEG_HDR_UDP | ICE_FLOW_SEG_HDR_IPV6);
		if (status)
			device_printf(dev,
				      "ice_add_rss_cfg on VSI %d failed for udp6 flow, err %s aq_err %s\n",
				      vsi->idx, ice_status_str(status), ice_aq_str(hw->adminq.sq_last_status));
	}

	/* Warn about RSS hash types which are not supported */
	/* coverity[dead_error_condition] */
	if (rss_hash_config & ~ICE_DEFAULT_RSS_HASH_CONFIG) {
		device_printf(dev,
			      "ice_add_rss_cfg on VSI %d could not configure every requested hash type\n",
			      vsi->idx);
	}
}

/**
 * ice_set_rss_lut - Program the RSS lookup table for a VSI
 * @vsi: the VSI to configure
 *
 * Programs the RSS lookup table for a given VSI. We use
 * rss_get_indirection_to_bucket which will use the indirection table provided
 * by the kernel RSS interface when available. If the kernel RSS interface is
 * not available, we will fall back to a simple round-robin fashion queue
 * assignment.
 */
static int
ice_set_rss_lut(struct ice_vsi *vsi)
{
	struct ice_softc *sc = vsi->sc;
	struct ice_hw *hw = &sc->hw;
	device_t dev = sc->dev;
	enum ice_status status;
	int i, err = 0;
	u8 *lut;

	lut = (u8 *)malloc(vsi->rss_table_size, M_ICE, M_NOWAIT|M_ZERO);
	if (!lut) {
		device_printf(dev, "Failed to allocate RSS lut memory\n");
		return (ENOMEM);
	}

	/* Populate the LUT with max no. of queues. If the RSS kernel
	 * interface is disabled, this will assign the lookup table in
	 * a simple round robin fashion
	 */
	for (i = 0; i < vsi->rss_table_size; i++) {
		/* XXX: this needs to be changed if num_rx_queues ever counts
		 * more than just the RSS queues */
		lut[i] = rss_get_indirection_to_bucket(i) % vsi->num_rx_queues;
	}

	status = ice_aq_set_rss_lut(hw, vsi->idx, vsi->rss_lut_type,
				    lut, vsi->rss_table_size);
	if (status) {
		device_printf(dev,
			      "Cannot set RSS lut, err %s aq_err %s\n",
			      ice_status_str(status), ice_aq_str(hw->adminq.sq_last_status));
		err = (EIO);
	}

	free(lut, M_ICE);
	return err;
}

/**
 * ice_config_rss - Configure RSS for a VSI
 * @vsi: the VSI to configure
 *
 * If FEATURE_RSS is enabled, configures the RSS lookup table and hash key for
 * a given VSI.
 */
int
ice_config_rss(struct ice_vsi *vsi)
{
	int err;

	/* Nothing to do, if RSS is not enabled */
	if (!ice_is_bit_set(vsi->sc->feat_en, ICE_FEATURE_RSS))
		return 0;

	err = ice_set_rss_key(vsi);
	if (err)
		return err;

	ice_set_rss_flow_flds(vsi);

	return ice_set_rss_lut(vsi);
}

/**
 * ice_log_pkg_init - Log a message about status of DDP initialization
 * @sc: the device softc pointer
 * @pkg_status: the status result of ice_copy_and_init_pkg
 *
 * Called by ice_load_pkg after an attempt to download the DDP package
 * contents to the device. Determines whether the download was successful or
 * not and logs an appropriate message for the system administrator.
 *
 * @post if a DDP package was previously downloaded on another port and it
 * is not compatible with this driver, pkg_status will be updated to reflect
 * this, and the driver will transition to safe mode.
 */
void
ice_log_pkg_init(struct ice_softc *sc, enum ice_status *pkg_status)
{
	struct ice_hw *hw = &sc->hw;
	device_t dev = sc->dev;
	struct sbuf *active_pkg, *os_pkg;

	active_pkg = sbuf_new_auto();
	ice_active_pkg_version_str(hw, active_pkg);
	sbuf_finish(active_pkg);

	os_pkg = sbuf_new_auto();
	ice_os_pkg_version_str(hw, os_pkg);
	sbuf_finish(os_pkg);

	switch (*pkg_status) {
	case ICE_SUCCESS:
		/* The package download AdminQ command returned success because
		 * this download succeeded or ICE_ERR_AQ_NO_WORK since there is
		 * already a package loaded on the device.
		 */
		if (hw->pkg_ver.major == hw->active_pkg_ver.major &&
		    hw->pkg_ver.minor == hw->active_pkg_ver.minor &&
		    hw->pkg_ver.update == hw->active_pkg_ver.update &&
		    hw->pkg_ver.draft == hw->active_pkg_ver.draft &&
		    !memcmp(hw->pkg_name, hw->active_pkg_name,
			    sizeof(hw->pkg_name))) {
			switch (hw->pkg_dwnld_status) {
			case ICE_AQ_RC_OK:
				device_printf(dev,
					      "The DDP package was successfully loaded: %s.\n",
					      sbuf_data(active_pkg));
				break;
			case ICE_AQ_RC_EEXIST:
				device_printf(dev,
					      "DDP package already present on device: %s.\n",
					      sbuf_data(active_pkg));
				break;
			default:
				/* We do not expect this to occur, but the
				 * extra messaging is here in case something
				 * changes in the ice_init_pkg flow.
				 */
				device_printf(dev,
					      "DDP package already present on device: %s.  An unexpected error occurred, pkg_dwnld_status %s.\n",
					      sbuf_data(active_pkg),
					      ice_aq_str(hw->pkg_dwnld_status));
				break;
			}
		} else if (pkg_ver_compatible(&hw->active_pkg_ver) == 0) {
			device_printf(dev,
				      "The driver could not load the DDP package file because a compatible DDP package is already present on the device.  The device has package %s.  The ice_ddp module has package: %s.\n",
				      sbuf_data(active_pkg),
				      sbuf_data(os_pkg));
		} else if (pkg_ver_compatible(&hw->active_pkg_ver) > 0) {
			device_printf(dev,
				      "The device has a DDP package that is higher than the driver supports.  The device has package %s.  The driver requires version %d.%d.x.x.  Entering Safe Mode.\n",
				      sbuf_data(active_pkg),
				      ICE_PKG_SUPP_VER_MAJ, ICE_PKG_SUPP_VER_MNR);
			*pkg_status = ICE_ERR_NOT_SUPPORTED;
		} else {
			device_printf(dev,
				      "The device has a DDP package that is lower than the driver supports.  The device has package %s.  The driver requires version %d.%d.x.x.  Entering Safe Mode.\n",
				      sbuf_data(active_pkg),
				      ICE_PKG_SUPP_VER_MAJ, ICE_PKG_SUPP_VER_MNR);
			*pkg_status = ICE_ERR_NOT_SUPPORTED;
		}
		break;
	case ICE_ERR_NOT_SUPPORTED:
		/*
		 * This assumes that the active_pkg_ver will not be
		 * initialized if the ice_ddp package version is not
		 * supported.
		 */
		if (pkg_ver_empty(&hw->active_pkg_ver, hw->active_pkg_name)) {
			/* The ice_ddp version is not supported */
			if (pkg_ver_compatible(&hw->pkg_ver) > 0) {
				device_printf(dev,
					      "The DDP package in the ice_ddp module is higher than the driver supports.  The ice_ddp module has package %s.  The driver requires version %d.%d.x.x.  Please use an updated driver.  Entering Safe Mode.\n",
					      sbuf_data(os_pkg),
					      ICE_PKG_SUPP_VER_MAJ, ICE_PKG_SUPP_VER_MNR);
			} else if (pkg_ver_compatible(&hw->pkg_ver) < 0) {
				device_printf(dev,
					      "The DDP package in the ice_ddp module is lower than the driver supports.  The ice_ddp module has package %s.  The driver requires version %d.%d.x.x.  Please use an updated ice_ddp module.  Entering Safe Mode.\n",
					      sbuf_data(os_pkg),
					      ICE_PKG_SUPP_VER_MAJ, ICE_PKG_SUPP_VER_MNR);
			} else {
				device_printf(dev,
					      "An unknown error (%s aq_err %s) occurred when loading the DDP package.  The ice_ddp module has package %s.  The device has package %s.  The driver requires version %d.%d.x.x.  Entering Safe Mode.\n",
					      ice_status_str(*pkg_status),
					      ice_aq_str(hw->pkg_dwnld_status),
					      sbuf_data(os_pkg),
					      sbuf_data(active_pkg),
					      ICE_PKG_SUPP_VER_MAJ, ICE_PKG_SUPP_VER_MNR);
			}
		} else {
			if (pkg_ver_compatible(&hw->active_pkg_ver) > 0) {
				device_printf(dev,
					      "The device has a DDP package that is higher than the driver supports.  The device has package %s.  The driver requires version %d.%d.x.x.  Entering Safe Mode.\n",
					      sbuf_data(active_pkg),
					      ICE_PKG_SUPP_VER_MAJ, ICE_PKG_SUPP_VER_MNR);
			} else if (pkg_ver_compatible(&hw->active_pkg_ver) < 0) {
				device_printf(dev,
					      "The device has a DDP package that is lower than the driver supports.  The device has package %s.  The driver requires version %d.%d.x.x.  Entering Safe Mode.\n",
					      sbuf_data(active_pkg),
					      ICE_PKG_SUPP_VER_MAJ, ICE_PKG_SUPP_VER_MNR);
			} else {
				device_printf(dev,
					      "An unknown error (%s aq_err %s) occurred when loading the DDP package.  The ice_ddp module has package %s.  The device has package %s.  The driver requires version %d.%d.x.x.  Entering Safe Mode.\n",
					      ice_status_str(*pkg_status),
					      ice_aq_str(hw->pkg_dwnld_status),
					      sbuf_data(os_pkg),
					      sbuf_data(active_pkg),
					      ICE_PKG_SUPP_VER_MAJ, ICE_PKG_SUPP_VER_MNR);
			}
		}
		break;
	case ICE_ERR_CFG:
	case ICE_ERR_BUF_TOO_SHORT:
	case ICE_ERR_PARAM:
		device_printf(dev,
			      "The DDP package in the ice_ddp module is invalid.  Entering Safe Mode\n");
		break;
	case ICE_ERR_FW_DDP_MISMATCH:
		device_printf(dev,
			      "The firmware loaded on the device is not compatible with the DDP package.  Please update the device's NVM.  Entering safe mode.\n");
		break;
	case ICE_ERR_AQ_ERROR:
		switch (hw->pkg_dwnld_status) {
		case ICE_AQ_RC_ENOSEC:
		case ICE_AQ_RC_EBADSIG:
			device_printf(dev,
				 "The DDP package in the ice_ddp module cannot be loaded because its signature is not valid.  Please use a valid ice_ddp module.  Entering Safe Mode.\n");
			goto free_sbufs;
		case ICE_AQ_RC_ESVN:
			device_printf(dev,
				 "The DDP package in the ice_ddp module could not be loaded because its security revision is too low.  Please use an updated ice_ddp module.  Entering Safe Mode.\n");
			goto free_sbufs;
		case ICE_AQ_RC_EBADMAN:
		case ICE_AQ_RC_EBADBUF:
			device_printf(dev,
				 "An error occurred on the device while loading the DDP package.  Entering Safe Mode.\n");
			goto free_sbufs;
		default:
			break;
		}
		/* fall-through */
	default:
		device_printf(dev,
			 "An unknown error (%s aq_err %s) occurred when loading the DDP package.  Entering Safe Mode.\n",
			 ice_status_str(*pkg_status),
			 ice_aq_str(hw->pkg_dwnld_status));
		break;
	}

free_sbufs:
	sbuf_delete(active_pkg);
	sbuf_delete(os_pkg);
}

/**
 * ice_load_pkg_file - Load the DDP package file using firmware_get
 * @sc: device private softc
 *
 * Use firmware_get to load the DDP package memory and then request that
 * firmware download the package contents and program the relevant hardware
 * bits.
 *
 * This function makes a copy of the DDP package memory which is tracked in
 * the ice_hw structure. The copy will be managed and released by
 * ice_deinit_hw(). This allows the firmware reference to be immediately
 * released using firmware_put.
 */
void
ice_load_pkg_file(struct ice_softc *sc)
{
	struct ice_hw *hw = &sc->hw;
	device_t dev = sc->dev;
	enum ice_status status;
	const struct firmware *pkg;

	pkg = firmware_get("ice_ddp");
	if (!pkg) {
		device_printf(dev, "The DDP package module (ice_ddp) failed to load or could not be found. Entering Safe Mode.\n");
		if (cold)
			device_printf(dev,
				      "The DDP package module cannot be automatically loaded while booting. You may want to specify ice_ddp_load=\"YES\" in your loader.conf\n");
		ice_set_bit(ICE_FEATURE_SAFE_MODE, sc->feat_cap);
		ice_set_bit(ICE_FEATURE_SAFE_MODE, sc->feat_en);
		return;
	}

	/* Copy and download the pkg contents */
	status = ice_copy_and_init_pkg(hw, (const u8 *)pkg->data, pkg->datasize);

	/* Release the firmware reference */
	firmware_put(pkg, FIRMWARE_UNLOAD);

	/* Check the active DDP package version and log a message */
	ice_log_pkg_init(sc, &status);

	/* Place the driver into safe mode */
	if (status != ICE_SUCCESS) {
		ice_set_bit(ICE_FEATURE_SAFE_MODE, sc->feat_cap);
		ice_set_bit(ICE_FEATURE_SAFE_MODE, sc->feat_en);
	}
}

/**
 * ice_get_ifnet_counter - Retrieve counter value for a given ifnet counter
 * @vsi: the vsi to retrieve the value for
 * @counter: the counter type to retrieve
 *
 * Returns the value for a given ifnet counter. To do so, we calculate the
 * value based on the matching hardware statistics.
 */
uint64_t
ice_get_ifnet_counter(struct ice_vsi *vsi, ift_counter counter)
{
	struct ice_hw_port_stats *hs = &vsi->sc->stats.cur;
	struct ice_eth_stats *es = &vsi->hw_stats.cur;

	/* For some statistics, especially those related to error flows, we do
	 * not have per-VSI counters. In this case, we just report the global
	 * counters.
	 */

	switch (counter) {
	case IFCOUNTER_IPACKETS:
		return (es->rx_unicast + es->rx_multicast + es->rx_broadcast);
	case IFCOUNTER_IERRORS:
		return (hs->crc_errors + hs->illegal_bytes +
			hs->mac_local_faults + hs->mac_remote_faults +
			hs->rx_len_errors + hs->rx_undersize +
			hs->rx_oversize + hs->rx_fragments + hs->rx_jabber);
	case IFCOUNTER_OPACKETS:
		return (es->tx_unicast + es->tx_multicast + es->tx_broadcast);
	case IFCOUNTER_OERRORS:
		return (es->tx_errors);
	case IFCOUNTER_COLLISIONS:
		return (0);
	case IFCOUNTER_IBYTES:
		return (es->rx_bytes);
	case IFCOUNTER_OBYTES:
		return (es->tx_bytes);
	case IFCOUNTER_IMCASTS:
		return (es->rx_multicast);
	case IFCOUNTER_OMCASTS:
		return (es->tx_multicast);
	case IFCOUNTER_IQDROPS:
		return (es->rx_discards);
	case IFCOUNTER_OQDROPS:
		return (hs->tx_dropped_link_down);
	case IFCOUNTER_NOPROTO:
		return (es->rx_unknown_protocol);
	default:
		return if_get_counter_default(vsi->sc->ifp, counter);
	}
}

/**
 * ice_save_pci_info - Save PCI configuration fields in HW struct
 * @hw: the ice_hw struct to save the PCI information in
 * @dev: the device to get the PCI information from
 *
 * This should only be called once, early in the device attach
 * process.
 */
void
ice_save_pci_info(struct ice_hw *hw, device_t dev)
{
	hw->vendor_id = pci_get_vendor(dev);
	hw->device_id = pci_get_device(dev);
	hw->subsystem_vendor_id = pci_get_subvendor(dev);
	hw->subsystem_device_id = pci_get_subdevice(dev);
	hw->revision_id = pci_get_revid(dev);
	hw->bus.device = pci_get_slot(dev);
	hw->bus.func = pci_get_function(dev);
}

/**
 * ice_replay_all_vsi_cfg - Replace configuration for all VSIs after reset
 * @sc: the device softc
 *
 * Replace the configuration for each VSI, and then cleanup replay
 * information. Called after a hardware reset in order to reconfigure the
 * active VSIs.
 */
int
ice_replay_all_vsi_cfg(struct ice_softc *sc)
{
	struct ice_hw *hw = &sc->hw;
	enum ice_status status;
	int i;

	for (i = 0 ; i < sc->num_available_vsi; i++) {
		struct ice_vsi *vsi = sc->all_vsi[i];

		if (!vsi)
			continue;

		status = ice_replay_vsi(hw, vsi->idx);
		if (status) {
			device_printf(sc->dev, "Failed to replay VSI %d, err %s aq_err %s\n",
				      vsi->idx, ice_status_str(status),
				      ice_aq_str(hw->adminq.sq_last_status));
			return (EIO);
		}
	}

	/* Cleanup replay filters after successful reconfiguration */
	ice_replay_post(hw);
	return (0);
}

/**
 * ice_clean_vsi_rss_cfg - Cleanup RSS configuration for a given VSI
 * @vsi: pointer to the VSI structure
 *
 * Cleanup the advanced RSS configuration for a given VSI. This is necessary
 * during driver removal to ensure that all RSS resources are properly
 * released.
 *
 * @remark this function doesn't report an error as it is expected to be
 * called during driver reset and unload, and there isn't much the driver can
 * do if freeing RSS resources fails.
 */
static void
ice_clean_vsi_rss_cfg(struct ice_vsi *vsi)
{
	struct ice_softc *sc = vsi->sc;
	struct ice_hw *hw = &sc->hw;
	device_t dev = sc->dev;
	enum ice_status status;

	status = ice_rem_vsi_rss_cfg(hw, vsi->idx);
	if (status)
		device_printf(dev,
			      "Failed to remove RSS configuration for VSI %d, err %s\n",
			      vsi->idx, ice_status_str(status));

	/* Remove this VSI from the RSS list */
	ice_rem_vsi_rss_list(hw, vsi->idx);
}

/**
 * ice_clean_all_vsi_rss_cfg - Cleanup RSS configuration for all VSIs
 * @sc: the device softc pointer
 *
 * Cleanup the advanced RSS configuration for all VSIs on a given PF
 * interface.
 *
 * @remark This should be called while preparing for a reset, to cleanup stale
 * RSS configuration for all VSIs.
 */
void
ice_clean_all_vsi_rss_cfg(struct ice_softc *sc)
{
	int i;

	/* No need to cleanup if RSS is not enabled */
	if (!ice_is_bit_set(sc->feat_en, ICE_FEATURE_RSS))
		return;

	for (i = 0; i < sc->num_available_vsi; i++) {
		struct ice_vsi *vsi = sc->all_vsi[i];

		if (vsi)
			ice_clean_vsi_rss_cfg(vsi);
	}
}

/**
 * ice_requested_fec_mode - Return the requested FEC mode as a string
 * @pi: The port info structure
 *
 * Return a string representing the requested FEC mode.
 */
static const char *
ice_requested_fec_mode(struct ice_port_info *pi)
{
	struct ice_aqc_get_phy_caps_data pcaps = { 0 };
	enum ice_status status;

	status = ice_aq_get_phy_caps(pi, false, ICE_AQC_REPORT_SW_CFG,
				     &pcaps, NULL);
	if (status)
		/* Just report unknown if we can't get capabilities */
		return "Unknown";

	/* Check if RS-FEC has been requested first */
	if (pcaps.link_fec_options & (ICE_AQC_PHY_FEC_25G_RS_528_REQ |
				      ICE_AQC_PHY_FEC_25G_RS_544_REQ))
		return ice_fec_str(ICE_FEC_RS);

	/* If RS FEC has not been requested, then check BASE-R */
	if (pcaps.link_fec_options & (ICE_AQC_PHY_FEC_10G_KR_40G_KR4_REQ |
				      ICE_AQC_PHY_FEC_25G_KR_REQ))
		return ice_fec_str(ICE_FEC_BASER);

	return ice_fec_str(ICE_FEC_NONE);
}

/**
 * ice_negotiated_fec_mode - Return the negotiated FEC mode as a string
 * @pi: The port info structure
 *
 * Return a string representing the current FEC mode.
 */
static const char *
ice_negotiated_fec_mode(struct ice_port_info *pi)
{
	/* First, check if RS has been requested first */
	if (pi->phy.link_info.fec_info & (ICE_AQ_LINK_25G_RS_528_FEC_EN |
					  ICE_AQ_LINK_25G_RS_544_FEC_EN))
		return ice_fec_str(ICE_FEC_RS);

	/* If RS FEC has not been requested, then check BASE-R */
	if (pi->phy.link_info.fec_info & ICE_AQ_LINK_25G_KR_FEC_EN)
		return ice_fec_str(ICE_FEC_BASER);

	return ice_fec_str(ICE_FEC_NONE);
}

/**
 * ice_autoneg_mode - Return string indicating of autoneg completed
 * @pi: The port info structure
 *
 * Return "True" if autonegotiation is completed, "False" otherwise.
 */
static const char *
ice_autoneg_mode(struct ice_port_info *pi)
{
	if (pi->phy.link_info.an_info & ICE_AQ_AN_COMPLETED)
		return "True";
	else
		return "False";
}

/**
 * ice_flowcontrol_mode - Return string indicating the Flow Control mode
 * @pi: The port info structure
 *
 * Returns the current Flow Control mode as a string.
 */
static const char *
ice_flowcontrol_mode(struct ice_port_info *pi)
{
	return ice_fc_str(pi->fc.current_mode);
}

/**
 * ice_link_up_msg - Log a link up message with associated info
 * @sc: the device private softc
 *
 * Log a link up message with LOG_NOTICE message level. Include information
 * about the duplex, FEC mode, autonegotiation and flow control.
 */
void
ice_link_up_msg(struct ice_softc *sc)
{
	struct ice_hw *hw = &sc->hw;
	struct ifnet *ifp = sc->ifp;
	const char *speed, *req_fec, *neg_fec, *autoneg, *flowcontrol;

	speed = ice_aq_speed_to_str(hw->port_info);
	req_fec = ice_requested_fec_mode(hw->port_info);
	neg_fec = ice_negotiated_fec_mode(hw->port_info);
	autoneg = ice_autoneg_mode(hw->port_info);
	flowcontrol = ice_flowcontrol_mode(hw->port_info);

	log(LOG_NOTICE, "%s: Link is up, %s Full Duplex, Requested FEC: %s, Negotiated FEC: %s, Autoneg: %s, Flow Control: %s\n",
	    ifp->if_xname, speed, req_fec, neg_fec, autoneg, flowcontrol);
}

/**
 * ice_update_laa_mac - Update MAC address if Locally Administered
 * @sc: the device softc
 *
 * Update the device MAC address when a Locally Administered Address is
 * assigned.
 *
 * This function does *not* update the MAC filter list itself. Instead, it
 * should be called after ice_rm_pf_default_mac_filters, so that the previous
 * address filter will be removed, and before ice_cfg_pf_default_mac_filters,
 * so that the new address filter will be assigned.
 */
int
ice_update_laa_mac(struct ice_softc *sc)
{
	const u8 *lladdr = (const u8 *)IF_LLADDR(sc->ifp);
	struct ice_hw *hw = &sc->hw;
	enum ice_status status;

	/* If the address is the same, then there is nothing to update */
	if (!memcmp(lladdr, hw->port_info->mac.lan_addr, ETHER_ADDR_LEN))
		return (0);

	/* Reject Multicast addresses */
	if (ETHER_IS_MULTICAST(lladdr))
		return (EINVAL);

	status = ice_aq_manage_mac_write(hw, lladdr, ICE_AQC_MAN_MAC_UPDATE_LAA_WOL, NULL);
	if (status) {
		device_printf(sc->dev, "Failed to write mac %6D to firmware, err %s aq_err %s\n",
			      lladdr, ":", ice_status_str(status),
			      ice_aq_str(hw->adminq.sq_last_status));
		return (EFAULT);
	}

	/* Copy the address into place of the LAN address. */
	bcopy(lladdr, hw->port_info->mac.lan_addr, ETHER_ADDR_LEN);

	return (0);
}

/**
 * ice_get_and_print_bus_info - Save (PCI) bus info and print messages
 * @sc: device softc
 *
 * This will potentially print out a warning message if bus bandwidth
 * is insufficient for full-speed operation.
 *
 * This should only be called once, during the attach process, after
 * hw->port_info has been filled out with port link topology information
 * (from the Get PHY Capabilities Admin Queue command).
 */
void
ice_get_and_print_bus_info(struct ice_softc *sc)
{
	struct ice_hw *hw = &sc->hw;
	device_t dev = sc->dev;
	u16 pci_link_status;
	int offset;

	pci_find_cap(dev, PCIY_EXPRESS, &offset);
	pci_link_status = pci_read_config(dev, offset + PCIER_LINK_STA, 2);

	/* Fill out hw struct with PCIE link status info */
	ice_set_pci_link_status_data(hw, pci_link_status);

	/* Use info to print out bandwidth messages */
	ice_print_bus_link_data(dev, hw);

	if (ice_pcie_bandwidth_check(sc)) {
		device_printf(dev,
		    "PCI-Express bandwidth available for this device may be insufficient for optimal performance.\n");
		device_printf(dev,
		    "Please move the device to a different PCI-e link with more lanes and/or higher transfer rate.\n");
	}
}

/**
 * ice_pcie_bus_speed_to_rate - Convert driver bus speed enum value to
 * a 64-bit baudrate.
 * @speed: enum value to convert
 *
 * This only goes up to PCIE Gen 4.
 */
static uint64_t
ice_pcie_bus_speed_to_rate(enum ice_pcie_bus_speed speed)
{
	/* If the PCI-E speed is Gen1 or Gen2, then report
	 * only 80% of bus speed to account for encoding overhead.
	 */
	switch (speed) {
	case ice_pcie_speed_2_5GT:
		return IF_Gbps(2);
	case ice_pcie_speed_5_0GT:
		return IF_Gbps(4);
	case ice_pcie_speed_8_0GT:
		return IF_Gbps(8);
	case ice_pcie_speed_16_0GT:
		return IF_Gbps(16);
	case ice_pcie_speed_unknown:
	default:
		return 0;
	}
}

/**
 * ice_pcie_lnk_width_to_int - Convert driver pci-e width enum value to
 * a 32-bit number.
 * @width: enum value to convert
 */
static int
ice_pcie_lnk_width_to_int(enum ice_pcie_link_width width)
{
	switch (width) {
	case ice_pcie_lnk_x1:
		return (1);
	case ice_pcie_lnk_x2:
		return (2);
	case ice_pcie_lnk_x4:
		return (4);
	case ice_pcie_lnk_x8:
		return (8);
	case ice_pcie_lnk_x12:
		return (12);
	case ice_pcie_lnk_x16:
		return (16);
	case ice_pcie_lnk_x32:
		return (32);
	case ice_pcie_lnk_width_resrv:
	case ice_pcie_lnk_width_unknown:
	default:
		return (0);
	}
}

/**
 * ice_pcie_bandwidth_check - Check if PCI-E bandwidth is sufficient for
 * full-speed device operation.
 * @sc: adapter softc
 *
 * Returns 0 if sufficient; 1 if not.
 */
static uint8_t
ice_pcie_bandwidth_check(struct ice_softc *sc)
{
	struct ice_hw *hw = &sc->hw;
	int num_ports, pcie_width;
	u64 pcie_speed, port_speed;

	MPASS(hw->port_info);

	num_ports = bitcount32(hw->func_caps.common_cap.valid_functions);
	port_speed = ice_phy_types_to_max_rate(hw->port_info);
	pcie_speed = ice_pcie_bus_speed_to_rate(hw->bus.speed);
	pcie_width = ice_pcie_lnk_width_to_int(hw->bus.width);

	/*
	 * If 2x100, clamp ports to 1 -- 2nd port is intended for
	 * failover.
	 */
	if (port_speed == IF_Gbps(100))
		num_ports = 1;

	return !!((num_ports * port_speed) > pcie_speed * pcie_width);
}

/**
 * ice_print_bus_link_data - Print PCI-E bandwidth information
 * @dev: device to print string for
 * @hw: hw struct with PCI-e link information
 */
static void
ice_print_bus_link_data(device_t dev, struct ice_hw *hw)
{
        device_printf(dev, "PCI Express Bus: Speed %s %s\n",
            ((hw->bus.speed == ice_pcie_speed_16_0GT) ? "16.0GT/s" :
            (hw->bus.speed == ice_pcie_speed_8_0GT) ? "8.0GT/s" :
            (hw->bus.speed == ice_pcie_speed_5_0GT) ? "5.0GT/s" :
            (hw->bus.speed == ice_pcie_speed_2_5GT) ? "2.5GT/s" : "Unknown"),
            (hw->bus.width == ice_pcie_lnk_x32) ? "Width x32" :
            (hw->bus.width == ice_pcie_lnk_x16) ? "Width x16" :
            (hw->bus.width == ice_pcie_lnk_x12) ? "Width x12" :
            (hw->bus.width == ice_pcie_lnk_x8) ? "Width x8" :
            (hw->bus.width == ice_pcie_lnk_x4) ? "Width x4" :
            (hw->bus.width == ice_pcie_lnk_x2) ? "Width x2" :
            (hw->bus.width == ice_pcie_lnk_x1) ? "Width x1" : "Width Unknown");
}

/**
 * ice_set_pci_link_status_data - store PCI bus info
 * @hw: pointer to hardware structure
 * @link_status: the link status word from PCI config space
 *
 * Stores the PCI bus info (speed, width, type) within the ice_hw structure
 **/
static void
ice_set_pci_link_status_data(struct ice_hw *hw, u16 link_status)
{
	u16 reg;

	hw->bus.type = ice_bus_pci_express;

	reg = (link_status & PCIEM_LINK_STA_WIDTH) >> 4;

	switch (reg) {
	case ice_pcie_lnk_x1:
	case ice_pcie_lnk_x2:
	case ice_pcie_lnk_x4:
	case ice_pcie_lnk_x8:
	case ice_pcie_lnk_x12:
	case ice_pcie_lnk_x16:
	case ice_pcie_lnk_x32:
		hw->bus.width = (enum ice_pcie_link_width)reg;
		break;
	default:
		hw->bus.width = ice_pcie_lnk_width_unknown;
		break;
	}

	reg = (link_status & PCIEM_LINK_STA_SPEED) + 0x14;

	switch (reg) {
	case ice_pcie_speed_2_5GT:
	case ice_pcie_speed_5_0GT:
	case ice_pcie_speed_8_0GT:
	case ice_pcie_speed_16_0GT:
		hw->bus.speed = (enum ice_pcie_bus_speed)reg;
		break;
	default:
		hw->bus.speed = ice_pcie_speed_unknown;
		break;
	}
}

/**
 * ice_init_link_events - Initialize Link Status Events mask
 * @sc: the device softc
 *
 * Initialize the Link Status Events mask to disable notification of link
 * events we don't care about in software. Also request that link status
 * events be enabled.
 */
int
ice_init_link_events(struct ice_softc *sc)
{
	struct ice_hw *hw = &sc->hw;
	enum ice_status status;
	u16 wanted_events;

	/* Set the bits for the events that we want to be notified by */
	wanted_events = (ICE_AQ_LINK_EVENT_UPDOWN |
			 ICE_AQ_LINK_EVENT_MEDIA_NA |
			 ICE_AQ_LINK_EVENT_MODULE_QUAL_FAIL);

	/* request that every event except the wanted events be masked */
	status = ice_aq_set_event_mask(hw, hw->port_info->lport, ~wanted_events, NULL);
	if (status) {
		device_printf(sc->dev,
			      "Failed to set link status event mask, err %s aq_err %s\n",
			      ice_status_str(status), ice_aq_str(hw->adminq.sq_last_status));
		return (EIO);
	}

	/* Request link info with the LSE bit set to enable link status events */
	status = ice_aq_get_link_info(hw->port_info, true, NULL, NULL);
	if (status) {
		device_printf(sc->dev,
			      "Failed to enable link status events, err %s aq_err %s\n",
			      ice_status_str(status), ice_aq_str(hw->adminq.sq_last_status));
		return (EIO);
	}

	return (0);
}

/**
 * ice_handle_mdd_event - Handle possibly malicious events
 * @sc: the device softc
 *
 * Called by the admin task if an MDD detection interrupt is triggered.
 * Identifies possibly malicious events coming from VFs. Also triggers for
 * similar incorrect behavior from the PF as well.
 */
void
ice_handle_mdd_event(struct ice_softc *sc)
{
	struct ice_hw *hw = &sc->hw;
	bool mdd_detected = false, request_reinit = false;
	device_t dev = sc->dev;
	u32 reg;

	if (!ice_testandclear_state(&sc->state, ICE_STATE_MDD_PENDING))
		return;

	reg = rd32(hw, GL_MDET_TX_TCLAN);
	if (reg & GL_MDET_TX_TCLAN_VALID_M) {
		u8 pf_num  = (reg & GL_MDET_TX_TCLAN_PF_NUM_M) >> GL_MDET_TX_TCLAN_PF_NUM_S;
		u16 vf_num = (reg & GL_MDET_TX_TCLAN_VF_NUM_M) >> GL_MDET_TX_TCLAN_VF_NUM_S;
		u8 event   = (reg & GL_MDET_TX_TCLAN_MAL_TYPE_M) >> GL_MDET_TX_TCLAN_MAL_TYPE_S;
		u16 queue  = (reg & GL_MDET_TX_TCLAN_QNUM_M) >> GL_MDET_TX_TCLAN_QNUM_S;

		device_printf(dev, "Malicious Driver Detection Tx Descriptor check event '%s' on Tx queue %u PF# %u VF# %u\n",
			      ice_mdd_tx_tclan_str(event), queue, pf_num, vf_num);

		/* Only clear this event if it matches this PF, that way other
		 * PFs can read the event and determine VF and queue number.
		 */
		if (pf_num == hw->pf_id)
			wr32(hw, GL_MDET_TX_TCLAN, 0xffffffff);

		mdd_detected = true;
	}

	/* Determine what triggered the MDD event */
	reg = rd32(hw, GL_MDET_TX_PQM);
	if (reg & GL_MDET_TX_PQM_VALID_M) {
		u8 pf_num  = (reg & GL_MDET_TX_PQM_PF_NUM_M) >> GL_MDET_TX_PQM_PF_NUM_S;
		u16 vf_num = (reg & GL_MDET_TX_PQM_VF_NUM_M) >> GL_MDET_TX_PQM_VF_NUM_S;
		u8 event   = (reg & GL_MDET_TX_PQM_MAL_TYPE_M) >> GL_MDET_TX_PQM_MAL_TYPE_S;
		u16 queue  = (reg & GL_MDET_TX_PQM_QNUM_M) >> GL_MDET_TX_PQM_QNUM_S;

		device_printf(dev, "Malicious Driver Detection Tx Quanta check event '%s' on Tx queue %u PF# %u VF# %u\n",
			      ice_mdd_tx_pqm_str(event), queue, pf_num, vf_num);

		/* Only clear this event if it matches this PF, that way other
		 * PFs can read the event and determine VF and queue number.
		 */
		if (pf_num == hw->pf_id)
			wr32(hw, GL_MDET_TX_PQM, 0xffffffff);

		mdd_detected = true;
	}

	reg = rd32(hw, GL_MDET_RX);
	if (reg & GL_MDET_RX_VALID_M) {
		u8 pf_num  = (reg & GL_MDET_RX_PF_NUM_M) >> GL_MDET_RX_PF_NUM_S;
		u16 vf_num = (reg & GL_MDET_RX_VF_NUM_M) >> GL_MDET_RX_VF_NUM_S;
		u8 event   = (reg & GL_MDET_RX_MAL_TYPE_M) >> GL_MDET_RX_MAL_TYPE_S;
		u16 queue  = (reg & GL_MDET_RX_QNUM_M) >> GL_MDET_RX_QNUM_S;

		device_printf(dev, "Malicious Driver Detection Rx event '%s' on Rx queue %u PF# %u VF# %u\n",
			      ice_mdd_rx_str(event), queue, pf_num, vf_num);

		/* Only clear this event if it matches this PF, that way other
		 * PFs can read the event and determine VF and queue number.
		 */
		if (pf_num == hw->pf_id)
			wr32(hw, GL_MDET_RX, 0xffffffff);

		mdd_detected = true;
	}

	/* Now, confirm that this event actually affects this PF, by checking
	 * the PF registers.
	 */
	if (mdd_detected) {
		reg = rd32(hw, PF_MDET_TX_TCLAN);
		if (reg & PF_MDET_TX_TCLAN_VALID_M) {
			wr32(hw, PF_MDET_TX_TCLAN, 0xffff);
			sc->soft_stats.tx_mdd_count++;
			request_reinit = true;
		}

		reg = rd32(hw, PF_MDET_TX_PQM);
		if (reg & PF_MDET_TX_PQM_VALID_M) {
			wr32(hw, PF_MDET_TX_PQM, 0xffff);
			sc->soft_stats.tx_mdd_count++;
			request_reinit = true;
		}

		reg = rd32(hw, PF_MDET_RX);
		if (reg & PF_MDET_RX_VALID_M) {
			wr32(hw, PF_MDET_RX, 0xffff);
			sc->soft_stats.rx_mdd_count++;
			request_reinit = true;
		}
	}

	/* TODO: Implement logic to detect and handle events caused by VFs. */

	/* request that the upper stack re-initialize the Tx/Rx queues */
	if (request_reinit)
		ice_request_stack_reinit(sc);

	ice_flush(hw);
}

/**
 * ice_init_dcb_setup - Initialize DCB settings for HW
 * @sc: the device softc
 *
 * This needs to be called after the fw_lldp_agent sysctl is added, since that
 * can update the device's LLDP agent status if a tunable value is set.
 *
 * Get and store the initial state of DCB settings on driver load. Print out
 * informational messages as well.
 */
void
ice_init_dcb_setup(struct ice_softc *sc)
{
	struct ice_hw *hw = &sc->hw;
	device_t dev = sc->dev;
	bool dcbx_agent_status;
	enum ice_status status;

	/* Don't do anything if DCB isn't supported */
	if (!hw->func_caps.common_cap.dcb) {
		device_printf(dev, "%s: No DCB support\n",
		    __func__);
		return;
	}

	hw->port_info->dcbx_status = ice_get_dcbx_status(hw);
	if (hw->port_info->dcbx_status != ICE_DCBX_STATUS_DONE &&
	    hw->port_info->dcbx_status != ICE_DCBX_STATUS_IN_PROGRESS) {
		/*
		 * Start DCBX agent, but not LLDP. The return value isn't
		 * checked here because a more detailed dcbx agent status is
		 * retrieved and checked in ice_init_dcb() and below.
		 */
		ice_aq_start_stop_dcbx(hw, true, &dcbx_agent_status, NULL);
	}

	/* This sets hw->port_info->is_sw_lldp */
	status = ice_init_dcb(hw, true);

	/* If there is an error, then FW LLDP is not in a usable state */
	if (status != 0 && status != ICE_ERR_NOT_READY) {
		/* Don't print an error message if the return code from the AQ
		 * cmd performed in ice_init_dcb() is is EPERM; that means the
		 * FW LLDP engine is disabled, and that is a valid state.
		 */
		if (!(status == ICE_ERR_AQ_ERROR &&
		      hw->adminq.sq_last_status == ICE_AQ_RC_EPERM)) {
			device_printf(dev, "DCB init failed, err %s aq_err %s\n",
				      ice_status_str(status),
				      ice_aq_str(hw->adminq.sq_last_status));
		}
		hw->port_info->dcbx_status = ICE_DCBX_STATUS_NOT_STARTED;
	}

	switch (hw->port_info->dcbx_status) {
	case ICE_DCBX_STATUS_DIS:
		ice_debug(hw, ICE_DBG_DCB, "DCBX disabled\n");
		break;
	case ICE_DCBX_STATUS_NOT_STARTED:
		ice_debug(hw, ICE_DBG_DCB, "DCBX not started\n");
		break;
	case ICE_DCBX_STATUS_MULTIPLE_PEERS:
		ice_debug(hw, ICE_DBG_DCB, "DCBX detected multiple peers\n");
		break;
	default:
		break;
	}

	/* LLDP disabled in FW */
	if (hw->port_info->is_sw_lldp) {
		ice_add_rx_lldp_filter(sc);
		device_printf(dev, "Firmware LLDP agent disabled\n");
	} else {
		ice_del_rx_lldp_filter(sc);
	}
}

/**
 * ice_handle_mib_change_event - helper function to log LLDP MIB change events
 * @sc: device softc
 * @event: event received on a control queue
 *
 * Prints out the type of an LLDP MIB change event in a DCB debug message.
 *
 * XXX: Should be extended to do more if the driver decides to notify other SW
 * of LLDP MIB changes, or needs to extract info from the MIB.
 */
static void
ice_handle_mib_change_event(struct ice_softc *sc, struct ice_rq_event_info *event)
{
	struct ice_aqc_lldp_get_mib *params =
	    (struct ice_aqc_lldp_get_mib *)&event->desc.params.lldp_get_mib;
	u8 mib_type, bridge_type, tx_status;

	/* XXX: To get the contents of the MIB that caused the event, set the
	 * ICE_DBG_AQ debug mask and read that output
	 */
	static const char* mib_type_strings[] = {
	    "Local MIB",
	    "Remote MIB",
	    "Reserved",
	    "Reserved"
	};
	static const char* bridge_type_strings[] = {
	    "Nearest Bridge",
	    "Non-TPMR Bridge",
	    "Reserved",
	    "Reserved"
	};
	static const char* tx_status_strings[] = {
	    "Port's TX active",
	    "Port's TX suspended and drained",
	    "Reserved",
	    "Port's TX suspended and srained; blocked TC pipe flushed"
	};

	mib_type = (params->type & ICE_AQ_LLDP_MIB_TYPE_M) >>
	    ICE_AQ_LLDP_MIB_TYPE_S;
	bridge_type = (params->type & ICE_AQ_LLDP_BRID_TYPE_M) >>
	    ICE_AQ_LLDP_BRID_TYPE_S;
	tx_status = (params->type & ICE_AQ_LLDP_TX_M) >>
	    ICE_AQ_LLDP_TX_S;

	ice_debug(&sc->hw, ICE_DBG_DCB, "LLDP MIB Change Event (%s, %s, %s)\n",
	    mib_type_strings[mib_type], bridge_type_strings[bridge_type],
	    tx_status_strings[tx_status]);
}

/**
 * ice_send_version - Send driver version to firmware
 * @sc: the device private softc
 *
 * Send the driver version to the firmware. This must be called as early as
 * possible after ice_init_hw().
 */
int
ice_send_version(struct ice_softc *sc)
{
	struct ice_driver_ver driver_version = {0};
	struct ice_hw *hw = &sc->hw;
	device_t dev = sc->dev;
	enum ice_status status;

	driver_version.major_ver = ice_major_version;
	driver_version.minor_ver = ice_minor_version;
	driver_version.build_ver = ice_patch_version;
	driver_version.subbuild_ver = ice_rc_version;

	strlcpy((char *)driver_version.driver_string, ice_driver_version,
		sizeof(driver_version.driver_string));

	status = ice_aq_send_driver_ver(hw, &driver_version, NULL);
	if (status) {
		device_printf(dev, "Unable to send driver version to firmware, err %s aq_err %s\n",
			      ice_status_str(status), ice_aq_str(hw->adminq.sq_last_status));
		return (EIO);
	}

	return (0);
}

/**
 * ice_handle_lan_overflow_event - helper function to log LAN overflow events
 * @sc: device softc
 * @event: event received on a control queue
 *
 * Prints out a message when a LAN overflow event is detected on a receive
 * queue.
 */
static void
ice_handle_lan_overflow_event(struct ice_softc *sc, struct ice_rq_event_info *event)
{
	struct ice_aqc_event_lan_overflow *params =
	    (struct ice_aqc_event_lan_overflow *)&event->desc.params.lan_overflow;
	struct ice_hw *hw = &sc->hw;

	ice_debug(hw, ICE_DBG_DCB, "LAN overflow event detected, prtdcb_ruptq=0x%08x, qtx_ctl=0x%08x\n",
		  LE32_TO_CPU(params->prtdcb_ruptq),
		  LE32_TO_CPU(params->qtx_ctl));
}

/**
 * ice_add_ethertype_to_list - Add an Ethertype filter to a filter list
 * @vsi: the VSI to target packets to
 * @list: the list to add the filter to
 * @ethertype: the Ethertype to filter on
 * @direction: The direction of the filter (Tx or Rx)
 * @action: the action to take
 *
 * Add an Ethertype filter to a filter list. Used to forward a series of
 * filters to the firmware for configuring the switch.
 *
 * Returns 0 on success, and an error code on failure.
 */
static int
ice_add_ethertype_to_list(struct ice_vsi *vsi, struct ice_list_head *list,
			  u16 ethertype, u16 direction,
			  enum ice_sw_fwd_act_type action)
{
	struct ice_fltr_list_entry *entry;

	MPASS((direction == ICE_FLTR_TX) || (direction == ICE_FLTR_RX));

	entry = (__typeof(entry))malloc(sizeof(*entry), M_ICE, M_NOWAIT|M_ZERO);
	if (!entry)
		return (ENOMEM);

	entry->fltr_info.flag = direction;
	entry->fltr_info.src_id = ICE_SRC_ID_VSI;
	entry->fltr_info.lkup_type = ICE_SW_LKUP_ETHERTYPE;
	entry->fltr_info.fltr_act = action;
	entry->fltr_info.vsi_handle = vsi->idx;
	entry->fltr_info.l_data.ethertype_mac.ethertype = ethertype;

	LIST_ADD(&entry->list_entry, list);

	return 0;
}

#define ETHERTYPE_PAUSE_FRAMES 0x8808
#define ETHERTYPE_LLDP_FRAMES 0x88cc

/**
 * ice_cfg_pf_ethertype_filters - Configure switch to drop ethertypes
 * @sc: the device private softc
 *
 * Configure the switch to drop PAUSE frames and LLDP frames transmitted from
 * the host. This prevents malicious VFs from sending these frames and being
 * able to control or configure the network.
 */
int
ice_cfg_pf_ethertype_filters(struct ice_softc *sc)
{
	struct ice_list_head ethertype_list;
	struct ice_vsi *vsi = &sc->pf_vsi;
	struct ice_hw *hw = &sc->hw;
	device_t dev = sc->dev;
	enum ice_status status;
	int err = 0;

	INIT_LIST_HEAD(&ethertype_list);

	/*
	 * Note that the switch filters will ignore the VSI index for the drop
	 * action, so we only need to program drop filters once for the main
	 * VSI.
	 */

	/* Configure switch to drop all Tx pause frames coming from any VSI. */
	if (sc->enable_tx_fc_filter) {
		err = ice_add_ethertype_to_list(vsi, &ethertype_list,
						ETHERTYPE_PAUSE_FRAMES,
						ICE_FLTR_TX, ICE_DROP_PACKET);
		if (err)
			goto free_ethertype_list;
	}

	/* Configure switch to drop LLDP frames coming from any VSI */
	if (sc->enable_tx_lldp_filter) {
		err = ice_add_ethertype_to_list(vsi, &ethertype_list,
						ETHERTYPE_LLDP_FRAMES,
						ICE_FLTR_TX, ICE_DROP_PACKET);
		if (err)
			goto free_ethertype_list;
	}

	status = ice_add_eth_mac(hw, &ethertype_list);
	if (status) {
		device_printf(dev,
			      "Failed to add Tx Ethertype filters, err %s aq_err %s\n",
			      ice_status_str(status),
			      ice_aq_str(hw->adminq.sq_last_status));
		err = (EIO);
	}

free_ethertype_list:
	ice_free_fltr_list(&ethertype_list);
	return err;
}

/**
 * ice_add_rx_lldp_filter - add ethertype filter for Rx LLDP frames
 * @sc: the device private structure
 *
 * Add a switch ethertype filter which forwards the LLDP frames to the main PF
 * VSI. Called when the fw_lldp_agent is disabled, to allow the LLDP frames to
 * be forwarded to the stack.
 */
static void
ice_add_rx_lldp_filter(struct ice_softc *sc)
{
	struct ice_list_head ethertype_list;
	struct ice_vsi *vsi = &sc->pf_vsi;
	struct ice_hw *hw = &sc->hw;
	device_t dev = sc->dev;
	enum ice_status status;
	int err;

	INIT_LIST_HEAD(&ethertype_list);

	/* Forward Rx LLDP frames to the stack */
	err = ice_add_ethertype_to_list(vsi, &ethertype_list,
					ETHERTYPE_LLDP_FRAMES,
					ICE_FLTR_RX, ICE_FWD_TO_VSI);
	if (err) {
		device_printf(dev,
			      "Failed to add Rx LLDP filter, err %s\n",
			      ice_err_str(err));
		goto free_ethertype_list;
	}

	status = ice_add_eth_mac(hw, &ethertype_list);
	if (status == ICE_ERR_ALREADY_EXISTS) {
		; /* Don't complain if we try to add a filter that already exists */
	} else if (status) {
		device_printf(dev,
			      "Failed to add Rx LLDP filter, err %s aq_err %s\n",
			      ice_status_str(status),
			      ice_aq_str(hw->adminq.sq_last_status));
	}

free_ethertype_list:
	ice_free_fltr_list(&ethertype_list);
}

/**
 * ice_del_rx_lldp_filter - Remove ethertype filter for Rx LLDP frames
 * @sc: the device private structure
 *
 * Remove the switch filter forwarding LLDP frames to the main PF VSI, called
 * when the firmware LLDP agent is enabled, to stop routing LLDP frames to the
 * stack.
 */
static void
ice_del_rx_lldp_filter(struct ice_softc *sc)
{
	struct ice_list_head ethertype_list;
	struct ice_vsi *vsi = &sc->pf_vsi;
	struct ice_hw *hw = &sc->hw;
	device_t dev = sc->dev;
	enum ice_status status;
	int err;

	INIT_LIST_HEAD(&ethertype_list);

	/* Remove filter forwarding Rx LLDP frames to the stack */
	err = ice_add_ethertype_to_list(vsi, &ethertype_list,
					ETHERTYPE_LLDP_FRAMES,
					ICE_FLTR_RX, ICE_FWD_TO_VSI);
	if (err) {
		device_printf(dev,
			      "Failed to remove Rx LLDP filter, err %s\n",
			      ice_err_str(err));
		goto free_ethertype_list;
	}

	status = ice_remove_eth_mac(hw, &ethertype_list);
	if (status == ICE_ERR_DOES_NOT_EXIST) {
		; /* Don't complain if we try to remove a filter that doesn't exist */
	} else if (status) {
		device_printf(dev,
			      "Failed to remove Rx LLDP filter, err %s aq_err %s\n",
			      ice_status_str(status),
			      ice_aq_str(hw->adminq.sq_last_status));
	}

free_ethertype_list:
	ice_free_fltr_list(&ethertype_list);
}

/**
 * ice_init_link_configuration -- Setup link in different ways depending
 * on whether media is available or not.
 * @sc: device private structure
 *
 * Called at the end of the attach process to either set default link
 * parameters if there is media available, or force HW link down and
 * set a state bit if there is no media.
 */
void
ice_init_link_configuration(struct ice_softc *sc)
{
	struct ice_port_info *pi = sc->hw.port_info;
	struct ice_hw *hw = &sc->hw;
	device_t dev = sc->dev;
	enum ice_status status;

	pi->phy.get_link_info = true;
	status = ice_get_link_status(pi, &sc->link_up);
	if (status != ICE_SUCCESS) {
		device_printf(dev,
		    "%s: ice_get_link_status failed; status %s, aq_err %s\n",
		    __func__, ice_status_str(status),
		    ice_aq_str(hw->adminq.sq_last_status));
		return;
	}

	if (pi->phy.link_info.link_info & ICE_AQ_MEDIA_AVAILABLE) {
		ice_clear_state(&sc->state, ICE_STATE_NO_MEDIA);
		/* Apply default link settings */
		ice_apply_saved_phy_cfg(sc);
	} else {
		 /* Set link down, and poll for media available in timer. This prevents the
		  * driver from receiving spurious link-related events.
		  */
		ice_set_state(&sc->state, ICE_STATE_NO_MEDIA);
		status = ice_aq_set_link_restart_an(pi, false, NULL);
		if (status != ICE_SUCCESS)
			device_printf(dev,
			    "%s: ice_aq_set_link_restart_an: status %s, aq_err %s\n",
			    __func__, ice_status_str(status),
			    ice_aq_str(hw->adminq.sq_last_status));
	}
}

/**
 * ice_apply_saved_phy_req_to_cfg -- Write saved user PHY settings to cfg data
 * @pi: port info struct
 * @pcaps: TOPO_CAPS capability data to use for defaults
 * @cfg: new PHY config data to be modified
 *
 * Applies user settings for advertised speeds to the PHY type fields in the
 * supplied PHY config struct. It uses the data from pcaps to check if the
 * saved settings are invalid and uses the pcaps data instead if they are
 * invalid.
 */
static void
ice_apply_saved_phy_req_to_cfg(struct ice_port_info *pi,
			       struct ice_aqc_get_phy_caps_data *pcaps,
			       struct ice_aqc_set_phy_cfg_data *cfg)
{
	u64 phy_low = 0, phy_high = 0;

	ice_update_phy_type(&phy_low, &phy_high, pi->phy.curr_user_speed_req);
	cfg->phy_type_low = pcaps->phy_type_low & htole64(phy_low);
	cfg->phy_type_high = pcaps->phy_type_high & htole64(phy_high);

	/* Can't use saved user speed request; use NVM default PHY capabilities */
	if (!cfg->phy_type_low && !cfg->phy_type_high) {
		cfg->phy_type_low = pcaps->phy_type_low;
		cfg->phy_type_high = pcaps->phy_type_high;
	}
}

/**
 * ice_apply_saved_fec_req_to_cfg -- Write saved user FEC mode to cfg data
 * @pi: port info struct
 * @pcaps: TOPO_CAPS capability data to use for defaults
 * @cfg: new PHY config data to be modified
 *
 * Applies user setting for FEC mode to PHY config struct. It uses the data
 * from pcaps to check if the saved settings are invalid and uses the pcaps
 * data instead if they are invalid.
 */
static void
ice_apply_saved_fec_req_to_cfg(struct ice_port_info *pi,
			       struct ice_aqc_get_phy_caps_data *pcaps,
			       struct ice_aqc_set_phy_cfg_data *cfg)
{
	ice_cfg_phy_fec(pi, cfg, pi->phy.curr_user_fec_req);

	/* Can't use saved user FEC mode; use NVM default PHY capabilities */
	if (cfg->link_fec_opt &&
	    !(cfg->link_fec_opt & pcaps->link_fec_options)) {
		cfg->caps |= pcaps->caps & ICE_AQC_PHY_EN_AUTO_FEC;
		cfg->link_fec_opt = pcaps->link_fec_options;
	}
}

/**
 * ice_apply_saved_fc_req_to_cfg -- Write saved user flow control mode to cfg data
 * @pi: port info struct
 * @cfg: new PHY config data to be modified
 *
 * Applies user setting for flow control mode to PHY config struct. There are
 * no invalid flow control mode settings; if there are, then this function
 * treats them like "ICE_FC_NONE".
 */
static void
ice_apply_saved_fc_req_to_cfg(struct ice_port_info *pi,
			      struct ice_aqc_set_phy_cfg_data *cfg)
{
	cfg->caps &= ~(ICE_AQ_PHY_ENA_TX_PAUSE_ABILITY |
		       ICE_AQ_PHY_ENA_RX_PAUSE_ABILITY);

	switch (pi->phy.curr_user_fc_req) {
	case ICE_FC_FULL:
		cfg->caps |= ICE_AQ_PHY_ENA_TX_PAUSE_ABILITY |
			    ICE_AQ_PHY_ENA_RX_PAUSE_ABILITY;
		break;
	case ICE_FC_RX_PAUSE:
		cfg->caps |= ICE_AQ_PHY_ENA_RX_PAUSE_ABILITY;
		break;
	case ICE_FC_TX_PAUSE:
		cfg->caps |= ICE_AQ_PHY_ENA_TX_PAUSE_ABILITY;
		break;
	default:
		/* ICE_FC_NONE */
		break;
	}
}

/**
 * ice_apply_saved_user_req_to_cfg -- Apply all saved user settings to AQ cfg data
 * @pi: port info struct
 * @pcaps: TOPO_CAPS capability data to use for defaults
 * @cfg: new PHY config data to be modified
 *
 * Applies user settings for advertised speeds, FEC mode, and flow control
 * mode to the supplied PHY config struct; it uses the data from pcaps to check
 * if the saved settings are invalid and uses the pcaps data instead if they
 * are invalid.
 */
static void
ice_apply_saved_user_req_to_cfg(struct ice_port_info *pi,
				struct ice_aqc_get_phy_caps_data *pcaps,
				struct ice_aqc_set_phy_cfg_data *cfg)
{
	ice_apply_saved_phy_req_to_cfg(pi, pcaps, cfg);
	ice_apply_saved_fec_req_to_cfg(pi, pcaps, cfg);
	ice_apply_saved_fc_req_to_cfg(pi, cfg);
}

/**
 * ice_apply_saved_phy_cfg -- Re-apply user PHY config settings
 * @sc: device private structure
 *
 * Takes the saved user PHY config settings, overwrites the NVM
 * default with them if they're valid, and uses the Set PHY Config AQ command
 * to apply them.
 *
 * Intended for use when media is inserted.
 *
 * @pre Port has media available
 */
void
ice_apply_saved_phy_cfg(struct ice_softc *sc)
{
	struct ice_aqc_set_phy_cfg_data cfg = { 0 };
	struct ice_port_info *pi = sc->hw.port_info;
	struct ice_aqc_get_phy_caps_data pcaps = { 0 };
	struct ice_hw *hw = &sc->hw;
	device_t dev = sc->dev;
	enum ice_status status;

	status = ice_aq_get_phy_caps(pi, false, ICE_AQC_REPORT_TOPO_CAP,
				     &pcaps, NULL);
	if (status != ICE_SUCCESS) {
		device_printf(dev,
		    "%s: ice_aq_get_phy_caps (TOPO_CAP) failed; status %s, aq_err %s\n",
		    __func__, ice_status_str(status),
		    ice_aq_str(hw->adminq.sq_last_status));
		return;
	}

	/* Setup new PHY config */
	ice_copy_phy_caps_to_cfg(pi, &pcaps, &cfg);

	/* Apply settings requested by user */
	ice_apply_saved_user_req_to_cfg(pi, &pcaps, &cfg);

	/* Enable link and re-negotiate it */
	cfg.caps |= ICE_AQ_PHY_ENA_AUTO_LINK_UPDT | ICE_AQ_PHY_ENA_LINK;

	status = ice_aq_set_phy_cfg(hw, pi, &cfg, NULL);
	if (status != ICE_SUCCESS) {
		if ((status == ICE_ERR_AQ_ERROR) &&
		    (hw->adminq.sq_last_status == ICE_AQ_RC_EBUSY))
			device_printf(dev,
			    "%s: User PHY cfg not applied; no media in port\n",
			    __func__);
		else
			device_printf(dev,
			    "%s: ice_aq_set_phy_cfg failed; status %s, aq_err %s\n",
			    __func__, ice_status_str(status),
			    ice_aq_str(hw->adminq.sq_last_status));
	}
}

/**
 * ice_print_ldo_tlv - Print out LDO TLV information
 * @sc: device private structure
 * @tlv: LDO TLV information from the adapter NVM
 *
 * Dump out the information in tlv to the kernel message buffer; intended for
 * debugging purposes.
 */
static void
ice_print_ldo_tlv(struct ice_softc *sc, struct ice_link_default_override_tlv *tlv)
{
	device_t dev = sc->dev;

	device_printf(dev, "TLV: -options     0x%02x\n", tlv->options);
	device_printf(dev, "     -phy_config  0x%02x\n", tlv->phy_config);
	device_printf(dev, "     -fec_options 0x%02x\n", tlv->fec_options);
	device_printf(dev, "     -phy_high    0x%016llx\n",
	    (unsigned long long)tlv->phy_type_high);
	device_printf(dev, "     -phy_low     0x%016llx\n",
	    (unsigned long long)tlv->phy_type_low);
}

/**
 * ice_set_link_management_mode -- Strict or lenient link management
 * @sc: device private structure
 *
 * Some NVMs give the adapter the option to advertise a superset of link
 * configurations.  This checks to see if that option is enabled.
 * Further, the NVM could also provide a specific set of configurations
 * to try; these are cached in the driver's private structure if they
 * are available.
 */
void
ice_set_link_management_mode(struct ice_softc *sc)
{
	struct ice_port_info *pi = sc->hw.port_info;
	device_t dev = sc->dev;
	struct ice_link_default_override_tlv tlv = { 0 };
	enum ice_status status;

	/* Port must be in strict mode if FW version is below a certain
	 * version. (i.e. Don't set lenient mode features)
	 */
	if (!(ice_fw_supports_link_override(&sc->hw)))
		return;

	status = ice_get_link_default_override(&tlv, pi);
	if (status != ICE_SUCCESS) {
		device_printf(dev,
		    "%s: ice_get_link_default_override failed; status %s, aq_err %s\n",
		    __func__, ice_status_str(status),
		    ice_aq_str(sc->hw.adminq.sq_last_status));
		return;
	}

	if (sc->hw.debug_mask & ICE_DBG_LINK)
		ice_print_ldo_tlv(sc, &tlv);

	/* Set lenient link mode */
	if (ice_is_bit_set(sc->feat_cap, ICE_FEATURE_LENIENT_LINK_MODE) &&
	    (!(tlv.options & ICE_LINK_OVERRIDE_STRICT_MODE)))
		ice_set_bit(ICE_FEATURE_LENIENT_LINK_MODE, sc->feat_en);

	/* Default overrides only work if in lenient link mode */
	if (ice_is_bit_set(sc->feat_cap, ICE_FEATURE_DEFAULT_OVERRIDE) &&
	    ice_is_bit_set(sc->feat_en, ICE_FEATURE_LENIENT_LINK_MODE) &&
	    (tlv.options & ICE_LINK_OVERRIDE_EN))
		ice_set_bit(ICE_FEATURE_DEFAULT_OVERRIDE, sc->feat_en);

	/* Cache the LDO TLV structure in the driver, since it won't change
	 * during the driver's lifetime.
	 */
	sc->ldo_tlv = tlv;
}

/**
 * ice_init_saved_phy_cfg -- Set cached user PHY cfg settings with NVM defaults
 * @sc: device private structure
 *
 * This should be called before the tunables for these link settings
 * (e.g. advertise_speed) are added -- so that these defaults don't overwrite
 * the cached values that the sysctl handlers will write.
 *
 * This also needs to be called before ice_init_link_configuration, to ensure
 * that there are sane values that can be written if there is media available
 * in the port.
 */
void
ice_init_saved_phy_cfg(struct ice_softc *sc)
{
	struct ice_port_info *pi = sc->hw.port_info;
	struct ice_aqc_get_phy_caps_data pcaps = { 0 };
	struct ice_hw *hw = &sc->hw;
	device_t dev = sc->dev;
	enum ice_status status;
	u64 phy_low, phy_high;

	status = ice_aq_get_phy_caps(pi, false, ICE_AQC_REPORT_TOPO_CAP,
				     &pcaps, NULL);
	if (status != ICE_SUCCESS) {
		device_printf(dev,
		    "%s: ice_aq_get_phy_caps (TOPO_CAP) failed; status %s, aq_err %s\n",
		    __func__, ice_status_str(status),
		    ice_aq_str(hw->adminq.sq_last_status));
		return;
	}

	phy_low = le64toh(pcaps.phy_type_low);
	phy_high = le64toh(pcaps.phy_type_high);

	/* Save off initial config parameters */
	pi->phy.curr_user_speed_req =
	   ice_aq_phy_types_to_sysctl_speeds(phy_low, phy_high);
	pi->phy.curr_user_fec_req = ice_caps_to_fec_mode(pcaps.caps,
	    pcaps.link_fec_options);
	pi->phy.curr_user_fc_req = ice_caps_to_fc_mode(pcaps.caps);
}

/**
 * ice_module_init - Driver callback to handle module load
 *
 * Callback for handling module load events. This function should initialize
 * any data structures that are used for the life of the device driver.
 */
static int
ice_module_init(void)
{
	return (0);
}

/**
 * ice_module_exit - Driver callback to handle module exit
 *
 * Callback for handling module unload events. This function should release
 * any resources initialized during ice_module_init.
 *
 * If this function returns non-zero, the module will not be unloaded. It
 * should only return such a value if the module cannot be unloaded at all,
 * such as due to outstanding memory references that cannot be revoked.
 */
static int
ice_module_exit(void)
{
	return (0);
}

/**
 * ice_module_event_handler - Callback for module events
 * @mod: unused module_t parameter
 * @what: the event requested
 * @arg: unused event argument
 *
 * Callback used to handle module events from the stack. Used to allow the
 * driver to define custom behavior that should happen at module load and
 * unload.
 */
int
ice_module_event_handler(module_t __unused mod, int what, void __unused *arg)
{
	switch (what) {
	case MOD_LOAD:
		return ice_module_init();
	case MOD_UNLOAD:
		return ice_module_exit();
	default:
		/* TODO: do we need to handle MOD_QUIESCE and MOD_SHUTDOWN? */
		return (EOPNOTSUPP);
	}
}

/**
 * ice_handle_nvm_access_ioctl - Handle an NVM access ioctl request
 * @sc: the device private softc
 * @ifd: ifdrv ioctl request pointer
 */
int
ice_handle_nvm_access_ioctl(struct ice_softc *sc, struct ifdrv *ifd)
{
	union ice_nvm_access_data *data;
	struct ice_nvm_access_cmd *cmd;
	size_t ifd_len = ifd->ifd_len, malloc_len;
	struct ice_hw *hw = &sc->hw;
	device_t dev = sc->dev;
	enum ice_status status;
	u8 *nvm_buffer;
	int err;

	/*
	 * ifioctl forwards SIOCxDRVSPEC to iflib without performing
	 * a privilege check. In turn, iflib forwards the ioctl to the driver
	 * without performing a privilege check. Perform one here to ensure
	 * that non-privileged threads cannot access this interface.
	 */
	err = priv_check(curthread, PRIV_DRIVER);
	if (err)
		return (err);

	if (ifd_len < sizeof(struct ice_nvm_access_cmd)) {
		device_printf(dev, "%s: ifdrv length is too small. Got %zu, but expected %zu\n",
			      __func__, ifd_len, sizeof(struct ice_nvm_access_cmd));
		return (EINVAL);
	}

	if (ifd->ifd_data == NULL) {
		device_printf(dev, "%s: ifd data buffer not present.\n",
			      __func__);
		return (EINVAL);
	}

	/*
	 * If everything works correctly, ice_handle_nvm_access should not
	 * modify data past the size of the ioctl length. However, it could
	 * lead to memory corruption if it did. Make sure to allocate at least
	 * enough space for the command and data regardless. This
	 * ensures that any access to the data union will not access invalid
	 * memory.
	 */
	malloc_len = max(ifd_len, sizeof(*data) + sizeof(*cmd));

	nvm_buffer = (u8 *)malloc(malloc_len, M_ICE, M_ZERO | M_WAITOK);
	if (!nvm_buffer)
		return (ENOMEM);

	/* Copy the NVM access command and data in from user space */
	/* coverity[tainted_data_argument] */
	err = copyin(ifd->ifd_data, nvm_buffer, ifd_len);
	if (err) {
		device_printf(dev, "%s: Copying request from user space failed, err %s\n",
			      __func__, ice_err_str(err));
		goto cleanup_free_nvm_buffer;
	}

	/*
	 * The NVM command structure is immediately followed by data which
	 * varies in size based on the command.
	 */
	cmd = (struct ice_nvm_access_cmd *)nvm_buffer;
	data = (union ice_nvm_access_data *)(nvm_buffer + sizeof(struct ice_nvm_access_cmd));

	/* Handle the NVM access request */
	status = ice_handle_nvm_access(hw, cmd, data);
	if (status)
		ice_debug(hw, ICE_DBG_NVM,
			  "NVM access request failed, err %s\n",
			  ice_status_str(status));

	/* Copy the possibly modified contents of the handled request out */
	err = copyout(nvm_buffer, ifd->ifd_data, ifd_len);
	if (err) {
		device_printf(dev, "%s: Copying response back to user space failed, err %s\n",
			      __func__, ice_err_str(err));
		goto cleanup_free_nvm_buffer;
	}

	/* Convert private status to an error code for proper ioctl response */
	switch (status) {
	case ICE_SUCCESS:
		err = (0);
		break;
	case ICE_ERR_NO_MEMORY:
		err = (ENOMEM);
		break;
	case ICE_ERR_OUT_OF_RANGE:
		err = (ENOTTY);
		break;
	case ICE_ERR_PARAM:
	default:
		err = (EINVAL);
		break;
	}

cleanup_free_nvm_buffer:
	free(nvm_buffer, M_ICE);
	return err;
}

/**
 * ice_read_sff_eeprom - Read data from SFF eeprom
 * @sc: device softc
 * @dev_addr: I2C device address (typically 0xA0 or 0xA2)
 * @offset: offset into the eeprom
 * @data: pointer to data buffer to store read data in
 * @length: length to read; max length is 16
 *
 * Read from the SFF eeprom in the module for this PF's port. For more details
 * on the contents of an SFF eeprom, refer to SFF-8724 (SFP), SFF-8636 (QSFP),
 * and SFF-8024 (both).
 */
int
ice_read_sff_eeprom(struct ice_softc *sc, u16 dev_addr, u16 offset, u8* data, u16 length)
{
	struct ice_hw *hw = &sc->hw;
	int error = 0, retries = 0;
	enum ice_status status;
	u16 lport;

	if (length > 16)
		return (EINVAL);

	if (ice_test_state(&sc->state, ICE_STATE_RECOVERY_MODE))
		return (ENOSYS);

	if (ice_test_state(&sc->state, ICE_STATE_NO_MEDIA))
		return (ENXIO);

	/* Set bit to indicate lport value is valid */
	lport = hw->port_info->lport | (0x1 << 8);

	do {
		status = ice_aq_sff_eeprom(hw, lport, dev_addr,
					   offset, 0, 0, data, length,
					   false, NULL);
		if (!status) {
			error = 0;
			break;
		}
		if (status == ICE_ERR_AQ_ERROR &&
		    hw->adminq.sq_last_status == ICE_AQ_RC_EBUSY) {
			error = EBUSY;
			continue;
		}
		if (status == ICE_ERR_AQ_ERROR &&
		    hw->adminq.sq_last_status == ICE_AQ_RC_EACCES) {
			/* FW says I2C access isn't supported */
			error = EACCES;
			break;
		}
		if (status == ICE_ERR_AQ_ERROR &&
		    hw->adminq.sq_last_status == ICE_AQ_RC_EPERM) {
			device_printf(sc->dev,
				  "%s: Module pointer location specified in command does not permit the required operation.\n",
				  __func__);
			error = EPERM;
			break;
		} else {
			device_printf(sc->dev,
				  "%s: Error reading I2C data: err %s aq_err %s\n",
				  __func__, ice_status_str(status),
				  ice_aq_str(hw->adminq.sq_last_status));
			error = EIO;
			break;
		}
	} while (retries++ < ICE_I2C_MAX_RETRIES);

	if (error == EBUSY)
		device_printf(sc->dev,
			  "%s: Error reading I2C data after %d retries\n",
			  __func__, ICE_I2C_MAX_RETRIES);

	return (error);
}

/**
 * ice_handle_i2c_req - Driver independent I2C request handler
 * @sc: device softc
 * @req: The I2C parameters to use
 *
 * Read from the port's I2C eeprom using the parameters from the ioctl.
 */
int
ice_handle_i2c_req(struct ice_softc *sc, struct ifi2creq *req)
{
	return ice_read_sff_eeprom(sc, req->dev_addr, req->offset, req->data, req->len);
}

/**
 * ice_sysctl_read_i2c_diag_data - Read some module diagnostic data via i2c
 * @oidp: sysctl oid structure
 * @arg1: pointer to private data structure
 * @arg2: unused
 * @req: sysctl request pointer
 *
 * Read 8 bytes of diagnostic data from the SFF eeprom in the (Q)SFP module
 * inserted into the port.
 *
 *             | SFP A2  | QSFP Lower Page
 * ------------|---------|----------------
 * Temperature | 96-97	 | 22-23
 * Vcc         | 98-99   | 26-27
 * TX power    | 102-103 | 34-35..40-41
 * RX power    | 104-105 | 50-51..56-57
 */
static int
ice_sysctl_read_i2c_diag_data(SYSCTL_HANDLER_ARGS)
{
	struct ice_softc *sc = (struct ice_softc *)arg1;
	device_t dev = sc->dev;
	struct sbuf *sbuf;
	int error = 0;
	u8 data[16];

	UNREFERENCED_PARAMETER(arg2);
	UNREFERENCED_PARAMETER(oidp);

	if (ice_driver_is_detaching(sc))
		return (ESHUTDOWN);

	if (req->oldptr == NULL) {
		error = SYSCTL_OUT(req, 0, 128);
		return (error);
	}

	error = ice_read_sff_eeprom(sc, 0xA0, 0, data, 1);
	if (error)
		return (error);

	/* 0x3 for SFP; 0xD/0x11 for QSFP+/QSFP28 */
	if (data[0] == 0x3) {
		/*
		 * Check for:
		 * - Internally calibrated data
		 * - Diagnostic monitoring is implemented
		 */
		ice_read_sff_eeprom(sc, 0xA0, 92, data, 1);
		if (!(data[0] & 0x60)) {
			device_printf(dev, "Module doesn't support diagnostics: 0xA0[92] = %02X\n", data[0]);
			return (ENODEV);
		}

		sbuf = sbuf_new_for_sysctl(NULL, NULL, 128, req);

		ice_read_sff_eeprom(sc, 0xA2, 96, data, 4);
		for (int i = 0; i < 4; i++)
			sbuf_printf(sbuf, "%02X ", data[i]);

		ice_read_sff_eeprom(sc, 0xA2, 102, data, 4);
		for (int i = 0; i < 4; i++)
			sbuf_printf(sbuf, "%02X ", data[i]);
	} else if (data[0] == 0xD || data[0] == 0x11) {
		/*
		 * QSFP+ modules are always internally calibrated, and must indicate
		 * what types of diagnostic monitoring are implemented
		 */
		sbuf = sbuf_new_for_sysctl(NULL, NULL, 128, req);

		ice_read_sff_eeprom(sc, 0xA0, 22, data, 2);
		for (int i = 0; i < 2; i++)
			sbuf_printf(sbuf, "%02X ", data[i]);

		ice_read_sff_eeprom(sc, 0xA0, 26, data, 2);
		for (int i = 0; i < 2; i++)
			sbuf_printf(sbuf, "%02X ", data[i]);

		ice_read_sff_eeprom(sc, 0xA0, 34, data, 2);
		for (int i = 0; i < 2; i++)
			sbuf_printf(sbuf, "%02X ", data[i]);

		ice_read_sff_eeprom(sc, 0xA0, 50, data, 2);
		for (int i = 0; i < 2; i++)
			sbuf_printf(sbuf, "%02X ", data[i]);
	} else {
		device_printf(dev, "Module is not SFP/SFP+/SFP28/QSFP+ (%02X)\n", data[0]);
		return (ENODEV);
	}

	sbuf_finish(sbuf);
	sbuf_delete(sbuf);

	return (0);
}

/**
 * ice_alloc_intr_tracking - Setup interrupt tracking structures
 * @sc: device softc structure
 *
 * Sets up the resource manager for keeping track of interrupt allocations,
 * and initializes the tracking maps for the PF's interrupt allocations.
 *
 * Unlike the scheme for queues, this is done in one step since both the
 * manager and the maps both have the same lifetime.
 *
 * @returns 0 on success, or an error code on failure.
 */
int
ice_alloc_intr_tracking(struct ice_softc *sc)
{
	struct ice_hw *hw = &sc->hw;
	device_t dev = sc->dev;
	int err;

	/* Initialize the interrupt allocation manager */
	err = ice_resmgr_init_contig_only(&sc->imgr,
	    hw->func_caps.common_cap.num_msix_vectors);
	if (err) {
		device_printf(dev, "Unable to initialize PF interrupt manager: %s\n",
			      ice_err_str(err));
		return (err);
	}

	/* Allocate PF interrupt mapping storage */
	if (!(sc->pf_imap =
	      (u16 *)malloc(sizeof(u16) * hw->func_caps.common_cap.num_msix_vectors,
	      M_ICE, M_NOWAIT))) {
		device_printf(dev, "Unable to allocate PF imap memory\n");
		err = ENOMEM;
		goto free_imgr;
	}
	for (u32 i = 0; i < hw->func_caps.common_cap.num_msix_vectors; i++) {
		sc->pf_imap[i] = ICE_INVALID_RES_IDX;
	}

	return (0);

free_imgr:
	ice_resmgr_destroy(&sc->imgr);
	return (err);
}

/**
 * ice_free_intr_tracking - Free PF interrupt tracking structures
 * @sc: device softc structure
 *
 * Frees the interrupt resource allocation manager and the PF's owned maps.
 *
 * VF maps are released when the owning VF's are destroyed, which should always
 * happen before this function is called.
 */
void
ice_free_intr_tracking(struct ice_softc *sc)
{
	if (sc->pf_imap) {
		ice_resmgr_release_map(&sc->imgr, sc->pf_imap,
				       sc->lan_vectors);
		free(sc->pf_imap, M_ICE);
		sc->pf_imap = NULL;
	}

	ice_resmgr_destroy(&sc->imgr);
}

/**
 * ice_apply_supported_speed_filter - Mask off unsupported speeds
 * @phy_type_low: bit-field for the low quad word of PHY types
 * @phy_type_high: bit-field for the high quad word of PHY types
 *
 * Given the two quad words containing the supported PHY types,
 * this function will mask off the speeds that are not currently
 * supported by the device.
 */
static void
ice_apply_supported_speed_filter(u64 *phy_type_low, u64 *phy_type_high)
{
	u64 phylow_mask;

	/* We won't offer anything lower than 1G for any part,
	 * but we also won't offer anything under 25G for 100G
	 * parts.
	 */
	phylow_mask = ~(ICE_PHY_TYPE_LOW_1000BASE_T - 1);
	if (*phy_type_high ||
	    *phy_type_low & ~(ICE_PHY_TYPE_LOW_100GBASE_CR4 - 1))
		phylow_mask = ~(ICE_PHY_TYPE_LOW_25GBASE_T - 1);
	*phy_type_low &= phylow_mask;
}

/**
 * ice_get_phy_types - Report appropriate PHY types
 * @sc: device softc structure
 * @phy_type_low: bit-field for the low quad word of PHY types
 * @phy_type_high: bit-field for the high quad word of PHY types
 *
 * Populate the two quad words with bits representing the PHY types
 * supported by the device.  This is really just a wrapper around
 * the ice_aq_get_phy_caps() that chooses the appropriate report
 * mode (lenient or strict) and reports back only the relevant PHY
 * types.  In lenient mode the capabilities are retrieved with the
 * NVM_CAP report mode, otherwise they're retrieved using the
 * TOPO_CAP report mode (NVM intersected with current media).
 *
 * @returns 0 on success, or an error code on failure.
 */
static enum ice_status
ice_get_phy_types(struct ice_softc *sc, u64 *phy_type_low, u64 *phy_type_high)
{
	struct ice_aqc_get_phy_caps_data pcaps = { 0 };
	struct ice_port_info *pi = sc->hw.port_info;
	device_t dev = sc->dev;
	enum ice_status status;
	u8 report_mode;

	if (ice_is_bit_set(sc->feat_en, ICE_FEATURE_LENIENT_LINK_MODE))
		report_mode = ICE_AQC_REPORT_NVM_CAP;
	else
		report_mode = ICE_AQC_REPORT_TOPO_CAP;
	status = ice_aq_get_phy_caps(pi, false, report_mode, &pcaps, NULL);
	if (status != ICE_SUCCESS) {
		device_printf(dev,
		    "%s: ice_aq_get_phy_caps (%s) failed; status %s, aq_err %s\n",
		    __func__, (report_mode) ? "TOPO_CAP" : "NVM_CAP",
		    ice_status_str(status),
		    ice_aq_str(sc->hw.adminq.sq_last_status));
		return (status);
	}

	*phy_type_low = le64toh(pcaps.phy_type_low);
	*phy_type_high = le64toh(pcaps.phy_type_high);

	return (ICE_SUCCESS);
}
