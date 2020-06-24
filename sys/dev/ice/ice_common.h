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

#ifndef _ICE_COMMON_H_
#define _ICE_COMMON_H_

#include "ice_type.h"
#include "ice_nvm.h"
#include "ice_flex_pipe.h"
#include "virtchnl.h"
#include "ice_switch.h"

enum ice_fw_modes {
	ICE_FW_MODE_NORMAL,
	ICE_FW_MODE_DBG,
	ICE_FW_MODE_REC,
	ICE_FW_MODE_ROLLBACK
};

/* prototype for functions used for SW locks */
void ice_free_list(struct LIST_HEAD_TYPE *list);
void ice_init_lock(struct ice_lock *lock);
void ice_acquire_lock(struct ice_lock *lock);
void ice_release_lock(struct ice_lock *lock);
void ice_destroy_lock(struct ice_lock *lock);

void *ice_alloc_dma_mem(struct ice_hw *hw, struct ice_dma_mem *m, u64 size);
void ice_free_dma_mem(struct ice_hw *hw, struct ice_dma_mem *m);

void ice_idle_aq(struct ice_hw *hw, struct ice_ctl_q_info *cq);
bool ice_sq_done(struct ice_hw *hw, struct ice_ctl_q_info *cq);

enum ice_status ice_update_sr_checksum(struct ice_hw *hw);
enum ice_status ice_validate_sr_checksum(struct ice_hw *hw, u16 *checksum);
enum ice_status ice_nvm_validate_checksum(struct ice_hw *hw);
enum ice_status ice_init_hw(struct ice_hw *hw);
void ice_deinit_hw(struct ice_hw *hw);
enum ice_status ice_check_reset(struct ice_hw *hw);
enum ice_status ice_reset(struct ice_hw *hw, enum ice_reset_req req);

enum ice_status ice_create_all_ctrlq(struct ice_hw *hw);
enum ice_status ice_init_all_ctrlq(struct ice_hw *hw);
void ice_shutdown_all_ctrlq(struct ice_hw *hw);
void ice_destroy_all_ctrlq(struct ice_hw *hw);
enum ice_status
ice_clean_rq_elem(struct ice_hw *hw, struct ice_ctl_q_info *cq,
		  struct ice_rq_event_info *e, u16 *pending);
enum ice_status
ice_get_link_status(struct ice_port_info *pi, bool *link_up);
enum ice_status ice_update_link_info(struct ice_port_info *pi);
enum ice_status
ice_acquire_nvm(struct ice_hw *hw, enum ice_aq_res_access_type access);
void ice_release_nvm(struct ice_hw *hw);
enum ice_status
ice_aq_read_nvm(struct ice_hw *hw, u16 module_typeid, u32 offset, u16 length,
		void *data, bool last_command, bool read_shadow_ram,
		struct ice_sq_cd *cd);
enum ice_status
ice_acquire_res(struct ice_hw *hw, enum ice_aq_res_ids res,
		enum ice_aq_res_access_type access, u32 timeout);
void ice_release_res(struct ice_hw *hw, enum ice_aq_res_ids res);
enum ice_status
ice_alloc_hw_res(struct ice_hw *hw, u16 type, u16 num, bool btm, u16 *res);
enum ice_status
ice_free_hw_res(struct ice_hw *hw, u16 type, u16 num, u16 *res);
enum ice_status
ice_aq_alloc_free_res(struct ice_hw *hw, u16 num_entries,
		      struct ice_aqc_alloc_free_res_elem *buf, u16 buf_size,
		      enum ice_adminq_opc opc, struct ice_sq_cd *cd);
enum ice_status
ice_sq_send_cmd(struct ice_hw *hw, struct ice_ctl_q_info *cq,
		struct ice_aq_desc *desc, void *buf, u16 buf_size,
		struct ice_sq_cd *cd);
void ice_clear_pxe_mode(struct ice_hw *hw);

enum ice_status ice_get_caps(struct ice_hw *hw);

void ice_set_safe_mode_caps(struct ice_hw *hw);

enum ice_status ice_set_mac_type(struct ice_hw *hw);

/* Define a macro that will align a pointer to point to the next memory address
 * that falls on the given power of 2 (i.e., 2, 4, 8, 16, 32, 64...). For
 * example, given the variable pointer = 0x1006, then after the following call:
 *
 *      pointer = ICE_ALIGN(pointer, 4)
 *
 * ... the value of pointer would equal 0x1008, since 0x1008 is the next
 * address after 0x1006 which is divisible by 4.
 */
#define ICE_ALIGN(ptr, align)	(((ptr) + ((align) - 1)) & ~((align) - 1))

enum ice_status
ice_write_rxq_ctx(struct ice_hw *hw, struct ice_rlan_ctx *rlan_ctx,
		  u32 rxq_index);
enum ice_status ice_clear_rxq_ctx(struct ice_hw *hw, u32 rxq_index);
enum ice_status
ice_clear_tx_cmpltnq_ctx(struct ice_hw *hw, u32 tx_cmpltnq_index);
enum ice_status
ice_write_tx_cmpltnq_ctx(struct ice_hw *hw,
			 struct ice_tx_cmpltnq_ctx *tx_cmpltnq_ctx,
			 u32 tx_cmpltnq_index);
enum ice_status
ice_clear_tx_drbell_q_ctx(struct ice_hw *hw, u32 tx_drbell_q_index);
enum ice_status
ice_write_tx_drbell_q_ctx(struct ice_hw *hw,
			  struct ice_tx_drbell_q_ctx *tx_drbell_q_ctx,
			  u32 tx_drbell_q_index);

enum ice_status
ice_aq_get_rss_lut(struct ice_hw *hw, u16 vsi_handle, u8 lut_type, u8 *lut,
		   u16 lut_size);
enum ice_status
ice_aq_set_rss_lut(struct ice_hw *hw, u16 vsi_handle, u8 lut_type, u8 *lut,
		   u16 lut_size);
enum ice_status
ice_aq_get_rss_key(struct ice_hw *hw, u16 vsi_handle,
		   struct ice_aqc_get_set_rss_keys *keys);
enum ice_status
ice_aq_set_rss_key(struct ice_hw *hw, u16 vsi_handle,
		   struct ice_aqc_get_set_rss_keys *keys);
enum ice_status
ice_aq_add_lan_txq(struct ice_hw *hw, u8 count,
		   struct ice_aqc_add_tx_qgrp *qg_list, u16 buf_size,
		   struct ice_sq_cd *cd);
enum ice_status
ice_aq_move_recfg_lan_txq(struct ice_hw *hw, u8 num_qs, bool is_move,
			  bool is_tc_change, bool subseq_call, bool flush_pipe,
			  u8 timeout, u32 *blocked_cgds,
			  struct ice_aqc_move_txqs_data *buf, u16 buf_size,
			  u8 *txqs_moved, struct ice_sq_cd *cd);

bool ice_check_sq_alive(struct ice_hw *hw, struct ice_ctl_q_info *cq);
enum ice_status ice_aq_q_shutdown(struct ice_hw *hw, bool unloading);
void ice_fill_dflt_direct_cmd_desc(struct ice_aq_desc *desc, u16 opcode);
extern const struct ice_ctx_ele ice_tlan_ctx_info[];
enum ice_status
ice_set_ctx(u8 *src_ctx, u8 *dest_ctx, const struct ice_ctx_ele *ce_info);

enum ice_status
ice_aq_send_cmd(struct ice_hw *hw, struct ice_aq_desc *desc,
		void *buf, u16 buf_size, struct ice_sq_cd *cd);
enum ice_status ice_aq_get_fw_ver(struct ice_hw *hw, struct ice_sq_cd *cd);

enum ice_status
ice_aq_send_driver_ver(struct ice_hw *hw, struct ice_driver_ver *dv,
		       struct ice_sq_cd *cd);
enum ice_status
ice_aq_set_port_params(struct ice_port_info *pi, u16 bad_frame_vsi,
		       bool save_bad_pac, bool pad_short_pac, bool double_vlan,
		       struct ice_sq_cd *cd);
enum ice_status
ice_aq_get_phy_caps(struct ice_port_info *pi, bool qual_mods, u8 report_mode,
		    struct ice_aqc_get_phy_caps_data *caps,
		    struct ice_sq_cd *cd);
enum ice_status
ice_aq_discover_caps(struct ice_hw *hw, void *buf, u16 buf_size, u32 *cap_count,
		     enum ice_adminq_opc opc, struct ice_sq_cd *cd);
void
ice_update_phy_type(u64 *phy_type_low, u64 *phy_type_high,
		    u16 link_speeds_bitmap);
enum ice_status
ice_aq_manage_mac_read(struct ice_hw *hw, void *buf, u16 buf_size,
		       struct ice_sq_cd *cd);
enum ice_status
ice_aq_manage_mac_write(struct ice_hw *hw, const u8 *mac_addr, u8 flags,
			struct ice_sq_cd *cd);

enum ice_status ice_clear_pf_cfg(struct ice_hw *hw);
enum ice_status
ice_aq_set_phy_cfg(struct ice_hw *hw, struct ice_port_info *pi,
		   struct ice_aqc_set_phy_cfg_data *cfg, struct ice_sq_cd *cd);
bool ice_fw_supports_link_override(struct ice_hw *hw);
enum ice_status
ice_get_link_default_override(struct ice_link_default_override_tlv *ldo,
			      struct ice_port_info *pi);

enum ice_fc_mode ice_caps_to_fc_mode(u8 caps);
enum ice_fec_mode ice_caps_to_fec_mode(u8 caps, u8 fec_options);
enum ice_status
ice_set_fc(struct ice_port_info *pi, u8 *aq_failures,
	   bool ena_auto_link_update);
bool
ice_phy_caps_equals_cfg(struct ice_aqc_get_phy_caps_data *caps,
			struct ice_aqc_set_phy_cfg_data *cfg);
void
ice_copy_phy_caps_to_cfg(struct ice_port_info *pi,
			 struct ice_aqc_get_phy_caps_data *caps,
			 struct ice_aqc_set_phy_cfg_data *cfg);
enum ice_status
ice_cfg_phy_fec(struct ice_port_info *pi, struct ice_aqc_set_phy_cfg_data *cfg,
		enum ice_fec_mode fec);
enum ice_status
ice_aq_set_link_restart_an(struct ice_port_info *pi, bool ena_link,
			   struct ice_sq_cd *cd);
enum ice_status
ice_aq_set_mac_cfg(struct ice_hw *hw, u16 max_frame_size, struct ice_sq_cd *cd);
enum ice_status
ice_aq_get_link_info(struct ice_port_info *pi, bool ena_lse,
		     struct ice_link_status *link, struct ice_sq_cd *cd);
enum ice_status
ice_aq_set_event_mask(struct ice_hw *hw, u8 port_num, u16 mask,
		      struct ice_sq_cd *cd);
enum ice_status
ice_aq_set_mac_loopback(struct ice_hw *hw, bool ena_lpbk, struct ice_sq_cd *cd);

enum ice_status
ice_aq_set_port_id_led(struct ice_port_info *pi, bool is_orig_mode,
		       struct ice_sq_cd *cd);
enum ice_status
ice_aq_sff_eeprom(struct ice_hw *hw, u16 lport, u8 bus_addr,
		  u16 mem_addr, u8 page, u8 set_page, u8 *data, u8 length,
		  bool write, struct ice_sq_cd *cd);

enum ice_status
ice_get_ctx(u8 *src_ctx, u8 *dest_ctx, struct ice_ctx_ele *ce_info);
enum ice_status
__ice_write_sr_word(struct ice_hw *hw, u32 offset, const u16 *data);
enum ice_status
__ice_write_sr_buf(struct ice_hw *hw, u32 offset, u16 words, const u16 *data);
enum ice_status
ice_dis_vsi_txq(struct ice_port_info *pi, u16 vsi_handle, u8 tc, u8 num_queues,
		u16 *q_handle, u16 *q_ids, u32 *q_teids,
		enum ice_disq_rst_src rst_src, u16 vmvf_num,
		struct ice_sq_cd *cd);
enum ice_status
ice_cfg_vsi_lan(struct ice_port_info *pi, u16 vsi_handle, u16 tc_bitmap,
		u16 *max_lanqs);
enum ice_status
ice_ena_vsi_txq(struct ice_port_info *pi, u16 vsi_handle, u8 tc, u16 q_handle,
		u8 num_qgrps, struct ice_aqc_add_tx_qgrp *buf, u16 buf_size,
		struct ice_sq_cd *cd);
enum ice_status ice_replay_vsi(struct ice_hw *hw, u16 vsi_handle);
void ice_replay_post(struct ice_hw *hw);
void ice_sched_replay_agg_vsi_preinit(struct ice_hw *hw);
void ice_sched_replay_agg(struct ice_hw *hw);
enum ice_status ice_sched_replay_tc_node_bw(struct ice_port_info *pi);
enum ice_status ice_replay_vsi_agg(struct ice_hw *hw, u16 vsi_handle);
enum ice_status
ice_sched_replay_q_bw(struct ice_port_info *pi, struct ice_q_ctx *q_ctx);
struct ice_q_ctx *
ice_get_lan_q_ctx(struct ice_hw *hw, u16 vsi_handle, u8 tc, u16 q_handle);
void
ice_stat_update40(struct ice_hw *hw, u32 reg, bool prev_stat_loaded,
		  u64 *prev_stat, u64 *cur_stat);
void
ice_stat_update32(struct ice_hw *hw, u32 reg, bool prev_stat_loaded,
		  u64 *prev_stat, u64 *cur_stat);
void
ice_stat_update_repc(struct ice_hw *hw, u16 vsi_handle, bool prev_stat_loaded,
		     struct ice_eth_stats *cur_stats);
enum ice_fw_modes ice_get_fw_mode(struct ice_hw *hw);
void ice_print_rollback_msg(struct ice_hw *hw);
bool ice_is_generic_mac(struct ice_hw *hw);
enum ice_status
ice_aq_alternate_write(struct ice_hw *hw, u32 reg_addr0, u32 reg_val0,
		       u32 reg_addr1, u32 reg_val1);
enum ice_status
ice_aq_alternate_read(struct ice_hw *hw, u32 reg_addr0, u32 *reg_val0,
		      u32 reg_addr1, u32 *reg_val1);
enum ice_status
ice_aq_alternate_write_done(struct ice_hw *hw, u8 bios_mode,
			    bool *reset_needed);
enum ice_status ice_aq_alternate_clear(struct ice_hw *hw);
enum ice_status
ice_sched_query_elem(struct ice_hw *hw, u32 node_teid,
		     struct ice_aqc_get_elem *buf);
enum ice_status
ice_get_cur_lldp_persist_status(struct ice_hw *hw, u32 *lldp_status);
enum ice_status
ice_get_dflt_lldp_persist_status(struct ice_hw *hw, u32 *lldp_status);
enum ice_status ice_get_netlist_ver_info(struct ice_hw *hw);
#endif /* _ICE_COMMON_H_ */
