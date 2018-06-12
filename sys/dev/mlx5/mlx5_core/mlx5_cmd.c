/*-
 * Copyright (c) 2013-2017, Mellanox Technologies, Ltd.  All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS `AS IS' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
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

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/random.h>
#include <linux/io-mapping.h>
#include <linux/hardirq.h>
#include <linux/ktime.h>
#include <dev/mlx5/driver.h>

#include "mlx5_core.h"

static int mlx5_copy_from_msg(void *to, struct mlx5_cmd_msg *from, int size);
static void mlx5_free_cmd_msg(struct mlx5_core_dev *dev,
			      struct mlx5_cmd_msg *msg);
static void free_msg(struct mlx5_core_dev *dev, struct mlx5_cmd_msg *msg);

enum {
	CMD_IF_REV = 5,
};

enum {
	CMD_MODE_POLLING,
	CMD_MODE_EVENTS
};

enum {
	NUM_LONG_LISTS	  = 2,
	NUM_MED_LISTS	  = 64,
	LONG_LIST_SIZE	  = (2ULL * 1024 * 1024 * 1024 / PAGE_SIZE) * 8 + 16 +
				MLX5_CMD_DATA_BLOCK_SIZE,
	MED_LIST_SIZE	  = 16 + MLX5_CMD_DATA_BLOCK_SIZE,
};

enum {
	MLX5_CMD_DELIVERY_STAT_OK			= 0x0,
	MLX5_CMD_DELIVERY_STAT_SIGNAT_ERR		= 0x1,
	MLX5_CMD_DELIVERY_STAT_TOK_ERR			= 0x2,
	MLX5_CMD_DELIVERY_STAT_BAD_BLK_NUM_ERR		= 0x3,
	MLX5_CMD_DELIVERY_STAT_OUT_PTR_ALIGN_ERR	= 0x4,
	MLX5_CMD_DELIVERY_STAT_IN_PTR_ALIGN_ERR		= 0x5,
	MLX5_CMD_DELIVERY_STAT_FW_ERR			= 0x6,
	MLX5_CMD_DELIVERY_STAT_IN_LENGTH_ERR		= 0x7,
	MLX5_CMD_DELIVERY_STAT_OUT_LENGTH_ERR		= 0x8,
	MLX5_CMD_DELIVERY_STAT_RES_FLD_NOT_CLR_ERR	= 0x9,
	MLX5_CMD_DELIVERY_STAT_CMD_DESCR_ERR		= 0x10,
};

static struct mlx5_cmd_work_ent *alloc_cmd(struct mlx5_cmd *cmd,
					   struct mlx5_cmd_msg *in,
					   int uin_size,
					   struct mlx5_cmd_msg *out,
					   void *uout, int uout_size,
					   mlx5_cmd_cbk_t cbk,
					   void *context, int page_queue)
{
	gfp_t alloc_flags = cbk ? GFP_ATOMIC : GFP_KERNEL;
	struct mlx5_cmd_work_ent *ent;

	ent = kzalloc(sizeof(*ent), alloc_flags);
	if (!ent)
		return ERR_PTR(-ENOMEM);

	ent->in		= in;
	ent->uin_size	= uin_size;
	ent->out	= out;
	ent->uout	= uout;
	ent->uout_size	= uout_size;
	ent->callback	= cbk;
	ent->context	= context;
	ent->cmd	= cmd;
	ent->page_queue = page_queue;

	return ent;
}

static u8 alloc_token(struct mlx5_cmd *cmd)
{
	u8 token;

	spin_lock(&cmd->token_lock);
	cmd->token++;
	if (cmd->token == 0)
		cmd->token++;
	token = cmd->token;
	spin_unlock(&cmd->token_lock);

	return token;
}

static int alloc_ent(struct mlx5_cmd_work_ent *ent)
{
	unsigned long flags;
	struct mlx5_cmd *cmd = ent->cmd;
	struct mlx5_core_dev *dev =
		container_of(cmd, struct mlx5_core_dev, cmd);
	int ret = cmd->max_reg_cmds;

	spin_lock_irqsave(&cmd->alloc_lock, flags);
	if (!ent->page_queue) {
		ret = find_first_bit(&cmd->bitmask, cmd->max_reg_cmds);
		if (ret >= cmd->max_reg_cmds)
			ret = -1;
	}

	if (dev->state != MLX5_DEVICE_STATE_UP)
		ret = -1;

	if (ret != -1) {
		ent->busy = 1;
		ent->idx = ret;
		clear_bit(ent->idx, &cmd->bitmask);
		cmd->ent_arr[ent->idx] = ent;
	}
	spin_unlock_irqrestore(&cmd->alloc_lock, flags);

	return ret;
}

static void free_ent(struct mlx5_cmd *cmd, int idx)
{
	unsigned long flags;

	spin_lock_irqsave(&cmd->alloc_lock, flags);
	set_bit(idx, &cmd->bitmask);
	spin_unlock_irqrestore(&cmd->alloc_lock, flags);
}

static struct mlx5_cmd_layout *get_inst(struct mlx5_cmd *cmd, int idx)
{
	return cmd->cmd_buf + (idx << cmd->log_stride);
}

static u8 xor8_buf(void *buf, int len)
{
	u8 *ptr = buf;
	u8 sum = 0;
	int i;

	for (i = 0; i < len; i++)
		sum ^= ptr[i];

	return sum;
}

static int verify_block_sig(struct mlx5_cmd_prot_block *block)
{
	if (xor8_buf(block->rsvd0, sizeof(*block) - sizeof(block->data) - 1) != 0xff)
		return -EINVAL;

	if (xor8_buf(block, sizeof(*block)) != 0xff)
		return -EINVAL;

	return 0;
}

static void calc_block_sig(struct mlx5_cmd_prot_block *block, u8 token,
			   int csum)
{
	block->token = token;
	if (csum) {
		block->ctrl_sig = ~xor8_buf(block->rsvd0, sizeof(*block) -
					    sizeof(block->data) - 2);
		block->sig = ~xor8_buf(block, sizeof(*block) - 1);
	}
}

static void
calc_chain_sig(struct mlx5_cmd_msg *msg, u8 token, int csum)
{
	size_t i;

	for (i = 0; i != (msg->numpages * MLX5_NUM_CMDS_IN_ADAPTER_PAGE); i++) {
		struct mlx5_cmd_prot_block *block;

		block = mlx5_fwp_get_virt(msg, i * MLX5_CMD_MBOX_SIZE);

		/* compute signature */
		calc_block_sig(block, token, csum);

		/* check for last block */
		if (block->next == 0)
			break;
	}

	/* make sure data gets written to RAM */
	mlx5_fwp_flush(msg);
}

static void set_signature(struct mlx5_cmd_work_ent *ent, int csum)
{
	ent->lay->sig = ~xor8_buf(ent->lay, sizeof(*ent->lay));
	calc_chain_sig(ent->in, ent->token, csum);
	calc_chain_sig(ent->out, ent->token, csum);
}

static void poll_timeout(struct mlx5_cmd_work_ent *ent)
{
	struct mlx5_core_dev *dev = container_of(ent->cmd,
						 struct mlx5_core_dev, cmd);
	int poll_end = jiffies +
				msecs_to_jiffies(MLX5_CMD_TIMEOUT_MSEC + 1000);
	u8 own;

	do {
		own = ent->lay->status_own;
		if (!(own & CMD_OWNER_HW) ||
		    dev->state != MLX5_DEVICE_STATE_UP) {
			ent->ret = 0;
			return;
		}
		usleep_range(5000, 10000);
	} while (time_before(jiffies, poll_end));

	ent->ret = -ETIMEDOUT;
}

static void free_cmd(struct mlx5_cmd_work_ent *ent)
{
	kfree(ent);
}

static int
verify_signature(struct mlx5_cmd_work_ent *ent)
{
	struct mlx5_cmd_msg *msg = ent->out;
	size_t i;
	int err;
	u8 sig;

	sig = xor8_buf(ent->lay, sizeof(*ent->lay));
	if (sig != 0xff)
		return -EINVAL;

	for (i = 0; i != (msg->numpages * MLX5_NUM_CMDS_IN_ADAPTER_PAGE); i++) {
		struct mlx5_cmd_prot_block *block;

		block = mlx5_fwp_get_virt(msg, i * MLX5_CMD_MBOX_SIZE);

		/* compute signature */
		err = verify_block_sig(block);
		if (err != 0)
			return (err);

		/* check for last block */
		if (block->next == 0)
			break;
	}
	return (0);
}

static void dump_buf(void *buf, int size, int data_only, int offset)
{
	__be32 *p = buf;
	int i;

	for (i = 0; i < size; i += 16) {
		pr_debug("%03x: %08x %08x %08x %08x\n", offset, be32_to_cpu(p[0]),
			 be32_to_cpu(p[1]), be32_to_cpu(p[2]),
			 be32_to_cpu(p[3]));
		p += 4;
		offset += 16;
	}
	if (!data_only)
		pr_debug("\n");
}

const char *mlx5_command_str(int command)
{
	switch (command) {
	case MLX5_CMD_OP_QUERY_HCA_CAP:
		return "QUERY_HCA_CAP";

	case MLX5_CMD_OP_SET_HCA_CAP:
		return "SET_HCA_CAP";

	case MLX5_CMD_OP_QUERY_ADAPTER:
		return "QUERY_ADAPTER";

	case MLX5_CMD_OP_INIT_HCA:
		return "INIT_HCA";

	case MLX5_CMD_OP_TEARDOWN_HCA:
		return "TEARDOWN_HCA";

	case MLX5_CMD_OP_ENABLE_HCA:
		return "MLX5_CMD_OP_ENABLE_HCA";

	case MLX5_CMD_OP_DISABLE_HCA:
		return "MLX5_CMD_OP_DISABLE_HCA";

	case MLX5_CMD_OP_QUERY_PAGES:
		return "QUERY_PAGES";

	case MLX5_CMD_OP_MANAGE_PAGES:
		return "MANAGE_PAGES";

	case MLX5_CMD_OP_QUERY_ISSI:
		return "QUERY_ISSI";

	case MLX5_CMD_OP_SET_ISSI:
		return "SET_ISSI";

	case MLX5_CMD_OP_CREATE_MKEY:
		return "CREATE_MKEY";

	case MLX5_CMD_OP_QUERY_MKEY:
		return "QUERY_MKEY";

	case MLX5_CMD_OP_DESTROY_MKEY:
		return "DESTROY_MKEY";

	case MLX5_CMD_OP_QUERY_SPECIAL_CONTEXTS:
		return "QUERY_SPECIAL_CONTEXTS";

	case MLX5_CMD_OP_PAGE_FAULT_RESUME:
		return "PAGE_FAULT_RESUME";

	case MLX5_CMD_OP_CREATE_EQ:
		return "CREATE_EQ";

	case MLX5_CMD_OP_DESTROY_EQ:
		return "DESTROY_EQ";

	case MLX5_CMD_OP_QUERY_EQ:
		return "QUERY_EQ";

	case MLX5_CMD_OP_GEN_EQE:
		return "GEN_EQE";

	case MLX5_CMD_OP_CREATE_CQ:
		return "CREATE_CQ";

	case MLX5_CMD_OP_DESTROY_CQ:
		return "DESTROY_CQ";

	case MLX5_CMD_OP_QUERY_CQ:
		return "QUERY_CQ";

	case MLX5_CMD_OP_MODIFY_CQ:
		return "MODIFY_CQ";

	case MLX5_CMD_OP_CREATE_QP:
		return "CREATE_QP";

	case MLX5_CMD_OP_DESTROY_QP:
		return "DESTROY_QP";

	case MLX5_CMD_OP_RST2INIT_QP:
		return "RST2INIT_QP";

	case MLX5_CMD_OP_INIT2RTR_QP:
		return "INIT2RTR_QP";

	case MLX5_CMD_OP_RTR2RTS_QP:
		return "RTR2RTS_QP";

	case MLX5_CMD_OP_RTS2RTS_QP:
		return "RTS2RTS_QP";

	case MLX5_CMD_OP_SQERR2RTS_QP:
		return "SQERR2RTS_QP";

	case MLX5_CMD_OP_2ERR_QP:
		return "2ERR_QP";

	case MLX5_CMD_OP_2RST_QP:
		return "2RST_QP";

	case MLX5_CMD_OP_QUERY_QP:
		return "QUERY_QP";

	case MLX5_CMD_OP_SQD_RTS_QP:
		return "SQD_RTS_QP";

	case MLX5_CMD_OP_MAD_IFC:
		return "MAD_IFC";

	case MLX5_CMD_OP_INIT2INIT_QP:
		return "INIT2INIT_QP";

	case MLX5_CMD_OP_CREATE_PSV:
		return "CREATE_PSV";

	case MLX5_CMD_OP_DESTROY_PSV:
		return "DESTROY_PSV";

	case MLX5_CMD_OP_CREATE_SRQ:
		return "CREATE_SRQ";

	case MLX5_CMD_OP_DESTROY_SRQ:
		return "DESTROY_SRQ";

	case MLX5_CMD_OP_QUERY_SRQ:
		return "QUERY_SRQ";

	case MLX5_CMD_OP_ARM_RQ:
		return "ARM_RQ";

	case MLX5_CMD_OP_CREATE_XRC_SRQ:
		return "CREATE_XRC_SRQ";

	case MLX5_CMD_OP_DESTROY_XRC_SRQ:
		return "DESTROY_XRC_SRQ";

	case MLX5_CMD_OP_QUERY_XRC_SRQ:
		return "QUERY_XRC_SRQ";

	case MLX5_CMD_OP_ARM_XRC_SRQ:
		return "ARM_XRC_SRQ";

	case MLX5_CMD_OP_CREATE_DCT:
		return "CREATE_DCT";

	case MLX5_CMD_OP_SET_DC_CNAK_TRACE:
		return "SET_DC_CNAK_TRACE";

	case MLX5_CMD_OP_DESTROY_DCT:
		return "DESTROY_DCT";

	case MLX5_CMD_OP_DRAIN_DCT:
		return "DRAIN_DCT";

	case MLX5_CMD_OP_QUERY_DCT:
		return "QUERY_DCT";

	case MLX5_CMD_OP_ARM_DCT_FOR_KEY_VIOLATION:
		return "ARM_DCT_FOR_KEY_VIOLATION";

	case MLX5_CMD_OP_QUERY_VPORT_STATE:
		return "QUERY_VPORT_STATE";

	case MLX5_CMD_OP_MODIFY_VPORT_STATE:
		return "MODIFY_VPORT_STATE";

	case MLX5_CMD_OP_QUERY_ESW_VPORT_CONTEXT:
		return "QUERY_ESW_VPORT_CONTEXT";

	case MLX5_CMD_OP_MODIFY_ESW_VPORT_CONTEXT:
		return "MODIFY_ESW_VPORT_CONTEXT";

	case MLX5_CMD_OP_QUERY_NIC_VPORT_CONTEXT:
		return "QUERY_NIC_VPORT_CONTEXT";

	case MLX5_CMD_OP_MODIFY_NIC_VPORT_CONTEXT:
		return "MODIFY_NIC_VPORT_CONTEXT";

	case MLX5_CMD_OP_QUERY_ROCE_ADDRESS:
		return "QUERY_ROCE_ADDRESS";

	case MLX5_CMD_OP_SET_ROCE_ADDRESS:
		return "SET_ROCE_ADDRESS";

	case MLX5_CMD_OP_QUERY_HCA_VPORT_CONTEXT:
		return "QUERY_HCA_VPORT_CONTEXT";

	case MLX5_CMD_OP_MODIFY_HCA_VPORT_CONTEXT:
		return "MODIFY_HCA_VPORT_CONTEXT";

	case MLX5_CMD_OP_QUERY_HCA_VPORT_GID:
		return "QUERY_HCA_VPORT_GID";

	case MLX5_CMD_OP_QUERY_HCA_VPORT_PKEY:
		return "QUERY_HCA_VPORT_PKEY";

	case MLX5_CMD_OP_QUERY_VPORT_COUNTER:
		return "QUERY_VPORT_COUNTER";

	case MLX5_CMD_OP_SET_WOL_ROL:
		return "SET_WOL_ROL";

	case MLX5_CMD_OP_QUERY_WOL_ROL:
		return "QUERY_WOL_ROL";

	case MLX5_CMD_OP_ALLOC_Q_COUNTER:
		return "ALLOC_Q_COUNTER";

	case MLX5_CMD_OP_DEALLOC_Q_COUNTER:
		return "DEALLOC_Q_COUNTER";

	case MLX5_CMD_OP_QUERY_Q_COUNTER:
		return "QUERY_Q_COUNTER";

	case MLX5_CMD_OP_ALLOC_PD:
		return "ALLOC_PD";

	case MLX5_CMD_OP_DEALLOC_PD:
		return "DEALLOC_PD";

	case MLX5_CMD_OP_ALLOC_UAR:
		return "ALLOC_UAR";

	case MLX5_CMD_OP_DEALLOC_UAR:
		return "DEALLOC_UAR";

	case MLX5_CMD_OP_CONFIG_INT_MODERATION:
		return "CONFIG_INT_MODERATION";

	case MLX5_CMD_OP_ATTACH_TO_MCG:
		return "ATTACH_TO_MCG";

	case MLX5_CMD_OP_DETACH_FROM_MCG:
		return "DETACH_FROM_MCG";

	case MLX5_CMD_OP_GET_DROPPED_PACKET_LOG:
		return "GET_DROPPED_PACKET_LOG";

	case MLX5_CMD_OP_QUERY_MAD_DEMUX:
		return "QUERY_MAD_DEMUX";

	case MLX5_CMD_OP_SET_MAD_DEMUX:
		return "SET_MAD_DEMUX";

	case MLX5_CMD_OP_NOP:
		return "NOP";

	case MLX5_CMD_OP_ALLOC_XRCD:
		return "ALLOC_XRCD";

	case MLX5_CMD_OP_DEALLOC_XRCD:
		return "DEALLOC_XRCD";

	case MLX5_CMD_OP_ALLOC_TRANSPORT_DOMAIN:
		return "ALLOC_TRANSPORT_DOMAIN";

	case MLX5_CMD_OP_DEALLOC_TRANSPORT_DOMAIN:
		return "DEALLOC_TRANSPORT_DOMAIN";

	case MLX5_CMD_OP_QUERY_CONG_STATUS:
		return "QUERY_CONG_STATUS";

	case MLX5_CMD_OP_MODIFY_CONG_STATUS:
		return "MODIFY_CONG_STATUS";

	case MLX5_CMD_OP_QUERY_CONG_PARAMS:
		return "QUERY_CONG_PARAMS";

	case MLX5_CMD_OP_MODIFY_CONG_PARAMS:
		return "MODIFY_CONG_PARAMS";

	case MLX5_CMD_OP_QUERY_CONG_STATISTICS:
		return "QUERY_CONG_STATISTICS";

	case MLX5_CMD_OP_ADD_VXLAN_UDP_DPORT:
		return "ADD_VXLAN_UDP_DPORT";

	case MLX5_CMD_OP_DELETE_VXLAN_UDP_DPORT:
		return "DELETE_VXLAN_UDP_DPORT";

	case MLX5_CMD_OP_SET_L2_TABLE_ENTRY:
		return "SET_L2_TABLE_ENTRY";

	case MLX5_CMD_OP_QUERY_L2_TABLE_ENTRY:
		return "QUERY_L2_TABLE_ENTRY";

	case MLX5_CMD_OP_DELETE_L2_TABLE_ENTRY:
		return "DELETE_L2_TABLE_ENTRY";

	case MLX5_CMD_OP_CREATE_RMP:
		return "CREATE_RMP";

	case MLX5_CMD_OP_MODIFY_RMP:
		return "MODIFY_RMP";

	case MLX5_CMD_OP_DESTROY_RMP:
		return "DESTROY_RMP";

	case MLX5_CMD_OP_QUERY_RMP:
		return "QUERY_RMP";

	case MLX5_CMD_OP_CREATE_RQT:
		return "CREATE_RQT";

	case MLX5_CMD_OP_MODIFY_RQT:
		return "MODIFY_RQT";

	case MLX5_CMD_OP_DESTROY_RQT:
		return "DESTROY_RQT";

	case MLX5_CMD_OP_QUERY_RQT:
		return "QUERY_RQT";

	case MLX5_CMD_OP_ACCESS_REG:
		return "MLX5_CMD_OP_ACCESS_REG";

	case MLX5_CMD_OP_CREATE_SQ:
		return "CREATE_SQ";

	case MLX5_CMD_OP_MODIFY_SQ:
		return "MODIFY_SQ";

	case MLX5_CMD_OP_DESTROY_SQ:
		return "DESTROY_SQ";

	case MLX5_CMD_OP_QUERY_SQ:
		return "QUERY_SQ";

	case MLX5_CMD_OP_CREATE_RQ:
		return "CREATE_RQ";

	case MLX5_CMD_OP_MODIFY_RQ:
		return "MODIFY_RQ";

	case MLX5_CMD_OP_DESTROY_RQ:
		return "DESTROY_RQ";

	case MLX5_CMD_OP_QUERY_RQ:
		return "QUERY_RQ";

	case MLX5_CMD_OP_CREATE_TIR:
		return "CREATE_TIR";

	case MLX5_CMD_OP_MODIFY_TIR:
		return "MODIFY_TIR";

	case MLX5_CMD_OP_DESTROY_TIR:
		return "DESTROY_TIR";

	case MLX5_CMD_OP_QUERY_TIR:
		return "QUERY_TIR";

	case MLX5_CMD_OP_CREATE_TIS:
		return "CREATE_TIS";

	case MLX5_CMD_OP_MODIFY_TIS:
		return "MODIFY_TIS";

	case MLX5_CMD_OP_DESTROY_TIS:
		return "DESTROY_TIS";

	case MLX5_CMD_OP_QUERY_TIS:
		return "QUERY_TIS";

	case MLX5_CMD_OP_CREATE_FLOW_TABLE:
		return "CREATE_FLOW_TABLE";

	case MLX5_CMD_OP_DESTROY_FLOW_TABLE:
		return "DESTROY_FLOW_TABLE";

	case MLX5_CMD_OP_QUERY_FLOW_TABLE:
		return "QUERY_FLOW_TABLE";

	case MLX5_CMD_OP_CREATE_FLOW_GROUP:
		return "CREATE_FLOW_GROUP";

	case MLX5_CMD_OP_DESTROY_FLOW_GROUP:
		return "DESTROY_FLOW_GROUP";

	case MLX5_CMD_OP_QUERY_FLOW_GROUP:
		return "QUERY_FLOW_GROUP";

	case MLX5_CMD_OP_SET_FLOW_TABLE_ENTRY:
		return "SET_FLOW_TABLE_ENTRY";

	case MLX5_CMD_OP_QUERY_FLOW_TABLE_ENTRY:
		return "QUERY_FLOW_TABLE_ENTRY";

	case MLX5_CMD_OP_DELETE_FLOW_TABLE_ENTRY:
		return "DELETE_FLOW_TABLE_ENTRY";

	case MLX5_CMD_OP_SET_DIAGNOSTICS:
		return "MLX5_CMD_OP_SET_DIAGNOSTICS";

	case MLX5_CMD_OP_QUERY_DIAGNOSTICS:
		return "MLX5_CMD_OP_QUERY_DIAGNOSTICS";

	default: return "unknown command opcode";
	}
}

static void dump_command(struct mlx5_core_dev *dev,
			 struct mlx5_cmd_work_ent *ent, int input)
{
	u16 op = be16_to_cpu(((struct mlx5_inbox_hdr *)(ent->lay->in))->opcode);
	struct mlx5_cmd_msg *msg = input ? ent->in : ent->out;
	size_t i;
	int data_only;
	int offset = 0;
	int msg_len = input ? ent->uin_size : ent->uout_size;
	int dump_len;

	data_only = !!(mlx5_core_debug_mask & (1 << MLX5_CMD_DATA));

	if (data_only)
		mlx5_core_dbg_mask(dev, 1 << MLX5_CMD_DATA,
				   "dump command data %s(0x%x) %s\n",
				   mlx5_command_str(op), op,
				   input ? "INPUT" : "OUTPUT");
	else
		mlx5_core_dbg(dev, "dump command %s(0x%x) %s\n",
			      mlx5_command_str(op), op,
			      input ? "INPUT" : "OUTPUT");

	if (data_only) {
		if (input) {
			dump_buf(ent->lay->in, sizeof(ent->lay->in), 1, offset);
			offset += sizeof(ent->lay->in);
		} else {
			dump_buf(ent->lay->out, sizeof(ent->lay->out), 1, offset);
			offset += sizeof(ent->lay->out);
		}
	} else {
		dump_buf(ent->lay, sizeof(*ent->lay), 0, offset);
		offset += sizeof(*ent->lay);
	}

	for (i = 0; i != (msg->numpages * MLX5_NUM_CMDS_IN_ADAPTER_PAGE); i++) {
		struct mlx5_cmd_prot_block *block;

		block = mlx5_fwp_get_virt(msg, i * MLX5_CMD_MBOX_SIZE);

		if (data_only) {
			if (offset >= msg_len)
				break;
			dump_len = min_t(int,
			    MLX5_CMD_DATA_BLOCK_SIZE, msg_len - offset);

			dump_buf(block->data, dump_len, 1, offset);
			offset += MLX5_CMD_DATA_BLOCK_SIZE;
		} else {
			mlx5_core_dbg(dev, "command block:\n");
			dump_buf(block, sizeof(*block), 0, offset);
			offset += sizeof(*block);
		}

		/* check for last block */
		if (block->next == 0)
			break;
	}

	if (data_only)
		pr_debug("\n");
}

static int set_internal_err_outbox(struct mlx5_core_dev *dev, u16 opcode,
				   struct mlx5_outbox_hdr *hdr)
{
	hdr->status = 0;
	hdr->syndrome = 0;

	switch (opcode) {
	case MLX5_CMD_OP_TEARDOWN_HCA:
	case MLX5_CMD_OP_DISABLE_HCA:
	case MLX5_CMD_OP_MANAGE_PAGES:
	case MLX5_CMD_OP_DESTROY_MKEY:
	case MLX5_CMD_OP_DESTROY_EQ:
	case MLX5_CMD_OP_DESTROY_CQ:
	case MLX5_CMD_OP_DESTROY_QP:
	case MLX5_CMD_OP_DESTROY_PSV:
	case MLX5_CMD_OP_DESTROY_SRQ:
	case MLX5_CMD_OP_DESTROY_XRC_SRQ:
	case MLX5_CMD_OP_DESTROY_DCT:
	case MLX5_CMD_OP_DEALLOC_Q_COUNTER:
	case MLX5_CMD_OP_DEALLOC_PD:
	case MLX5_CMD_OP_DEALLOC_UAR:
	case MLX5_CMD_OP_DETACH_FROM_MCG:
	case MLX5_CMD_OP_DEALLOC_XRCD:
	case MLX5_CMD_OP_DEALLOC_TRANSPORT_DOMAIN:
	case MLX5_CMD_OP_DELETE_VXLAN_UDP_DPORT:
	case MLX5_CMD_OP_DELETE_L2_TABLE_ENTRY:
	case MLX5_CMD_OP_DESTROY_LAG:
	case MLX5_CMD_OP_DESTROY_VPORT_LAG:
	case MLX5_CMD_OP_DESTROY_TIR:
	case MLX5_CMD_OP_DESTROY_SQ:
	case MLX5_CMD_OP_DESTROY_RQ:
	case MLX5_CMD_OP_DESTROY_RMP:
	case MLX5_CMD_OP_DESTROY_TIS:
	case MLX5_CMD_OP_DESTROY_RQT:
	case MLX5_CMD_OP_DESTROY_FLOW_TABLE:
	case MLX5_CMD_OP_DESTROY_FLOW_GROUP:
	case MLX5_CMD_OP_DELETE_FLOW_TABLE_ENTRY:
	case MLX5_CMD_OP_DEALLOC_FLOW_COUNTER:
	case MLX5_CMD_OP_2ERR_QP:
	case MLX5_CMD_OP_2RST_QP:
	case MLX5_CMD_OP_MODIFY_NIC_VPORT_CONTEXT:
	case MLX5_CMD_OP_MODIFY_FLOW_TABLE:
	case MLX5_CMD_OP_SET_FLOW_TABLE_ENTRY:
	case MLX5_CMD_OP_SET_FLOW_TABLE_ROOT:
	case MLX5_CMD_OP_DEALLOC_ENCAP_HEADER:
	case MLX5_CMD_OP_DESTROY_SCHEDULING_ELEMENT:
	case MLX5_CMD_OP_DESTROY_QOS_PARA_VPORT:
	case MLX5_CMD_OP_MODIFY_VPORT_STATE:
	case MLX5_CMD_OP_MODIFY_SQ:
	case MLX5_CMD_OP_MODIFY_RQ:
	case MLX5_CMD_OP_MODIFY_TIS:
	case MLX5_CMD_OP_MODIFY_LAG:
	case MLX5_CMD_OP_MODIFY_TIR:
	case MLX5_CMD_OP_MODIFY_RMP:
	case MLX5_CMD_OP_MODIFY_RQT:
	case MLX5_CMD_OP_MODIFY_SCHEDULING_ELEMENT:
	case MLX5_CMD_OP_MODIFY_CONG_PARAMS:
	case MLX5_CMD_OP_MODIFY_CONG_STATUS:
	case MLX5_CMD_OP_MODIFY_CQ:
	case MLX5_CMD_OP_MODIFY_ESW_VPORT_CONTEXT:
	case MLX5_CMD_OP_MODIFY_HCA_VPORT_CONTEXT:
	case MLX5_CMD_OP_MODIFY_OTHER_HCA_CAP:
	case MLX5_CMD_OP_ACCESS_REG:
	case MLX5_CMD_OP_DRAIN_DCT:
		return 0;

	case MLX5_CMD_OP_ADD_VXLAN_UDP_DPORT:
	case MLX5_CMD_OP_ALLOC_ENCAP_HEADER:
	case MLX5_CMD_OP_ALLOC_FLOW_COUNTER:
	case MLX5_CMD_OP_ALLOC_PD:
	case MLX5_CMD_OP_ALLOC_Q_COUNTER:
	case MLX5_CMD_OP_ALLOC_TRANSPORT_DOMAIN:
	case MLX5_CMD_OP_ALLOC_UAR:
	case MLX5_CMD_OP_ALLOC_XRCD:
	case MLX5_CMD_OP_ARM_DCT_FOR_KEY_VIOLATION:
	case MLX5_CMD_OP_ARM_RQ:
	case MLX5_CMD_OP_ARM_XRC_SRQ:
	case MLX5_CMD_OP_ATTACH_TO_MCG:
	case MLX5_CMD_OP_CONFIG_INT_MODERATION:
	case MLX5_CMD_OP_CREATE_CQ:
	case MLX5_CMD_OP_CREATE_DCT:
	case MLX5_CMD_OP_CREATE_EQ:
	case MLX5_CMD_OP_CREATE_FLOW_GROUP:
	case MLX5_CMD_OP_CREATE_FLOW_TABLE:
	case MLX5_CMD_OP_CREATE_LAG:
	case MLX5_CMD_OP_CREATE_MKEY:
	case MLX5_CMD_OP_CREATE_PSV:
	case MLX5_CMD_OP_CREATE_QOS_PARA_VPORT:
	case MLX5_CMD_OP_CREATE_QP:
	case MLX5_CMD_OP_CREATE_RMP:
	case MLX5_CMD_OP_CREATE_RQ:
	case MLX5_CMD_OP_CREATE_RQT:
	case MLX5_CMD_OP_CREATE_SCHEDULING_ELEMENT:
	case MLX5_CMD_OP_CREATE_SQ:
	case MLX5_CMD_OP_CREATE_SRQ:
	case MLX5_CMD_OP_CREATE_TIR:
	case MLX5_CMD_OP_CREATE_TIS:
	case MLX5_CMD_OP_CREATE_VPORT_LAG:
	case MLX5_CMD_OP_CREATE_XRC_SRQ:
	case MLX5_CMD_OP_ENABLE_HCA:
	case MLX5_CMD_OP_GEN_EQE:
	case MLX5_CMD_OP_GET_DROPPED_PACKET_LOG:
	case MLX5_CMD_OP_INIT2INIT_QP:
	case MLX5_CMD_OP_INIT2RTR_QP:
	case MLX5_CMD_OP_INIT_HCA:
	case MLX5_CMD_OP_MAD_IFC:
	case MLX5_CMD_OP_NOP:
	case MLX5_CMD_OP_PAGE_FAULT_RESUME:
	case MLX5_CMD_OP_QUERY_ADAPTER:
	case MLX5_CMD_OP_QUERY_CONG_PARAMS:
	case MLX5_CMD_OP_QUERY_CONG_STATISTICS:
	case MLX5_CMD_OP_QUERY_CONG_STATUS:
	case MLX5_CMD_OP_QUERY_CQ:
	case MLX5_CMD_OP_QUERY_DCT:
	case MLX5_CMD_OP_QUERY_EQ:
	case MLX5_CMD_OP_QUERY_ESW_VPORT_CONTEXT:
	case MLX5_CMD_OP_QUERY_FLOW_COUNTER:
	case MLX5_CMD_OP_QUERY_FLOW_GROUP:
	case MLX5_CMD_OP_QUERY_FLOW_TABLE:
	case MLX5_CMD_OP_QUERY_FLOW_TABLE_ENTRY:
	case MLX5_CMD_OP_QUERY_HCA_CAP:
	case MLX5_CMD_OP_QUERY_HCA_VPORT_CONTEXT:
	case MLX5_CMD_OP_QUERY_HCA_VPORT_GID:
	case MLX5_CMD_OP_QUERY_HCA_VPORT_PKEY:
	case MLX5_CMD_OP_QUERY_ISSI:
	case MLX5_CMD_OP_QUERY_L2_TABLE_ENTRY:
	case MLX5_CMD_OP_QUERY_LAG:
	case MLX5_CMD_OP_QUERY_MAD_DEMUX:
	case MLX5_CMD_OP_QUERY_MKEY:
	case MLX5_CMD_OP_QUERY_NIC_VPORT_CONTEXT:
	case MLX5_CMD_OP_QUERY_OTHER_HCA_CAP:
	case MLX5_CMD_OP_QUERY_PAGES:
	case MLX5_CMD_OP_QUERY_QP:
	case MLX5_CMD_OP_QUERY_Q_COUNTER:
	case MLX5_CMD_OP_QUERY_RMP:
	case MLX5_CMD_OP_QUERY_ROCE_ADDRESS:
	case MLX5_CMD_OP_QUERY_RQ:
	case MLX5_CMD_OP_QUERY_RQT:
	case MLX5_CMD_OP_QUERY_SCHEDULING_ELEMENT:
	case MLX5_CMD_OP_QUERY_SPECIAL_CONTEXTS:
	case MLX5_CMD_OP_QUERY_SQ:
	case MLX5_CMD_OP_QUERY_SRQ:
	case MLX5_CMD_OP_QUERY_TIR:
	case MLX5_CMD_OP_QUERY_TIS:
	case MLX5_CMD_OP_QUERY_VPORT_COUNTER:
	case MLX5_CMD_OP_QUERY_VPORT_STATE:
	case MLX5_CMD_OP_QUERY_XRC_SRQ:
	case MLX5_CMD_OP_RST2INIT_QP:
	case MLX5_CMD_OP_RTR2RTS_QP:
	case MLX5_CMD_OP_RTS2RTS_QP:
	case MLX5_CMD_OP_SET_DC_CNAK_TRACE:
	case MLX5_CMD_OP_SET_HCA_CAP:
	case MLX5_CMD_OP_SET_ISSI:
	case MLX5_CMD_OP_SET_L2_TABLE_ENTRY:
	case MLX5_CMD_OP_SET_MAD_DEMUX:
	case MLX5_CMD_OP_SET_ROCE_ADDRESS:
	case MLX5_CMD_OP_SQD_RTS_QP:
	case MLX5_CMD_OP_SQERR2RTS_QP:
		hdr->status = MLX5_CMD_STAT_INT_ERR;
		hdr->syndrome = 0xFFFFFFFF;
		return -ECANCELED;
	default:
		mlx5_core_err(dev, "Unknown FW command (%d)\n", opcode);
		return -EINVAL;
	}
}

static void complete_command(struct mlx5_cmd_work_ent *ent)
{
	struct mlx5_cmd *cmd = ent->cmd;
	struct mlx5_core_dev *dev = container_of(cmd, struct mlx5_core_dev,
						 cmd);
	mlx5_cmd_cbk_t callback;
	void *context;

	s64 ds;
	struct mlx5_cmd_stats *stats;
	unsigned long flags;
	int err;
	struct semaphore *sem;

	if (ent->page_queue)
		sem = &cmd->pages_sem;
	else
		sem = &cmd->sem;

	if (dev->state != MLX5_DEVICE_STATE_UP) {
		struct mlx5_outbox_hdr *out_hdr =
			(struct mlx5_outbox_hdr *)ent->out;
		struct mlx5_inbox_hdr *in_hdr =
			(struct mlx5_inbox_hdr *)(ent->in->first.data);
		u16 opcode = be16_to_cpu(in_hdr->opcode);

		ent->ret = set_internal_err_outbox(dev,
						   opcode,
						   out_hdr);
	}

	if (ent->callback) {
		ds = ent->ts2 - ent->ts1;
		if (ent->op < ARRAY_SIZE(cmd->stats)) {
			stats = &cmd->stats[ent->op];
			spin_lock_irqsave(&stats->lock, flags);
			stats->sum += ds;
			++stats->n;
			spin_unlock_irqrestore(&stats->lock, flags);
		}

		callback = ent->callback;
		context = ent->context;
		err = ent->ret;
		if (!err)
			err = mlx5_copy_from_msg(ent->uout,
						 ent->out,
						 ent->uout_size);

		mlx5_free_cmd_msg(dev, ent->out);
		free_msg(dev, ent->in);

		free_cmd(ent);
		callback(err, context);
	} else {
		complete(&ent->done);
	}
	up(sem);
}

static void cmd_work_handler(struct work_struct *work)
{
	struct mlx5_cmd_work_ent *ent = container_of(work, struct mlx5_cmd_work_ent, work);
	struct mlx5_cmd *cmd = ent->cmd;
	struct mlx5_core_dev *dev = container_of(cmd, struct mlx5_core_dev, cmd);
	struct mlx5_cmd_layout *lay;
	struct semaphore *sem;

	sem = ent->page_queue ? &cmd->pages_sem : &cmd->sem;
	if (cmd->moving_to_polling) {
		mlx5_core_warn(dev, "not expecting command execution, ignoring...\n");
		return;
	}

	down(sem);

	if (alloc_ent(ent) < 0) {
		complete_command(ent);
		return;
	}

	ent->token = alloc_token(cmd);
	lay = get_inst(cmd, ent->idx);
	ent->lay = lay;
	memset(lay, 0, sizeof(*lay));
	memcpy(lay->in, ent->in->first.data, sizeof(lay->in));
	ent->op = be32_to_cpu(lay->in[0]) >> 16;
	if (ent->in->numpages != 0)
		lay->in_ptr = cpu_to_be64(mlx5_fwp_get_dma(ent->in, 0));
	if (ent->out->numpages != 0)
		lay->out_ptr = cpu_to_be64(mlx5_fwp_get_dma(ent->out, 0));
	lay->inlen = cpu_to_be32(ent->uin_size);
	lay->outlen = cpu_to_be32(ent->uout_size);
	lay->type = MLX5_PCI_CMD_XPORT;
	lay->token = ent->token;
	lay->status_own = CMD_OWNER_HW;
	set_signature(ent, !cmd->checksum_disabled);
	dump_command(dev, ent, 1);
	ent->ts1 = ktime_get_ns();
	ent->busy = 0;
	/* ring doorbell after the descriptor is valid */
	mlx5_core_dbg(dev, "writing 0x%x to command doorbell\n", 1 << ent->idx);
	/* make sure data is written to RAM */
	mlx5_fwp_flush(cmd->cmd_page);
	iowrite32be(1 << ent->idx, &dev->iseg->cmd_dbell);
	mmiowb();
	/* if not in polling don't use ent after this point*/
	if (cmd->mode == CMD_MODE_POLLING) {
		poll_timeout(ent);
		/* make sure we read the descriptor after ownership is SW */
		mlx5_cmd_comp_handler(dev, 1U << ent->idx);
	}
}

static const char *deliv_status_to_str(u8 status)
{
	switch (status) {
	case MLX5_CMD_DELIVERY_STAT_OK:
		return "no errors";
	case MLX5_CMD_DELIVERY_STAT_SIGNAT_ERR:
		return "signature error";
	case MLX5_CMD_DELIVERY_STAT_TOK_ERR:
		return "token error";
	case MLX5_CMD_DELIVERY_STAT_BAD_BLK_NUM_ERR:
		return "bad block number";
	case MLX5_CMD_DELIVERY_STAT_OUT_PTR_ALIGN_ERR:
		return "output pointer not aligned to block size";
	case MLX5_CMD_DELIVERY_STAT_IN_PTR_ALIGN_ERR:
		return "input pointer not aligned to block size";
	case MLX5_CMD_DELIVERY_STAT_FW_ERR:
		return "firmware internal error";
	case MLX5_CMD_DELIVERY_STAT_IN_LENGTH_ERR:
		return "command input length error";
	case MLX5_CMD_DELIVERY_STAT_OUT_LENGTH_ERR:
		return "command ouput length error";
	case MLX5_CMD_DELIVERY_STAT_RES_FLD_NOT_CLR_ERR:
		return "reserved fields not cleared";
	case MLX5_CMD_DELIVERY_STAT_CMD_DESCR_ERR:
		return "bad command descriptor type";
	default:
		return "unknown status code";
	}
}

static u16 msg_to_opcode(struct mlx5_cmd_msg *in)
{
	struct mlx5_inbox_hdr *hdr = (struct mlx5_inbox_hdr *)(in->first.data);

	return be16_to_cpu(hdr->opcode);
}

static int wait_func(struct mlx5_core_dev *dev, struct mlx5_cmd_work_ent *ent)
{
	int timeout = msecs_to_jiffies(MLX5_CMD_TIMEOUT_MSEC);
	struct mlx5_cmd *cmd = &dev->cmd;
	int err;

	if (cmd->mode == CMD_MODE_POLLING) {
		wait_for_completion(&ent->done);
		err = ent->ret;
	} else {
		if (!wait_for_completion_timeout(&ent->done, timeout))
			err = -ETIMEDOUT;
		else
			err = 0;
	}

	if (err == -ETIMEDOUT) {
		mlx5_core_warn(dev, "%s(0x%x) timeout. Will cause a leak of a command resource\n",
			       mlx5_command_str(msg_to_opcode(ent->in)),
			       msg_to_opcode(ent->in));
	}
	mlx5_core_dbg(dev, "err %d, delivery status %s(%d)\n",
		      err, deliv_status_to_str(ent->status), ent->status);

	return err;
}

/*  Notes:
 *    1. Callback functions may not sleep
 *    2. page queue commands do not support asynchrous completion
 */
static int mlx5_cmd_invoke(struct mlx5_core_dev *dev, struct mlx5_cmd_msg *in,
			   int uin_size,
			   struct mlx5_cmd_msg *out, void *uout, int uout_size,
			   mlx5_cmd_cbk_t callback,
			   void *context, int page_queue, u8 *status)
{
	struct mlx5_cmd *cmd = &dev->cmd;
	struct mlx5_cmd_work_ent *ent;
	struct mlx5_cmd_stats *stats;
	int err = 0;
	s64 ds;
	u16 op;

	if (callback && page_queue)
		return -EINVAL;

	ent = alloc_cmd(cmd, in, uin_size, out, uout, uout_size, callback,
			context, page_queue);
	if (IS_ERR(ent))
		return PTR_ERR(ent);

	if (!callback)
		init_completion(&ent->done);

	INIT_WORK(&ent->work, cmd_work_handler);
	if (page_queue) {
		cmd_work_handler(&ent->work);
	} else if (!queue_work(cmd->wq, &ent->work)) {
		mlx5_core_warn(dev, "failed to queue work\n");
		err = -ENOMEM;
		goto out_free;
	}

	if (!callback) {
		err = wait_func(dev, ent);
		if (err == -ETIMEDOUT)
			goto out;

		ds = ent->ts2 - ent->ts1;
		op = be16_to_cpu(((struct mlx5_inbox_hdr *)in->first.data)->opcode);
		if (op < ARRAY_SIZE(cmd->stats)) {
			stats = &cmd->stats[op];
			spin_lock_irq(&stats->lock);
			stats->sum += ds;
			++stats->n;
			spin_unlock_irq(&stats->lock);
		}
		mlx5_core_dbg_mask(dev, 1 << MLX5_CMD_TIME,
				   "fw exec time for %s is %lld nsec\n",
				   mlx5_command_str(op), (long long)ds);
		*status = ent->status;
		free_cmd(ent);
	}

	return err;

out_free:
	free_cmd(ent);
out:
	return err;
}

static int mlx5_copy_to_msg(struct mlx5_cmd_msg *to, void *from, size_t size)
{
	size_t delta;
	size_t i;

	if (to == NULL || from == NULL)
		return (-ENOMEM);

	delta = min_t(size_t, size, sizeof(to->first.data));
	memcpy(to->first.data, from, delta);
	from = (char *)from + delta;
	size -= delta;

	for (i = 0; size != 0; i++) {
		struct mlx5_cmd_prot_block *block;

		block = mlx5_fwp_get_virt(to, i * MLX5_CMD_MBOX_SIZE);

		delta = min_t(size_t, size, MLX5_CMD_DATA_BLOCK_SIZE);
		memcpy(block->data, from, delta);
		from = (char *)from + delta;
		size -= delta;
	}
	return (0);
}

static int mlx5_copy_from_msg(void *to, struct mlx5_cmd_msg *from, int size)
{
	size_t delta;
	size_t i;

	if (to == NULL || from == NULL)
		return (-ENOMEM);

	delta = min_t(size_t, size, sizeof(from->first.data));
	memcpy(to, from->first.data, delta);
	to = (char *)to + delta;
	size -= delta;

	for (i = 0; size != 0; i++) {
		struct mlx5_cmd_prot_block *block;

		block = mlx5_fwp_get_virt(from, i * MLX5_CMD_MBOX_SIZE);

		delta = min_t(size_t, size, MLX5_CMD_DATA_BLOCK_SIZE);
		memcpy(to, block->data, delta);
		to = (char *)to + delta;
		size -= delta;
	}
	return (0);
}

static struct mlx5_cmd_msg *
mlx5_alloc_cmd_msg(struct mlx5_core_dev *dev, gfp_t flags, size_t size)
{
	struct mlx5_cmd_msg *msg;
	size_t blen;
	size_t n;
	size_t i;

	blen = size - min_t(size_t, sizeof(msg->first.data), size);
	n = howmany(blen, MLX5_CMD_DATA_BLOCK_SIZE);

	msg = mlx5_fwp_alloc(dev, flags, howmany(n, MLX5_NUM_CMDS_IN_ADAPTER_PAGE));
	if (msg == NULL)
		return (ERR_PTR(-ENOMEM));

	for (i = 0; i != n; i++) {
		struct mlx5_cmd_prot_block *block;

		block = mlx5_fwp_get_virt(msg, i * MLX5_CMD_MBOX_SIZE);

		memset(block, 0, MLX5_CMD_MBOX_SIZE);

		if (i != (n - 1)) {
			u64 dma = mlx5_fwp_get_dma(msg, (i + 1) * MLX5_CMD_MBOX_SIZE);
			block->next = cpu_to_be64(dma);
		}
		block->block_num = cpu_to_be32(i);
	}

	/* make sure initial data is written to RAM */
	mlx5_fwp_flush(msg);

	return (msg);
}

static void
mlx5_free_cmd_msg(struct mlx5_core_dev *dev, struct mlx5_cmd_msg *msg)
{

	mlx5_fwp_free(msg);
}

static void set_wqname(struct mlx5_core_dev *dev)
{
	struct mlx5_cmd *cmd = &dev->cmd;

	snprintf(cmd->wq_name, sizeof(cmd->wq_name), "mlx5_cmd_%s",
		 dev_name(&dev->pdev->dev));
}

static void clean_debug_files(struct mlx5_core_dev *dev)
{
}


void mlx5_cmd_use_events(struct mlx5_core_dev *dev)
{
	struct mlx5_cmd *cmd = &dev->cmd;
	int i;

	for (i = 0; i < cmd->max_reg_cmds; i++)
		down(&cmd->sem);

	down(&cmd->pages_sem);

	flush_workqueue(cmd->wq);

	cmd->mode = CMD_MODE_EVENTS;

	up(&cmd->pages_sem);
	for (i = 0; i < cmd->max_reg_cmds; i++)
		up(&cmd->sem);
}

void mlx5_cmd_use_polling(struct mlx5_core_dev *dev)
{
	struct mlx5_cmd *cmd = &dev->cmd;

	synchronize_irq(dev->priv.eq_table.pages_eq.irqn);
	flush_workqueue(dev->priv.pg_wq);
	cmd->moving_to_polling = 1;
	flush_workqueue(cmd->wq);
	cmd->mode = CMD_MODE_POLLING;
	cmd->moving_to_polling = 0;
}

static void free_msg(struct mlx5_core_dev *dev, struct mlx5_cmd_msg *msg)
{
	unsigned long flags;

	if (msg->cache) {
		spin_lock_irqsave(&msg->cache->lock, flags);
		list_add_tail(&msg->list, &msg->cache->head);
		spin_unlock_irqrestore(&msg->cache->lock, flags);
	} else {
		mlx5_free_cmd_msg(dev, msg);
	}
}

void mlx5_cmd_comp_handler(struct mlx5_core_dev *dev, u32 vector)
{
	struct mlx5_cmd *cmd = &dev->cmd;
	struct mlx5_cmd_work_ent *ent;
	int i;

	/* make sure data gets read from RAM */
	mlx5_fwp_invalidate(cmd->cmd_page);

	while (vector != 0) {
		i = ffs(vector) - 1;
		vector &= ~(1U << i);
		ent = cmd->ent_arr[i];
		ent->ts2 = ktime_get_ns();
		memcpy(ent->out->first.data, ent->lay->out,
		       sizeof(ent->lay->out));
		/* make sure data gets read from RAM */
		mlx5_fwp_invalidate(ent->out);
		dump_command(dev, ent, 0);
		if (!ent->ret) {
			if (!cmd->checksum_disabled)
				ent->ret = verify_signature(ent);
			else
				ent->ret = 0;
			ent->status = ent->lay->status_own >> 1;

			mlx5_core_dbg(dev,
				      "FW command ret 0x%x, status %s(0x%x)\n",
				      ent->ret,
				      deliv_status_to_str(ent->status),
				      ent->status);
		}
		free_ent(cmd, ent->idx);
		complete_command(ent);
	}
}
EXPORT_SYMBOL(mlx5_cmd_comp_handler);

void mlx5_trigger_cmd_completions(struct mlx5_core_dev *dev)
{
	unsigned long vector;
	int i = 0;
	unsigned long flags;
	synchronize_irq(dev->priv.eq_table.cmd_eq.irqn);
	spin_lock_irqsave(&dev->cmd.alloc_lock, flags);
	vector = ~dev->cmd.bitmask & ((1ul << (1 << dev->cmd.log_sz)) - 1);
	spin_unlock_irqrestore(&dev->cmd.alloc_lock, flags);

	if (!vector)
		return;

	for (i = 0; i < (1 << dev->cmd.log_sz); i++) {
		struct mlx5_cmd_work_ent *ent = dev->cmd.ent_arr[i];

		if (!test_bit(i, &vector))
			continue;

		while (ent->busy)
			usleep_range(1000, 1100);
		free_ent(&dev->cmd, i);
		complete_command(ent);
	}
}
EXPORT_SYMBOL(mlx5_trigger_cmd_completions);

static int status_to_err(u8 status)
{
	return status ? -1 : 0; /* TBD more meaningful codes */
}

static struct mlx5_cmd_msg *alloc_msg(struct mlx5_core_dev *dev, int in_size,
				      gfp_t gfp)
{
	struct mlx5_cmd_msg *msg = ERR_PTR(-ENOMEM);
	struct mlx5_cmd *cmd = &dev->cmd;
	struct cache_ent *ent = NULL;

	if (in_size > MED_LIST_SIZE && in_size <= LONG_LIST_SIZE)
		ent = &cmd->cache.large;
	else if (in_size > 16 && in_size <= MED_LIST_SIZE)
		ent = &cmd->cache.med;

	if (ent) {
		spin_lock_irq(&ent->lock);
		if (!list_empty(&ent->head)) {
			msg = list_entry(ent->head.next, struct mlx5_cmd_msg,
					 list);
			list_del(&msg->list);
		}
		spin_unlock_irq(&ent->lock);
	}

	if (IS_ERR(msg))
		msg = mlx5_alloc_cmd_msg(dev, gfp, in_size);

	return msg;
}

static int is_manage_pages(struct mlx5_inbox_hdr *in)
{
	return be16_to_cpu(in->opcode) == MLX5_CMD_OP_MANAGE_PAGES;
}

static int cmd_exec_helper(struct mlx5_core_dev *dev,
			   void *in, int in_size,
			   void *out, int out_size,
			   mlx5_cmd_cbk_t callback, void *context)
{
	struct mlx5_cmd_msg *inb;
	struct mlx5_cmd_msg *outb;
	int pages_queue;
	const gfp_t gfp = GFP_KERNEL;
	int err;
	u8 status = 0;

	pages_queue = is_manage_pages(in);

	inb = alloc_msg(dev, in_size, gfp);
	if (IS_ERR(inb)) {
		err = PTR_ERR(inb);
		return err;
	}

	err = mlx5_copy_to_msg(inb, in, in_size);
	if (err) {
		mlx5_core_warn(dev, "err %d\n", err);
		goto out_in;
	}

	outb = mlx5_alloc_cmd_msg(dev, gfp, out_size);
	if (IS_ERR(outb)) {
		err = PTR_ERR(outb);
		goto out_in;
	}

	err = mlx5_cmd_invoke(dev, inb, in_size, outb, out, out_size, callback,
			      context, pages_queue, &status);
	if (err) {
		if (err == -ETIMEDOUT)
			return err;
		goto out_out;
	}

	mlx5_core_dbg(dev, "err %d, status %d\n", err, status);
	if (status) {
		err = status_to_err(status);
		goto out_out;
	}

	if (callback)
		return err;

	err = mlx5_copy_from_msg(out, outb, out_size);

out_out:
	mlx5_free_cmd_msg(dev, outb);

out_in:
	free_msg(dev, inb);
	return err;
}

int mlx5_cmd_exec(struct mlx5_core_dev *dev, void *in, int in_size, void *out,
		  int out_size)
{
	return cmd_exec_helper(dev, in, in_size, out, out_size, NULL, NULL);
}
EXPORT_SYMBOL(mlx5_cmd_exec);

int mlx5_cmd_exec_cb(struct mlx5_core_dev *dev, void *in, int in_size,
		     void *out, int out_size, mlx5_cmd_cbk_t callback,
		     void *context)
{
	return cmd_exec_helper(dev, in, in_size, out, out_size, callback, context);
}
EXPORT_SYMBOL(mlx5_cmd_exec_cb);

static void destroy_msg_cache(struct mlx5_core_dev *dev)
{
	struct mlx5_cmd *cmd = &dev->cmd;
	struct mlx5_cmd_msg *msg;
	struct mlx5_cmd_msg *n;

	list_for_each_entry_safe(msg, n, &cmd->cache.large.head, list) {
		list_del(&msg->list);
		mlx5_free_cmd_msg(dev, msg);
	}

	list_for_each_entry_safe(msg, n, &cmd->cache.med.head, list) {
		list_del(&msg->list);
		mlx5_free_cmd_msg(dev, msg);
	}
}

static int create_msg_cache(struct mlx5_core_dev *dev)
{
	struct mlx5_cmd *cmd = &dev->cmd;
	struct mlx5_cmd_msg *msg;
	int err;
	int i;

	spin_lock_init(&cmd->cache.large.lock);
	INIT_LIST_HEAD(&cmd->cache.large.head);
	spin_lock_init(&cmd->cache.med.lock);
	INIT_LIST_HEAD(&cmd->cache.med.head);

	for (i = 0; i < NUM_LONG_LISTS; i++) {
		msg = mlx5_alloc_cmd_msg(dev, GFP_KERNEL, LONG_LIST_SIZE);
		if (IS_ERR(msg)) {
			err = PTR_ERR(msg);
			goto ex_err;
		}
		msg->cache = &cmd->cache.large;
		list_add_tail(&msg->list, &cmd->cache.large.head);
	}

	for (i = 0; i < NUM_MED_LISTS; i++) {
		msg = mlx5_alloc_cmd_msg(dev, GFP_KERNEL, MED_LIST_SIZE);
		if (IS_ERR(msg)) {
			err = PTR_ERR(msg);
			goto ex_err;
		}
		msg->cache = &cmd->cache.med;
		list_add_tail(&msg->list, &cmd->cache.med.head);
	}

	return 0;

ex_err:
	destroy_msg_cache(dev);
	return err;
}

static int
alloc_cmd_page(struct mlx5_core_dev *dev, struct mlx5_cmd *cmd)
{
	int err;

	sx_init(&cmd->dma_sx, "MLX5-DMA-SX");
	mtx_init(&cmd->dma_mtx, "MLX5-DMA-MTX", NULL, MTX_DEF);
	cv_init(&cmd->dma_cv, "MLX5-DMA-CV");

	/*
	 * Create global DMA descriptor tag for allocating
	 * 4K firmware pages:
	 */
	err = -bus_dma_tag_create(
	    bus_get_dma_tag(dev->pdev->dev.bsddev),
	    MLX5_ADAPTER_PAGE_SIZE,	/* alignment */
	    0,				/* no boundary */
	    BUS_SPACE_MAXADDR,		/* lowaddr */
	    BUS_SPACE_MAXADDR,		/* highaddr */
	    NULL, NULL,			/* filter, filterarg */
	    MLX5_ADAPTER_PAGE_SIZE,	/* maxsize */
	    1,				/* nsegments */
	    MLX5_ADAPTER_PAGE_SIZE,	/* maxsegsize */
	    0,				/* flags */
	    NULL, NULL,			/* lockfunc, lockfuncarg */
	    &cmd->dma_tag);
	if (err != 0)
		goto failure_destroy_sx;

	cmd->cmd_page = mlx5_fwp_alloc(dev, GFP_KERNEL, 1);
	if (cmd->cmd_page == NULL) {
		err = -ENOMEM;
		goto failure_alloc_page;
	}
	cmd->dma = mlx5_fwp_get_dma(cmd->cmd_page, 0);
	cmd->cmd_buf = mlx5_fwp_get_virt(cmd->cmd_page, 0);
	return (0);

failure_alloc_page:
	bus_dma_tag_destroy(cmd->dma_tag);

failure_destroy_sx:
	cv_destroy(&cmd->dma_cv);
	mtx_destroy(&cmd->dma_mtx);
	sx_destroy(&cmd->dma_sx);
	return (err);
}

static void
free_cmd_page(struct mlx5_core_dev *dev, struct mlx5_cmd *cmd)
{

	mlx5_fwp_free(cmd->cmd_page);
	bus_dma_tag_destroy(cmd->dma_tag);
	cv_destroy(&cmd->dma_cv);
	mtx_destroy(&cmd->dma_mtx);
	sx_destroy(&cmd->dma_sx);
}

int mlx5_cmd_init(struct mlx5_core_dev *dev)
{
	struct mlx5_cmd *cmd = &dev->cmd;
	u32 cmd_h, cmd_l;
	u16 cmd_if_rev;
	int err;
	int i;

	cmd_if_rev = cmdif_rev_get(dev);
	if (cmd_if_rev != CMD_IF_REV) {
		device_printf((&dev->pdev->dev)->bsddev, "ERR: ""Driver cmdif rev(%d) differs from firmware's(%d)\n", CMD_IF_REV, cmd_if_rev);
		return -EINVAL;
	}

	err = alloc_cmd_page(dev, cmd);
	if (err)
		goto err_free_pool;

	cmd_l = ioread32be(&dev->iseg->cmdq_addr_l_sz) & 0xff;
	cmd->log_sz = cmd_l >> 4 & 0xf;
	cmd->log_stride = cmd_l & 0xf;
	if (1 << cmd->log_sz > MLX5_MAX_COMMANDS) {
		device_printf((&dev->pdev->dev)->bsddev, "ERR: ""firmware reports too many outstanding commands %d\n", 1 << cmd->log_sz);
		err = -EINVAL;
		goto err_free_page;
	}

	if (cmd->log_sz + cmd->log_stride > MLX5_ADAPTER_PAGE_SHIFT) {
		device_printf((&dev->pdev->dev)->bsddev, "ERR: ""command queue size overflow\n");
		err = -EINVAL;
		goto err_free_page;
	}

	cmd->checksum_disabled = 1;
	cmd->max_reg_cmds = (1 << cmd->log_sz) - 1;
	cmd->bitmask = (1 << cmd->max_reg_cmds) - 1;

	cmd->cmdif_rev = ioread32be(&dev->iseg->cmdif_rev_fw_sub) >> 16;
	if (cmd->cmdif_rev > CMD_IF_REV) {
		device_printf((&dev->pdev->dev)->bsddev, "ERR: ""driver does not support command interface version. driver %d, firmware %d\n", CMD_IF_REV, cmd->cmdif_rev);
		err = -ENOTSUPP;
		goto err_free_page;
	}

	spin_lock_init(&cmd->alloc_lock);
	spin_lock_init(&cmd->token_lock);
	for (i = 0; i < ARRAY_SIZE(cmd->stats); i++)
		spin_lock_init(&cmd->stats[i].lock);

	sema_init(&cmd->sem, cmd->max_reg_cmds);
	sema_init(&cmd->pages_sem, 1);

	cmd_h = (u32)((u64)(cmd->dma) >> 32);
	cmd_l = (u32)(cmd->dma);
	if (cmd_l & 0xfff) {
		device_printf((&dev->pdev->dev)->bsddev, "ERR: ""invalid command queue address\n");
		err = -ENOMEM;
		goto err_free_page;
	}

	iowrite32be(cmd_h, &dev->iseg->cmdq_addr_h);
	iowrite32be(cmd_l, &dev->iseg->cmdq_addr_l_sz);

	/* Make sure firmware sees the complete address before we proceed */
	wmb();

	mlx5_core_dbg(dev, "descriptor at dma 0x%llx\n", (unsigned long long)(cmd->dma));

	cmd->mode = CMD_MODE_POLLING;

	err = create_msg_cache(dev);
	if (err) {
		device_printf((&dev->pdev->dev)->bsddev, "ERR: ""failed to create command cache\n");
		goto err_free_page;
	}

	set_wqname(dev);
	cmd->wq = create_singlethread_workqueue(cmd->wq_name);
	if (!cmd->wq) {
		device_printf((&dev->pdev->dev)->bsddev, "ERR: ""failed to create command workqueue\n");
		err = -ENOMEM;
		goto err_cache;
	}

	return 0;

err_cache:
	destroy_msg_cache(dev);

err_free_page:
	free_cmd_page(dev, cmd);

err_free_pool:
	return err;
}
EXPORT_SYMBOL(mlx5_cmd_init);

void mlx5_cmd_cleanup(struct mlx5_core_dev *dev)
{
	struct mlx5_cmd *cmd = &dev->cmd;

	clean_debug_files(dev);
	destroy_workqueue(cmd->wq);
	destroy_msg_cache(dev);
	free_cmd_page(dev, cmd);
}
EXPORT_SYMBOL(mlx5_cmd_cleanup);

static const char *cmd_status_str(u8 status)
{
	switch (status) {
	case MLX5_CMD_STAT_OK:
		return "OK";
	case MLX5_CMD_STAT_INT_ERR:
		return "internal error";
	case MLX5_CMD_STAT_BAD_OP_ERR:
		return "bad operation";
	case MLX5_CMD_STAT_BAD_PARAM_ERR:
		return "bad parameter";
	case MLX5_CMD_STAT_BAD_SYS_STATE_ERR:
		return "bad system state";
	case MLX5_CMD_STAT_BAD_RES_ERR:
		return "bad resource";
	case MLX5_CMD_STAT_RES_BUSY:
		return "resource busy";
	case MLX5_CMD_STAT_LIM_ERR:
		return "limits exceeded";
	case MLX5_CMD_STAT_BAD_RES_STATE_ERR:
		return "bad resource state";
	case MLX5_CMD_STAT_IX_ERR:
		return "bad index";
	case MLX5_CMD_STAT_NO_RES_ERR:
		return "no resources";
	case MLX5_CMD_STAT_BAD_INP_LEN_ERR:
		return "bad input length";
	case MLX5_CMD_STAT_BAD_OUTP_LEN_ERR:
		return "bad output length";
	case MLX5_CMD_STAT_BAD_QP_STATE_ERR:
		return "bad QP state";
	case MLX5_CMD_STAT_BAD_PKT_ERR:
		return "bad packet (discarded)";
	case MLX5_CMD_STAT_BAD_SIZE_OUTS_CQES_ERR:
		return "bad size too many outstanding CQEs";
	default:
		return "unknown status";
	}
}

static int cmd_status_to_err_helper(u8 status)
{
	switch (status) {
	case MLX5_CMD_STAT_OK:				return 0;
	case MLX5_CMD_STAT_INT_ERR:			return -EIO;
	case MLX5_CMD_STAT_BAD_OP_ERR:			return -EINVAL;
	case MLX5_CMD_STAT_BAD_PARAM_ERR:		return -EINVAL;
	case MLX5_CMD_STAT_BAD_SYS_STATE_ERR:		return -EIO;
	case MLX5_CMD_STAT_BAD_RES_ERR:			return -EINVAL;
	case MLX5_CMD_STAT_RES_BUSY:			return -EBUSY;
	case MLX5_CMD_STAT_LIM_ERR:			return -ENOMEM;
	case MLX5_CMD_STAT_BAD_RES_STATE_ERR:		return -EINVAL;
	case MLX5_CMD_STAT_IX_ERR:			return -EINVAL;
	case MLX5_CMD_STAT_NO_RES_ERR:			return -EAGAIN;
	case MLX5_CMD_STAT_BAD_INP_LEN_ERR:		return -EIO;
	case MLX5_CMD_STAT_BAD_OUTP_LEN_ERR:		return -EIO;
	case MLX5_CMD_STAT_BAD_QP_STATE_ERR:		return -EINVAL;
	case MLX5_CMD_STAT_BAD_PKT_ERR:			return -EINVAL;
	case MLX5_CMD_STAT_BAD_SIZE_OUTS_CQES_ERR:	return -EINVAL;
	default:					return -EIO;
	}
}

/* this will be available till all the commands use set/get macros */
int mlx5_cmd_status_to_err(struct mlx5_outbox_hdr *hdr)
{
	if (!hdr->status)
		return 0;

	printf("mlx5_core: WARN: ""command failed, status %s(0x%x), syndrome 0x%x\n", cmd_status_str(hdr->status), hdr->status, be32_to_cpu(hdr->syndrome));

	return cmd_status_to_err_helper(hdr->status);
}

int mlx5_cmd_status_to_err_v2(void *ptr)
{
	u32	syndrome;
	u8	status;

	status = be32_to_cpu(*(__be32 *)ptr) >> 24;
	if (!status)
		return 0;

	syndrome = be32_to_cpu(*(__be32 *)(ptr + 4));

	printf("mlx5_core: WARN: ""command failed, status %s(0x%x), syndrome 0x%x\n", cmd_status_str(status), status, syndrome);

	return cmd_status_to_err_helper(status);
}

