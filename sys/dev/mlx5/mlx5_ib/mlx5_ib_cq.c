/*-
 * Copyright (c) 2013-2015, Mellanox Technologies, Ltd.  All rights reserved.
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

#include <linux/kref.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_user_verbs.h>
#include "mlx5_ib.h"
#include "user.h"

static void mlx5_ib_cq_comp(struct mlx5_core_cq *cq)
{
	struct ib_cq *ibcq = &to_mibcq(cq)->ibcq;

	ibcq->comp_handler(ibcq, ibcq->cq_context);
}

static void mlx5_ib_cq_event(struct mlx5_core_cq *mcq, int type)
{
	struct mlx5_ib_cq *cq = container_of(mcq, struct mlx5_ib_cq, mcq);
	struct mlx5_ib_dev *dev = to_mdev(cq->ibcq.device);
	struct ib_cq *ibcq = &cq->ibcq;
	struct ib_event event;

	if (type != MLX5_EVENT_TYPE_CQ_ERROR) {
		mlx5_ib_warn(dev, "Unexpected event type %d on CQ %06x\n",
			     type, mcq->cqn);
		return;
	}

	if (ibcq->event_handler) {
		event.device     = &dev->ib_dev;
		event.event      = IB_EVENT_CQ_ERR;
		event.element.cq = ibcq;
		ibcq->event_handler(&event, ibcq->cq_context);
	}
}

static void *get_cqe_from_buf(struct mlx5_ib_cq_buf *buf, int n, int size)
{
	return mlx5_buf_offset(&buf->buf, n * size);
}

static void *get_cqe(struct mlx5_ib_cq *cq, int n)
{
	return get_cqe_from_buf(&cq->buf, n, cq->mcq.cqe_sz);
}

static u8 sw_ownership_bit(int n, int nent)
{
	return (n & nent) ? 1 : 0;
}

static void *get_sw_cqe(struct mlx5_ib_cq *cq, int n)
{
	void *cqe = get_cqe(cq, n & cq->ibcq.cqe);
	struct mlx5_cqe64 *cqe64;

	cqe64 = (cq->mcq.cqe_sz == 64) ? cqe : cqe + 64;

	if (likely((cqe64->op_own) >> 4 != MLX5_CQE_INVALID) &&
	    !((cqe64->op_own & MLX5_CQE_OWNER_MASK) ^ !!(n & (cq->ibcq.cqe + 1)))) {
		return cqe;
	} else {
		return NULL;
	}
}

static void *next_cqe_sw(struct mlx5_ib_cq *cq)
{
	return get_sw_cqe(cq, cq->mcq.cons_index);
}

static enum ib_wc_opcode get_umr_comp(struct mlx5_ib_wq *wq, int idx)
{
	switch (wq->swr_ctx[idx].wr_data) {
	case IB_WR_LOCAL_INV:
		return IB_WC_LOCAL_INV;

	case IB_WR_FAST_REG_MR:
		return IB_WC_FAST_REG_MR;

	default:
		printf("mlx5_ib: WARN: ""unknown completion status\n");
		return 0;
	}
}

static void handle_good_req(struct ib_wc *wc, struct mlx5_cqe64 *cqe,
			    struct mlx5_ib_wq *wq, int idx)
{
	wc->wc_flags = 0;
	switch (be32_to_cpu(cqe->sop_drop_qpn) >> 24) {
	case MLX5_OPCODE_RDMA_WRITE_IMM:
		wc->wc_flags |= IB_WC_WITH_IMM;
	case MLX5_OPCODE_RDMA_WRITE:
		wc->opcode    = IB_WC_RDMA_WRITE;
		break;
	case MLX5_OPCODE_SEND_IMM:
		wc->wc_flags |= IB_WC_WITH_IMM;
	case MLX5_OPCODE_NOP:
	case MLX5_OPCODE_SEND:
	case MLX5_OPCODE_SEND_INVAL:
		wc->opcode    = IB_WC_SEND;
		break;
	case MLX5_OPCODE_RDMA_READ:
		wc->opcode    = IB_WC_RDMA_READ;
		wc->byte_len  = be32_to_cpu(cqe->byte_cnt);
		break;
	case MLX5_OPCODE_ATOMIC_CS:
		wc->opcode    = IB_WC_COMP_SWAP;
		wc->byte_len  = 8;
		break;
	case MLX5_OPCODE_ATOMIC_FA:
		wc->opcode    = IB_WC_FETCH_ADD;
		wc->byte_len  = 8;
		break;
	case MLX5_OPCODE_ATOMIC_MASKED_CS:
		wc->opcode    = IB_WC_MASKED_COMP_SWAP;
		wc->byte_len  = 8;
		break;
	case MLX5_OPCODE_ATOMIC_MASKED_FA:
		wc->opcode    = IB_WC_MASKED_FETCH_ADD;
		wc->byte_len  = 8;
		break;
	case MLX5_OPCODE_BIND_MW:
		wc->opcode    = IB_WC_BIND_MW;
		break;
	case MLX5_OPCODE_UMR:
		wc->opcode = get_umr_comp(wq, idx);
		break;
	}
}

enum {
	MLX5_GRH_IN_BUFFER = 1,
	MLX5_GRH_IN_CQE	   = 2,
};

static void handle_responder(struct ib_wc *wc, struct mlx5_cqe64 *cqe,
			     struct mlx5_ib_qp *qp)
{
	struct mlx5_ib_dev *dev = to_mdev(qp->ibqp.device);
	struct mlx5_ib_srq *srq;
	struct mlx5_ib_wq *wq;
	u16 wqe_ctr;
	u8 g;
#if defined(DX_ROCE_V1_5) || defined(DX_WINDOWS)
	u8 udp_header_valid;
#endif

	if (qp->ibqp.srq || qp->ibqp.xrcd) {
		struct mlx5_core_srq *msrq = NULL;

		if (qp->ibqp.xrcd) {
			msrq = mlx5_core_get_srq(dev->mdev,
						 be32_to_cpu(cqe->srqn));
			srq = to_mibsrq(msrq);
		} else {
			srq = to_msrq(qp->ibqp.srq);
		}
		if (srq) {
			wqe_ctr = be16_to_cpu(cqe->wqe_counter);
			wc->wr_id = srq->wrid[wqe_ctr];
			mlx5_ib_free_srq_wqe(srq, wqe_ctr);
			if (msrq && atomic_dec_and_test(&msrq->refcount))
				complete(&msrq->free);
		}
	} else {
		wq	  = &qp->rq;
		wc->wr_id = wq->rwr_ctx[wq->tail & (wq->wqe_cnt - 1)].wrid;
		++wq->tail;
	}
	wc->byte_len = be32_to_cpu(cqe->byte_cnt);

	switch (cqe->op_own >> 4) {
	case MLX5_CQE_RESP_WR_IMM:
		wc->opcode	= IB_WC_RECV_RDMA_WITH_IMM;
		wc->wc_flags	= IB_WC_WITH_IMM;
		wc->ex.imm_data = cqe->imm_inval_pkey;
		break;
	case MLX5_CQE_RESP_SEND:
		wc->opcode   = IB_WC_RECV;
		wc->wc_flags = 0;
		break;
	case MLX5_CQE_RESP_SEND_IMM:
		wc->opcode	= IB_WC_RECV;
		wc->wc_flags	= IB_WC_WITH_IMM;
		wc->ex.imm_data = cqe->imm_inval_pkey;
		break;
	case MLX5_CQE_RESP_SEND_INV:
		wc->opcode	= IB_WC_RECV;
		wc->wc_flags	= IB_WC_WITH_INVALIDATE;
		wc->ex.invalidate_rkey = be32_to_cpu(cqe->imm_inval_pkey);
		break;
	}
	wc->slid	   = be16_to_cpu(cqe->slid);
	wc->sl		   = (be32_to_cpu(cqe->flags_rqpn) >> 24) & 0xf;
	wc->src_qp	   = be32_to_cpu(cqe->flags_rqpn) & 0xffffff;
	wc->dlid_path_bits = cqe->ml_path;
	g = (be32_to_cpu(cqe->flags_rqpn) >> 28) & 3;
	wc->wc_flags |= g ? IB_WC_GRH : 0;
	wc->pkey_index     = be32_to_cpu(cqe->imm_inval_pkey) & 0xffff;

#if defined(DX_ROCE_V1_5) || defined(DX_WINDOWS)
	udp_header_valid = wc->sl & 0x8;
	if (udp_header_valid)
		wc->wc_flags |= IB_WC_WITH_UDP_HDR;

#endif
}

static void dump_cqe(struct mlx5_ib_dev *dev, struct mlx5_err_cqe *cqe)
{
	__be32 *p = (__be32 *)cqe;
	int i;

	mlx5_ib_warn(dev, "dump error cqe\n");
	for (i = 0; i < sizeof(*cqe) / 16; i++, p += 4)
		printf("mlx5_ib: INFO: ""%08x %08x %08x %08x\n", be32_to_cpu(p[0]), be32_to_cpu(p[1]), be32_to_cpu(p[2]), be32_to_cpu(p[3]));
}

static void mlx5_handle_error_cqe(struct mlx5_ib_dev *dev,
				  struct mlx5_err_cqe *cqe,
				  struct ib_wc *wc)
{
	int dump = 1;

	switch (cqe->syndrome) {
	case MLX5_CQE_SYNDROME_LOCAL_LENGTH_ERR:
		wc->status = IB_WC_LOC_LEN_ERR;
		break;
	case MLX5_CQE_SYNDROME_LOCAL_QP_OP_ERR:
		wc->status = IB_WC_LOC_QP_OP_ERR;
		break;
	case MLX5_CQE_SYNDROME_LOCAL_PROT_ERR:
		wc->status = IB_WC_LOC_PROT_ERR;
		break;
	case MLX5_CQE_SYNDROME_WR_FLUSH_ERR:
		dump = 0;
		wc->status = IB_WC_WR_FLUSH_ERR;
		break;
	case MLX5_CQE_SYNDROME_MW_BIND_ERR:
		wc->status = IB_WC_MW_BIND_ERR;
		break;
	case MLX5_CQE_SYNDROME_BAD_RESP_ERR:
		wc->status = IB_WC_BAD_RESP_ERR;
		break;
	case MLX5_CQE_SYNDROME_LOCAL_ACCESS_ERR:
		wc->status = IB_WC_LOC_ACCESS_ERR;
		break;
	case MLX5_CQE_SYNDROME_REMOTE_INVAL_REQ_ERR:
		wc->status = IB_WC_REM_INV_REQ_ERR;
		break;
	case MLX5_CQE_SYNDROME_REMOTE_ACCESS_ERR:
		wc->status = IB_WC_REM_ACCESS_ERR;
		break;
	case MLX5_CQE_SYNDROME_REMOTE_OP_ERR:
		wc->status = IB_WC_REM_OP_ERR;
		break;
	case MLX5_CQE_SYNDROME_TRANSPORT_RETRY_EXC_ERR:
		wc->status = IB_WC_RETRY_EXC_ERR;
		dump = 0;
		break;
	case MLX5_CQE_SYNDROME_RNR_RETRY_EXC_ERR:
		wc->status = IB_WC_RNR_RETRY_EXC_ERR;
		dump = 0;
		break;
	case MLX5_CQE_SYNDROME_REMOTE_ABORTED_ERR:
		wc->status = IB_WC_REM_ABORT_ERR;
		break;
	default:
		wc->status = IB_WC_GENERAL_ERR;
		break;
	}

	wc->vendor_err = cqe->vendor_err_synd;
	if (dump)
		dump_cqe(dev, cqe);
}

static int is_atomic_response(struct mlx5_ib_qp *qp, u16 idx)
{
	/* TBD: waiting decision
	*/
	return 0;
}

static void *mlx5_get_atomic_laddr(struct mlx5_ib_qp *qp, u16 idx)
{
	struct mlx5_wqe_data_seg *dpseg;
	void *addr;

	dpseg = mlx5_get_send_wqe(qp, idx) + sizeof(struct mlx5_wqe_ctrl_seg) +
		sizeof(struct mlx5_wqe_raddr_seg) +
		sizeof(struct mlx5_wqe_atomic_seg);
	addr = (void *)(uintptr_t)be64_to_cpu(dpseg->addr);
	return addr;
}

static void handle_atomic(struct mlx5_ib_qp *qp, struct mlx5_cqe64 *cqe64,
			  u16 idx)
{
	void *addr;
	int byte_count;
	int i;

	if (!is_atomic_response(qp, idx))
		return;

	byte_count = be32_to_cpu(cqe64->byte_cnt);
	addr = mlx5_get_atomic_laddr(qp, idx);

	if (byte_count == 4) {
		*(u32 *)addr = be32_to_cpu(*((__be32 *)addr));
	} else {
		for (i = 0; i < byte_count; i += 8) {
			*(u64 *)addr = be64_to_cpu(*((__be64 *)addr));
			addr += 8;
		}
	}

	return;
}

static void handle_atomics(struct mlx5_ib_qp *qp, struct mlx5_cqe64 *cqe64,
			   u16 tail, u16 head)
{
	u16 idx;

	do {
		idx = tail & (qp->sq.wqe_cnt - 1);
		handle_atomic(qp, cqe64, idx);
		if (idx == head)
			break;

		tail = qp->sq.swr_ctx[idx].w_list.next;
	} while (1);
	tail = qp->sq.swr_ctx[idx].w_list.next;
	qp->sq.last_poll = tail;
}

static void free_cq_buf(struct mlx5_ib_dev *dev, struct mlx5_ib_cq_buf *buf)
{
	mlx5_buf_free(dev->mdev, &buf->buf);
}

static void sw_send_comp(struct mlx5_ib_qp *qp, int num_entries,
			 struct ib_wc *wc, int *npolled)
{
	struct mlx5_ib_wq *wq;
	unsigned cur;
	unsigned idx;
	int np;
	int i;

	wq = &qp->sq;
	cur = wq->head - wq->tail;
	np = *npolled;

	if (cur == 0)
		return;

	for (i = 0;  i < cur && np < num_entries; i++) {
		idx = wq->last_poll & (wq->wqe_cnt - 1);
		wc->wr_id = wq->swr_ctx[idx].wrid;
		wc->status = IB_WC_WR_FLUSH_ERR;
		wc->vendor_err = MLX5_CQE_SYNDROME_WR_FLUSH_ERR;
		wq->tail++;
		np++;
		wc->qp = &qp->ibqp;
		wc++;
		wq->last_poll = wq->swr_ctx[idx].w_list.next;
	}
	*npolled = np;
}

static void sw_recv_comp(struct mlx5_ib_qp *qp, int num_entries,
			 struct ib_wc *wc, int *npolled)
{
	struct mlx5_ib_wq *wq;
	unsigned cur;
	int np;
	int i;

	wq = &qp->rq;
	cur = wq->head - wq->tail;
	np = *npolled;

	if (cur == 0)
		return;

	for (i = 0;  i < cur && np < num_entries; i++) {
		wc->wr_id = wq->rwr_ctx[wq->tail & (wq->wqe_cnt - 1)].wrid;
		wc->status = IB_WC_WR_FLUSH_ERR;
		wc->vendor_err = MLX5_CQE_SYNDROME_WR_FLUSH_ERR;
		wq->tail++;
		np++;
		wc->qp = &qp->ibqp;
		wc++;
	}
	*npolled = np;
}

static void mlx5_ib_poll_sw_comp(struct mlx5_ib_cq *cq, int num_entries,
				 struct ib_wc *wc, int *npolled)
{
	struct mlx5_ib_qp *qp;

	*npolled = 0;
	/* Find uncompleted WQEs belonging to that cq and retrun mmics ones */
	list_for_each_entry(qp, &cq->list_send_qp, cq_send_list) {
		sw_send_comp(qp, num_entries, wc + *npolled, npolled);
		if (*npolled >= num_entries)
			return;
	}

	list_for_each_entry(qp, &cq->list_recv_qp, cq_recv_list) {
		sw_recv_comp(qp, num_entries, wc + *npolled, npolled);
		if (*npolled >= num_entries)
			return;
	}
}

static inline u32 mlx5_ib_base_mkey(const u32 key)
{
	return key & 0xffffff00u;
}

static int mlx5_poll_one(struct mlx5_ib_cq *cq,
			 struct mlx5_ib_qp **cur_qp,
			 struct ib_wc *wc)
{
	struct mlx5_ib_dev *dev = to_mdev(cq->ibcq.device);
	struct mlx5_err_cqe *err_cqe;
	struct mlx5_cqe64 *cqe64;
	struct mlx5_core_qp *mqp;
	struct mlx5_ib_wq *wq;
	struct mlx5_sig_err_cqe *sig_err_cqe;
	struct mlx5_core_mr *mmr;
	struct mlx5_ib_mr *mr;
	unsigned long flags;
	u8 opcode;
	u32 qpn;
	u16 wqe_ctr;
	void *cqe;
	int idx;

repoll:
	cqe = next_cqe_sw(cq);
	if (!cqe)
		return -EAGAIN;

	cqe64 = (cq->mcq.cqe_sz == 64) ? cqe : cqe + 64;

	++cq->mcq.cons_index;

	/* Make sure we read CQ entry contents after we've checked the
	 * ownership bit.
	 */
	rmb();

	opcode = cqe64->op_own >> 4;
	if (unlikely(opcode == MLX5_CQE_RESIZE_CQ)) {
		if (likely(cq->resize_buf)) {
			free_cq_buf(dev, &cq->buf);
			cq->buf = *cq->resize_buf;
			kfree(cq->resize_buf);
			cq->resize_buf = NULL;
			goto repoll;
		} else {
			mlx5_ib_warn(dev, "unexpected resize cqe\n");
		}
	}

	qpn = ntohl(cqe64->sop_drop_qpn) & 0xffffff;
	if (!*cur_qp || (qpn != (*cur_qp)->ibqp.qp_num)) {
		/* We do not have to take the QP table lock here,
		 * because CQs will be locked while QPs are removed
		 * from the table.
		 */
		mqp = __mlx5_qp_lookup(dev->mdev, qpn);
		if (unlikely(!mqp)) {
			mlx5_ib_warn(dev, "CQE@CQ %06x for unknown QPN %6x\n",
				     cq->mcq.cqn, qpn);
			return -EINVAL;
		}

		*cur_qp = to_mibqp(mqp);
	}

	wc->qp  = &(*cur_qp)->ibqp;
	switch (opcode) {
	case MLX5_CQE_REQ:
		wq = &(*cur_qp)->sq;
		wqe_ctr = be16_to_cpu(cqe64->wqe_counter);
		idx = wqe_ctr & (wq->wqe_cnt - 1);
		handle_good_req(wc, cqe64, wq, idx);
		handle_atomics(*cur_qp, cqe64, wq->last_poll, idx);
		wc->wr_id = wq->swr_ctx[idx].wrid;
		wq->tail = wq->swr_ctx[idx].wqe_head + 1;
		if (unlikely(wq->swr_ctx[idx].w_list.opcode &
		    MLX5_OPCODE_SIGNATURE_CANCELED))
			wc->status = IB_WC_GENERAL_ERR;
		else
			wc->status = IB_WC_SUCCESS;
		break;
	case MLX5_CQE_RESP_WR_IMM:
	case MLX5_CQE_RESP_SEND:
	case MLX5_CQE_RESP_SEND_IMM:
	case MLX5_CQE_RESP_SEND_INV:
		handle_responder(wc, cqe64, *cur_qp);
		wc->status = IB_WC_SUCCESS;
		break;
	case MLX5_CQE_RESIZE_CQ:
		break;
	case MLX5_CQE_REQ_ERR:
	case MLX5_CQE_RESP_ERR:
		err_cqe = (struct mlx5_err_cqe *)cqe64;
		mlx5_handle_error_cqe(dev, err_cqe, wc);
		mlx5_ib_dbg(dev, "%s error cqe on cqn 0x%x:\n",
			    opcode == MLX5_CQE_REQ_ERR ?
			    "Requestor" : "Responder", cq->mcq.cqn);
		mlx5_ib_dbg(dev, "syndrome 0x%x, vendor syndrome 0x%x\n",
			    err_cqe->syndrome, err_cqe->vendor_err_synd);
		if (opcode == MLX5_CQE_REQ_ERR) {
			wq = &(*cur_qp)->sq;
			wqe_ctr = be16_to_cpu(cqe64->wqe_counter);
			idx = wqe_ctr & (wq->wqe_cnt - 1);
			wc->wr_id = wq->swr_ctx[idx].wrid;
			wq->tail = wq->swr_ctx[idx].wqe_head + 1;
		} else {
			struct mlx5_ib_srq *srq;

			if ((*cur_qp)->ibqp.srq) {
				srq = to_msrq((*cur_qp)->ibqp.srq);
				wqe_ctr = be16_to_cpu(cqe64->wqe_counter);
				wc->wr_id = srq->wrid[wqe_ctr];
				mlx5_ib_free_srq_wqe(srq, wqe_ctr);
			} else {
				wq = &(*cur_qp)->rq;
				wc->wr_id = wq->rwr_ctx[wq->tail & (wq->wqe_cnt - 1)].wrid;
				++wq->tail;
			}
		}
		break;
	case MLX5_CQE_SIG_ERR:
		sig_err_cqe = (struct mlx5_sig_err_cqe *)cqe64;

		spin_lock_irqsave(&dev->mdev->priv.mr_table.lock, flags);
		mmr = __mlx5_mr_lookup(dev->mdev,
					 mlx5_ib_base_mkey(be32_to_cpu(sig_err_cqe->mkey)));
		if (unlikely(!mmr)) {
			spin_unlock_irqrestore(&dev->mdev->priv.mr_table.lock, flags);
			mlx5_ib_warn(dev, "CQE@CQ %06x for unknown MR %6x\n",
				     cq->mcq.cqn, be32_to_cpu(sig_err_cqe->mkey));
			return -EINVAL;
		}

		mr = to_mibmr(mmr);
		mr->sig->sig_err_exists = true;
		mr->sig->sigerr_count++;

		mlx5_ib_warn(dev, "CQN: 0x%x Got SIGERR\n", cq->mcq.cqn);

		spin_unlock_irqrestore(&dev->mdev->priv.mr_table.lock, flags);
		goto repoll;
	}

	return 0;
}

int mlx5_ib_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *wc)
{
	struct mlx5_ib_cq *cq = to_mcq(ibcq);
	struct mlx5_ib_qp *cur_qp = NULL;
	struct mlx5_ib_dev *dev = to_mdev(cq->ibcq.device);
	struct mlx5_core_dev *mdev = dev->mdev;
	unsigned long flags;
	int npolled;
	int err = 0;

	spin_lock_irqsave(&cq->lock, flags);
	if (mdev->state == MLX5_DEVICE_STATE_INTERNAL_ERROR) {
		mlx5_ib_poll_sw_comp(cq, num_entries, wc, &npolled);
		goto out;
	}

	for (npolled = 0; npolled < num_entries; npolled++) {
		err = mlx5_poll_one(cq, &cur_qp, wc + npolled);
		if (err)
			break;
	}

	if (npolled)
		mlx5_cq_set_ci(&cq->mcq);
out:
	spin_unlock_irqrestore(&cq->lock, flags);

	if (err == 0 || err == -EAGAIN)
		return npolled;
	else
		return err;
}

int mlx5_ib_arm_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags flags)
{
	struct mlx5_core_dev *mdev = to_mdev(ibcq->device)->mdev;
	void __iomem *uar_page = mdev->priv.uuari.uars[0].map;


	mlx5_cq_arm(&to_mcq(ibcq)->mcq,
		    (flags & IB_CQ_SOLICITED_MASK) == IB_CQ_SOLICITED ?
		    MLX5_CQ_DB_REQ_NOT_SOL : MLX5_CQ_DB_REQ_NOT,
		    uar_page,
		    MLX5_GET_DOORBELL_LOCK(&mdev->priv.cq_uar_lock),
		    to_mcq(ibcq)->mcq.cons_index);

	return 0;
}

static int alloc_cq_buf(struct mlx5_ib_dev *dev, struct mlx5_ib_cq_buf *buf,
			int nent, int cqe_size)
{
	int err;

	err = mlx5_buf_alloc(dev->mdev, nent * cqe_size,
			     PAGE_SIZE * 2, &buf->buf);
	if (err) {
		mlx5_ib_err(dev, "alloc failed\n");
		return err;
	}

	buf->cqe_size = cqe_size;
	buf->nent = nent;

	return 0;
}

static int create_cq_user(struct mlx5_ib_dev *dev, struct ib_udata *udata,
			  struct ib_ucontext *context, struct mlx5_ib_cq *cq,
			  int entries, struct mlx5_create_cq_mbox_in **cqb,
			  int *cqe_size, int *index, int *inlen)
{
	struct mlx5_exp_ib_create_cq ucmd;
	size_t ucmdlen;
	int page_shift;
	int npages;
	int ncont;
	int err;

	memset(&ucmd, 0, sizeof(ucmd));

	ucmdlen =
		(udata->inlen - sizeof(struct ib_uverbs_cmd_hdr) <
		sizeof(struct mlx5_ib_create_cq)) ?
		(sizeof(struct mlx5_ib_create_cq) - sizeof(ucmd.reserved)) :
		sizeof(struct mlx5_ib_create_cq);

	if (ib_copy_from_udata(&ucmd, udata, ucmdlen)) {
		mlx5_ib_err(dev, "copy failed\n");
		return -EFAULT;
	}

	if (ucmdlen == sizeof(ucmd) && ucmd.reserved != 0) {
		mlx5_ib_err(dev, "command corrupted\n");
		return -EINVAL;
	}

	if (ucmd.cqe_size != 64 && ucmd.cqe_size != 128) {
		mlx5_ib_warn(dev, "wrong CQE size %d\n", ucmd.cqe_size);
		return -EINVAL;
	}

	*cqe_size = ucmd.cqe_size;

	cq->buf.umem = ib_umem_get(context, ucmd.buf_addr,
				   entries * ucmd.cqe_size,
				   IB_ACCESS_LOCAL_WRITE, 1);
	if (IS_ERR(cq->buf.umem)) {
		err = PTR_ERR(cq->buf.umem);
		return err;
	}

	err = mlx5_ib_db_map_user(to_mucontext(context), ucmd.db_addr,
				  &cq->db);
	if (err) {
		mlx5_ib_warn(dev, "map failed\n");
		goto err_umem;
	}

	mlx5_ib_cont_pages(cq->buf.umem, ucmd.buf_addr, &npages, &page_shift,
			   &ncont, NULL);
	mlx5_ib_dbg(dev, "addr 0x%llx, size %u, npages %d, page_shift %d, ncont %d\n",
		    (unsigned long long)ucmd.buf_addr, entries * ucmd.cqe_size,
		    npages, page_shift, ncont);

	*inlen = sizeof(**cqb) + sizeof(*(*cqb)->pas) * ncont;
	*cqb = mlx5_vzalloc(*inlen);
	if (!*cqb) {
		err = -ENOMEM;
		goto err_db;
	}

	mlx5_ib_populate_pas(dev, cq->buf.umem, page_shift, (*cqb)->pas, 0);
	(*cqb)->ctx.log_pg_sz = page_shift - MLX5_ADAPTER_PAGE_SHIFT;

	*index = to_mucontext(context)->uuari.uars[0].index;

	if (*cqe_size == 64 && MLX5_CAP_GEN(dev->mdev, cqe_compression)) {
		if (ucmd.exp_data.cqe_comp_en == 1 &&
		    (ucmd.exp_data.comp_mask & MLX5_EXP_CREATE_CQ_MASK_CQE_COMP_EN)) {
			MLX5_SET(cqc, &(*cqb)->ctx, cqe_compression_en, 1);
			if (ucmd.exp_data.cqe_comp_recv_type ==
			    MLX5_IB_CQE_FORMAT_CSUM &&
			    (ucmd.exp_data.comp_mask &
			    MLX5_EXP_CREATE_CQ_MASK_CQE_COMP_RECV_TYPE))
				MLX5_SET(cqc, &(*cqb)->ctx, mini_cqe_res_format,
					 MLX5_IB_CQE_FORMAT_CSUM);
		}
	}

	return 0;

err_db:
	mlx5_ib_db_unmap_user(to_mucontext(context), &cq->db);

err_umem:
	ib_umem_release(cq->buf.umem);
	return err;
}

static void destroy_cq_user(struct mlx5_ib_cq *cq, struct ib_ucontext *context)
{

	mlx5_ib_db_unmap_user(to_mucontext(context), &cq->db);
	ib_umem_release(cq->buf.umem);
}

static void init_cq_buf(struct mlx5_ib_cq *cq, struct mlx5_ib_cq_buf *buf)
{
	int i;
	void *cqe;
	struct mlx5_cqe64 *cqe64;

	for (i = 0; i < buf->nent; i++) {
		cqe = get_cqe_from_buf(buf, i, buf->cqe_size);
		cqe64 = buf->cqe_size == 64 ? cqe : cqe + 64;
		cqe64->op_own = MLX5_CQE_INVALID << 4;
	}
}

static int create_cq_kernel(struct mlx5_ib_dev *dev, struct mlx5_ib_cq *cq,
			    int entries, int cqe_size,
			    struct mlx5_create_cq_mbox_in **cqb,
			    int *index, int *inlen)
{
	int err;

	err = mlx5_db_alloc(dev->mdev, &cq->db);
	if (err)
		return err;

	cq->mcq.set_ci_db  = cq->db.db;
	cq->mcq.arm_db     = cq->db.db + 1;
	cq->mcq.cqe_sz = cqe_size;

	err = alloc_cq_buf(dev, &cq->buf, entries, cqe_size);
	if (err)
		goto err_db;

	init_cq_buf(cq, &cq->buf);

	*inlen = sizeof(**cqb) + sizeof(*(*cqb)->pas) * cq->buf.buf.npages;
	*cqb = mlx5_vzalloc(*inlen);
	if (!*cqb) {
		err = -ENOMEM;
		goto err_buf;
	}
	mlx5_fill_page_array(&cq->buf.buf, (*cqb)->pas);

	(*cqb)->ctx.log_pg_sz = cq->buf.buf.page_shift - MLX5_ADAPTER_PAGE_SHIFT;
	*index = dev->mdev->priv.uuari.uars[0].index;

	return 0;

err_buf:
	free_cq_buf(dev, &cq->buf);

err_db:
	mlx5_db_free(dev->mdev, &cq->db);
	return err;
}

static void destroy_cq_kernel(struct mlx5_ib_dev *dev, struct mlx5_ib_cq *cq)
{
	free_cq_buf(dev, &cq->buf);
	mlx5_db_free(dev->mdev, &cq->db);
}

struct ib_cq *mlx5_ib_create_cq(struct ib_device *ibdev,
				struct ib_cq_init_attr *attr,
				struct ib_ucontext *context,
				struct ib_udata *udata)
{
	struct mlx5_create_cq_mbox_in *cqb = NULL;
	struct mlx5_ib_dev *dev = to_mdev(ibdev);
	struct mlx5_ib_cq *cq;
	int entries = attr->cqe;
	int vector = attr->comp_vector;
	int uninitialized_var(index);
	int uninitialized_var(inlen);
	int cqe_size;
	int irqn;
	int eqn;
	int err;

	if (entries < 0 || roundup_pow_of_two(entries + 1) >
	    (1 << MLX5_CAP_GEN(dev->mdev, log_max_cq_sz))) {
		mlx5_ib_warn(dev, "wrong entries number %d(%ld), max %d\n",
			     entries, roundup_pow_of_two(entries + 1),
			     1 << MLX5_CAP_GEN(dev->mdev, log_max_cq_sz));
		return ERR_PTR(-EINVAL);
	}

	entries = roundup_pow_of_two(entries + 1);

	cq = kzalloc(sizeof(*cq), GFP_KERNEL);
	if (!cq)
		return ERR_PTR(-ENOMEM);

	cq->ibcq.cqe = entries - 1;
	mutex_init(&cq->resize_mutex);
	spin_lock_init(&cq->lock);
	cq->resize_buf = NULL;
	cq->resize_umem = NULL;

	INIT_LIST_HEAD(&cq->list_send_qp);
	INIT_LIST_HEAD(&cq->list_recv_qp);

	if (context) {
		err = create_cq_user(dev, udata, context, cq, entries,
				     &cqb, &cqe_size, &index, &inlen);
		if (err)
			goto err_create;
	} else {
		cqe_size = (cache_line_size() >= 128 ? 128 : 64);
		err = create_cq_kernel(dev, cq, entries, cqe_size, &cqb,
				       &index, &inlen);
		if (err)
			goto err_create;
	}

	cq->cqe_size = cqe_size;
	cqb->ctx.cqe_sz_flags = cqe_sz_to_mlx_sz(cqe_size) << 5;
	cqb->ctx.log_sz_usr_page = cpu_to_be32((ilog2(entries) << 24) | index);
	err = mlx5_vector2eqn(dev->mdev, vector, &eqn, &irqn);
	if (err)
		goto err_cqb;

	cqb->ctx.c_eqn = cpu_to_be16(eqn);
	cqb->ctx.db_record_addr = cpu_to_be64(cq->db.dma);

	err = mlx5_core_create_cq(dev->mdev, &cq->mcq, cqb, inlen);
	if (err)
		goto err_cqb;

	mlx5_ib_dbg(dev, "cqn 0x%x\n", cq->mcq.cqn);
	cq->mcq.irqn = irqn;
	cq->mcq.comp  = mlx5_ib_cq_comp;
	cq->mcq.event = mlx5_ib_cq_event;

	if (context)
		if (ib_copy_to_udata(udata, &cq->mcq.cqn, sizeof(__u32))) {
			err = -EFAULT;
			goto err_cmd;
		}


	kvfree(cqb);
	return &cq->ibcq;

err_cmd:
	mlx5_core_destroy_cq(dev->mdev, &cq->mcq);

err_cqb:
	kvfree(cqb);
	if (context)
		destroy_cq_user(cq, context);
	else
		destroy_cq_kernel(dev, cq);

err_create:
	kfree(cq);

	return ERR_PTR(err);
}


int mlx5_ib_destroy_cq(struct ib_cq *cq)
{
	struct mlx5_ib_dev *dev = to_mdev(cq->device);
	struct mlx5_ib_cq *mcq = to_mcq(cq);
	struct ib_ucontext *context = NULL;

	if (cq->uobject)
		context = cq->uobject->context;

	mlx5_core_destroy_cq(dev->mdev, &mcq->mcq);
	if (context)
		destroy_cq_user(mcq, context);
	else
		destroy_cq_kernel(dev, mcq);

	kfree(mcq);

	return 0;
}

static int is_equal_rsn(struct mlx5_cqe64 *cqe64, u32 rsn)
{
	return rsn == (ntohl(cqe64->sop_drop_qpn) & 0xffffff);
}

void __mlx5_ib_cq_clean(struct mlx5_ib_cq *cq, u32 rsn, struct mlx5_ib_srq *srq)
{
	struct mlx5_cqe64 *cqe64, *dest64;
	void *cqe, *dest;
	u32 prod_index;
	int nfreed = 0;
	u8 owner_bit;

	if (!cq)
		return;

	/* First we need to find the current producer index, so we
	 * know where to start cleaning from.  It doesn't matter if HW
	 * adds new entries after this loop -- the QP we're worried
	 * about is already in RESET, so the new entries won't come
	 * from our QP and therefore don't need to be checked.
	 */
	for (prod_index = cq->mcq.cons_index; get_sw_cqe(cq, prod_index); prod_index++)
		if (prod_index == cq->mcq.cons_index + cq->ibcq.cqe)
			break;

	/* Now sweep backwards through the CQ, removing CQ entries
	 * that match our QP by copying older entries on top of them.
	 */
	while ((int) --prod_index - (int) cq->mcq.cons_index >= 0) {
		cqe = get_cqe(cq, prod_index & cq->ibcq.cqe);
		cqe64 = (cq->mcq.cqe_sz == 64) ? cqe : cqe + 64;
		if (is_equal_rsn(cqe64, rsn)) {
			if (srq && (ntohl(cqe64->srqn) & 0xffffff))
				mlx5_ib_free_srq_wqe(srq, be16_to_cpu(cqe64->wqe_counter));
			++nfreed;
		} else if (nfreed) {
			dest = get_cqe(cq, (prod_index + nfreed) & cq->ibcq.cqe);
			dest64 = (cq->mcq.cqe_sz == 64) ? dest : dest + 64;
			owner_bit = dest64->op_own & MLX5_CQE_OWNER_MASK;
			memcpy(dest, cqe, cq->mcq.cqe_sz);
			dest64->op_own = owner_bit |
				(dest64->op_own & ~MLX5_CQE_OWNER_MASK);
		}
	}

	if (nfreed) {
		cq->mcq.cons_index += nfreed;
		/* Make sure update of buffer contents is done before
		 * updating consumer index.
		 */
		wmb();
		mlx5_cq_set_ci(&cq->mcq);
	}
}

void mlx5_ib_cq_clean(struct mlx5_ib_cq *cq, u32 qpn, struct mlx5_ib_srq *srq)
{
	if (!cq)
		return;

	spin_lock_irq(&cq->lock);
	__mlx5_ib_cq_clean(cq, qpn, srq);
	spin_unlock_irq(&cq->lock);
}

int mlx5_ib_modify_cq(struct ib_cq *cq, struct ib_cq_attr *attr, int cq_attr_mask)
{
	struct mlx5_modify_cq_mbox_in *in;
	struct mlx5_ib_dev *dev = to_mdev(cq->device);
	struct mlx5_ib_cq *mcq = to_mcq(cq);
	u16 cq_count = attr->moderation.cq_count;
	u16 cq_period = attr->moderation.cq_period;

	int err;
	u32 fsel = 0;

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	in->cqn = cpu_to_be32(mcq->mcq.cqn);
	if (cq_attr_mask & IB_CQ_MODERATION) {
		if (MLX5_CAP_GEN(dev->mdev, cq_moderation)) {
			fsel |= (MLX5_CQ_MODIFY_PERIOD | MLX5_CQ_MODIFY_COUNT);
			if (cq_period & 0xf000) {
				/* A value higher than 0xfff is required, better
				 * use the largest value possible. */
				cq_period = 0xfff;
				printf("mlx5_ib: INFO: ""period supported is limited to 12 bits\n");
			}

			in->ctx.cq_period = cpu_to_be16(cq_period);
			in->ctx.cq_max_count = cpu_to_be16(cq_count);
		} else {
			err = -ENOSYS;
			goto out;
		}
	}
	in->field_select = cpu_to_be32(fsel);
	err = mlx5_core_modify_cq(dev->mdev, &mcq->mcq, in, sizeof(*in));

out:
	kfree(in);
	if (err)
		mlx5_ib_warn(dev, "modify cq 0x%x failed\n", mcq->mcq.cqn);

	return err;
}

static int resize_user(struct mlx5_ib_dev *dev, struct mlx5_ib_cq *cq,
		       int entries, struct ib_udata *udata, int *npas,
		       int *page_shift, int *cqe_size)
{
	struct mlx5_ib_resize_cq ucmd;
	struct ib_umem *umem;
	int err;
	int npages;
	struct ib_ucontext *context = cq->buf.umem->context;

	err = ib_copy_from_udata(&ucmd, udata, sizeof(ucmd));
	if (err)
		return err;

	if (ucmd.reserved0 || ucmd.reserved1)
		return -EINVAL;

	umem = ib_umem_get(context, ucmd.buf_addr, entries * ucmd.cqe_size,
			   IB_ACCESS_LOCAL_WRITE, 1);
	if (IS_ERR(umem)) {
		err = PTR_ERR(umem);
		return err;
	}

	mlx5_ib_cont_pages(umem, ucmd.buf_addr, &npages, page_shift,
			   npas, NULL);

	cq->resize_umem = umem;
	*cqe_size = ucmd.cqe_size;

	return 0;
}

static void un_resize_user(struct mlx5_ib_cq *cq)
{
	ib_umem_release(cq->resize_umem);
}

static int resize_kernel(struct mlx5_ib_dev *dev, struct mlx5_ib_cq *cq,
			 int entries, int cqe_size)
{
	int err;

	cq->resize_buf = kzalloc(sizeof(*cq->resize_buf), GFP_KERNEL);
	if (!cq->resize_buf)
		return -ENOMEM;

	err = alloc_cq_buf(dev, cq->resize_buf, entries, cqe_size);
	if (err)
		goto ex;

	init_cq_buf(cq, cq->resize_buf);

	return 0;

ex:
	kfree(cq->resize_buf);
	return err;
}

static void un_resize_kernel(struct mlx5_ib_dev *dev, struct mlx5_ib_cq *cq)
{
	free_cq_buf(dev, cq->resize_buf);
	cq->resize_buf = NULL;
}

static int copy_resize_cqes(struct mlx5_ib_cq *cq)
{
	struct mlx5_ib_dev *dev = to_mdev(cq->ibcq.device);
	struct mlx5_cqe64 *scqe64;
	struct mlx5_cqe64 *dcqe64;
	void *start_cqe;
	void *scqe;
	void *dcqe;
	int ssize;
	int dsize;
	int i;
	u8 sw_own;

	ssize = cq->buf.cqe_size;
	dsize = cq->resize_buf->cqe_size;
	if (ssize != dsize) {
		mlx5_ib_warn(dev, "resize from different cqe size is not supported\n");
		return -EINVAL;
	}

	i = cq->mcq.cons_index;
	scqe = get_sw_cqe(cq, i);
	scqe64 = ssize == 64 ? scqe : scqe + 64;
	start_cqe = scqe;
	if (!scqe) {
		mlx5_ib_warn(dev, "expected cqe in sw ownership\n");
		return -EINVAL;
	}

	while ((scqe64->op_own >> 4) != MLX5_CQE_RESIZE_CQ) {
		dcqe = get_cqe_from_buf(cq->resize_buf,
					(i + 1) & (cq->resize_buf->nent),
					dsize);
		dcqe64 = dsize == 64 ? dcqe : dcqe + 64;
		sw_own = sw_ownership_bit(i + 1, cq->resize_buf->nent);
		memcpy(dcqe, scqe, dsize);
		dcqe64->op_own = (dcqe64->op_own & ~MLX5_CQE_OWNER_MASK) | sw_own;

		++i;
		scqe = get_sw_cqe(cq, i);
		scqe64 = ssize == 64 ? scqe : scqe + 64;
		if (!scqe) {
			mlx5_ib_warn(dev, "expected cqe in sw ownership\n");
			return -EINVAL;
		}

		if (scqe == start_cqe) {
			printf("mlx5_ib: WARN: ""resize CQ failed to get resize CQE, CQN 0x%x\n", cq->mcq.cqn);
			return -ENOMEM;
		}
	}
	++cq->mcq.cons_index;
	return 0;
}

int mlx5_ib_resize_cq(struct ib_cq *ibcq, int entries, struct ib_udata *udata)
{
	struct mlx5_ib_dev *dev = to_mdev(ibcq->device);
	struct mlx5_ib_cq *cq = to_mcq(ibcq);
	struct mlx5_modify_cq_mbox_in *in;
	int err;
	int npas;
	int page_shift;
	int inlen;
	int uninitialized_var(cqe_size);
	unsigned long flags;

	if (!MLX5_CAP_GEN(dev->mdev, cq_resize)) {
		mlx5_ib_warn(dev, "Firmware does not support resize CQ\n");
		return -ENOSYS;
	}

	if (entries < 1 || roundup_pow_of_two(entries + 1) >
	    (1 << MLX5_CAP_GEN(dev->mdev, log_max_cq_sz))) {
		mlx5_ib_warn(dev, "wrong entries number %d(%ld), max %d\n",
			     entries, roundup_pow_of_two(entries + 1),
			     1 << MLX5_CAP_GEN(dev->mdev, log_max_cq_sz));
		return -EINVAL;
	}

	entries = roundup_pow_of_two(entries + 1);

	if (entries == ibcq->cqe + 1)
		return 0;

	mutex_lock(&cq->resize_mutex);
	if (udata) {
		err = resize_user(dev, cq, entries, udata, &npas, &page_shift,
				  &cqe_size);
	} else {
		cqe_size = 64;
		err = resize_kernel(dev, cq, entries, cqe_size);
		if (!err) {
			npas = cq->resize_buf->buf.npages;
			page_shift = cq->resize_buf->buf.page_shift;
		}
	}

	if (err) {
		mlx5_ib_warn(dev, "resize failed: %d\n", err);
		goto ex;
	}

	inlen = sizeof(*in) + npas * sizeof(in->pas[0]);
	in = mlx5_vzalloc(inlen);
	if (!in) {
		err = -ENOMEM;
		goto ex_resize;
	}

	if (udata)
		mlx5_ib_populate_pas(dev, cq->resize_umem, page_shift,
				     in->pas, 0);
	else
		mlx5_fill_page_array(&cq->resize_buf->buf, in->pas);

	in->field_select = cpu_to_be32(MLX5_MODIFY_CQ_MASK_LOG_SIZE  |
				       MLX5_MODIFY_CQ_MASK_PG_OFFSET |
				       MLX5_MODIFY_CQ_MASK_PG_SIZE);
	in->ctx.log_pg_sz = page_shift - MLX5_ADAPTER_PAGE_SHIFT;
	in->ctx.cqe_sz_flags = cqe_sz_to_mlx_sz(cqe_size) << 5;
	in->ctx.page_offset = 0;
	in->ctx.log_sz_usr_page = cpu_to_be32(ilog2(entries) << 24);
	in->hdr.opmod = cpu_to_be16(MLX5_CQ_OPMOD_RESIZE);
	in->cqn = cpu_to_be32(cq->mcq.cqn);

	err = mlx5_core_modify_cq(dev->mdev, &cq->mcq, in, inlen);
	if (err) {
		mlx5_ib_warn(dev, "modify cq failed: %d\n", err);
		goto ex_alloc;
	}

	if (udata) {
		cq->ibcq.cqe = entries - 1;
		ib_umem_release(cq->buf.umem);
		cq->buf.umem = cq->resize_umem;
		cq->resize_umem = NULL;
	} else {
		struct mlx5_ib_cq_buf tbuf;
		int resized = 0;

		spin_lock_irqsave(&cq->lock, flags);
		if (cq->resize_buf) {
			err = copy_resize_cqes(cq);
			if (!err) {
				tbuf = cq->buf;
				cq->buf = *cq->resize_buf;
				kfree(cq->resize_buf);
				cq->resize_buf = NULL;
				resized = 1;
			}
		}
		cq->ibcq.cqe = entries - 1;
		spin_unlock_irqrestore(&cq->lock, flags);
		if (resized)
			free_cq_buf(dev, &tbuf);
	}
	mutex_unlock(&cq->resize_mutex);

	kvfree(in);
	return 0;

ex_alloc:
	kvfree(in);

ex_resize:
	if (udata)
		un_resize_user(cq);
	else
		un_resize_kernel(dev, cq);
ex:
	mutex_unlock(&cq->resize_mutex);
	return err;
}

int mlx5_ib_get_cqe_size(struct mlx5_ib_dev *dev, struct ib_cq *ibcq)
{
	struct mlx5_ib_cq *cq;

	if (!ibcq)
		return 128;

	cq = to_mcq(ibcq);
	return cq->cqe_size;
}
