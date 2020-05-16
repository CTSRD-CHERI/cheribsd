/*-
 * BSD LICENSE
 *
 * Copyright (c) 2015-2019 Amazon.com, Inc. or its affiliates.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "ena_sysctl.h"

static void	ena_sysctl_add_wd(struct ena_adapter *);
static void	ena_sysctl_add_stats(struct ena_adapter *);
static void	ena_sysctl_add_tuneables(struct ena_adapter *);
static int	ena_sysctl_buf_ring_size(SYSCTL_HANDLER_ARGS);
static int	ena_sysctl_rx_queue_size(SYSCTL_HANDLER_ARGS);

static SYSCTL_NODE(_hw, OID_AUTO, ena, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "ENA driver parameters");

/*
 * Logging level for changing verbosity of the output
 */
int ena_log_level = ENA_ALERT | ENA_WARNING;
SYSCTL_INT(_hw_ena, OID_AUTO, log_level, CTLFLAG_RWTUN,
    &ena_log_level, 0, "Logging level indicating verbosity of the logs");

/*
 * Use 9k mbufs for the Rx buffers. Default to 0 (use page size mbufs instead).
 * Using 9k mbufs in low memory conditions might cause allocation to take a lot
 * of time and lead to the OS instability as it needs to look for the contiguous
 * pages.
 * However, page size mbufs has a bit smaller throughput than 9k mbufs, so if
 * the network performance is the priority, the 9k mbufs can be used.
 */
int ena_enable_9k_mbufs = 0;
SYSCTL_INT(_hw_ena, OID_AUTO, enable_9k_mbufs, CTLFLAG_RDTUN,
    &ena_enable_9k_mbufs, 0, "Use 9 kB mbufs for Rx descriptors");

void
ena_sysctl_add_nodes(struct ena_adapter *adapter)
{
	ena_sysctl_add_wd(adapter);
	ena_sysctl_add_stats(adapter);
	ena_sysctl_add_tuneables(adapter);
}

static void
ena_sysctl_add_wd(struct ena_adapter *adapter)
{
	device_t dev;

	struct sysctl_ctx_list *ctx;
	struct sysctl_oid *tree;
	struct sysctl_oid_list *child;

	dev = adapter->pdev;

	ctx = device_get_sysctl_ctx(dev);
	tree = device_get_sysctl_tree(dev);
	child = SYSCTL_CHILDREN(tree);

	/* Sysctl calls for Watchdog service */
	SYSCTL_ADD_INT(ctx, child, OID_AUTO, "wd_active",
	    CTLFLAG_RWTUN, &adapter->wd_active, 0,
	    "Watchdog is active");

	SYSCTL_ADD_QUAD(ctx, child, OID_AUTO, "keep_alive_timeout",
	    CTLFLAG_RWTUN, &adapter->keep_alive_timeout,
	    "Timeout for Keep Alive messages");

	SYSCTL_ADD_QUAD(ctx, child, OID_AUTO, "missing_tx_timeout",
	    CTLFLAG_RWTUN, &adapter->missing_tx_timeout,
	    "Timeout for TX completion");

	SYSCTL_ADD_U32(ctx, child, OID_AUTO, "missing_tx_max_queues",
	    CTLFLAG_RWTUN, &adapter->missing_tx_max_queues, 0,
	    "Number of TX queues to check per run");

	SYSCTL_ADD_U32(ctx, child, OID_AUTO, "missing_tx_threshold",
	    CTLFLAG_RWTUN, &adapter->missing_tx_threshold, 0,
	    "Max number of timeouted packets");
}

static void
ena_sysctl_add_stats(struct ena_adapter *adapter)
{
	device_t dev;

	struct ena_ring *tx_ring;
	struct ena_ring *rx_ring;

	struct ena_hw_stats *hw_stats;
	struct ena_stats_dev *dev_stats;
	struct ena_stats_tx *tx_stats;
	struct ena_stats_rx *rx_stats;
	struct ena_com_stats_admin *admin_stats;

	struct sysctl_ctx_list *ctx;
	struct sysctl_oid *tree;
	struct sysctl_oid_list *child;

	struct sysctl_oid *queue_node, *tx_node, *rx_node, *hw_node;
	struct sysctl_oid *admin_node;
	struct sysctl_oid_list *queue_list, *tx_list, *rx_list, *hw_list;
	struct sysctl_oid_list *admin_list;

#define QUEUE_NAME_LEN 32
	char namebuf[QUEUE_NAME_LEN];
	int i;

	dev = adapter->pdev;

	ctx = device_get_sysctl_ctx(dev);
	tree = device_get_sysctl_tree(dev);
	child = SYSCTL_CHILDREN(tree);

	tx_ring = adapter->tx_ring;
	rx_ring = adapter->rx_ring;

	hw_stats = &adapter->hw_stats;
	dev_stats = &adapter->dev_stats;
	admin_stats = &adapter->ena_dev->admin_queue.stats;

	SYSCTL_ADD_COUNTER_U64(ctx, child, OID_AUTO, "wd_expired",
	    CTLFLAG_RD, &dev_stats->wd_expired,
	    "Watchdog expiry count");
	SYSCTL_ADD_COUNTER_U64(ctx, child, OID_AUTO, "interface_up",
	    CTLFLAG_RD, &dev_stats->interface_up,
	    "Network interface up count");
	SYSCTL_ADD_COUNTER_U64(ctx, child, OID_AUTO, "interface_down",
	    CTLFLAG_RD, &dev_stats->interface_down,
	    "Network interface down count");
	SYSCTL_ADD_COUNTER_U64(ctx, child, OID_AUTO, "admin_q_pause",
	    CTLFLAG_RD, &dev_stats->admin_q_pause,
	    "Admin queue pauses");

	for (i = 0; i < adapter->num_queues; ++i, ++tx_ring, ++rx_ring) {
		snprintf(namebuf, QUEUE_NAME_LEN, "queue%d", i);

		queue_node = SYSCTL_ADD_NODE(ctx, child, OID_AUTO,
		    namebuf, CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, "Queue Name");
		queue_list = SYSCTL_CHILDREN(queue_node);

		/* TX specific stats */
		tx_node = SYSCTL_ADD_NODE(ctx, queue_list, OID_AUTO,
		    "tx_ring", CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, "TX ring");
		tx_list = SYSCTL_CHILDREN(tx_node);

		tx_stats = &tx_ring->tx_stats;

		SYSCTL_ADD_COUNTER_U64(ctx, tx_list, OID_AUTO,
		    "count", CTLFLAG_RD,
		    &tx_stats->cnt, "Packets sent");
		SYSCTL_ADD_COUNTER_U64(ctx, tx_list, OID_AUTO,
		    "bytes", CTLFLAG_RD,
		    &tx_stats->bytes, "Bytes sent");
		SYSCTL_ADD_COUNTER_U64(ctx, tx_list, OID_AUTO,
		    "prepare_ctx_err", CTLFLAG_RD,
		    &tx_stats->prepare_ctx_err,
		    "TX buffer preparation failures");
		SYSCTL_ADD_COUNTER_U64(ctx, tx_list, OID_AUTO,
		    "dma_mapping_err", CTLFLAG_RD,
		    &tx_stats->dma_mapping_err, "DMA mapping failures");
		SYSCTL_ADD_COUNTER_U64(ctx, tx_list, OID_AUTO,
		    "doorbells", CTLFLAG_RD,
		    &tx_stats->doorbells, "Queue doorbells");
		SYSCTL_ADD_COUNTER_U64(ctx, tx_list, OID_AUTO,
		    "missing_tx_comp", CTLFLAG_RD,
		    &tx_stats->missing_tx_comp, "TX completions missed");
		SYSCTL_ADD_COUNTER_U64(ctx, tx_list, OID_AUTO,
		    "bad_req_id", CTLFLAG_RD,
		    &tx_stats->bad_req_id, "Bad request id count");
		SYSCTL_ADD_COUNTER_U64(ctx, tx_list, OID_AUTO,
		        "mbuf_collapses", CTLFLAG_RD,
		        &tx_stats->collapse,
		        "Mbuf collapse count");
		SYSCTL_ADD_COUNTER_U64(ctx, tx_list, OID_AUTO,
		        "mbuf_collapse_err", CTLFLAG_RD,
		        &tx_stats->collapse_err,
		        "Mbuf collapse failures");
		SYSCTL_ADD_COUNTER_U64(ctx, tx_list, OID_AUTO,
		    "queue_wakeups", CTLFLAG_RD,
		    &tx_stats->queue_wakeup, "Queue wakeups");
		SYSCTL_ADD_COUNTER_U64(ctx, tx_list, OID_AUTO,
		    "queue_stops", CTLFLAG_RD,
		    &tx_stats->queue_stop, "Queue stops");
		SYSCTL_ADD_COUNTER_U64(ctx, tx_list, OID_AUTO,
		    "llq_buffer_copy", CTLFLAG_RD,
		    &tx_stats->llq_buffer_copy,
		    "Header copies for llq transaction");

		/* RX specific stats */
		rx_node = SYSCTL_ADD_NODE(ctx, queue_list, OID_AUTO,
		    "rx_ring", CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, "RX ring");
		rx_list = SYSCTL_CHILDREN(rx_node);

		rx_stats = &rx_ring->rx_stats;

		SYSCTL_ADD_COUNTER_U64(ctx, rx_list, OID_AUTO,
		    "count", CTLFLAG_RD,
		    &rx_stats->cnt, "Packets received");
		SYSCTL_ADD_COUNTER_U64(ctx, rx_list, OID_AUTO,
		    "bytes", CTLFLAG_RD,
		    &rx_stats->bytes, "Bytes received");
		SYSCTL_ADD_COUNTER_U64(ctx, rx_list, OID_AUTO,
		    "refil_partial", CTLFLAG_RD,
		    &rx_stats->refil_partial, "Partial refilled mbufs");
		SYSCTL_ADD_COUNTER_U64(ctx, rx_list, OID_AUTO,
		    "bad_csum", CTLFLAG_RD,
		    &rx_stats->bad_csum, "Bad RX checksum");
		SYSCTL_ADD_COUNTER_U64(ctx, rx_list, OID_AUTO,
		    "mbuf_alloc_fail", CTLFLAG_RD,
		    &rx_stats->mbuf_alloc_fail, "Failed mbuf allocs");
		SYSCTL_ADD_COUNTER_U64(ctx, rx_list, OID_AUTO,
		    "mjum_alloc_fail", CTLFLAG_RD,
		    &rx_stats->mjum_alloc_fail, "Failed jumbo mbuf allocs");
		SYSCTL_ADD_COUNTER_U64(ctx, rx_list, OID_AUTO,
		    "dma_mapping_err", CTLFLAG_RD,
		    &rx_stats->dma_mapping_err, "DMA mapping errors");
		SYSCTL_ADD_COUNTER_U64(ctx, rx_list, OID_AUTO,
		    "bad_desc_num", CTLFLAG_RD,
		    &rx_stats->bad_desc_num, "Bad descriptor count");
		SYSCTL_ADD_COUNTER_U64(ctx, rx_list, OID_AUTO,
		    "bad_req_id", CTLFLAG_RD,
		    &rx_stats->bad_req_id, "Bad request id count");
		SYSCTL_ADD_COUNTER_U64(ctx, rx_list, OID_AUTO,
		    "empty_rx_ring", CTLFLAG_RD,
		    &rx_stats->empty_rx_ring, "RX descriptors depletion count");
	}

	/* Stats read from device */
	hw_node = SYSCTL_ADD_NODE(ctx, child, OID_AUTO, "hw_stats",
	    CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, "Statistics from hardware");
	hw_list = SYSCTL_CHILDREN(hw_node);

	SYSCTL_ADD_COUNTER_U64(ctx, hw_list, OID_AUTO, "rx_packets", CTLFLAG_RD,
	    &hw_stats->rx_packets, "Packets received");
	SYSCTL_ADD_COUNTER_U64(ctx, hw_list, OID_AUTO, "tx_packets", CTLFLAG_RD,
	    &hw_stats->tx_packets, "Packets transmitted");
	SYSCTL_ADD_COUNTER_U64(ctx, hw_list, OID_AUTO, "rx_bytes", CTLFLAG_RD,
	    &hw_stats->rx_bytes, "Bytes received");
	SYSCTL_ADD_COUNTER_U64(ctx, hw_list, OID_AUTO, "tx_bytes", CTLFLAG_RD,
	    &hw_stats->tx_bytes, "Bytes transmitted");
	SYSCTL_ADD_COUNTER_U64(ctx, hw_list, OID_AUTO, "rx_drops", CTLFLAG_RD,
	    &hw_stats->rx_drops, "Receive packet drops");

	/* ENA Admin queue stats */
	admin_node = SYSCTL_ADD_NODE(ctx, child, OID_AUTO, "admin_stats",
	    CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, "ENA Admin Queue statistics");
	admin_list = SYSCTL_CHILDREN(admin_node);

	SYSCTL_ADD_U32(ctx, admin_list, OID_AUTO, "aborted_cmd", CTLFLAG_RD,
	    &admin_stats->aborted_cmd, 0, "Aborted commands");
	SYSCTL_ADD_U32(ctx, admin_list, OID_AUTO, "sumbitted_cmd", CTLFLAG_RD,
	    &admin_stats->submitted_cmd, 0, "Submitted commands");
	SYSCTL_ADD_U32(ctx, admin_list, OID_AUTO, "completed_cmd", CTLFLAG_RD,
	    &admin_stats->completed_cmd, 0, "Completed commands");
	SYSCTL_ADD_U32(ctx, admin_list, OID_AUTO, "out_of_space", CTLFLAG_RD,
	    &admin_stats->out_of_space, 0, "Queue out of space");
	SYSCTL_ADD_U32(ctx, admin_list, OID_AUTO, "no_completion", CTLFLAG_RD,
	    &admin_stats->no_completion, 0, "Commands not completed");
}

static void
ena_sysctl_add_tuneables(struct ena_adapter *adapter)
{
	device_t dev;

	struct sysctl_ctx_list *ctx;
	struct sysctl_oid *tree;
	struct sysctl_oid_list *child;

	dev = adapter->pdev;

	ctx = device_get_sysctl_ctx(dev);
	tree = device_get_sysctl_tree(dev);
	child = SYSCTL_CHILDREN(tree);

	/* Tuneable number of buffers in the buf-ring (drbr) */
	SYSCTL_ADD_PROC(ctx, child, OID_AUTO, "buf_ring_size",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_NEEDGIANT, adapter, 0,
	    ena_sysctl_buf_ring_size, "I", "Size of the bufring");

	/* Tuneable number of Rx ring size */
	SYSCTL_ADD_PROC(ctx, child, OID_AUTO, "rx_queue_size",
	    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_NEEDGIANT, adapter, 0,
	    ena_sysctl_rx_queue_size, "I", "Size of the Rx ring. "
	    "The size should be a power of 2. Max value is 8K");
}


static int
ena_sysctl_buf_ring_size(SYSCTL_HANDLER_ARGS)
{
	struct ena_adapter *adapter = arg1;
	int val;
	int error;

	val = 0;
	error = sysctl_wire_old_buffer(req, sizeof(int));
	if (error == 0) {
		val = adapter->buf_ring_size;
		error = sysctl_handle_int(oidp, &val, 0, req);
	}
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (val < 0)
		return (EINVAL);

	device_printf(adapter->pdev,
	    "Requested new buf ring size: %d. Old size: %d\n",
	    val, adapter->buf_ring_size);

	if (val != adapter->buf_ring_size) {
		adapter->buf_ring_size = val;
		adapter->reset_reason = ENA_REGS_RESET_OS_TRIGGER;
		ENA_FLAG_SET_ATOMIC(ENA_FLAG_TRIGGER_RESET, adapter);
	}

	return (0);
}

static int
ena_sysctl_rx_queue_size(SYSCTL_HANDLER_ARGS)
{
	struct ena_adapter *adapter = arg1;
	int val;
	int error;

	val = 0;
	error = sysctl_wire_old_buffer(req, sizeof(int));
	if (error == 0) {
		val = adapter->rx_ring_size;
		error = sysctl_handle_int(oidp, &val, 0, req);
	}
	if (error != 0 || req->newptr == NULL)
		return (error);
	if  (val < 16)
		return (EINVAL);

	device_printf(adapter->pdev,
	    "Requested new rx queue size: %d. Old size: %d\n",
	    val, adapter->rx_ring_size);

	if (val != adapter->rx_ring_size) {
		adapter->rx_ring_size = val;
		adapter->reset_reason = ENA_REGS_RESET_OS_TRIGGER;
		ENA_FLAG_SET_ATOMIC(ENA_FLAG_TRIGGER_RESET, adapter);
	}

	return (0);
}
