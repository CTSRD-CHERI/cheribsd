/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (C) 2012-2016 Intel Corporation
 * All rights reserved.
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

#include "opt_cam.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/ioccom.h>
#include <sys/proc.h>
#include <sys/smp.h>
#include <sys/uio.h>

#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>

#include "nvme_private.h"

#define B4_CHK_RDY_DELAY_MS	2300		/* work arond controller bug */

static void nvme_ctrlr_construct_and_submit_aer(struct nvme_controller *ctrlr,
						struct nvme_async_event_request *aer);
static void nvme_ctrlr_setup_interrupts(struct nvme_controller *ctrlr);

static int
nvme_ctrlr_allocate_bar(struct nvme_controller *ctrlr)
{

	ctrlr->resource_id = PCIR_BAR(0);

	ctrlr->resource = bus_alloc_resource_any(ctrlr->dev, SYS_RES_MEMORY,
	    &ctrlr->resource_id, RF_ACTIVE);

	if(ctrlr->resource == NULL) {
		nvme_printf(ctrlr, "unable to allocate pci resource\n");
		return (ENOMEM);
	}

	ctrlr->bus_tag = rman_get_bustag(ctrlr->resource);
	ctrlr->bus_handle = rman_get_bushandle(ctrlr->resource);
	ctrlr->regs = (struct nvme_registers *)ctrlr->bus_handle;

	/*
	 * The NVMe spec allows for the MSI-X table to be placed behind
	 *  BAR 4/5, separate from the control/doorbell registers.  Always
	 *  try to map this bar, because it must be mapped prior to calling
	 *  pci_alloc_msix().  If the table isn't behind BAR 4/5,
	 *  bus_alloc_resource() will just return NULL which is OK.
	 */
	ctrlr->bar4_resource_id = PCIR_BAR(4);
	ctrlr->bar4_resource = bus_alloc_resource_any(ctrlr->dev, SYS_RES_MEMORY,
	    &ctrlr->bar4_resource_id, RF_ACTIVE);

	return (0);
}

static int
nvme_ctrlr_construct_admin_qpair(struct nvme_controller *ctrlr)
{
	struct nvme_qpair	*qpair;
	uint32_t		num_entries;
	int			error;

	qpair = &ctrlr->adminq;

	num_entries = NVME_ADMIN_ENTRIES;
	TUNABLE_INT_FETCH("hw.nvme.admin_entries", &num_entries);
	/*
	 * If admin_entries was overridden to an invalid value, revert it
	 *  back to our default value.
	 */
	if (num_entries < NVME_MIN_ADMIN_ENTRIES ||
	    num_entries > NVME_MAX_ADMIN_ENTRIES) {
		nvme_printf(ctrlr, "invalid hw.nvme.admin_entries=%d "
		    "specified\n", num_entries);
		num_entries = NVME_ADMIN_ENTRIES;
	}

	/*
	 * The admin queue's max xfer size is treated differently than the
	 *  max I/O xfer size.  16KB is sufficient here - maybe even less?
	 */
	error = nvme_qpair_construct(qpair, 
				     0, /* qpair ID */
				     0, /* vector */
				     num_entries,
				     NVME_ADMIN_TRACKERS,
				     ctrlr);
	return (error);
}

static int
nvme_ctrlr_construct_io_qpairs(struct nvme_controller *ctrlr)
{
	struct nvme_qpair	*qpair;
	union cap_lo_register	cap_lo;
	int			i, error, num_entries, num_trackers;

	num_entries = NVME_IO_ENTRIES;
	TUNABLE_INT_FETCH("hw.nvme.io_entries", &num_entries);

	/*
	 * NVMe spec sets a hard limit of 64K max entries, but
	 *  devices may specify a smaller limit, so we need to check
	 *  the MQES field in the capabilities register.
	 */
	cap_lo.raw = nvme_mmio_read_4(ctrlr, cap_lo);
	num_entries = min(num_entries, cap_lo.bits.mqes+1);

	num_trackers = NVME_IO_TRACKERS;
	TUNABLE_INT_FETCH("hw.nvme.io_trackers", &num_trackers);

	num_trackers = max(num_trackers, NVME_MIN_IO_TRACKERS);
	num_trackers = min(num_trackers, NVME_MAX_IO_TRACKERS);
	/*
	 * No need to have more trackers than entries in the submit queue.
	 *  Note also that for a queue size of N, we can only have (N-1)
	 *  commands outstanding, hence the "-1" here.
	 */
	num_trackers = min(num_trackers, (num_entries-1));

	/*
	 * Our best estimate for the maximum number of I/Os that we should
	 * noramlly have in flight at one time. This should be viewed as a hint,
	 * not a hard limit and will need to be revisitted when the upper layers
	 * of the storage system grows multi-queue support.
	 */
	ctrlr->max_hw_pend_io = num_trackers * ctrlr->num_io_queues * 3 / 4;

	/*
	 * This was calculated previously when setting up interrupts, but
	 *  a controller could theoretically support fewer I/O queues than
	 *  MSI-X vectors.  So calculate again here just to be safe.
	 */
	ctrlr->num_cpus_per_ioq = howmany(mp_ncpus, ctrlr->num_io_queues);

	ctrlr->ioq = malloc(ctrlr->num_io_queues * sizeof(struct nvme_qpair),
	    M_NVME, M_ZERO | M_WAITOK);

	for (i = 0; i < ctrlr->num_io_queues; i++) {
		qpair = &ctrlr->ioq[i];

		/*
		 * Admin queue has ID=0. IO queues start at ID=1 -
		 *  hence the 'i+1' here.
		 *
		 * For I/O queues, use the controller-wide max_xfer_size
		 *  calculated in nvme_attach().
		 */
		error = nvme_qpair_construct(qpair,
				     i+1, /* qpair ID */
				     ctrlr->msix_enabled ? i+1 : 0, /* vector */
				     num_entries,
				     num_trackers,
				     ctrlr);
		if (error)
			return (error);

		/*
		 * Do not bother binding interrupts if we only have one I/O
		 *  interrupt thread for this controller.
		 */
		if (ctrlr->num_io_queues > 1)
			bus_bind_intr(ctrlr->dev, qpair->res,
			    i * ctrlr->num_cpus_per_ioq);
	}

	return (0);
}

static void
nvme_ctrlr_fail(struct nvme_controller *ctrlr)
{
	int i;

	ctrlr->is_failed = TRUE;
	nvme_qpair_fail(&ctrlr->adminq);
	if (ctrlr->ioq != NULL) {
		for (i = 0; i < ctrlr->num_io_queues; i++)
			nvme_qpair_fail(&ctrlr->ioq[i]);
	}
	nvme_notify_fail_consumers(ctrlr);
}

void
nvme_ctrlr_post_failed_request(struct nvme_controller *ctrlr,
    struct nvme_request *req)
{

	mtx_lock(&ctrlr->lock);
	STAILQ_INSERT_TAIL(&ctrlr->fail_req, req, stailq);
	mtx_unlock(&ctrlr->lock);
	taskqueue_enqueue(ctrlr->taskqueue, &ctrlr->fail_req_task);
}

static void
nvme_ctrlr_fail_req_task(void *arg, int pending)
{
	struct nvme_controller	*ctrlr = arg;
	struct nvme_request	*req;

	mtx_lock(&ctrlr->lock);
	while (!STAILQ_EMPTY(&ctrlr->fail_req)) {
		req = STAILQ_FIRST(&ctrlr->fail_req);
		STAILQ_REMOVE_HEAD(&ctrlr->fail_req, stailq);
		nvme_qpair_manual_complete_request(req->qpair, req,
		    NVME_SCT_GENERIC, NVME_SC_ABORTED_BY_REQUEST, TRUE);
	}
	mtx_unlock(&ctrlr->lock);
}

static int
nvme_ctrlr_wait_for_ready(struct nvme_controller *ctrlr, int desired_val)
{
	int ms_waited;
	union csts_register csts;

	csts.raw = nvme_mmio_read_4(ctrlr, csts);

	ms_waited = 0;
	while (csts.bits.rdy != desired_val) {
		if (ms_waited++ > ctrlr->ready_timeout_in_ms) {
			nvme_printf(ctrlr, "controller ready did not become %d "
			    "within %d ms\n", desired_val, ctrlr->ready_timeout_in_ms);
			return (ENXIO);
		}
		DELAY(1000);
		csts.raw = nvme_mmio_read_4(ctrlr, csts);
	}

	return (0);
}

static int
nvme_ctrlr_disable(struct nvme_controller *ctrlr)
{
	union cc_register cc;
	union csts_register csts;
	int err;

	cc.raw = nvme_mmio_read_4(ctrlr, cc);
	csts.raw = nvme_mmio_read_4(ctrlr, csts);

	/*
	 * Per 3.1.5 in NVME 1.3 spec, transitioning CC.EN from 0 to 1
	 * when CSTS.RDY is 1 or transitioning CC.EN from 1 to 0 when
	 * CSTS.RDY is 0 "has undefined results" So make sure that CSTS.RDY
	 * isn't the desired value. Short circuit if we're already disabled.
	 */
	if (cc.bits.en == 1) {
		if (csts.bits.rdy == 0) {
			/* EN == 1, wait for  RDY == 1 or fail */
			err = nvme_ctrlr_wait_for_ready(ctrlr, 1);
			if (err != 0)
				return (err);
		}
	} else {
		/* EN == 0 already wait for RDY == 0 */
		if (csts.bits.rdy == 0)
			return (0);
		else
			return (nvme_ctrlr_wait_for_ready(ctrlr, 0));
	}

	cc.bits.en = 0;
	nvme_mmio_write_4(ctrlr, cc, cc.raw);
	/*
	 * Some drives have issues with accessing the mmio after we
	 * disable, so delay for a bit after we write the bit to
	 * cope with these issues.
	 */
	if (ctrlr->quirks & QUIRK_DELAY_B4_CHK_RDY)
		pause("nvmeR", B4_CHK_RDY_DELAY_MS * hz / 1000);
	return (nvme_ctrlr_wait_for_ready(ctrlr, 0));
}

static int
nvme_ctrlr_enable(struct nvme_controller *ctrlr)
{
	union cc_register	cc;
	union csts_register	csts;
	union aqa_register	aqa;
	int			err;

	cc.raw = nvme_mmio_read_4(ctrlr, cc);
	csts.raw = nvme_mmio_read_4(ctrlr, csts);

	/*
	 * See note in nvme_ctrlr_disable. Short circuit if we're already enabled.
	 */
	if (cc.bits.en == 1) {
		if (csts.bits.rdy == 1)
			return (0);
		else
			return (nvme_ctrlr_wait_for_ready(ctrlr, 1));
	} else {
		/* EN == 0 already wait for RDY == 0 or fail */
		err = nvme_ctrlr_wait_for_ready(ctrlr, 0);
		if (err != 0)
			return (err);
	}

	nvme_mmio_write_8(ctrlr, asq, ctrlr->adminq.cmd_bus_addr);
	DELAY(5000);
	nvme_mmio_write_8(ctrlr, acq, ctrlr->adminq.cpl_bus_addr);
	DELAY(5000);

	aqa.raw = 0;
	/* acqs and asqs are 0-based. */
	aqa.bits.acqs = ctrlr->adminq.num_entries-1;
	aqa.bits.asqs = ctrlr->adminq.num_entries-1;
	nvme_mmio_write_4(ctrlr, aqa, aqa.raw);
	DELAY(5000);

	cc.bits.en = 1;
	cc.bits.css = 0;
	cc.bits.ams = 0;
	cc.bits.shn = 0;
	cc.bits.iosqes = 6; /* SQ entry size == 64 == 2^6 */
	cc.bits.iocqes = 4; /* CQ entry size == 16 == 2^4 */

	/* This evaluates to 0, which is according to spec. */
	cc.bits.mps = (PAGE_SIZE >> 13);

	nvme_mmio_write_4(ctrlr, cc, cc.raw);

	return (nvme_ctrlr_wait_for_ready(ctrlr, 1));
}

int
nvme_ctrlr_hw_reset(struct nvme_controller *ctrlr)
{
	int i, err;

	nvme_admin_qpair_disable(&ctrlr->adminq);
	/*
	 * I/O queues are not allocated before the initial HW
	 *  reset, so do not try to disable them.  Use is_initialized
	 *  to determine if this is the initial HW reset.
	 */
	if (ctrlr->is_initialized) {
		for (i = 0; i < ctrlr->num_io_queues; i++)
			nvme_io_qpair_disable(&ctrlr->ioq[i]);
	}

	DELAY(100*1000);

	err = nvme_ctrlr_disable(ctrlr);
	if (err != 0)
		return err;
	return (nvme_ctrlr_enable(ctrlr));
}

void
nvme_ctrlr_reset(struct nvme_controller *ctrlr)
{
	int cmpset;

	cmpset = atomic_cmpset_32(&ctrlr->is_resetting, 0, 1);

	if (cmpset == 0 || ctrlr->is_failed)
		/*
		 * Controller is already resetting or has failed.  Return
		 *  immediately since there is no need to kick off another
		 *  reset in these cases.
		 */
		return;

	taskqueue_enqueue(ctrlr->taskqueue, &ctrlr->reset_task);
}

static int
nvme_ctrlr_identify(struct nvme_controller *ctrlr)
{
	struct nvme_completion_poll_status	status;

	status.done = FALSE;
	nvme_ctrlr_cmd_identify_controller(ctrlr, &ctrlr->cdata,
	    nvme_completion_poll_cb, &status);
	while (status.done == FALSE)
		pause("nvme", 1);
	if (nvme_completion_is_error(&status.cpl)) {
		nvme_printf(ctrlr, "nvme_identify_controller failed!\n");
		return (ENXIO);
	}

	/*
	 * Use MDTS to ensure our default max_xfer_size doesn't exceed what the
	 *  controller supports.
	 */
	if (ctrlr->cdata.mdts > 0)
		ctrlr->max_xfer_size = min(ctrlr->max_xfer_size,
		    ctrlr->min_page_size * (1 << (ctrlr->cdata.mdts)));

	return (0);
}

static int
nvme_ctrlr_set_num_qpairs(struct nvme_controller *ctrlr)
{
	struct nvme_completion_poll_status	status;
	int					cq_allocated, sq_allocated;

	status.done = FALSE;
	nvme_ctrlr_cmd_set_num_queues(ctrlr, ctrlr->num_io_queues,
	    nvme_completion_poll_cb, &status);
	while (status.done == FALSE)
		pause("nvme", 1);
	if (nvme_completion_is_error(&status.cpl)) {
		nvme_printf(ctrlr, "nvme_ctrlr_set_num_qpairs failed!\n");
		return (ENXIO);
	}

	/*
	 * Data in cdw0 is 0-based.
	 * Lower 16-bits indicate number of submission queues allocated.
	 * Upper 16-bits indicate number of completion queues allocated.
	 */
	sq_allocated = (status.cpl.cdw0 & 0xFFFF) + 1;
	cq_allocated = (status.cpl.cdw0 >> 16) + 1;

	/*
	 * Controller may allocate more queues than we requested,
	 *  so use the minimum of the number requested and what was
	 *  actually allocated.
	 */
	ctrlr->num_io_queues = min(ctrlr->num_io_queues, sq_allocated);
	ctrlr->num_io_queues = min(ctrlr->num_io_queues, cq_allocated);

	return (0);
}

static int
nvme_ctrlr_create_qpairs(struct nvme_controller *ctrlr)
{
	struct nvme_completion_poll_status	status;
	struct nvme_qpair			*qpair;
	int					i;

	for (i = 0; i < ctrlr->num_io_queues; i++) {
		qpair = &ctrlr->ioq[i];

		status.done = FALSE;
		nvme_ctrlr_cmd_create_io_cq(ctrlr, qpair, qpair->vector,
		    nvme_completion_poll_cb, &status);
		while (status.done == FALSE)
			pause("nvme", 1);
		if (nvme_completion_is_error(&status.cpl)) {
			nvme_printf(ctrlr, "nvme_create_io_cq failed!\n");
			return (ENXIO);
		}

		status.done = FALSE;
		nvme_ctrlr_cmd_create_io_sq(qpair->ctrlr, qpair,
		    nvme_completion_poll_cb, &status);
		while (status.done == FALSE)
			pause("nvme", 1);
		if (nvme_completion_is_error(&status.cpl)) {
			nvme_printf(ctrlr, "nvme_create_io_sq failed!\n");
			return (ENXIO);
		}
	}

	return (0);
}

static int
nvme_ctrlr_construct_namespaces(struct nvme_controller *ctrlr)
{
	struct nvme_namespace	*ns;
	uint32_t 		i;

	for (i = 0; i < min(ctrlr->cdata.nn, NVME_MAX_NAMESPACES); i++) {
		ns = &ctrlr->ns[i];
		nvme_ns_construct(ns, i+1, ctrlr);
	}

	return (0);
}

static boolean_t
is_log_page_id_valid(uint8_t page_id)
{

	switch (page_id) {
	case NVME_LOG_ERROR:
	case NVME_LOG_HEALTH_INFORMATION:
	case NVME_LOG_FIRMWARE_SLOT:
		return (TRUE);
	}

	return (FALSE);
}

static uint32_t
nvme_ctrlr_get_log_page_size(struct nvme_controller *ctrlr, uint8_t page_id)
{
	uint32_t	log_page_size;

	switch (page_id) {
	case NVME_LOG_ERROR:
		log_page_size = min(
		    sizeof(struct nvme_error_information_entry) *
		    ctrlr->cdata.elpe,
		    NVME_MAX_AER_LOG_SIZE);
		break;
	case NVME_LOG_HEALTH_INFORMATION:
		log_page_size = sizeof(struct nvme_health_information_page);
		break;
	case NVME_LOG_FIRMWARE_SLOT:
		log_page_size = sizeof(struct nvme_firmware_page);
		break;
	default:
		log_page_size = 0;
		break;
	}

	return (log_page_size);
}

static void
nvme_ctrlr_log_critical_warnings(struct nvme_controller *ctrlr,
    union nvme_critical_warning_state state)
{

	if (state.bits.available_spare == 1)
		nvme_printf(ctrlr, "available spare space below threshold\n");

	if (state.bits.temperature == 1)
		nvme_printf(ctrlr, "temperature above threshold\n");

	if (state.bits.device_reliability == 1)
		nvme_printf(ctrlr, "device reliability degraded\n");

	if (state.bits.read_only == 1)
		nvme_printf(ctrlr, "media placed in read only mode\n");

	if (state.bits.volatile_memory_backup == 1)
		nvme_printf(ctrlr, "volatile memory backup device failed\n");

	if (state.bits.reserved != 0)
		nvme_printf(ctrlr,
		    "unknown critical warning(s): state = 0x%02x\n", state.raw);
}

static void
nvme_ctrlr_async_event_log_page_cb(void *arg, const struct nvme_completion *cpl)
{
	struct nvme_async_event_request		*aer = arg;
	struct nvme_health_information_page	*health_info;

	/*
	 * If the log page fetch for some reason completed with an error,
	 *  don't pass log page data to the consumers.  In practice, this case
	 *  should never happen.
	 */
	if (nvme_completion_is_error(cpl))
		nvme_notify_async_consumers(aer->ctrlr, &aer->cpl,
		    aer->log_page_id, NULL, 0);
	else {
		if (aer->log_page_id == NVME_LOG_HEALTH_INFORMATION) {
			health_info = (struct nvme_health_information_page *)
			    aer->log_page_buffer;
			nvme_ctrlr_log_critical_warnings(aer->ctrlr,
			    health_info->critical_warning);
			/*
			 * Critical warnings reported through the
			 *  SMART/health log page are persistent, so
			 *  clear the associated bits in the async event
			 *  config so that we do not receive repeated
			 *  notifications for the same event.
			 */
			aer->ctrlr->async_event_config.raw &=
			    ~health_info->critical_warning.raw;
			nvme_ctrlr_cmd_set_async_event_config(aer->ctrlr,
			    aer->ctrlr->async_event_config, NULL, NULL);
		}


		/*
		 * Pass the cpl data from the original async event completion,
		 *  not the log page fetch.
		 */
		nvme_notify_async_consumers(aer->ctrlr, &aer->cpl,
		    aer->log_page_id, aer->log_page_buffer, aer->log_page_size);
	}

	/*
	 * Repost another asynchronous event request to replace the one
	 *  that just completed.
	 */
	nvme_ctrlr_construct_and_submit_aer(aer->ctrlr, aer);
}

static void
nvme_ctrlr_async_event_cb(void *arg, const struct nvme_completion *cpl)
{
	struct nvme_async_event_request	*aer = arg;

	if (nvme_completion_is_error(cpl)) {
		/*
		 *  Do not retry failed async event requests.  This avoids
		 *  infinite loops where a new async event request is submitted
		 *  to replace the one just failed, only to fail again and
		 *  perpetuate the loop.
		 */
		return;
	}

	/* Associated log page is in bits 23:16 of completion entry dw0. */
	aer->log_page_id = (cpl->cdw0 & 0xFF0000) >> 16;

	nvme_printf(aer->ctrlr, "async event occurred (log page id=0x%x)\n",
	    aer->log_page_id);

	if (is_log_page_id_valid(aer->log_page_id)) {
		aer->log_page_size = nvme_ctrlr_get_log_page_size(aer->ctrlr,
		    aer->log_page_id);
		memcpy(&aer->cpl, cpl, sizeof(*cpl));
		nvme_ctrlr_cmd_get_log_page(aer->ctrlr, aer->log_page_id,
		    NVME_GLOBAL_NAMESPACE_TAG, aer->log_page_buffer,
		    aer->log_page_size, nvme_ctrlr_async_event_log_page_cb,
		    aer);
		/* Wait to notify consumers until after log page is fetched. */
	} else {
		nvme_notify_async_consumers(aer->ctrlr, cpl, aer->log_page_id,
		    NULL, 0);

		/*
		 * Repost another asynchronous event request to replace the one
		 *  that just completed.
		 */
		nvme_ctrlr_construct_and_submit_aer(aer->ctrlr, aer);
	}
}

static void
nvme_ctrlr_construct_and_submit_aer(struct nvme_controller *ctrlr,
    struct nvme_async_event_request *aer)
{
	struct nvme_request *req;

	aer->ctrlr = ctrlr;
	req = nvme_allocate_request_null(nvme_ctrlr_async_event_cb, aer);
	aer->req = req;

	/*
	 * Disable timeout here, since asynchronous event requests should by
	 *  nature never be timed out.
	 */
	req->timeout = FALSE;
	req->cmd.opc = NVME_OPC_ASYNC_EVENT_REQUEST;
	nvme_ctrlr_submit_admin_request(ctrlr, req);
}

static void
nvme_ctrlr_configure_aer(struct nvme_controller *ctrlr)
{
	struct nvme_completion_poll_status	status;
	struct nvme_async_event_request		*aer;
	uint32_t				i;

	ctrlr->async_event_config.raw = 0xFF;
	ctrlr->async_event_config.bits.reserved = 0;

	status.done = FALSE;
	nvme_ctrlr_cmd_get_feature(ctrlr, NVME_FEAT_TEMPERATURE_THRESHOLD,
	    0, NULL, 0, nvme_completion_poll_cb, &status);
	while (status.done == FALSE)
		pause("nvme", 1);
	if (nvme_completion_is_error(&status.cpl) ||
	    (status.cpl.cdw0 & 0xFFFF) == 0xFFFF ||
	    (status.cpl.cdw0 & 0xFFFF) == 0x0000) {
		nvme_printf(ctrlr, "temperature threshold not supported\n");
		ctrlr->async_event_config.bits.temperature = 0;
	}

	nvme_ctrlr_cmd_set_async_event_config(ctrlr,
	    ctrlr->async_event_config, NULL, NULL);

	/* aerl is a zero-based value, so we need to add 1 here. */
	ctrlr->num_aers = min(NVME_MAX_ASYNC_EVENTS, (ctrlr->cdata.aerl+1));

	for (i = 0; i < ctrlr->num_aers; i++) {
		aer = &ctrlr->aer[i];
		nvme_ctrlr_construct_and_submit_aer(ctrlr, aer);
	}
}

static void
nvme_ctrlr_configure_int_coalescing(struct nvme_controller *ctrlr)
{

	ctrlr->int_coal_time = 0;
	TUNABLE_INT_FETCH("hw.nvme.int_coal_time",
	    &ctrlr->int_coal_time);

	ctrlr->int_coal_threshold = 0;
	TUNABLE_INT_FETCH("hw.nvme.int_coal_threshold",
	    &ctrlr->int_coal_threshold);

	nvme_ctrlr_cmd_set_interrupt_coalescing(ctrlr, ctrlr->int_coal_time,
	    ctrlr->int_coal_threshold, NULL, NULL);
}

static void
nvme_ctrlr_start(void *ctrlr_arg)
{
	struct nvme_controller *ctrlr = ctrlr_arg;
	uint32_t old_num_io_queues;
	int i;

	/*
	 * Only reset adminq here when we are restarting the
	 *  controller after a reset.  During initialization,
	 *  we have already submitted admin commands to get
	 *  the number of I/O queues supported, so cannot reset
	 *  the adminq again here.
	 */
	if (ctrlr->is_resetting) {
		nvme_qpair_reset(&ctrlr->adminq);
	}

	for (i = 0; i < ctrlr->num_io_queues; i++)
		nvme_qpair_reset(&ctrlr->ioq[i]);

	nvme_admin_qpair_enable(&ctrlr->adminq);

	if (nvme_ctrlr_identify(ctrlr) != 0) {
		nvme_ctrlr_fail(ctrlr);
		return;
	}

	/*
	 * The number of qpairs are determined during controller initialization,
	 *  including using NVMe SET_FEATURES/NUMBER_OF_QUEUES to determine the
	 *  HW limit.  We call SET_FEATURES again here so that it gets called
	 *  after any reset for controllers that depend on the driver to
	 *  explicit specify how many queues it will use.  This value should
	 *  never change between resets, so panic if somehow that does happen.
	 */
	if (ctrlr->is_resetting) {
		old_num_io_queues = ctrlr->num_io_queues;
		if (nvme_ctrlr_set_num_qpairs(ctrlr) != 0) {
			nvme_ctrlr_fail(ctrlr);
			return;
		}

		if (old_num_io_queues != ctrlr->num_io_queues) {
			panic("num_io_queues changed from %u to %u",
			      old_num_io_queues, ctrlr->num_io_queues);
		}
	}

	if (nvme_ctrlr_create_qpairs(ctrlr) != 0) {
		nvme_ctrlr_fail(ctrlr);
		return;
	}

	if (nvme_ctrlr_construct_namespaces(ctrlr) != 0) {
		nvme_ctrlr_fail(ctrlr);
		return;
	}

	nvme_ctrlr_configure_aer(ctrlr);
	nvme_ctrlr_configure_int_coalescing(ctrlr);

	for (i = 0; i < ctrlr->num_io_queues; i++)
		nvme_io_qpair_enable(&ctrlr->ioq[i]);
}

void
nvme_ctrlr_start_config_hook(void *arg)
{
	struct nvme_controller *ctrlr = arg;

	nvme_qpair_reset(&ctrlr->adminq);
	nvme_admin_qpair_enable(&ctrlr->adminq);

	if (nvme_ctrlr_set_num_qpairs(ctrlr) == 0 &&
	    nvme_ctrlr_construct_io_qpairs(ctrlr) == 0)
		nvme_ctrlr_start(ctrlr);
	else
		nvme_ctrlr_fail(ctrlr);

	nvme_sysctl_initialize_ctrlr(ctrlr);
	config_intrhook_disestablish(&ctrlr->config_hook);

	ctrlr->is_initialized = 1;
	nvme_notify_new_controller(ctrlr);
}

static void
nvme_ctrlr_reset_task(void *arg, int pending)
{
	struct nvme_controller	*ctrlr = arg;
	int			status;

	nvme_printf(ctrlr, "resetting controller\n");
	status = nvme_ctrlr_hw_reset(ctrlr);
	/*
	 * Use pause instead of DELAY, so that we yield to any nvme interrupt
	 *  handlers on this CPU that were blocked on a qpair lock. We want
	 *  all nvme interrupts completed before proceeding with restarting the
	 *  controller.
	 *
	 * XXX - any way to guarantee the interrupt handlers have quiesced?
	 */
	pause("nvmereset", hz / 10);
	if (status == 0)
		nvme_ctrlr_start(ctrlr);
	else
		nvme_ctrlr_fail(ctrlr);

	atomic_cmpset_32(&ctrlr->is_resetting, 1, 0);
}

/*
 * Poll all the queues enabled on the device for completion.
 */
void
nvme_ctrlr_poll(struct nvme_controller *ctrlr)
{
	int i;

	nvme_qpair_process_completions(&ctrlr->adminq);

	for (i = 0; i < ctrlr->num_io_queues; i++)
		if (ctrlr->ioq && ctrlr->ioq[i].cpl)
			nvme_qpair_process_completions(&ctrlr->ioq[i]);
}

/*
 * Poll the single-vector intertrupt case: num_io_queues will be 1 and
 * there's only a single vector. While we're polling, we mask further
 * interrupts in the controller.
 */
void
nvme_ctrlr_intx_handler(void *arg)
{
	struct nvme_controller *ctrlr = arg;

	nvme_mmio_write_4(ctrlr, intms, 1);
	nvme_ctrlr_poll(ctrlr);
	nvme_mmio_write_4(ctrlr, intmc, 1);
}

static int
nvme_ctrlr_configure_intx(struct nvme_controller *ctrlr)
{

	ctrlr->msix_enabled = 0;
	ctrlr->num_io_queues = 1;
	ctrlr->num_cpus_per_ioq = mp_ncpus;
	ctrlr->rid = 0;
	ctrlr->res = bus_alloc_resource_any(ctrlr->dev, SYS_RES_IRQ,
	    &ctrlr->rid, RF_SHAREABLE | RF_ACTIVE);

	if (ctrlr->res == NULL) {
		nvme_printf(ctrlr, "unable to allocate shared IRQ\n");
		return (ENOMEM);
	}

	bus_setup_intr(ctrlr->dev, ctrlr->res,
	    INTR_TYPE_MISC | INTR_MPSAFE, NULL, nvme_ctrlr_intx_handler,
	    ctrlr, &ctrlr->tag);

	if (ctrlr->tag == NULL) {
		nvme_printf(ctrlr, "unable to setup intx handler\n");
		return (ENOMEM);
	}

	return (0);
}

static void
nvme_pt_done(void *arg, const struct nvme_completion *cpl)
{
	struct nvme_pt_command *pt = arg;

	bzero(&pt->cpl, sizeof(pt->cpl));
	pt->cpl.cdw0 = cpl->cdw0;
	pt->cpl.status = cpl->status;
	pt->cpl.status.p = 0;

	mtx_lock(pt->driver_lock);
	wakeup(pt);
	mtx_unlock(pt->driver_lock);
}

int
nvme_ctrlr_passthrough_cmd(struct nvme_controller *ctrlr,
    struct nvme_pt_command *pt, uint32_t nsid, int is_user_buffer,
    int is_admin_cmd)
{
	struct nvme_request	*req;
	struct mtx		*mtx;
	struct buf		*buf = NULL;
	int			ret = 0;
	vm_offset_t		addr, end;

	if (pt->len > 0) {
		/*
		 * vmapbuf calls vm_fault_quick_hold_pages which only maps full
		 * pages. Ensure this request has fewer than MAXPHYS bytes when
		 * extended to full pages.
		 */
		addr = (vm_offset_t)pt->buf;
		end = round_page(addr + pt->len);
		addr = trunc_page(addr);
		if (end - addr > MAXPHYS)
			return EIO;

		if (pt->len > ctrlr->max_xfer_size) {
			nvme_printf(ctrlr, "pt->len (%d) "
			    "exceeds max_xfer_size (%d)\n", pt->len,
			    ctrlr->max_xfer_size);
			return EIO;
		}
		if (is_user_buffer) {
			/*
			 * Ensure the user buffer is wired for the duration of
			 *  this passthrough command.
			 */
			PHOLD(curproc);
			buf = getpbuf(NULL);
			buf->b_data = pt->buf;
			buf->b_bufsize = pt->len;
			buf->b_iocmd = pt->is_read ? BIO_READ : BIO_WRITE;
#ifdef NVME_UNMAPPED_BIO_SUPPORT
			if (vmapbuf(buf, 1) < 0) {
#else
			if (vmapbuf(buf) < 0) {
#endif
				ret = EFAULT;
				goto err;
			}
			req = nvme_allocate_request_vaddr(buf->b_data, pt->len, 
			    nvme_pt_done, pt);
		} else
			req = nvme_allocate_request_vaddr(pt->buf, pt->len,
			    nvme_pt_done, pt);
	} else
		req = nvme_allocate_request_null(nvme_pt_done, pt);

	req->cmd.opc	= pt->cmd.opc;
	req->cmd.cdw10	= pt->cmd.cdw10;
	req->cmd.cdw11	= pt->cmd.cdw11;
	req->cmd.cdw12	= pt->cmd.cdw12;
	req->cmd.cdw13	= pt->cmd.cdw13;
	req->cmd.cdw14	= pt->cmd.cdw14;
	req->cmd.cdw15	= pt->cmd.cdw15;

	req->cmd.nsid = nsid;

	if (is_admin_cmd)
		mtx = &ctrlr->lock;
	else
		mtx = &ctrlr->ns[nsid-1].lock;

	mtx_lock(mtx);
	pt->driver_lock = mtx;

	if (is_admin_cmd)
		nvme_ctrlr_submit_admin_request(ctrlr, req);
	else
		nvme_ctrlr_submit_io_request(ctrlr, req);

	mtx_sleep(pt, mtx, PRIBIO, "nvme_pt", 0);
	mtx_unlock(mtx);

	pt->driver_lock = NULL;

err:
	if (buf != NULL) {
		relpbuf(buf, NULL);
		PRELE(curproc);
	}

	return (ret);
}

static int
nvme_ctrlr_ioctl(struct cdev *cdev, u_long cmd, caddr_t arg, int flag,
    struct thread *td)
{
	struct nvme_controller			*ctrlr;
	struct nvme_pt_command			*pt;

	ctrlr = cdev->si_drv1;

	switch (cmd) {
	case NVME_RESET_CONTROLLER:
		nvme_ctrlr_reset(ctrlr);
		break;
	case NVME_PASSTHROUGH_CMD:
		pt = (struct nvme_pt_command *)arg;
		return (nvme_ctrlr_passthrough_cmd(ctrlr, pt, pt->cmd.nsid,
		    1 /* is_user_buffer */, 1 /* is_admin_cmd */));
	default:
		return (ENOTTY);
	}

	return (0);
}

static struct cdevsw nvme_ctrlr_cdevsw = {
	.d_version =	D_VERSION,
	.d_flags =	0,
	.d_ioctl =	nvme_ctrlr_ioctl
};

static void
nvme_ctrlr_setup_interrupts(struct nvme_controller *ctrlr)
{
	device_t	dev;
	int		per_cpu_io_queues;
	int		min_cpus_per_ioq;
	int		num_vectors_requested, num_vectors_allocated;
	int		num_vectors_available;

	dev = ctrlr->dev;
	min_cpus_per_ioq = 1;
	TUNABLE_INT_FETCH("hw.nvme.min_cpus_per_ioq", &min_cpus_per_ioq);

	if (min_cpus_per_ioq < 1) {
		min_cpus_per_ioq = 1;
	} else if (min_cpus_per_ioq > mp_ncpus) {
		min_cpus_per_ioq = mp_ncpus;
	}

	per_cpu_io_queues = 1;
	TUNABLE_INT_FETCH("hw.nvme.per_cpu_io_queues", &per_cpu_io_queues);

	if (per_cpu_io_queues == 0) {
		min_cpus_per_ioq = mp_ncpus;
	}

	ctrlr->force_intx = 0;
	TUNABLE_INT_FETCH("hw.nvme.force_intx", &ctrlr->force_intx);

	/*
	 * FreeBSD currently cannot allocate more than about 190 vectors at
	 *  boot, meaning that systems with high core count and many devices
	 *  requesting per-CPU interrupt vectors will not get their full
	 *  allotment.  So first, try to allocate as many as we may need to
	 *  understand what is available, then immediately release them.
	 *  Then figure out how many of those we will actually use, based on
	 *  assigning an equal number of cores to each I/O queue.
	 */

	/* One vector for per core I/O queue, plus one vector for admin queue. */
	num_vectors_available = min(pci_msix_count(dev), mp_ncpus + 1);
	if (pci_alloc_msix(dev, &num_vectors_available) != 0) {
		num_vectors_available = 0;
	}
	pci_release_msi(dev);

	if (ctrlr->force_intx || num_vectors_available < 2) {
		nvme_ctrlr_configure_intx(ctrlr);
		return;
	}

	/*
	 * Do not use all vectors for I/O queues - one must be saved for the
	 *  admin queue.
	 */
	ctrlr->num_cpus_per_ioq = max(min_cpus_per_ioq,
	    howmany(mp_ncpus, num_vectors_available - 1));

	ctrlr->num_io_queues = howmany(mp_ncpus, ctrlr->num_cpus_per_ioq);
	num_vectors_requested = ctrlr->num_io_queues + 1;
	num_vectors_allocated = num_vectors_requested;

	/*
	 * Now just allocate the number of vectors we need.  This should
	 *  succeed, since we previously called pci_alloc_msix()
	 *  successfully returning at least this many vectors, but just to
	 *  be safe, if something goes wrong just revert to INTx.
	 */
	if (pci_alloc_msix(dev, &num_vectors_allocated) != 0) {
		nvme_ctrlr_configure_intx(ctrlr);
		return;
	}

	if (num_vectors_allocated < num_vectors_requested) {
		pci_release_msi(dev);
		nvme_ctrlr_configure_intx(ctrlr);
		return;
	}

	ctrlr->msix_enabled = 1;
}

int
nvme_ctrlr_construct(struct nvme_controller *ctrlr, device_t dev)
{
	union cap_lo_register	cap_lo;
	union cap_hi_register	cap_hi;
	int			status, timeout_period;

	ctrlr->dev = dev;

	mtx_init(&ctrlr->lock, "nvme ctrlr lock", NULL, MTX_DEF);

	status = nvme_ctrlr_allocate_bar(ctrlr);

	if (status != 0)
		return (status);

	/*
	 * Software emulators may set the doorbell stride to something
	 *  other than zero, but this driver is not set up to handle that.
	 */
	cap_hi.raw = nvme_mmio_read_4(ctrlr, cap_hi);
	if (cap_hi.bits.dstrd != 0)
		return (ENXIO);

	ctrlr->min_page_size = 1 << (12 + cap_hi.bits.mpsmin);

	/* Get ready timeout value from controller, in units of 500ms. */
	cap_lo.raw = nvme_mmio_read_4(ctrlr, cap_lo);
	ctrlr->ready_timeout_in_ms = cap_lo.bits.to * 500;

	timeout_period = NVME_DEFAULT_TIMEOUT_PERIOD;
	TUNABLE_INT_FETCH("hw.nvme.timeout_period", &timeout_period);
	timeout_period = min(timeout_period, NVME_MAX_TIMEOUT_PERIOD);
	timeout_period = max(timeout_period, NVME_MIN_TIMEOUT_PERIOD);
	ctrlr->timeout_period = timeout_period;

	nvme_retry_count = NVME_DEFAULT_RETRY_COUNT;
	TUNABLE_INT_FETCH("hw.nvme.retry_count", &nvme_retry_count);

	ctrlr->enable_aborts = 0;
	TUNABLE_INT_FETCH("hw.nvme.enable_aborts", &ctrlr->enable_aborts);

	nvme_ctrlr_setup_interrupts(ctrlr);

	ctrlr->max_xfer_size = NVME_MAX_XFER_SIZE;
	if (nvme_ctrlr_construct_admin_qpair(ctrlr) != 0)
		return (ENXIO);

	ctrlr->cdev = make_dev(&nvme_ctrlr_cdevsw, device_get_unit(dev),
	    UID_ROOT, GID_WHEEL, 0600, "nvme%d", device_get_unit(dev));

	if (ctrlr->cdev == NULL)
		return (ENXIO);

	ctrlr->cdev->si_drv1 = (void *)ctrlr;

	ctrlr->taskqueue = taskqueue_create("nvme_taskq", M_WAITOK,
	    taskqueue_thread_enqueue, &ctrlr->taskqueue);
	taskqueue_start_threads(&ctrlr->taskqueue, 1, PI_DISK, "nvme taskq");

	ctrlr->is_resetting = 0;
	ctrlr->is_initialized = 0;
	ctrlr->notification_sent = 0;
	TASK_INIT(&ctrlr->reset_task, 0, nvme_ctrlr_reset_task, ctrlr);

	TASK_INIT(&ctrlr->fail_req_task, 0, nvme_ctrlr_fail_req_task, ctrlr);
	STAILQ_INIT(&ctrlr->fail_req);
	ctrlr->is_failed = FALSE;

	return (0);
}

void
nvme_ctrlr_destruct(struct nvme_controller *ctrlr, device_t dev)
{
	int				i;

	/*
	 *  Notify the controller of a shutdown, even though this is due to
	 *   a driver unload, not a system shutdown (this path is not invoked
	 *   during shutdown).  This ensures the controller receives a
	 *   shutdown notification in case the system is shutdown before
	 *   reloading the driver.
	 */
	nvme_ctrlr_shutdown(ctrlr);

	nvme_ctrlr_disable(ctrlr);
	taskqueue_free(ctrlr->taskqueue);

	for (i = 0; i < NVME_MAX_NAMESPACES; i++)
		nvme_ns_destruct(&ctrlr->ns[i]);

	if (ctrlr->cdev)
		destroy_dev(ctrlr->cdev);

	for (i = 0; i < ctrlr->num_io_queues; i++) {
		nvme_io_qpair_destroy(&ctrlr->ioq[i]);
	}

	free(ctrlr->ioq, M_NVME);

	nvme_admin_qpair_destroy(&ctrlr->adminq);

	if (ctrlr->resource != NULL) {
		bus_release_resource(dev, SYS_RES_MEMORY,
		    ctrlr->resource_id, ctrlr->resource);
	}

	if (ctrlr->bar4_resource != NULL) {
		bus_release_resource(dev, SYS_RES_MEMORY,
		    ctrlr->bar4_resource_id, ctrlr->bar4_resource);
	}

	if (ctrlr->tag)
		bus_teardown_intr(ctrlr->dev, ctrlr->res, ctrlr->tag);

	if (ctrlr->res)
		bus_release_resource(ctrlr->dev, SYS_RES_IRQ,
		    rman_get_rid(ctrlr->res), ctrlr->res);

	if (ctrlr->msix_enabled)
		pci_release_msi(dev);
}

void
nvme_ctrlr_shutdown(struct nvme_controller *ctrlr)
{
	union cc_register	cc;
	union csts_register	csts;
	int			ticks = 0;

	cc.raw = nvme_mmio_read_4(ctrlr, cc);
	cc.bits.shn = NVME_SHN_NORMAL;
	nvme_mmio_write_4(ctrlr, cc, cc.raw);
	csts.raw = nvme_mmio_read_4(ctrlr, csts);
	while ((csts.bits.shst != NVME_SHST_COMPLETE) && (ticks++ < 5*hz)) {
		pause("nvme shn", 1);
		csts.raw = nvme_mmio_read_4(ctrlr, csts);
	}
	if (csts.bits.shst != NVME_SHST_COMPLETE)
		nvme_printf(ctrlr, "did not complete shutdown within 5 seconds "
		    "of notification\n");
}

void
nvme_ctrlr_submit_admin_request(struct nvme_controller *ctrlr,
    struct nvme_request *req)
{

	nvme_qpair_submit_request(&ctrlr->adminq, req);
}

void
nvme_ctrlr_submit_io_request(struct nvme_controller *ctrlr,
    struct nvme_request *req)
{
	struct nvme_qpair       *qpair;

	qpair = &ctrlr->ioq[curcpu / ctrlr->num_cpus_per_ioq];
	nvme_qpair_submit_request(qpair, req);
}

device_t
nvme_ctrlr_get_device(struct nvme_controller *ctrlr)
{

	return (ctrlr->dev);
}

const struct nvme_controller_data *
nvme_ctrlr_get_data(struct nvme_controller *ctrlr)
{

	return (&ctrlr->cdata);
}
