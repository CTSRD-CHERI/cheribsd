/*-
 * Copyright (c) 2020 Emmanuel Vadot <manu@FreeBSD.org>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mutex.h>

#include <cam/cam.h>
#include <cam/cam_ccb.h>
#include <cam/cam_debug.h>
#include <cam/cam_sim.h>
#include <cam/cam_xpt_sim.h>
#include <cam/mmc/mmc_sim.h>

#include "mmc_sim_if.h"

static void
mmc_cam_default_poll(struct cam_sim *sim)
{

	return;
}

static void
mmc_cam_sim_default_action(struct cam_sim *sim, union ccb *ccb)
{
	struct mmc_sim *mmc_sim;
	struct ccb_trans_settings_mmc mmc;
	int rv;

	mmc_sim = cam_sim_softc(sim);

	if (mmc_sim == NULL) {
		ccb->ccb_h.status = CAM_SEL_TIMEOUT;
		xpt_done(ccb);
		return;
	}

	mtx_assert(&mmc_sim->mtx, MA_OWNED);

	switch (ccb->ccb_h.func_code) {
	case XPT_PATH_INQ:
		rv = MMC_SIM_GET_TRAN_SETTINGS(mmc_sim->dev, &mmc);
		if (rv != 0) {
			ccb->ccb_h.status = CAM_REQ_INVALID;
		} else {
			mmc_path_inq(&ccb->cpi, "Deglitch Networks",
			    sim, mmc.host_max_data);
		}
		break;
	case XPT_GET_TRAN_SETTINGS:
	{
		struct ccb_trans_settings *cts = &ccb->cts;

		rv = MMC_SIM_GET_TRAN_SETTINGS(mmc_sim->dev, &cts->proto_specific.mmc);
		if (rv != 0)
			ccb->ccb_h.status = CAM_REQ_INVALID;
		else {
			cts->protocol = PROTO_MMCSD;
			cts->protocol_version = 1;
			cts->transport = XPORT_MMCSD;
			cts->transport_version = 1;
			cts->xport_specific.valid = 0;
			ccb->ccb_h.status = CAM_REQ_CMP;
		}
		break;
	}
	case XPT_SET_TRAN_SETTINGS:
	{
		struct ccb_trans_settings *cts = &ccb->cts;

		rv = MMC_SIM_SET_TRAN_SETTINGS(mmc_sim->dev, &cts->proto_specific.mmc);
		if (rv != 0)
			ccb->ccb_h.status = CAM_REQ_INVALID;
		else
			ccb->ccb_h.status = CAM_REQ_CMP;
		break;
	}
	case XPT_RESET_BUS:
		ccb->ccb_h.status = CAM_REQ_CMP;
		break;
	case XPT_MMC_IO:
	{
		rv = MMC_SIM_CAM_REQUEST(mmc_sim->dev, ccb);
		if (rv != 0)
			ccb->ccb_h.status = CAM_REQ_INPROG;
		else
			ccb->ccb_h.status = CAM_REQ_INVALID;
		return;
		/* NOTREACHED */
		break;
	}
	default:
		ccb->ccb_h.status = CAM_REQ_INVALID;
		break;
	}
	xpt_done(ccb);
	return;
}

int
mmc_cam_sim_alloc(device_t dev, const char *name, struct mmc_sim *mmc_sim)
{
	char sim_name[64], mtx_name[64];

	mmc_sim->dev = dev;

	if ((mmc_sim->devq = cam_simq_alloc(1)) == NULL) {
		goto fail;
	}

	snprintf(sim_name, sizeof(sim_name), "%s_sim", name);
	snprintf(mtx_name, sizeof(mtx_name), "%s_mtx", name);

	mtx_init(&mmc_sim->mtx, sim_name, NULL, MTX_DEF);
	mmc_sim->sim = cam_sim_alloc_dev(mmc_cam_sim_default_action,
	    mmc_cam_default_poll,
	    name, mmc_sim, dev,
	    &mmc_sim->mtx, 1, 1, mmc_sim->devq);

	if (mmc_sim->sim == NULL) {
		cam_simq_free(mmc_sim->devq);
		device_printf(dev, "cannot allocate CAM SIM\n");
		goto fail;
	}

	mtx_lock(&mmc_sim->mtx);
	if (xpt_bus_register(mmc_sim->sim, dev, 0) != 0) {
		device_printf(dev, "cannot register SCSI pass-through bus\n");
		cam_sim_free(mmc_sim->sim, FALSE);
		cam_simq_free(mmc_sim->devq);
		mtx_unlock(&mmc_sim->mtx);
		goto fail;
	}

	mtx_unlock(&mmc_sim->mtx);

	return (0);

fail:
	mmc_cam_sim_free(mmc_sim);
	return (1);
}

void
mmc_cam_sim_free(struct mmc_sim *mmc_sim)
{

	if (mmc_sim->sim != NULL) {
		mtx_lock(&mmc_sim->mtx);
		xpt_bus_deregister(cam_sim_path(mmc_sim->sim));
		cam_sim_free(mmc_sim->sim, FALSE);
		mtx_unlock(&mmc_sim->mtx);
	}

	if (mmc_sim->devq != NULL)
		cam_simq_free(mmc_sim->devq);
}

void
mmc_cam_sim_discover(struct mmc_sim *mmc_sim)
{

	mmccam_start_discovery(mmc_sim->sim);
}
