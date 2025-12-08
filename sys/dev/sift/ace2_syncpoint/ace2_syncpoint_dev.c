/*-
 * Copyright (c) 2025 Capabilities Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency (DARPA) Contract No. FA8750-24-C-B047 ("DEC").
 */

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/module.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/sbuf.h>
#include <sys/uio.h>

#include "ace2_syncpoint_internal.h"

static d_open_t ace2_syncpoint_dev_open;
static d_read_t ace2_syncpoint_dev_read;
static d_write_t ace2_syncpoint_dev_write;
static d_close_t ace2_syncpoint_dev_close;

static struct cdevsw ace2_syncpoint_dev_cdevsw = {
	.d_version = D_VERSION,
	.d_name = "ace2_syncpoint",
	.d_open = ace2_syncpoint_dev_open,
	.d_read = ace2_syncpoint_dev_read,
	.d_write = ace2_syncpoint_dev_write,
	.d_close = ace2_syncpoint_dev_close,
};

static int
ace2_syncpoint_dev_open(struct cdev *dev, int oflags, int devtype,
    struct thread *td)
{
	int error = 0;

	/* Require same permissions as /dev/kmem. */
	error = priv_check(td, PRIV_KMEM_READ | PRIV_KMEM_WRITE);
	if (error != 0)
		goto out;
	error = securelevel_gt(td->td_ucred, 0);
	if (error != 0)
		goto out;
	ace2_syncpoint_open(dev->si_drv1);
out:
	return (error);
}

static int
ace2_syncpoint_dev_read(struct cdev *dev, struct uio *uio, int ioflag)
{
	struct ace2_syncpoint_completion *ascp;
	struct sbuf *sb;
	int error;

	ascp = dev->si_drv1;
	ace2_syncpoint_read(ascp);

	/*
	 * With the exception of asc_flags, all fields below are stable for
	 * the lifetime of a completion.  For flags, accept a lockless read.
	 */
	sb = sbuf_new_auto();
	sbuf_printf(sb, "BARRIER_ID: %ju\n", ascp->asc_id);

	/*
	 * XXXRW: Assess 'COMPLETED' semantics on Linux -- does it correspond
	 * to our 'WRITTEN' or our 'WRITTEN|CONTINUED'?
	 */
	sbuf_printf(sb, "STATUS: %s\n", (ascp->asc_flags &
	    ACE2_SYNCPOINT_FLAG_CONTINUED) ? "COMPLETED" : "WAITING");
	sbuf_printf(sb, "LABEL: %s\n", ascp->asc_label);
	sbuf_printf(sb, "FILE: %s\n", ascp->asc_file);
	sbuf_printf(sb, "LINE: %u\n", ascp->asc_line);
	sbuf_printf(sb, "FUNC: %s\n", ascp->asc_func);
	error = sbuf_finish(sb);
	if (error)
		goto out;
	error = uiomove_frombuf(sbuf_data(sb), sbuf_len(sb), uio);
out:
	sbuf_delete(sb);
	return (error);
}

static int
ace2_syncpoint_dev_write(struct cdev *dev, struct uio *uio, int ioflag)
{
	struct ace2_syncpoint_completion *ascp;

	/*
	 * Picked up from the SIFT version -- does this ever happen in
	 * FreeBSD?
	 */
	if (uio->uio_resid == 0)
		return (0);

	/* Discard any written data. */
	uio->uio_resid = 0;

	ascp = dev->si_drv1;
	ace2_syncpoint_write(ascp);
	return (0);
}


int
ace2_syncpoint_dev_close(struct cdev *dev, int fflag, int devtype,
    struct thread *td)
{

	ace2_syncpoint_close(dev->si_drv1);
	return (0);
}

int
ace2_syncpoint_makedev(struct ace2_syncpoint_completion *ascp)
{
	struct make_dev_args devargs;

	make_dev_args_init(&devargs);
	devargs.mda_devsw = &ace2_syncpoint_dev_cdevsw;
	devargs.mda_uid = UID_ROOT;
	devargs.mda_gid = GID_WHEEL;
	devargs.mda_mode = 0600;
	devargs.mda_si_drv1 = ascp;
	return (make_dev_s(&devargs, &ascp->asc_cdevsw, "ace2_syncpoint/%d",
	    (int)ascp->asc_id));
}

void
ace2_syncpoint_destroydev(struct ace2_syncpoint_completion *ascp,
    void (*cb)(void *))
{

	/* Possible only if make_dev failed? */
	if (ascp->asc_cdevsw != NULL)
		destroy_dev_sched_cb(ascp->asc_cdevsw, cb, ascp);
}
