/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Konrad Witaszczyk
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency (DARPA) Contract No. FA8750-24-C-B047 ("DEC").
 */

/*
 * This file is based on the skeleton example from:
 * https://docs.freebsd.org/en/books/arch-handbook/driverbasics/
 */

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/uio.h>

#include "sift_sa.h"
#include "sift_sa_private.h"

extern struct sift_sa_data sift_sa_data_private;

static d_read_t sift_sa_private_read;
static d_write_t sift_sa_private_write;

static struct cdevsw sift_sa_private_cdevsw = {
	.d_version	= D_VERSION,
	.d_read		= sift_sa_private_read,
	.d_write	= sift_sa_private_write,
	.d_name		= "sift_sa_private",
};

static struct cdev *sift_sa_private_dev;

static int
sift_sa_private_read(struct cdev *dev, struct uio *uio, int ioflag __unused)
{

	return (uiomove_frombuf(sift_sa_data_private.buffer,
	    sift_sa_data_private.size, uio));
}

static int
sift_sa_private_write(struct cdev *dev, struct uio *uio, int ioflag __unused)
{
	size_t amt;
	int error;

	if (uio->uio_offset != 0 && (uio->uio_offset !=
	    sift_sa_data_private.size)) {
		return (EINVAL);
	}
	if (uio->uio_offset == 0)
		sift_sa_data_private.size = 0;

	amt = MIN(uio->uio_resid, (BUFFER_SIZE - sift_sa_data_private.size));
	error = uiomove(sift_sa_data_private.buffer + uio->uio_offset, amt,
	    uio);
	sift_sa_data_private.size = uio->uio_offset;
	return (error);
}

int
sift_sa_private_load(void)
{

	return (make_dev_p(MAKEDEV_CHECKNAME | MAKEDEV_WAITOK,
	    &sift_sa_private_dev, &sift_sa_private_cdevsw,
	    0, UID_ROOT, GID_WHEEL, 0600, "sift_sa_private"));
}

int
sift_sa_private_unload(void)
{

	if (sift_sa_private_dev != NULL)
		destroy_dev(sift_sa_private_dev);
	return (0);
}
