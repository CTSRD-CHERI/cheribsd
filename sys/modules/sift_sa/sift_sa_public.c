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
#include "sift_sa_public.h"

extern struct sift_sa_data sift_sa_data_public;

static d_read_t sift_sa_public_read;
static d_write_t sift_sa_public_write;

static struct cdevsw sift_sa_public_cdevsw = {
	.d_version	= D_VERSION,
	.d_read		= sift_sa_public_read,
	.d_write	= sift_sa_public_write,
	.d_name		= "sift_sa_public",
};

static struct cdev *sift_sa_public_dev;

static int
sift_sa_public_read(struct cdev *dev, struct uio *uio, int ioflag __unused)
{

	/*
	 * NB: There is no buffer bounds check.
	 */
	return (uiomove(sift_sa_data_public.buffer + uio->uio_offset,
	    uio->uio_resid, uio));
}

static int
sift_sa_public_write(struct cdev *dev, struct uio *uio, int ioflag __unused)
{
	size_t amt;
	int error;

	if (uio->uio_offset != 0 && (uio->uio_offset !=
	    sift_sa_data_public.size)) {
		return (EINVAL);
	}
	if (uio->uio_offset == 0)
		sift_sa_data_public.size = 0;

	amt = MIN(uio->uio_resid, (BUFFER_SIZE - sift_sa_data_public.size));
	error = uiomove(sift_sa_data_public.buffer + uio->uio_offset, amt, uio);
	sift_sa_data_public.size = uio->uio_offset;
	return (error);
}

int
sift_sa_public_load(void)
{

	return (make_dev_p(MAKEDEV_CHECKNAME | MAKEDEV_WAITOK,
	    &sift_sa_public_dev, &sift_sa_public_cdevsw,
	    0, UID_ROOT, GID_WHEEL, 0666, "sift_sa_public"));
}

int
sift_sa_public_unload(void)
{

	if (sift_sa_public_dev != NULL)
		destroy_dev(sift_sa_public_dev);
	return (0);
}
