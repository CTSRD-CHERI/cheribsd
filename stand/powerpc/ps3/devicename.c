/*-
 * Copyright (c) 1998 Michael Smith <msmith@freebsd.org>
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

#include <sys/disklabel.h>

#include <stand.h>
#include <string.h>

#include "bootstrap.h"
#include "ps3.h"
#include "ps3devdesc.h"

static int ps3_parsedev(struct ps3_devdesc **dev, const char *devspec,
    const char **path);

/*
 * Point (dev) at an allocated device specifier for the device matching the
 * path in (devspec). If it contains an explicit device specification,
 * use that.  If not, use the default device.
 */
int
ps3_getdev(void **vdev, const char *devspec, const char **path)
{
	struct ps3_devdesc **dev = (struct ps3_devdesc **)vdev;
	int rv = 0;

	/*
	 * If it looks like this is just a path and no
	 * device, go with the current device.
	 */
	if ((devspec == NULL) || (devspec[0] == '/') ||
	    (strchr(devspec, ':') == NULL)) {
		rv = ps3_parsedev(dev, getenv("currdev"), NULL);

		if (rv == 0 && path != NULL)
			*path = devspec;
		return(rv);
	}

	/*
	 * Try to parse the device name off the beginning of the devspec.
	 */
	return (ps3_parsedev(dev, devspec, path));
}

/*
 * Point (dev) at an allocated device specifier matching the string version
 * at the beginning of (devspec).  Return a pointer to the remaining
 * text in (path).
 *
 * In all cases, the beginning of (devspec) is compared to the names
 * of known devices in the device switch, and then any following text
 * is parsed according to the rules applied to the device type.
 *
 * For disk-type devices, the syntax is:
 *
 * disk<unit>[<partition>]:
 *
 */
static int
ps3_parsedev(struct ps3_devdesc **dev, const char *devspec, const char **path)
{
	struct ps3_devdesc *idev;
	struct devsw *dv;
	char *cp;
	const char *np;
	int i, unit, pnum, ptype, err;

	/* minimum length check */
	if (strlen(devspec) < 2)
		return(EINVAL);

	/* look for a device that matches */
	for (i = 0, dv = NULL; devsw[i] != NULL; i++) {
		if (!strncmp(devspec, devsw[i]->dv_name,
		    strlen(devsw[i]->dv_name))) {
			dv = devsw[i];
			break;
		}
	}
	if (dv == NULL)
		return(ENOENT);
	idev = malloc(sizeof(struct ps3_devdesc));
	err = 0;
	np = (devspec + strlen(dv->dv_name));

	switch(dv->dv_type) {
	case DEVT_NONE:
		break;

	case DEVT_DISK:
		unit = -1;
		pnum = -1;
		ptype = -1;
		if (*np && (*np != ':')) {
			/* next comes the unit number */
			unit = strtol(np, &cp, 10);
			if (cp == np) {
				err = EUNIT;
				goto fail;
			}
			if (*cp && (*cp != ':')) {
				/* get partition */
				if (*cp == 'p' && *(cp + 1) &&
				    *(cp + 1) != ':') {
					pnum = strtol(cp + 1, &cp, 10);
					ptype = PTYPE_GPT;
				} else {
					pnum = *cp - 'a';
					ptype = PTYPE_BSDLABEL;
					if ((pnum < 0) ||
					    (pnum >= MAXPARTITIONS)) {
						err = EPART;
						goto fail;
					}
					cp++;
				}
			}
		}
		if (*cp && (*cp != ':')) {
			err = EINVAL;
			goto fail;
		}

		idev->d_unit = unit;
		idev->d_disk.pnum = pnum;
		idev->d_disk.ptype = ptype;
		idev->d_disk.data = NULL;
		if (path != NULL)
			*path = (*cp == 0) ? cp : cp + 1;
		break;

	case DEVT_NET:
	case DEVT_CD:
		/*
		 * PS3 only has one network interface (well, two, but
		 * netbooting over wireless is not something I'm going
		 * to worry about.
		 */

		idev->d_unit = 0;
		break;

	default:
		err = EINVAL;
		goto fail;
	}
	idev->d_dev = dv;
	idev->d_type = dv->dv_type;
	if (dev == NULL) {
		free(idev);
	} else {
		*dev = idev;
	}
	return (0);

fail:
	free(idev);
	return (err);
}


char *
ps3_fmtdev(void *vdev)
{
	struct ps3_devdesc *dev = (struct ps3_devdesc *)vdev;
	char *cp;
	static char buf[128];

	switch(dev->d_type) {
	case DEVT_NONE:
		strcpy(buf, "(no device)");
		break;

	case DEVT_DISK:
		cp = buf;
		cp += sprintf(cp, "%s%d", dev->d_dev->dv_name, dev->d_unit);
		if (dev->d_kind.disk.pnum >= 0) {
			if (dev->d_kind.disk.ptype == PTYPE_BSDLABEL)
				cp += sprintf(cp, "%c",
				    dev->d_kind.disk.pnum + 'a');
			else if (dev->d_kind.disk.ptype == PTYPE_GPT)
				cp += sprintf(cp, "p%i",
				    dev->d_kind.disk.pnum);
		}

		strcat(cp, ":");
		break;

	case DEVT_NET:
	case DEVT_CD:
		sprintf(buf, "%s%d:", dev->d_dev->dv_name, dev->d_unit);
		break;
	}
	return(buf);
}

/*
 * Set currdev to suit the value being supplied in (value).
 */
int
ps3_setcurrdev(struct env_var *ev, int flags, const void *value)
{
	struct ps3_devdesc *ncurr;
	int rv;

	if ((rv = ps3_parsedev(&ncurr, value, NULL)) != 0)
		return (rv);
	free(ncurr);
	env_setenv(ev->ev_name, flags | EV_NOHOOK, value, NULL, NULL);
	return (0);
}
