/*
 * Copyright (c) 2016, Marie Helene Kvello-Aune
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * thislist of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation and/or
 * other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

/*
 * Copyright (c) 1983, 1993
 *  The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
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

 /*
 * Copyright 1996 Massachusetts Institute of Technology
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that both the above copyright notice and this
 * permission notice appear in all copies, that both the above
 * copyright notice and this permission notice appear in all
 * supporting documentation, and that the name of M.I.T. not be used
 * in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  M.I.T. makes
 * no representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * THIS SOFTWARE IS PROVIDED BY M.I.T. ``AS IS''.  M.I.T. DISCLAIMS
 * ALL EXPRESS OR IMPLIED WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. IN NO EVENT
 * SHALL M.I.T. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_mib.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libifconfig.h"
#include "libifconfig_internal.h"


ifconfig_handle_t *
ifconfig_open(void)
{
	struct ifconfig_handle *h;

	h = calloc(1, sizeof(*h));
	for (int i = 0; i <= AF_MAX; i++) {
		h->sockets[i] = -1;
	}
	return (h);
}

void
ifconfig_close(ifconfig_handle_t *h)
{

	for (int i = 0; i <= AF_MAX; i++) {
		if (h->sockets[i] != -1) {
			(void)close(h->sockets[i]);
		}
	}
	free(h);
}

ifconfig_errtype
ifconfig_err_errtype(ifconfig_handle_t *h)
{

	return (h->error.errtype);
}

int
ifconfig_err_errno(ifconfig_handle_t *h)
{

	return (h->error.errcode);
}

unsigned long
ifconfig_err_ioctlreq(ifconfig_handle_t *h)
{

	return (h->error.ioctl_request);
}

int
ifconfig_get_description(ifconfig_handle_t *h, const char *name,
    char **description)
{
	struct ifreq ifr;
	char *descr;
	size_t descrlen;

	descr = NULL;
	descrlen = 64;
	memset(&ifr, 0, sizeof(ifr));
	(void)strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));

	for (;;) {
		if ((descr = reallocf(descr, descrlen)) == NULL) {
			h->error.errtype = OTHER;
			h->error.errcode = ENOMEM;
			return (-1);
		}

		ifr.ifr_buffer.buffer = descr;
		ifr.ifr_buffer.length = descrlen;
		if (ifconfig_ioctlwrap(h, AF_LOCAL, SIOCGIFDESCR, &ifr) != 0) {
			return (-1);
		}

		if (ifr.ifr_buffer.buffer == descr) {
			if (strlen(descr) > 0) {
				*description = strdup(descr);
				free(descr);
				return (0);
			}
		} else if (ifr.ifr_buffer.length > descrlen) {
			descrlen = ifr.ifr_buffer.length;
			continue;
		}
		break;
	}
	free(descr);
	h->error.errtype = OTHER;
	h->error.errcode = 0;
	return (-1);
}

int
ifconfig_set_description(ifconfig_handle_t *h, const char *name,
    const char *newdescription)
{
	struct ifreq ifr;
	int desclen;

	memset(&ifr, 0, sizeof(ifr));
	desclen = strlen(newdescription);

	/*
	 * Unset description if the new description is 0 characters long.
	 * TODO: Decide whether this should be an error condition instead.
	 */
	if (desclen == 0) {
		return (ifconfig_unset_description(h, name));
	}

	(void)strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	ifr.ifr_buffer.length = desclen + 1;
	ifr.ifr_buffer.buffer = strdup(newdescription);

	if (ifr.ifr_buffer.buffer == NULL) {
		h->error.errtype = OTHER;
		h->error.errcode = ENOMEM;
		return (-1);
	}

	if (ifconfig_ioctlwrap(h, AF_LOCAL, SIOCSIFDESCR,
	    &ifr) != 0) {
		free(ifr.ifr_buffer.buffer);
		return (-1);
	}

	free(ifr.ifr_buffer.buffer);
	return (0);
}

int
ifconfig_unset_description(ifconfig_handle_t *h, const char *name)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	(void)strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	ifr.ifr_buffer.length = 0;
	ifr.ifr_buffer.buffer = NULL;

	if (ifconfig_ioctlwrap(h, AF_LOCAL, SIOCSIFDESCR,
	    &ifr) < 0) {
		return (-1);
	}
	return (0);
}

int
ifconfig_set_name(ifconfig_handle_t *h, const char *name, const char *newname)
{
	struct ifreq ifr;
	char *tmpname;

	memset(&ifr, 0, sizeof(ifr));
	tmpname = strdup(newname);
	if (tmpname == NULL) {
		h->error.errtype = OTHER;
		h->error.errcode = ENOMEM;
		return (-1);
	}

	(void)strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	ifr.ifr_data = tmpname;
	if (ifconfig_ioctlwrap(h, AF_LOCAL, SIOCSIFNAME,
	    &ifr) != 0) {
		free(tmpname);
		return (-1);
	}

	free(tmpname);
	return (0);
}

int
ifconfig_get_orig_name(ifconfig_handle_t *h, const char *ifname,
    char **orig_name)
{
	struct ifmibdata ifmd;
	size_t len;
	int name[6];
	int i, maxifno;

	name[0] = CTL_NET;
	name[1] = PF_LINK;
	name[2] = NETLINK_GENERIC;
	name[3] = IFMIB_SYSTEM;
	name[4] = IFMIB_IFCOUNT;

	len = sizeof maxifno;
	if (sysctl(name, 5, &maxifno, &len, 0, 0) < 0) {
		h->error.errtype = OTHER;
		h->error.errcode = errno;
		return (-1);
	}

	name[3] = IFMIB_IFDATA;
	name[5] = IFDATA_GENERAL;
	for (i = 1; i <= maxifno; i++) {
		len = sizeof ifmd;
		name[4] = i;
		if (sysctl(name, 6, &ifmd, &len, 0, 0) < 0) {
			if (errno == ENOENT)
				continue;

			goto fail;
		}

		if (strncmp(ifmd.ifmd_name, ifname, IFNAMSIZ) != 0)
			continue;

		len = 0;
		name[5] = IFDATA_DRIVERNAME;
		if (sysctl(name, 6, NULL, &len, 0, 0) < 0)
			goto fail;

		*orig_name = malloc(len);
		if (*orig_name == NULL)
			goto fail;

		if (sysctl(name, 6, *orig_name, &len, 0, 0) < 0) {
			free(*orig_name);
			*orig_name = NULL;
			goto fail;
		}

		return (0);
	}

fail:
	h->error.errtype = OTHER;
	h->error.errcode = (i <= maxifno) ? errno : ENOENT;
	return (-1);
}

int
ifconfig_set_mtu(ifconfig_handle_t *h, const char *name, const int mtu)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	(void)strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	ifr.ifr_mtu = mtu;

	if (ifconfig_ioctlwrap(h, AF_LOCAL, SIOCSIFMTU,
	    &ifr) < 0) {
		return (-1);
	}

	return (0);
}

int
ifconfig_get_mtu(ifconfig_handle_t *h, const char *name, int *mtu)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	(void)strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));

	if (ifconfig_ioctlwrap(h, AF_LOCAL, SIOCGIFMTU,
	    &ifr) == -1) {
		return (-1);
	}

	*mtu = ifr.ifr_mtu;
	return (0);
}

int
ifconfig_set_metric(ifconfig_handle_t *h, const char *name, const int mtu)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	(void)strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	ifr.ifr_mtu = mtu;

	if (ifconfig_ioctlwrap(h, AF_LOCAL, SIOCSIFMETRIC,
	    &ifr) < 0) {
		return (-1);
	}

	return (0);
}

int
ifconfig_get_metric(ifconfig_handle_t *h, const char *name, int *metric)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	(void)strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));

	if (ifconfig_ioctlwrap(h, AF_LOCAL, SIOCGIFMETRIC,
	    &ifr) == -1) {
		return (-1);
	}

	*metric = ifr.ifr_metric;
	return (0);
}

int
ifconfig_set_capability(ifconfig_handle_t *h, const char *name,
    const int capability)
{
	struct ifreq ifr;
	struct ifconfig_capabilities ifcap;
	int flags, value;

	memset(&ifr, 0, sizeof(ifr));

	if (ifconfig_get_capability(h, name,
	    &ifcap) != 0) {
		return (-1);
	}

	value = capability;
	flags = ifcap.curcap;
	if (value < 0) {
		value = -value;
		flags &= ~value;
	} else {
		flags |= value;
	}
	flags &= ifcap.reqcap;

	(void)strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));

	/*
	 * TODO: Verify that it's safe to not have ifr.ifr_curcap
	 * set for this request.
	 */
	ifr.ifr_reqcap = flags;
	if (ifconfig_ioctlwrap(h, AF_LOCAL, SIOCSIFCAP,
	    &ifr) < 0) {
		return (-1);
	}
	return (0);
}

int
ifconfig_get_capability(ifconfig_handle_t *h, const char *name,
    struct ifconfig_capabilities *capability)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	(void)strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));

	if (ifconfig_ioctlwrap(h, AF_LOCAL, SIOCGIFCAP,
	    &ifr) < 0) {
		return (-1);
	}
	capability->curcap = ifr.ifr_curcap;
	capability->reqcap = ifr.ifr_reqcap;
	return (0);
}

int
ifconfig_destroy_interface(ifconfig_handle_t *h, const char *name)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	(void)strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));

	if (ifconfig_ioctlwrap(h, AF_LOCAL, SIOCIFDESTROY,
	    &ifr) < 0) {
		return (-1);
	}
	return (0);
}

int
ifconfig_create_interface(ifconfig_handle_t *h, const char *name, char **ifname)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	(void)strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));

	/*
	 * TODO:
	 * Insert special snowflake handling here. See GitHub issue #12 for details.
	 * In the meantime, hard-nosupport interfaces that need special handling.
	 */
	if ((strncmp(name, "wlan",
	    strlen("wlan")) == 0) ||
	    (strncmp(name, "vlan",
	    strlen("vlan")) == 0) ||
	    (strncmp(name, "vxlan",
	    strlen("vxlan")) == 0)) {
		h->error.errtype = OTHER;
		h->error.errcode = ENOSYS;
		return (-1);
	}

	/* No special handling for this interface type. */
	if (ifconfig_ioctlwrap(h, AF_LOCAL, SIOCIFCREATE2, &ifr) < 0) {
		return (-1);
	}

	*ifname = strdup(ifr.ifr_name);
	return (0);
}
