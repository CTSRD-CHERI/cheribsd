/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 1999 Poul-Henning Kamp.
 * Copyright (c) 2008 Bjoern A. Zeeb.
 * Copyright (c) 2009 James Gritton.
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

#include "opt_ddb.h"
#include "opt_inet.h"
#include "opt_inet6.h"

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/syscallsubr.h>

#include <netinet/in.h>

#include <compat/freebsd64/freebsd64_proto.h>

struct jail64_v0 {
	u_int32_t	version;
	char * /* __ptr64 */ path;
	char * /* __ptr64 */ hostname;
	u_int32_t	ip_number;
};

struct jail64 {
	uint32_t	version;
	char * /* __ptr64 */ path;
	char * /* __ptr64 */ hostname;
	char * /* __ptr64 */ jailname;
	uint32_t	ip4s;
	uint32_t	ip6s;
	struct in_addr * /* __ptr64 */ ip4;
	struct in6_addr * /* __ptr64 */ ip6;
};

int
freebsd64_jail(struct thread *td, struct freebsd64_jail_args *uap)
{
	uint32_t version;
	int error;
	void *jail = uap->jailp;

	error = copyin(jail, &version, sizeof(version));
	if (error)
		return (error);

	switch (version) {
	case 0: {
		struct jail64_v0 j0;
		struct in_addr ip4;

		/* FreeBSD single IPv4 jails. */
		error = copyin(jail, &j0, sizeof(struct jail64_v0));
		if (error)
			return (error);
		/* jail_v0 is host order */
		ip4.s_addr = htonl(j0.ip_number);
		return (kern_jail(td, __USER_CAP_STR(j0.path),
		    __USER_CAP_STR(j0.hostname), NULL, &ip4, 1,
		    NULL, 0, UIO_SYSSPACE)); }

	case 1:
		/*
		 * Version 1 was used by multi-IPv4 jail implementations
		 * that never made it into the official kernel.
		 */
		return (EINVAL);

	case 2:	{ /* JAIL_API_VERSION */
		struct jail64 j;
		/* FreeBSD multi-IPv4/IPv6,noIP jails. */
		error = copyin(jail, &j, sizeof(struct jail64));
		if (error)
			return (error);
		return (kern_jail(td, __USER_CAP_STR(j.path),
		    __USER_CAP_STR(j.hostname), __USER_CAP_STR(j.jailname),
		    __USER_CAP_STR(j.ip4), j.ip4s, __USER_CAP_STR(j.ip6),
		    j.ip6s, UIO_USERSPACE));
	}

	default:
		/* Sci-Fi jails are not supported, sorry. */
		return (EINVAL);
	}
}
