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

#include "opt_ddb.h"
#include "opt_inet.h"
#include "opt_inet6.h"

#include <sys/param.h>
#include <sys/abi_compat.h>
#include <sys/jail.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/syscallsubr.h>

#include <netinet/in.h>

#include <compat/freebsd64/freebsd64_proto.h>

struct jail64_v0 {
	uint32_t	version;
	uint64_t	path;
	uint64_t	hostname;
	uint32_t	ip_number;
};

struct jail64 {
	uint32_t	version;
	uint64_t	path;
	uint64_t	hostname;
	uint64_t	jailname;
	uint32_t	ip4s;
	uint32_t	ip6s;
	uint64_t	ip4;
	uint64_t	ip6;
};

int
freebsd64_jail(struct thread *td, struct freebsd64_jail_args *uap)
{
	uint32_t version;
	int error;
	void *jail = uap->jailp;
	struct jail j;

	error = copyin(__USER_CAP(jail, sizeof(version)), &version,
	    sizeof(version));
	if (error)
		return (error);

	switch (version) {
	case 0: {
		/* FreeBSD single IPv4 jails. */
		struct jail64_v0 j64_v0;

		bzero(&j, sizeof(j));
		error = copyin(__USER_CAP(jail, sizeof(j64_v0)), &j64_v0,
		    sizeof(j64_v0));
		if (error)
			return (error);
		CP(j64_v0, j, version);
		j.path = __USER_CAP_PATH(PTRIN(j64_v0.path));
		j.hostname = __USER_CAP_STR(PTRIN(j64_v0.hostname));
		j.ip4s = htonl(j64_v0.ip_number);	/* jail_v0 is host order */
		break;
	}

	case 1:
		/*
		 * Version 1 was used by multi-IPv4 jail implementations
		 * that never made it into the official kernel.
		 */
		return (EINVAL);

	case 2:	{ /* JAIL_API_VERSION */
		struct jail64 j64;
		/* FreeBSD multi-IPv4/IPv6,noIP jails. */
		error = copyin(__USER_CAP(jail, sizeof(j)), &j, sizeof(j));
		if (error)
			return (error);
		CP(j64, j, version);
		j.path = __USER_CAP_PATH(PTRIN(j.path));
		j.hostname = __USER_CAP_STR(PTRIN(j64.hostname));
		j.jailname = __USER_CAP_STR(PTRIN(j.jailname));
		CP(j64, j, ip4s);
		CP(j64, j, ip6s);
		j.ip4 = __USER_CAP(PTRIN(j.ip4), j.ip4s * sizeof(*j.ip4));
		j.ip6 = __USER_CAP(PTRIN(j.ip6), j.ip4s * sizeof(*j.ip6));
		break;
	}

	default:
		/* Sci-Fi jails are not supported, sorry. */
		return (EINVAL);
	}
	return (kern_jail(td, &j));
}
/*
 * CHERI CHANGES START
 * {
 *   "updated": 20230509,
 *   "target_type": "kernel",
 *   "changes": [
 *     "support"
 *   ]
 * }
 * CHERI CHANGES END
 */
