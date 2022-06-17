/*-
 * Copyright (c) 2022 Edward Tomasz Napierala <trasz@FreeBSD.org>
 * All rights reserved.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory as part of the CHERI for Hypervisors and Operating Systems
 * (CHaOS) project, funded by EPSRC grant EP/V000292/1.
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

#include "namespace.h"
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "un-namespace.h"

/*
 * XXX: LRU?
 */
int
cocachedpid(pid_t *pidp, void * __capability cookie)
{
	ENTRY item, *found;
	char *str;
	int error, ret;

	/*
	 * FreeBSD's hcreate(3) doesn't do anything, so don't bother.
	 *
	 * Btw, the hsearch(3) API defines the key must be a proper string.
	 * Sigh.
	 */
	ret = asprintf(&str, "%lp", cookie);
	if (ret <= 0)
		return (-1);
	item.key = str;
	found = hsearch(item, FIND);
	if (!found) {
		/*
		 * Slow path.
		 */
		error = cogetpid(pidp);
		if (error != 0)
			return (error);
		item.data = (void * __capability)(uintcap_t)*pidp;
		found = hsearch(item, ENTER);
		if (!found)
			return (-1);
		return (0);
	}

	/*
	 * Fast path.
	 */
	*pidp = (uintcap_t)found->data;
	return (0);
}
