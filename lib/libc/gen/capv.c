/*-
 * Copyright (c) 2020 Edward Tomasz Napierala <trasz@FreeBSD.org>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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

#include <sys/param.h>
#include <sys/auxv.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libc_private.h"

/*
 * Convenience function to insert capabilities into capv, mostly
 * to handle reallocation.
 */
int
capvset(int *capcp, void * __capability **capvp, int new_index, void * __capability new_value)
{
	void * __capability *capv;
	void * __capability *old_capv;
	int capc;

	capc = *capcp;
	capv = *capvp;

	if (capc <= new_index) {
		/*
		 * XXX: We can't free old_capv, we don't know how it's been allocated.
		 */
		old_capv = capv;
		capv = calloc(new_index + 1, sizeof(void * __capability));
		if (capv == NULL) {
			//err(1, "calloc");
			return (-1);
		}

		if (capc > 0)
			memcpy(capv, old_capv, capc * sizeof(void * __capability));
#ifdef notyet
		capc = (new_index < 16 ? 8 : new_index) * 2;
#else
		capc = new_index + 1;
#endif
	}

	capv[new_index] = new_value;

	*capcp = capc;
	*capvp = capv;

	return (0);
}
