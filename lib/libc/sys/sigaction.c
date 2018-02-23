/*
 * Copyright (c) 2014 The FreeBSD Foundation.
 * All rights reserved.
 *
 * Portions of this software were developed by Konstantin Belousov
 * under sponsorship from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice(s), this list of conditions and the following disclaimer as
 *    the first lines of this file unmodified other than the possible
 *    addition of one or more copyright notices.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice(s), this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER(S) ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
/* XXXAR: Hack to hide the static inline declaration for CHERIABI */
#define _BUILDING_SIGACTION
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include "libc_private.h"

__weak_reference(__sys_sigaction, __sigaction);
__weak_reference(sigaction, __libc_sigaction);

#ifdef __CHERI_PURE_CAPABILITY__
#include <cheri/cheric.h>
/*
 * In the CHERIABI case the sigaction declaration is inline so we need the
 * prototype here
 */
int	sigaction(int, const struct sigaction * __restrict,
	    struct sigaction * __restrict);

/*
 * In the CHERI pure capability ABI we also need to pass the CALLERS cgp to
 * the kernel. We do this by changing sigaction into an inline function that
 * passes cgp in addition to the normal parameters.
 */
int
cheriabi_sigaction(int sig, const struct sigaction *act,
    struct sigaction *oact, void* cgp)
{
	/*
	 * All the SIG_IGN, SIG_DFL, etc constants won't have the tag bit set
	 * so we can safely dereference act if it is tagged.
	 */
	if (cheri_gettag(act)) {
		struct sigaction copy;
		printf("%s: setting cgp for sigaction(%d) to %#p\n", __func__, sig, cgp);
		memcpy(&copy, act, sizeof(copy));
		copy.sa_cgp = cgp;
		return (__libc_sigaction(sig, &copy, oact));
	}

	return (__libc_sigaction(sig, act, oact));
}
#endif

#pragma weak sigaction
int
sigaction(int sig, const struct sigaction *act, struct sigaction *oact)
{

	return (((int (*)(int, const struct sigaction *, struct sigaction *))
	    __libc_interposing[INTERPOS_sigaction])(sig, act, oact));
}
