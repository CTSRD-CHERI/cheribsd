/*-
 * Copyright (c) 2015 SRI International
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
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
/*
 * CHERI CHANGES START
 * {
 *   "updated": 20181121,
 *   "target_type": "lib",
 *   "changes": [
 *     "calling_convention"
 *   ]
 * }
 * CHERI CHANGES END
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/ioctl.h>
#include <sys/types.h>
#include <stdarg.h>
#include <stddef.h>
#include "libc_private.h"

#ifdef __CHERI_PURE_CAPABILITY__
#include <cheri/cheric.h>
#endif

__weak_reference(__sys_ioctl, __ioctl);
#ifdef __CHERI_PURE_CAPABILITY__
__weak_reference(_ioctl, ioctl);
#endif

#ifndef __CHERI_PURE_CAPABILITY__
#pragma weak ioctl
int
ioctl(int fd, unsigned long com, ...)
#else
int _ioctl(int fd, unsigned long com, ...);
#pragma weak _ioctl
int
_ioctl(int fd, unsigned long com, ...)
#endif
{
	unsigned int size;
	va_list ap;
	void *data;

	size = IOCPARM_LEN(com);
	va_start(ap, com);
	if (size > 0) {
		if (com & IOC_VOID) {
			/*
			 * In the (size > 0 && com & IOC_VOID) case, the
			 * kernel assigns the value of data to an int
			 * and passes a pointer to that int down.
			 */
			/*
			 * XXX-BD: there is no telling what real
			 * applications are passing here.  We may want an
			 * __np_va_space_remaining() or the like to peak
			 * at the passed argument rather than crashing
			 * deep in a library.
			 */
			data = (void *)(intptr_t)(va_arg(ap, int));
		} else {
			data = va_arg(ap, void *);
		}
	} else {
#if defined(__CHERI_PURE_CAPABILITY__) && __mips__
		/*
		 * For some ioctls, the size is zero, but the handler still
		 * expect an address. This is done to skip the copyin in
		 * user_ioctl, and handle it manually in the ioctl handler.
		 */
		if (cheri_getlength((void *)ap) >= sizeof(void *))
			data = va_arg(ap, void *);
		else
			data = NULL;
#else
		/* Assume this was passed in a register. */
		data = (void *)(intptr_t)va_arg(ap, register_t);
#endif
	}
	va_end(ap);

	return (__sys_ioctl(fd, com, data));
}
