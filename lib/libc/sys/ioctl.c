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

#include <cheri/cheric.h>

#include <stdarg.h>
#include <stddef.h>
#include "libc_private.h"

#ifndef __CHERI_PURE_CAPABILITY__
__weak_reference(__sys_ioctl, __ioctl);
#else
__weak_reference(_ioctl, __ioctl);
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

	va_start(ap, com);

	/*
	 * In the (size > 0 && (com & IOC_VOID) != 0) case, the kernel assigns
	 * the value of data to an int and passes a pointer to that int down,
	 * so we want to extract an int here. Otherwise for (size > 0) we have
	 * a normal IN and/or OUT ioctl that takes a pointer to the actual data
	 * whose size is encoded, so we want to extract a pointer here.
	 *
	 * XXX: Not all ioctls adhere to the standard encoding, both in
	 * direction and in size. For example, GIO_KEYMAP is size == 0 with
	 * IOC_VOID as the real size doesn't fit in the parameter length field.
	 * In the size == 0 case, peek at the varargs array to see how much
	 * space is left. We may want an __np_va_space_remaining or the like to
	 * not assume the layout of the varargs array. This relies on varargs
	 * slots always being full capabilities with the integer in the address
	 * portion (or, if varargs bounds are not precise, that capabilities
	 * are little-endian), and always being capability-aligned if the
	 * varargs array capability's length is at least sizeof(void *) (which
	 * is true by virtue of stack-alignment on architectures without
	 * bounded varargs, and trivially true on architectures with bounded
	 * varargs, regardless of whether slots are capability-sized).
	 *
	 * Ideally these would be encoded differently to remove this ambiguity,
	 * perhaps as IOC_VOID with size(void *) like the int case.
	 */
	size = IOCPARM_LEN(com);
	if (size == 0)
		size = (void *)ap != NULL ?
		    cheri_bytes_remaining((void *)ap) : 0;
	else if ((com & IOC_VOID) != 0)
		size = sizeof(int);
	else
		size = sizeof(void *);

	if (size >= sizeof(void *))
		data = va_arg(ap, void *);
	else if (size >= sizeof(int))
		data = (void *)(intptr_t)va_arg(ap, int);
	else
		data = NULL;

	va_end(ap);

	return (__sys_ioctl(fd, com, data));
}
