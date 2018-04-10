/*-
 * Copyright (c) 2008 David E. O'Brien
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
 * 3. Neither the name of the author nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
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

#include "opt_compat.h"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysproto.h>
#include <sys/capsicum.h>
#include <sys/cdio.h>
#include <sys/fcntl.h>
#include <sys/filio.h>
#include <sys/file.h>
#include <sys/ioccom.h>
#include <sys/malloc.h>
#include <sys/memrange.h>
#include <sys/proc.h>
#include <sys/syscall.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/user.h>

#include <machine/endian.h>

#include <compat/cheriabi/cheriabi.h>
#include <compat/cheriabi/cheriabi_proto.h>
/* Must come last due to massive header polution breaking cheriabi_proto.h */
#include <compat/cheriabi/cheriabi_ioctl.h>

MALLOC_DECLARE(M_IOCTLOPS);

/*
 * cheriabi_ioctl_translate_in - translate ioctl command and structure
 *
 * Maps *_C command in `com` to `*t_comp`.
 *
 * Allocates the appropriate structure and populates it, returning it in
 * `*t_datap`.
 */
static int
cheriabi_ioctl_translate_in(u_long com, void *data, u_long *t_comp,
    void **t_datap)
{

	return (EINVAL);
}

static int
cheriabi_ioctl_translate_out(u_long com, void *data, void *t_data)
{

	return (EINVAL);
}

static int
ioctl_data_contains_pointers(u_long cmd)
{

	return (0);
}

#define SYS_IOCTL_SMALL_SIZE	128
#define SYS_IOCTL_SMALL_ALIGN	sizeof(void * __capability)
int
cheriabi_ioctl(struct thread *td, struct cheriabi_ioctl_args *uap)
{
	u_char smalldata[SYS_IOCTL_SMALL_SIZE] __aligned(SYS_IOCTL_SMALL_ALIGN);
	u_long com, t_com, o_com;
	int arg, error;
	u_int size;
	caddr_t data;
	void *t_data;

	if (uap->com > 0xffffffff) {
		printf(
		    "WARNING pid %d (%s): ioctl sign-extension ioctl %lx\n",
		    td->td_proc->p_pid, td->td_name, uap->com);
		uap->com &= 0xffffffff;
	}
	com = uap->com;

	/*
	 * Interpret high order word to find amount of data to be
	 * copied to/from the user's address space.
	 */
	size = IOCPARM_LEN(com);
	if ((size > IOCPARM_MAX) ||
	    ((com & (IOC_VOID  | IOC_IN | IOC_OUT)) == 0) ||
#if defined(COMPAT_FREEBSD5) || defined(COMPAT_FREEBSD4) || defined(COMPAT_43)
	    ((com & IOC_OUT) && size == 0) ||
#else
	    ((com & (IOC_IN | IOC_OUT)) && size == 0) ||
#endif
	    ((com & IOC_VOID) && size > 0 && size != sizeof(int)))
		return (ENOTTY);

	if (size > 0) {
		if (com & IOC_VOID) {
			/* Integer argument. */
			arg = (intptr_t)uap->data;
			data = (void *)&arg;
			size = 0;
		} else {
			if (size > SYS_IOCTL_SMALL_SIZE)
				data = malloc((u_long)size, M_IOCTLOPS, M_WAITOK);
			else
				data = smalldata;
		}
	} else
		data = (void *)&uap->data;
	t_data = NULL;
	if (com & IOC_IN) {
		error = copyincap_c(uap->data,
		    (__cheri_tocap void * __capability)data, size);
		if (error != 0)
			goto out;
		if (ioctl_data_contains_pointers(com)) {
			error = cheriabi_ioctl_translate_in(com, data, &t_com, &t_data);
			if (error != 0)
				goto out;
			o_com = com;
			com = t_com;
		}
	} else if (com & IOC_OUT) {
		/*
		 * Zero the buffer so the user always
		 * gets back something deterministic.
		 */
		bzero(data, size);
	}

	if (t_data == NULL)
		error = kern_ioctl(td, uap->fd, com, data);
	else
		error = kern_ioctl(td, uap->fd, com, t_data);

	if (t_data && error == 0)
		error = cheriabi_ioctl_translate_out(o_com, data, t_data);
	if (error == 0 && (com & IOC_OUT)) {
		error = copyoutcap_c(
		    (__cheri_tocap void * __capability)data,
		    uap->data, (u_int)size);
	}

out:
	if (size > SYS_IOCTL_SMALL_SIZE)
		free(data, M_IOCTLOPS);
	return (error);
}
