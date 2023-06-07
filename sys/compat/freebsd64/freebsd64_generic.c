/*-
 * Copyright (c) 2015-2019 SRI International
 * Copyright (c) 2002 Doug Rabson
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of
 * the DARPA SSITH research programme.
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

#include "opt_ktrace.h"

#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/ioccom.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/specialfd.h>
#include <sys/syscallsubr.h>
#include <sys/systm.h>
#include <sys/uio.h>

#include <compat/freebsd64/freebsd64.h>
#include <compat/freebsd64/freebsd64_proto.h>
#include <compat/freebsd64/freebsd64_util.h>

int
freebsd64_read(struct thread *td, struct freebsd64_read_args *uap)
{
	return (user_read(td, uap->fd, __USER_CAP(uap->buf, uap->nbyte),
	    uap->nbyte));
}

int
freebsd64_pread(struct thread *td, struct freebsd64_pread_args *uap)
{
	return (kern_pread(td, uap->fd, __USER_CAP(uap->buf, uap->nbyte),
	    uap->nbyte, uap->offset));
}

#if defined(COMPAT_FREEBSD6)
int
freebsd6_freebsd64_pread(struct thread *td,
    struct freebsd6_freebsd64_pread_args *uap)
{
	return (kern_pread(td, uap->fd, __USER_CAP(uap->buf, uap->nbyte),
	    uap->nbyte, uap->offset));
}
#endif

int
freebsd64_readv(struct thread *td, struct freebsd64_readv_args *uap)
{
	return (user_readv(td, uap->fd, __USER_CAP_ARRAY(uap->iovp,
	    uap->iovcnt), uap->iovcnt, freebsd64_copyinuio));
}

int
freebsd64_preadv(struct thread *td, struct freebsd64_preadv_args *uap)
{
	return (user_preadv(td, uap->fd, __USER_CAP_ARRAY(uap->iovp,
	    uap->iovcnt), uap->iovcnt, uap->offset, freebsd64_copyinuio));
}

int
freebsd64_write(struct thread *td, struct freebsd64_write_args *uap)
{
	return (kern_write(td, uap->fd, __USER_CAP(uap->buf, uap->nbyte),
	    uap->nbyte));
}

int
freebsd64_pwrite(struct thread *td, struct freebsd64_pwrite_args *uap)
{
	return (kern_pwrite(td, uap->fd, __USER_CAP(uap->buf, uap->nbyte),
	    uap->nbyte, uap->offset));
}

#if defined(COMPAT_FREEBSD6)
int
freebsd6_freebsd64_pwrite(struct thread *td,
    struct freebsd6_freebsd64_pwrite_args *uap)
{
	return (kern_pwrite(td, uap->fd, __USER_CAP(uap->buf, uap->nbyte),
	    uap->nbyte, uap->offset));
}
#endif

int
freebsd64_writev(struct thread *td, struct freebsd64_writev_args *uap)
{
	return (user_writev(td, uap->fd, __USER_CAP_ARRAY(uap->iovp,
	    uap->iovcnt), uap->iovcnt, freebsd64_copyinuio));
}

int
freebsd64_pwritev(struct thread *td, struct freebsd64_pwritev_args *uap)
{
	return (user_pwritev(td, uap->fd,
	    (struct iovec *__capability)__USER_CAP_ARRAY(uap->iovp,
		uap->iovcnt), uap->iovcnt, uap->offset, freebsd64_copyinuio));
}

int
freebsd64_ioctl(struct thread *td, struct freebsd64_ioctl_args *uap)
{
	u_long com;
	void * __capability udata;

	com = uap->com;
	if (com & IOC_VOID)
		udata = (void * __capability)(intcap_t)uap->data;
	else
		udata = __USER_CAP(uap->data, IOCPARM_LEN(com));

	return (user_ioctl(td, uap->fd, com, udata, &uap->data, 0));
}

int
freebsd64_fspacectl(struct thread *td, struct freebsd64_fspacectl_args *uap)
{
	return (user_fspacectl(td, uap->fd, uap->cmd,
	    (const void * __capability)__USER_CAP_OBJ(uap->rqsr), uap->flags,
	    __USER_CAP_OBJ(uap->rmsr)));
}

int
freebsd64___specialfd(struct thread *td,
    struct freebsd64___specialfd_args *args)
{
	void * __capability req;

	switch(args->type) {
	case SPECIALFD_EVENTFD:
		req = __USER_CAP(args->req, sizeof(struct specialfd_eventfd));
		break;
	default:
		return (EINVAL);
	}

	return (user_specialfd(td, args->type, req, args->len));
}

int
freebsd64_pselect(struct thread *td, struct freebsd64_pselect_args *uap)
{
	return (user_pselect(td, uap->nd, __USER_CAP_UNBOUND(uap->in),
	    __USER_CAP_UNBOUND(uap->ou), __USER_CAP_UNBOUND(uap->ex),
	    __USER_CAP_OBJ(uap->ts), __USER_CAP_OBJ(uap->sm)));
}

int
freebsd64_select(struct thread *td, struct freebsd64_select_args *uap)
{
	return (user_select(td, uap->nd, __USER_CAP_UNBOUND(uap->in),
	    __USER_CAP_UNBOUND(uap->ou), __USER_CAP_UNBOUND(uap->ex),
	    __USER_CAP_OBJ(uap->tv)));
}

int
freebsd64_poll(struct thread *td, struct freebsd64_poll_args *uap)
{
	return (user_poll(td, __USER_CAP_ARRAY(uap->fds, uap->nfds),
	    uap->nfds, uap->timeout));
}

int
freebsd64_ppoll(struct thread *td, struct freebsd64_ppoll_args *uap)
{
	return (user_ppoll(td, __USER_CAP_ARRAY(uap->fds, uap->nfds),
	    uap->nfds, __USER_CAP_OBJ(uap->ts), __USER_CAP_OBJ(uap->set)));
}
