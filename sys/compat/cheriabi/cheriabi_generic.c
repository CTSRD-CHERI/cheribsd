/*-
 * Copyright (c) 2002 Doug Rabson
 * Copyright (c) 2015-2018 SRI International
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_ktrace.h"

#define	EXPLICIT_USER_ACCESS

#include <sys/param.h>
#include <sys/poll.h>
#include <sys/syscallsubr.h>
#include <sys/systm.h>
#include <sys/uio.h>

#include <compat/cheriabi/cheriabi_proto.h>
#include <compat/cheriabi/cheriabi_util.h>

int
cheriabi_read(struct thread *td, struct cheriabi_read_args *uap)
{

	return (user_read(td, uap->fd, uap->buf, uap->nbyte));
}

int
cheriabi_pread(struct thread *td, struct cheriabi_pread_args *uap)
{

	return (kern_pread(td, uap->fd, uap->buf, uap->nbyte, uap->offset));
}

int
cheriabi_readv(struct thread *td, struct cheriabi_readv_args *uap)
{
	struct uio *auio;
	int error;

	error = cheriabi_copyinuio(uap->iovp, uap->iovcnt, &auio);
	if (error)
		return (error);
	error = kern_readv(td, uap->fd, auio);
	free(auio, M_IOV);
	return (error);
}

int
cheriabi_preadv(struct thread *td, struct cheriabi_preadv_args *uap)
{
	struct uio *auio;
	int error;

	error = cheriabi_copyinuio(uap->iovp, uap->iovcnt, &auio);
	if (error)
		return (error);
	error = kern_preadv(td, uap->fd, auio, uap->offset);
	free(auio, M_IOV);
	return (error);
}

int
cheriabi_write(struct thread *td, struct cheriabi_write_args *uap)
{

	return (kern_write(td, uap->fd, uap->buf, uap->nbyte));
}

int
cheriabi_pwrite(struct thread *td, struct cheriabi_pwrite_args *uap)
{

	return (kern_pwrite(td, uap->fd, uap->buf, uap->nbyte,
	    uap->offset));
}

int
cheriabi_writev(struct thread *td, struct cheriabi_writev_args *uap)
{
	struct uio *auio;
	int error;

	error = cheriabi_copyinuio(uap->iovp, uap->iovcnt, &auio);
	if (error)
		return (error);
	error = kern_writev(td, uap->fd, auio);
	free(auio, M_IOV);
	return (error);
}

int
cheriabi_pwritev(struct thread *td, struct cheriabi_pwritev_args *uap)
{
	struct uio *auio;
	int error;

	error = cheriabi_copyinuio(uap->iovp, uap->iovcnt, &auio);
	if (error)
		return (error);
	error = kern_pwritev(td, uap->fd, auio, uap->offset);
	free(auio, M_IOV);
	return (error);
}

int
cheriabi_ioctl(struct thread *td, struct cheriabi_ioctl_args *uap)
{

	return (user_ioctl(td, uap->fd, uap->com, uap->data,
	    &uap->data, 1));
}

int
cheriabi_pselect(struct thread *td, struct cheriabi_pselect_args *uap)
{

	return (user_pselect(td, uap->nd, uap->in, uap->ou, uap->ex,
	    uap->ts, uap->sm));
}

int
cheriabi_select(struct thread *td, struct cheriabi_select_args *uap)
{

	return (user_select(td, uap->nd, uap->in, uap->ou, uap->ex,
	    uap->tv));
}

int
cheriabi_poll(struct thread *td, struct cheriabi_poll_args *uap)
{

	return (user_poll(td, uap->fds, uap->nfds, uap->timeout));
}

int
cheriabi_ppoll(struct thread *td, struct cheriabi_ppoll_args *uap)
{

	return (user_ppoll(td, uap->fds, uap->nfds, uap->ts, uap->set));
}
