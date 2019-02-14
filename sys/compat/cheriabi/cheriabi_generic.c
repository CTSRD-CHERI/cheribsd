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

int
cheriabi_read(struct thread *td, struct cheriabi_read_args *uap)
{
	struct uio auio;
	kiovec_t aiov;
	int error;

	if (uap->nbyte > IOSIZE_MAX)
		return (EINVAL);
	IOVEC_INIT_C(&aiov, uap->buf, uap->nbyte);
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = uap->nbyte;
	auio.uio_segflg = UIO_USERSPACE;
	error = kern_readv(td, uap->fd, &auio);
	return(error);
}

int
cheriabi_pread(struct thread *td, struct cheriabi_pread_args *uap)
{
	struct uio auio;
	kiovec_t aiov;
	int error;

	if (uap->nbyte > IOSIZE_MAX)
		return (EINVAL);
	IOVEC_INIT_C(&aiov, uap->buf, uap->nbyte);
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = uap->nbyte;
	auio.uio_segflg = UIO_USERSPACE;
	error = kern_preadv(td, uap->fd, &auio, uap->offset);
	return (error);
}

int
cheriabi_write(struct thread *td, struct cheriabi_write_args *uap)
{
	struct uio auio;
	kiovec_t aiov;
	int error;

	if (uap->nbyte > IOSIZE_MAX)
		return (EINVAL);
	IOVEC_INIT_C(&aiov, __DECONST_CAP(void * __capability, uap->buf),
	    uap->nbyte);
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = uap->nbyte;
	auio.uio_segflg = UIO_USERSPACE;
	error = kern_writev(td, uap->fd, &auio);
	return(error);
}

int
cheriabi_pwrite(struct thread *td, struct cheriabi_pwrite_args *uap)
{
	struct uio auio;
	kiovec_t aiov;
	int error;

	if (uap->nbyte > IOSIZE_MAX)
		return (EINVAL);
	IOVEC_INIT_C(&aiov, __DECONST_CAP(void * __capability, uap->buf),
	    uap->nbyte);
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = uap->nbyte;
	auio.uio_segflg = UIO_USERSPACE;
	error = kern_pwritev(td, uap->fd, &auio, uap->offset);
	return(error);
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
	struct timespec ts;
	struct timeval tv, *tvp;
	sigset_t set, *uset;
	int error;

	if (uap->ts != NULL) {
		error = copyin(uap->ts, &ts, sizeof(ts));
		if (error != 0)
		    return (error);
		TIMESPEC_TO_TIMEVAL(&tv, &ts);
		tvp = &tv;
	} else
		tvp = NULL;
	if (uap->sm != NULL) {
		error = copyin(uap->sm, &set, sizeof(set));
		if (error != 0)
			return (error);
		uset = &set;
	} else
		uset = NULL;
	return (kern_pselect(td, uap->nd, uap->in, uap->ou, uap->ex, tvp,
	    uset, NFDBITS));
}

int
cheriabi_select(struct thread *td, struct cheriabi_select_args *uap)
{
	struct timeval tv, *tvp;
	int error;

	if (uap->tv != NULL) {
		error = copyin(uap->tv, &tv, sizeof(tv));
		if (error)
			return (error);
		tvp = &tv;
	} else
		tvp = NULL;

	return (kern_select(td, uap->nd, uap->in, uap->ou, uap->ex, tvp,
	    NFDBITS));
}

int
cheriabi_poll(struct thread *td, struct cheriabi_poll_args *uap)
{

	struct timespec ts, *tsp;

	if (uap->timeout != INFTIM) {
		if (uap->timeout < 0)
			return (EINVAL);
		ts.tv_sec = uap->timeout / 1000;
		ts.tv_nsec = (uap->timeout % 1000) * 1000000;
		tsp = &ts;
	} else
		tsp = NULL;

	return (kern_poll(td, uap->fds, uap->nfds, tsp, NULL));
}

int
cheriabi_ppoll(struct thread *td, struct cheriabi_ppoll_args *uap)
{
	struct timespec ts, *tsp;
	sigset_t set, *ssp;
	int error;

	if (uap->ts != NULL) {
		error = copyin(uap->ts, &ts, sizeof(ts));
		if (error)
			return (error);
		tsp = &ts;
	} else
		tsp = NULL;
	if (uap->set != NULL) {
		error = copyin(uap->set, &set, sizeof(set));
		if (error)
			return (error);
		ssp = &set;
	} else
		ssp = NULL;
		/*
		 * fds is still a pointer to user space. kern_poll() will
		 * perfrom the copyin.
		 */

	return (kern_poll(td, uap->fds, uap->nfds, tsp, ssp));
}
