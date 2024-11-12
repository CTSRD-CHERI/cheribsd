/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2018 Turing Robotic Industries Inc.
 * Copyright (c) 2000 Marcel Moolenaar
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

#include "../linux/linux_machdep.c"

CTASSERT(sizeof(struct l_iovec64) == 16);

int
linux64_copyiniov(struct l_iovec64 * __capability iovp64, l_ulong iovcnt,
    struct iovec **iovp, int error)
{
	struct l_iovec64 iov64;
	struct iovec *iov;
	uint64_t iovlen;
	int i;
	*iovp = NULL;
	if (iovcnt > UIO_MAXIOV)
		return (error);
	iovlen = iovcnt * sizeof(struct iovec);
	iov = malloc(iovlen, M_IOV, M_WAITOK);
	for (i = 0; i < iovcnt; i++) {
		error = copyin(&iovp64[i], &iov64, sizeof(struct l_iovec64));
		if (error) {
			free(iov, M_IOV);
			return (error);
		}
		IOVEC_INIT_C(&iov[i], __USER_CAP(iov64.iov_base,
		    iov64.iov_len), iov64.iov_len);
	}
	*iovp = iov;
	return(0);
}

int
linux64_copyinuio(struct l_iovec64 * __capability iovp, l_ulong iovcnt,
    struct uio **uiop)
{
	struct l_iovec64 iov64;
	struct iovec *iov;
	struct uio *uio;
	int error, i;

	*uiop = NULL;
	if (iovcnt > UIO_MAXIOV)
		return (EINVAL);
	uio = allocuio(iovcnt);
	iov = uio->uio_iov;
	for (i = 0; i < iovcnt; i++) {
		error = copyin(&iovp[i], &iov64, sizeof(struct l_iovec64));
		if (error) {
			freeuio(uio);
			return (error);
		}
		IOVEC_INIT_C(&iov[i], __USER_CAP(iov64.iov_base,
		    iov64.iov_len), iov64.iov_len);
	}
	uio->uio_iovcnt = iovcnt;
	uio->uio_segflg = UIO_USERSPACE;
	uio->uio_offset = -1;
	uio->uio_resid = 0;
	for (i = 0; i < iovcnt; i++) {
		if (iov->iov_len > SIZE_MAX - uio->uio_resid) {
			freeuio(uio);
			return (EINVAL);
		}
		uio->uio_resid += iov->iov_len;
		iov++;
	}
	*uiop = uio;
	return (0);
}