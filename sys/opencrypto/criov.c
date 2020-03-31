/*      $OpenBSD: criov.c,v 1.9 2002/01/29 15:48:29 jason Exp $	*/

/*-
 * Copyright (c) 1999 Theo de Raadt
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/uio.h>
#include <sys/limits.h>
#include <sys/lock.h>

#include <opencrypto/cryptodev.h>

/*
 * This macro is only for avoiding code duplication, as we need to skip
 * given number of bytes in the same way in three functions below.
 */
#define	CUIO_SKIP()	do {						\
	KASSERT(off >= 0, ("%s: off %d < 0", __func__, off));		\
	KASSERT(len >= 0, ("%s: len %d < 0", __func__, len));		\
	while (off > 0) {						\
		KASSERT(iol >= 0, ("%s: empty in skip", __func__));	\
		if (off < iov->iov_len)					\
			break;						\
		off -= iov->iov_len;					\
		iol--;							\
		iov++;							\
	}								\
} while (0)

void
cuio_copydata(struct uio* uio, int off, int len, caddr_t cp)
{
	struct iovec *iov = uio->uio_iov;
	int iol = uio->uio_iovcnt;
	unsigned count;

	CUIO_SKIP();
	while (len > 0) {
		KASSERT(iol >= 0, ("%s: empty", __func__));
		count = min(iov->iov_len - off, len);
		bcopy(((caddr_t)iov->iov_base) + off, cp, count);
		len -= count;
		cp += count;
		off = 0;
		iol--;
		iov++;
	}
}

void
cuio_copyback(struct uio* uio, int off, int len, c_caddr_t cp)
{
	struct iovec *iov = uio->uio_iov;
	int iol = uio->uio_iovcnt;
	unsigned count;

	CUIO_SKIP();
	while (len > 0) {
		KASSERT(iol >= 0, ("%s: empty", __func__));
		count = min(iov->iov_len - off, len);
		bcopy(cp, ((caddr_t)iov->iov_base) + off, count);
		len -= count;
		cp += count;
		off = 0;
		iol--;
		iov++;
	}
}

/*
 * Return the index and offset of location in iovec list.
 */
int
cuio_getptr(struct uio *uio, int loc, int *off)
{
	int ind, len;

	ind = 0;
	while (loc >= 0 && ind < uio->uio_iovcnt) {
		len = uio->uio_iov[ind].iov_len;
		if (len > loc) {
	    		*off = loc;
	    		return (ind);
		}
		loc -= len;
		ind++;
	}

	if (ind > 0 && loc == 0) {
		ind--;
		*off = uio->uio_iov[ind].iov_len;
		return (ind);
	}

	return (-1);
}

/*
 * Apply function f to the data in an iovec list starting "off" bytes from
 * the beginning, continuing for "len" bytes.
 */
int
cuio_apply(struct uio *uio, int off, int len, int (*f)(void *, void *, u_int),
    void *arg)
{
	struct iovec *iov = uio->uio_iov;
	int iol = uio->uio_iovcnt;
	unsigned count;
	int rval;

	CUIO_SKIP();
	while (len > 0) {
		KASSERT(iol >= 0, ("%s: empty", __func__));
		count = min(iov->iov_len - off, len);
		rval = (*f)(arg, ((caddr_t)iov->iov_base) + off, count);
		if (rval)
			return (rval);
		len -= count;
		off = 0;
		iol--;
		iov++;
	}
	return (0);
}

void
crypto_copyback(struct cryptop *crp, int off, int size, const void *src)
{

	switch (crp->crp_buf_type) {
	case CRYPTO_BUF_MBUF:
		m_copyback(crp->crp_mbuf, off, size, src);
		break;
	case CRYPTO_BUF_UIO:
		cuio_copyback(crp->crp_uio, off, size, src);
		break;
	case CRYPTO_BUF_CONTIG:
		bcopy(src, crp->crp_buf + off, size);
		break;
	default:
		panic("invalid crp buf type %d", crp->crp_buf_type);
	}
}

void
crypto_copydata(struct cryptop *crp, int off, int size, void *dst)
{

	switch (crp->crp_buf_type) {
	case CRYPTO_BUF_MBUF:
		m_copydata(crp->crp_mbuf, off, size, dst);
		break;
	case CRYPTO_BUF_UIO:
		cuio_copydata(crp->crp_uio, off, size, dst);
		break;
	case CRYPTO_BUF_CONTIG:
		bcopy(crp->crp_buf + off, dst, size);
		break;
	default:
		panic("invalid crp buf type %d", crp->crp_buf_type);
	}
}

int
crypto_apply(struct cryptop *crp, int off, int len,
    int (*f)(void *, void *, u_int), void *arg)
{
	int error;

	switch (crp->crp_buf_type) {
	case CRYPTO_BUF_MBUF:
		error = m_apply(crp->crp_mbuf, off, len, f, arg);
		break;
	case CRYPTO_BUF_UIO:
		error = cuio_apply(crp->crp_uio, off, len, f, arg);
		break;
	case CRYPTO_BUF_CONTIG:
		error = (*f)(arg, crp->crp_buf + off, len);
		break;
	default:
		panic("invalid crp buf type %d", crp->crp_buf_type);
	}
	return (error);
}

int
crypto_mbuftoiov(struct mbuf *mbuf, struct iovec **iovptr, int *cnt,
    int *allocated)
{
	struct iovec *iov;
	struct mbuf *m, *mtmp;
	int i, j;

	*allocated = 0;
	iov = *iovptr;
	if (iov == NULL)
		*cnt = 0;

	m = mbuf;
	i = 0;
	while (m != NULL) {
		if (i == *cnt) {
			/* we need to allocate a larger array */
			j = 1;
			mtmp = m;
			while ((mtmp = mtmp->m_next) != NULL)
				j++;
			iov = malloc(sizeof *iov * (i + j), M_CRYPTO_DATA,
			    M_NOWAIT);
			if (iov == NULL)
				return ENOMEM;
			*allocated = 1;
			*cnt = i + j;
			memcpy(iov, *iovptr, sizeof *iov * i);
		}

		iov[i].iov_base = m->m_data;
		iov[i].iov_len = m->m_len;

		i++;
		m = m->m_next;
	}

	if (*allocated)
		KASSERT(*cnt == i, ("did not allocate correct amount: %d != %d",
		    *cnt, i));

	*iovptr = iov;
	*cnt = i;
	return 0;
}

static inline void *
m_contiguous_subsegment(struct mbuf *m, size_t skip, size_t len)
{
	int rel_off;

	MPASS(skip <= INT_MAX);

	m = m_getptr(m, (int)skip, &rel_off);
	if (m == NULL)
		return (NULL);

	MPASS(rel_off >= 0);
	skip = rel_off;
	if (skip + len > m->m_len)
		return (NULL);

	return (mtod(m, char*) + skip);
}

static inline void *
cuio_contiguous_segment(struct uio *uio, size_t skip, size_t len)
{
	int rel_off, idx;

	MPASS(skip <= INT_MAX);
	idx = cuio_getptr(uio, (int)skip, &rel_off);
	if (idx < 0)
		return (NULL);

	MPASS(rel_off >= 0);
	skip = rel_off;
	if (skip + len > uio->uio_iov[idx].iov_len)
		return (NULL);
	return ((char *)uio->uio_iov[idx].iov_base + skip);
}

void *
crypto_contiguous_subsegment(struct cryptop *crp, size_t skip, size_t len)
{

	switch (crp->crp_buf_type) {
	case CRYPTO_BUF_MBUF:
		return (m_contiguous_subsegment(crp->crp_mbuf, skip, len));
	case CRYPTO_BUF_UIO:
		return (cuio_contiguous_segment(crp->crp_uio, skip, len));
	case CRYPTO_BUF_CONTIG:
		return (crp->crp_buf + skip);
	default:
		panic("invalid crp buf type %d", crp->crp_buf_type);
	}
}
