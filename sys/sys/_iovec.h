/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1982, 1986, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)uio.h	8.5 (Berkeley) 2/22/94
 * $FreeBSD$
 */

#ifndef _SYS__IOVEC_H_
#define	_SYS__IOVEC_H_

#include <sys/_types.h>

#ifndef _SIZE_T_DECLARED
typedef	__size_t	size_t;
#define	_SIZE_T_DECLARED
#endif

#ifndef _KERNEL
struct iovec {
	void *	iov_base;	/* Base address. */
	size_t			iov_len;	/* Length. */
};
#endif
#if __has_feature(capabilities)
struct iovec_c {
	void * __capability	iov_base;	/* Base address. */
	size_t			iov_len;	/* Length. */
};
#endif
struct iovec_native {
	void *	iov_base;	/* Base address. */
	size_t			iov_len;	/* Length. */
};
/* XXX: need some ifdefs */
#if __has_feature(capabilities)
typedef struct iovec_c		kiovec_t;
#else
typedef	struct iovec_native	kiovec_t;
#endif
typedef struct iovec_native	uiovec_t;

#if defined(_KERNEL)
#define	IOVEC_INIT(iovp, base, len)	do {				\
	(iovp)->iov_base = (__cheri_tocap void * __capability)(base);	\
	(iovp)->iov_len = (len);					\
} while(0)
#define IOVEC_INIT_C(iovp, base, len)	do {				\
	(iovp)->iov_base = (base);					\
	(iovp)->iov_len = (len);					\
} while(0)
#else
#define IOVEC_INIT(iovp, base, len)	do {				\
	(iovp)->iov_base = (base);					\
	(iovp)->iov_len = (len);					\
} while(0)
#define	IOVEC_INIT_C IOVEC_INIT
#endif

#define	IOVEC_INIT_STR(iovp, str)					\
	IOVEC_INIT(iovp, str, strlen(str) + 1)
#define	IOVEC_INIT_OBJ(iovp, obj)					\
	IOVEC_INIT(iovp, &(obj), sizeof(obj))

#define	IOVEC_ADVANCE(iovp, amt)	do {				\
	size_t amount = (amt);						\
	KASSERT(amount <= (iovp)->iov_len, ("%s: amount %zu > iov_len	\
	    %zu", __func__, amount, (iovp)->iov_len));			\
	(iovp)->iov_base = (char * __capability)((iovp)->iov_base) + amount; \
	(iovp)->iov_len -= amount;					\
} while(0)

#ifdef _KERNEL
struct uio;

typedef int (copyinuio_t)(void * __capability iovp, u_int iovcnt,
	    struct uio **iov);
#endif

#endif /* !_SYS__IOVEC_H_ */
// CHERI CHANGES START
// {
//   "updated": 20180629,
//   "target_type": "header",
//   "changes": [
//     "iovec-macros",
//     "kiovec_t"
//   ]
// }
// CHERI CHANGES END
