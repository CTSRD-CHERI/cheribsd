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
 */

#ifndef _SYS_UIO_H_
#define	_SYS_UIO_H_

#include <sys/cdefs.h>
#include <sys/_types.h>
#include <sys/_iovec.h>
#include <sys/_uio.h>

#ifndef _SSIZE_T_DECLARED
typedef	__ssize_t	ssize_t;
#define	_SSIZE_T_DECLARED
#endif

#ifndef _OFF_T_DECLARED
typedef	__off_t	off_t;
#define	_OFF_T_DECLARED
#endif

#ifdef _KERNEL
/*
 * The number of inlined iovecs can be measured by looking at the
 * distribution of M_IOV allocations with dtrace.
 * The number of inlined iovecs is tuned to capture the majority of
 * allocations during a kernel build, measured using the dtrace dtmalloc
 * provider as in
 * dtrace -n 'dtmalloc::iov:malloc {@ = lquantize(args[3], 16, 4096, 8);}'
 *
 * It is possible to check whethe this value is well-tuned by computing the
 * ratio of M_IOV allocations over the number of uio_zone allocations.
 * This ratio should be << 1, if not this value may require tuning.
 */
#define	UIO_INLINE_IOV	2
/*
 * Mark an UIO with an externally allocated iovec array.
 */
#define	UIO_EXT_IOVEC	1

struct uio {
	struct iovec	*uio_iov;	/* scatter/gather list */
	int	uio_flags;		/* uio iovec buffer flags */
#define	uio_startcopy uio_iovcnt
	int	uio_iovcnt;		/* length of scatter/gather list */
	off_t	uio_offset;		/* offset in target object */
	ssize_t	uio_resid;		/* remaining bytes to process */
	enum	uio_seg uio_segflg;	/* address space */
	enum	uio_rw uio_rw;		/* operation */
	struct	thread *uio_td;		/* owner */
#define	uio_endcopy uio_ext_iov
	union {
		struct iovec	uio_inline_iov[UIO_INLINE_IOV];	/* inline iovec
								   array */
		struct iovec	*uio_ext_iov;	/* external iovec array */
	};
} __aligned(sizeof(void * __capability));

#if __has_feature(capabilities)
static __inline void
uiomove_enable_cap(struct uio *uio)
{
	switch (uio->uio_rw) {
	case UIO_READ:
		uio->uio_rw = UIO_READ_CAP;
		break;
	case UIO_WRITE:
		uio->uio_rw = UIO_WRITE_CAP;
		break;
	default:
		break;
	}
}
#else
#define	uiomove_enable_cap(uio)
#endif

/*
 * Limits
 *
 * N.B.: UIO_MAXIOV must be no less than IOV_MAX from <sys/syslimits.h>
 * which in turn must be no less than _XOPEN_IOV_MAX from <limits.h>.  If
 * we ever make this tunable (probably pointless), then IOV_MAX should be
 * removed from <sys/syslimits.h> and applications would be expected to use
 * sysconf(3) to find out the correct value, or else assume the worst
 * (_XOPEN_IOV_MAX).  Perhaps UIO_MAXIOV should be simply defined as
 * IOV_MAX.
 */
#define UIO_MAXIOV	1024		/* max 1K of iov's */

struct vm_object;
struct vm_page;
struct bus_dma_segment;

struct uio *allocuio(u_int iovcnt);
void	freeuio(struct uio *uio);
struct uio *cloneuio(struct uio *uiop);
int	copyiniov(const struct iovec * __capability iovp, u_int iovcnt,
	    struct iovec **iov, int error);
int	copyinuio(const struct iovec * __capability iovp, u_int iovcnt,
	    struct uio **uiop);
int	copyout_map(struct thread *td, vm_pointer_t *addr, size_t sz);
int	copyout_unmap(struct thread *td, vm_pointer_t addr, size_t sz);
int	physcopyin(void *src, vm_paddr_t dst, size_t len);
int	physcopyout(vm_paddr_t src, void *dst, size_t len);
int	physcopyin_vlist(struct bus_dma_segment *src, off_t offset,
	    vm_paddr_t dst, size_t len);
int	physcopyout_vlist(vm_paddr_t src, struct bus_dma_segment *dst,
	    off_t offset, size_t len);
int	uiomove(void *cp, int n, struct uio *uio);
int	uiomove_frombuf(void *buf, int buflen, struct uio *uio);
int	uiomove_fromphys(struct vm_page *ma[], vm_offset_t offset, int n,
	    struct uio *uio);
int	uiomove_nofault(void *cp, int n, struct uio *uio);
int	uiomove_object(struct vm_object *obj, off_t obj_size, struct uio *uio);
int	updateiov(const struct uio *uiop, struct iovec * __capability iovp);

#else /* !_KERNEL */

__BEGIN_DECLS
ssize_t	readv(int, const struct iovec *, int);
ssize_t	writev(int, const struct iovec *, int);
#if __BSD_VISIBLE
ssize_t	preadv(int, const struct iovec *, int, off_t);
ssize_t	pwritev(int, const struct iovec *, int, off_t);
#endif
__END_DECLS

#endif /* _KERNEL */

#endif /* !_SYS_UIO_H_ */
// CHERI CHANGES START
// {
//   "updated": 20230509,
//   "target_type": "header",
//   "changes": [
//     "user_capabilities"
//   ],
//   "changes_purecap": [
//     "pointer_as_integer",
//     "pointer_shape",
//     "bounds_compression"
//   ]
// }
// CHERI CHANGES END
