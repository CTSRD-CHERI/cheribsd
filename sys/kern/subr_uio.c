/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1982, 1986, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Copyright (c) 2014 The FreeBSD Foundation
 *
 * Portions of this software were developed by Konstantin Belousov
 * under sponsorship from the FreeBSD Foundation.
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kdb.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/mman.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/rwlock.h>
#include <sys/sched.h>
#include <sys/sysent.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_extern.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/vm_map.h>

#include <machine/bus.h>

SYSCTL_INT(_kern, KERN_IOV_MAX, iov_max, CTLFLAG_RD, SYSCTL_NULL_INT_PTR, UIO_MAXIOV,
	"Maximum number of elements in an I/O vector; sysconf(_SC_IOV_MAX)");

static uma_zone_t uio_zone;

static int uiomove_flags(void *cp, int n, struct uio *uio, bool nofault,
    bool preserve_tags);

static void
uio_init(void *arg __unused)
{
	uio_zone = uma_zcreate("UIO", sizeof(struct uio),
	    NULL, NULL, NULL, NULL, UMA_ALIGN_PTR, 0);
}
SYSINIT(uio_init, SI_SUB_SYSCALLS, SI_ORDER_ANY, uio_init, NULL);

int
copyin_nofault(const void * __capability udaddr, void *kaddr, size_t len)
{
	int error, save;

	save = vm_fault_disable_pagefaults();
	error = copyin(udaddr, kaddr, len);
	vm_fault_enable_pagefaults(save);
	return (error);
}

int
copyout_nofault(const void *kaddr, void * __capability udaddr, size_t len)
{
	int error, save;

	save = vm_fault_disable_pagefaults();
	error = copyout(kaddr, udaddr, len);
	vm_fault_enable_pagefaults(save);
	return (error);
}

#if __has_feature(capabilities)
int
copyoutcap_nofault(const void *kaddr, void * __capability udaddr, size_t len)
{
	int error, save;

	save = vm_fault_disable_pagefaults();
	error = copyoutcap(kaddr, udaddr, len);
	vm_fault_enable_pagefaults(save);
	return (error);
}
#endif

#define	PHYS_PAGE_COUNT(len)	(howmany(len, PAGE_SIZE) + 1)

int
physcopyin(void *src, vm_paddr_t dst, size_t len)
{
	vm_page_t m[PHYS_PAGE_COUNT(len)];
	struct iovec iov[1];
	struct uio uio;
	int i;

	IOVEC_INIT(&iov[0], src, len);
	uio.uio_iov = iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = 0;
	uio.uio_resid = len;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_WRITE;
	for (i = 0; i < PHYS_PAGE_COUNT(len); i++, dst += PAGE_SIZE)
		m[i] = PHYS_TO_VM_PAGE(dst);
	return (uiomove_fromphys(m, dst & PAGE_MASK, len, &uio));
}

int
physcopyout(vm_paddr_t src, void *dst, size_t len)
{
	vm_page_t m[PHYS_PAGE_COUNT(len)];
	struct iovec iov[1];
	struct uio uio;
	int i;

	IOVEC_INIT(&iov[0], dst, len);
	uio.uio_iov = iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = 0;
	uio.uio_resid = len;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_READ;
	for (i = 0; i < PHYS_PAGE_COUNT(len); i++, src += PAGE_SIZE)
		m[i] = PHYS_TO_VM_PAGE(src);
	return (uiomove_fromphys(m, src & PAGE_MASK, len, &uio));
}

#undef PHYS_PAGE_COUNT

int
physcopyin_vlist(bus_dma_segment_t *src, off_t offset, vm_paddr_t dst,
    size_t len)
{
	size_t seg_len;
	int error;

	error = 0;
	while (offset >= src->ds_len) {
		offset -= src->ds_len;
		src++;
	}

	while (len > 0 && error == 0) {
		seg_len = MIN(src->ds_len - offset, len);
		error = physcopyin((char *)src->ds_vaddr + offset, dst,
		    seg_len);
		offset = 0;
		src++;
		len -= seg_len;
		dst += seg_len;
	}

	return (error);
}

int
physcopyout_vlist(vm_paddr_t src, bus_dma_segment_t *dst, off_t offset,
    size_t len)
{
	size_t seg_len;
	int error;

	error = 0;
	while (offset >= dst->ds_len) {
		offset -= dst->ds_len;
		dst++;
	}

	while (len > 0 && error == 0) {
		seg_len = MIN(dst->ds_len - offset, len);
		error = physcopyout(src, (char *)dst->ds_vaddr + offset,
		    seg_len);
		offset = 0;
		dst++;
		len -= seg_len;
		src += seg_len;
	}

	return (error);
}

int
uiomove(void *cp, int n, struct uio *uio)
{

	return (uiomove_flags(cp, n, uio, false, false));
}

int
uiomove_nofault(void *cp, int n, struct uio *uio)
{

	return (uiomove_flags(cp, n, uio, true, false));
}

int
uiomove_cap(void *cp, int n, struct uio *uio)
{

	return (uiomove_flags(cp, n, uio, false, true));
}


static int
uiomove_flags(void *cp, int n, struct uio *uio, bool nofault,
    bool preserve_tags)
{
	struct iovec *iov;
	size_t cnt;
	int error, newflags, save;

	save = error = 0;

	KASSERT(uio->uio_rw == UIO_READ || uio->uio_rw == UIO_WRITE,
	    ("uiomove: mode"));
	KASSERT(uio->uio_segflg != UIO_USERSPACE || uio->uio_td == curthread,
	    ("uiomove proc"));
	KASSERT(uio->uio_resid >= 0,
	    ("%s: uio %p resid underflow", __func__, uio));

	if (uio->uio_segflg == UIO_USERSPACE) {
		newflags = TDP_DEADLKTREAT;
		if (nofault) {
			/*
			 * Fail if a non-spurious page fault occurs.
			 */
			newflags |= TDP_NOFAULTING | TDP_RESETSPUR;
		} else {
			WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, NULL,
			    "Calling uiomove()");
		}
		save = curthread_pflags_set(newflags);
	} else {
		KASSERT(nofault == 0, ("uiomove: nofault"));
	}

	while (n > 0 && uio->uio_resid) {
		KASSERT(uio->uio_iovcnt > 0,
		    ("%s: uio %p iovcnt underflow", __func__, uio));

		iov = uio->uio_iov;
		cnt = iov->iov_len;
		if (cnt == 0) {
			uio->uio_iov++;
			uio->uio_iovcnt--;
			continue;
		}
		if (cnt > n)
			cnt = n;

		switch (uio->uio_segflg) {
		case UIO_USERSPACE:
			maybe_yield();
			if (preserve_tags) {
				if (uio->uio_rw == UIO_READ)
					error = copyoutcap(cp, iov->iov_base,
					    cnt);
				else
					error = copyincap(iov->iov_base, cp,
					    cnt);
			} else if (uio->uio_rw == UIO_READ)
				error = copyout(cp, iov->iov_base, cnt);
			else
				error = copyin(iov->iov_base, cp, cnt);
			if (error)
				goto out;
			break;

		case UIO_SYSSPACE:
			if (preserve_tags) {
				if (uio->uio_rw == UIO_READ)
					bcopy_c(PTR2CAP(cp), iov->iov_base,
					    cnt);
				else
					bcopy_c(iov->iov_base, PTR2CAP(cp),
					    cnt);
			} else if (uio->uio_rw == UIO_READ)
				bcopynocap_c(PTR2CAP(cp), iov->iov_base, cnt);
			else
				bcopynocap_c(iov->iov_base, PTR2CAP(cp), cnt);
			break;
		case UIO_NOCOPY:
			break;
		}
		IOVEC_ADVANCE(iov, cnt);
		uio->uio_resid -= cnt;
		uio->uio_offset += cnt;
		cp = (char *)cp + cnt;
		n -= cnt;
	}
out:
	if (save)
		curthread_pflags_restore(save);
	return (error);
}

/*
 * Wrapper for uiomove() that validates the arguments against a known-good
 * kernel buffer.  Currently, uiomove accepts a signed (n) argument, which
 * is almost definitely a bad thing, so we catch that here as well.  We
 * return a runtime failure, but it might be desirable to generate a runtime
 * assertion failure instead.
 */
int
uiomove_frombuf(void *buf, int buflen, struct uio *uio)
{
	size_t offset, n;

	if (uio->uio_offset < 0 || uio->uio_resid < 0 ||
	    (offset = uio->uio_offset) != uio->uio_offset)
		return (EINVAL);
	if (buflen <= 0 || offset >= buflen)
		return (0);
	if ((n = buflen - offset) > IOSIZE_MAX)
		return (EINVAL);
	return (uiomove((char *)buf + offset, n, uio));
}

/*
 * Give next character to user as result of read.
 */
int
ureadc(int c, struct uio *uio)
{
	struct iovec *iov;
	char * __capability iov_base;

	WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, NULL,
	    "Calling ureadc()");

again:
	if (uio->uio_iovcnt == 0 || uio->uio_resid == 0)
		panic("ureadc");
	iov = uio->uio_iov;
	if (iov->iov_len == 0) {
		uio->uio_iovcnt--;
		uio->uio_iov++;
		goto again;
	}
	switch (uio->uio_segflg) {
	case UIO_USERSPACE:
		if (subyte(iov->iov_base, c) < 0)
			return (EFAULT);
		break;

	case UIO_SYSSPACE:
		iov_base = iov->iov_base;
		*iov_base = c;
		break;

	case UIO_NOCOPY:
		break;
	}
	IOVEC_ADVANCE(iov, 1);
	uio->uio_resid--;
	uio->uio_offset++;
	return (0);
}

int
copyiniov(const struct iovec* __capability iovp, u_int iovcnt, struct iovec **iov,
    int error)
{
	struct iovec *iovs;
	size_t iovlen;

	*iov = NULL;
	if (iovcnt > UIO_MAXIOV)
		return (error);
	iovlen = iovcnt * sizeof(struct iovec);
	iovs = malloc(iovlen, M_IOV, M_WAITOK);
	error = copyincap(iovp, iovs, iovlen);
	if (error != 0)
		free(iovs, M_IOV);
	*iov = iovs;
	return (error);
}

int
copyinuio(const struct iovec * __capability iovp, u_int iovcnt,
    struct uio **uiop)
{
	struct iovec *iov;
	struct uio *uio;
	size_t iovlen;
	int error, i;

	*uiop = NULL;
	if (iovcnt > UIO_MAXIOV)
		return (EINVAL);
	iovlen = iovcnt * sizeof(struct iovec);
	uio = allocuio(iovcnt);
	iov = uio->uio_iov;
	error = copyincap(iovp, iov, iovlen);
	if (error != 0) {
		freeuio(uio);
		return (error);
	}
	uio->uio_iovcnt = iovcnt;
	uio->uio_segflg = UIO_USERSPACE;
	uio->uio_offset = -1;
	uio->uio_resid = 0;
	for (i = 0; i < iovcnt; i++) {
		if (iov->iov_len > IOSIZE_MAX - uio->uio_resid) {
			freeuio(uio);
			return (EINVAL);
		}
		uio->uio_resid += iov->iov_len;
		iov++;
	}
	*uiop = uio;
	return (0);
}

/*
 * Update the lengths in a userspace iovec to match those in a struct uio's
 * iovec.
 */
int
updateiov(const struct uio *uiop, struct iovec * __capability iovp)
{
	int i, error;

	for (i = 0; i < uiop->uio_iovcnt; i++) {
		error = suword(&iovp[i].iov_len, uiop->uio_iov[i].iov_len);
		if (error != 0)
			return (EFAULT);
	}
	return (0);
}

struct uio *
allocuio(u_int iovcnt)
{
	struct uio *uio;

	KASSERT(iovcnt <= UIO_MAXIOV,
	    ("Requested %u iovecs exceed UIO_MAXIOV", iovcnt));
	uio = uma_zalloc_arg(uio_zone, (void *)(uintptr_t)iovcnt, M_WAITOK);
#if defined(__CHERI_PURE_CAPABILITY__) && defined(__CHERI_SUBOBJECT_BOUNDS__)
	KASSERT(cheri_getlen(uio->uio_inline_iov) ==
	    UIO_INLINE_IOV * sizeof(struct iovec),
	    ("Malformed UIO structure, uio_inline_iov is not representable"));
#endif
	uio->uio_iov = uio->uio_inline_iov;
	uio->uio_flags = 0;
	if (iovcnt > UIO_INLINE_IOV) {
		uio->uio_ext_iov = malloc(iovcnt * sizeof(struct iovec), M_IOV,
		    M_WAITOK);
		uio->uio_iov = uio->uio_ext_iov;
		uio->uio_flags |= UIO_EXT_IOVEC;
	} else {
		uio->uio_iov = cheri_kern_setboundsexact(uio->uio_iov,
		    iovcnt * sizeof(struct iovec));
	}
	uio->uio_iovcnt = iovcnt;

	return (uio);
}

void
freeuio(struct uio *uio)
{
	if (uio == NULL)
		return;
	if (uio->uio_flags & UIO_EXT_IOVEC) {
#ifdef __CHERI_PURE_CAPABILITY__
		KASSERT(cheri_is_address_inbounds(uio->uio_ext_iov,
		    (ptraddr_t)uio->uio_iov),
		    ("IOV pointer is not within the external iov allocation"));
#endif
		free(uio->uio_ext_iov, M_IOV);
	}
	uma_zfree(uio_zone, uio);
}

struct uio *
cloneuio(struct uio *uiop)
{
	struct uio *uio;
	int iovlen;

	uio = allocuio(uiop->uio_iovcnt);
	bcopy(&uiop->uio_startcopy, &uio->uio_startcopy,
	    __rangeof(struct uio, uio_startcopy, uio_endcopy));
	iovlen = uiop->uio_iovcnt * sizeof(struct iovec);
	bcopy(uiop->uio_iov, uio->uio_iov, iovlen);
	return (uio);
}

/*
 * Map some anonymous memory in user space of size sz, rounded up to the page
 * boundary.
 */
int
copyout_map(struct thread *td, vm_pointer_t *addr, size_t sz)
{
	struct vmspace *vms;
	int error;
	vm_size_t size;

	vms = td->td_proc->p_vmspace;

	/*
	 * Map somewhere after heap in process memory.
	 */
	*addr = round_page((vm_pointer_t)vms->vm_daddr +
	    lim_max(td, RLIMIT_DATA));

	/* round size up to page boundary */
	size = (vm_size_t)round_page(sz);
	if (size == 0)
		return (EINVAL);
	error = vm_mmap_object(&vms->vm_map, addr, 0, size, VM_PROT_RW_CAP,
	    VM_PROT_ALL, MAP_PRIVATE | MAP_ANON, NULL, 0,
	    FALSE, td);
	return (error);
}

/*
 * Unmap memory in user space.
 */
int
copyout_unmap(struct thread *td, vm_pointer_t addr, size_t sz)
{
	vm_map_t map;
	vm_size_t size;

	if (sz == 0)
		return (0);

	map = &td->td_proc->p_vmspace->vm_map;
	size = (vm_size_t)round_page(sz);

	if (vm_map_remove(map, addr, addr + size) != KERN_SUCCESS)
		return (EINVAL);

	return (0);
}

int32_t
fuword32(volatile const void * __capability addr)
{
	int rv;
	int32_t val;

	rv = fueword32(addr, &val);
	return (rv == -1 ? -1 : val);
}

#if __SIZEOF_SIZE_T__ == 8
int64_t
fuword64(volatile const void * __capability addr)
{
	int rv;
	int64_t val;

	rv = fueword64(addr, &val);
	return (rv == -1 ? -1 : val);
}
#endif /* __SIZEOF_SIZE_T == 8 */

long
fuword(volatile const void * __capability addr)
{
	long val;
	int rv;

	rv = fueword(addr, &val);
	return (rv == -1 ? -1 : val);
}

uint32_t
casuword32(volatile uint32_t * __capability addr, uint32_t old, uint32_t new)
{
	int rv;
	uint32_t val;

	rv = casueword32(addr, old, &val, new);
	return (rv == -1 ? -1 : val);
}

u_long
casuword(volatile u_long * __capability addr, u_long old, u_long new)
{
	int rv;
	u_long val;

	rv = casueword(addr, old, &val, new);
	return (rv == -1 ? -1 : val);
}

// CHERI CHANGES START
// {
//   "updated": 20230509,
//   "target_type": "kernel",
//   "changes": [
//     "iovec-macros",
//     "user_capabilities"
//   ],
//   "changes_purecap": [
//     "support",
//     "pointer_as_integer",
//     "bounds_compression"
//   ]
// }
// CHERI CHANGES END
