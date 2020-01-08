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
 *
 *	@(#)kern_subr.c	8.3 (Berkeley) 1/21/94
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

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

static int uiomove_faultflag(void *cp, int n, struct uio *uio, int nofault);

int
copyin_nofault(const void *udaddr, void *kaddr, size_t len)
{
	int error, save;

	save = vm_fault_disable_pagefaults();
	error = copyin(udaddr, kaddr, len);
	vm_fault_enable_pagefaults(save);
	return (error);
}

#if __has_feature(capabilities)
int
copyin_nofault_c(const void * __capability udaddr, void *kaddr, size_t len)
{
	int error, save;

	save = vm_fault_disable_pagefaults();
	error = copyin_c(udaddr, kaddr, len);
	vm_fault_enable_pagefaults(save);
	return (error);
}
#endif

int
copyout_nofault(const void *kaddr, void *udaddr, size_t len)
{
	int error, save;

	save = vm_fault_disable_pagefaults();
	error = copyout(kaddr, udaddr, len);
	vm_fault_enable_pagefaults(save);
	return (error);
}

#if __has_feature(capabilities)
int
copyout_nofault_c(const void *kaddr, void * __capability udaddr,
    size_t len)
{
	int error, save;

	save = vm_fault_disable_pagefaults();
	error = copyout_c(kaddr, udaddr, len);
	vm_fault_enable_pagefaults(save);
	return (error);
}

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
		error = physcopyin((void *)(uintptr_t)(src->ds_addr + offset),
		    dst, seg_len);
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
		error = physcopyout(src, (void *)(uintptr_t)(dst->ds_addr +
		    offset), seg_len);
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

	return (uiomove_faultflag(cp, n, uio, 0));
}

int
uiomove_nofault(void *cp, int n, struct uio *uio)
{

	return (uiomove_faultflag(cp, n, uio, 1));
}

static int
uiomove_faultflag(void *cp, int n, struct uio *uio, int nofault)
{
	struct iovec *iov;
	size_t cnt;
	int error, newflags, save;

	save = error = 0;

	KASSERT(uio->uio_rw == UIO_READ || uio->uio_rw == UIO_WRITE,
	    ("uiomove: mode"));
	KASSERT(uio->uio_segflg != UIO_USERSPACE || uio->uio_td == curthread,
	    ("uiomove proc"));

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
			if (uio->uio_rw == UIO_READ)
				error = copyout_c(cp, iov->iov_base, cnt);
			else
				error = copyin_c(iov->iov_base, cp, cnt);
			if (error)
				goto out;
			break;

		case UIO_SYSSPACE:
			if (uio->uio_rw == UIO_READ)
				bcopy(cp,
				    (__cheri_fromcap void *)iov->iov_base,
				    cnt);
			else
				bcopy((__cheri_fromcap void *)iov->iov_base,
				    cp, cnt);
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
		if (subyte_c(iov->iov_base, c) < 0)
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
copyinfrom(const void * __restrict src, void * __restrict dst, size_t len,
    int seg)
{
	int error = 0;

	switch (seg) {
	case UIO_USERSPACE:
		error = copyin(src, dst, len);
		break;
	case UIO_SYSSPACE:
		bcopy(src, dst, len);
		break;
	default:
		panic("copyinfrom: bad seg %d\n", seg);
	}
	return (error);
}

int
copyinstrfrom(const void * __restrict src, void * __restrict dst, size_t len,
    size_t * __restrict copied, int seg)
{
	int error = 0;

	switch (seg) {
	case UIO_USERSPACE:
		error = copyinstr(src, dst, len, copied);
		break;
	case UIO_SYSSPACE:
		error = copystr(src, dst, len, copied);
		break;
	default:
		panic("copyinstrfrom: bad seg %d\n", seg);
	}
	return (error);
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
	iovlen = iovcnt * sizeof (struct iovec);
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
	iovlen = iovcnt * sizeof (struct iovec);
	uio = malloc(iovlen + sizeof *uio, M_IOV, M_WAITOK);
	iov = (struct iovec *)(uio + 1);
	error = copyincap(iovp, iov, iovlen);
	if (error != 0) {
		free(uio, M_IOV);
		return (error);
	}
	uio->uio_iov = iov;
	uio->uio_iovcnt = iovcnt;
	uio->uio_segflg = UIO_USERSPACE;
	uio->uio_offset = -1;
	uio->uio_resid = 0;
	for (i = 0; i < iovcnt; i++) {
		if (iov->iov_len > IOSIZE_MAX - uio->uio_resid) {
			free(uio, M_IOV);
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
updateiov(const struct uio *uiop, struct iovec *iovp)
{
	int i, error;

	for (i = 0; i < uiop->uio_iovcnt; i++) {
		error = suword(&iovp[i].iov_len, uiop->uio_iov[i].iov_len);
		if (error != 0)
			return (error);
	}
	return (0);
}

struct uio *
cloneuio(struct uio *uiop)
{
	struct uio *uio;
	int iovlen;

	iovlen = uiop->uio_iovcnt * sizeof (struct iovec);
	uio = malloc(iovlen + sizeof *uio, M_IOV, M_WAITOK);
	*uio = *uiop;
	uio->uio_iov = (struct iovec *)(uio + 1);
	cheri_bcopy(uiop->uio_iov, uio->uio_iov, iovlen);
	return (uio);
}

/*
 * Map some anonymous memory in user space of size sz, rounded up to the page
 * boundary.
 */
int
copyout_map(struct thread *td, vm_offset_t *addr, size_t sz)
{
	struct vmspace *vms;
	int error;
	vm_size_t size;

	vms = td->td_proc->p_vmspace;

	/*
	 * Map somewhere after heap in process memory.
	 */
	*addr = round_page((vm_offset_t)vms->vm_daddr +
	    lim_max(td, RLIMIT_DATA));

	/* round size up to page boundary */
	size = (vm_size_t)round_page(sz);
	if (size == 0)
		return (EINVAL);
	error = vm_mmap_object(&vms->vm_map, addr, 0, size, VM_PROT_READ |
	    VM_PROT_WRITE, VM_PROT_ALL, MAP_PRIVATE | MAP_ANON, NULL, 0,
	    FALSE, td);
	return (error);
}

/*
 * Unmap memory in user space.
 */
int
copyout_unmap(struct thread *td, vm_offset_t addr, size_t sz)
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

#if __has_feature(capabilities) && !defined(CHERI_IMPLICIT_USER_DDC)
static inline bool
allow_implicit_capability_use(void)
{

	if (SV_CURPROC_FLAG(SV_CHERI)) {
		kdb_backtrace();
		/* XXX-BD: kill process? */
		return (false);
	}
	return (true);
}

/*
 * Construct a user data capability.  Ordinarily, we use __USER_CAP to
 * retrieve DDC, but the pcb isn't set up yet in do_execve() so while
 * we're in there we derive one from whole cloth.
 *
 * Longer term, we should store appropriate capabilities in struct
 * image_args along the way and use those.
 */
static inline void * __capability
io_user_cap(volatile const void * uaddr, size_t len)
{
	bool inexec;
	vaddr_t base;

	/* XXX: this is rather expensive... */
	PROC_LOCK(curproc);
	inexec = ((curproc->p_flag & P_INEXEC) != 0);
	PROC_UNLOCK(curproc);

	if (inexec) {
		base = CHERI_REPRESENTABLE_BASE((vaddr_t)uaddr, len);
		len = CHERI_REPRESENTABLE_LENGTH(len);
		return (cheri_capability_build_user_data(
		    CHERI_CAP_USER_DATA_PERMS, base, len, (vaddr_t)uaddr - base));
	}
	return (__USER_CAP(uaddr, len));
}

int
copyinstr(const void *uaddr, void *kaddr, size_t len, size_t *done)
{

	if (!allow_implicit_capability_use())
		return (EPROT);

	return (copyinstr_c(io_user_cap(uaddr, len), kaddr, len, done));
}

int
copyin(const void *uaddr, void *kaddr, size_t len)
{

	if (!allow_implicit_capability_use())
		return (EPROT);

	return (copyin_c(io_user_cap(uaddr, len), kaddr, len));
}

int
copyout(const void *kaddr, void *uaddr, size_t len)
{

	if (!allow_implicit_capability_use())
		return (EPROT);

	return (copyout_c(kaddr, io_user_cap(uaddr, len), len));
}

int
fubyte(volatile const void *base)
{

	if (!allow_implicit_capability_use())
		return (-1);

	return (fubyte_c(io_user_cap(base, 1)));
}

int
fueword(volatile const void *base, long *val)
{

	if (!allow_implicit_capability_use())
		return (-1);

	return (fueword_c(io_user_cap(base, sizeof(long)), val));
}

int
fueword32(volatile const void *base, int32_t *val)
{

	if (!allow_implicit_capability_use())
		return (-1);

	return (fueword32_c(io_user_cap(base, sizeof(int32_t)), val));
}

int
fueword64(volatile const void *base, int64_t *val)
{

	if (!allow_implicit_capability_use())
		return (-1);

	return (fueword64_c(io_user_cap(base, sizeof(int64_t)), val));
}

int
subyte(volatile void *base, int byte)
{

	if (!allow_implicit_capability_use())
		return (-1);

	return (subyte_c(io_user_cap(base, 1), byte));
}

int
suword(volatile void *base, long word)
{

	if (!allow_implicit_capability_use())
		return (-1);

	return (suword_c(io_user_cap(base, sizeof(long)), word));
}

int
suword32(volatile void *base, int32_t word)
{

	if (!allow_implicit_capability_use())
		return (-1);

	return (suword32_c(io_user_cap(base, sizeof(int32_t)), word));
}

int
suword64(volatile void *base, int64_t word)
{

	if (!allow_implicit_capability_use())
		return (-1);

	return (suword64_c(io_user_cap(base, sizeof(int64_t)), word));
}

int
casueword32(volatile uint32_t *base, uint32_t oldval, uint32_t *oldvalp,
    uint32_t newval)
{

	if (!allow_implicit_capability_use())
		return (-1);

	return (casueword32_c(io_user_cap(base, sizeof(u_long)), oldval,
	    oldvalp, newval));
}

int
casueword(volatile u_long *p, u_long oldval, u_long *oldvalp, u_long newval)
{

	if (!allow_implicit_capability_use())
		return (-1);

	return (casueword_c(io_user_cap(p, sizeof(u_long)), oldval,
	    oldvalp, newval));
}

int
copyin_implicit_cap(const void *uaddr, void *kaddr, size_t len)
{

	return (copyin_c(cheri_capability_build_user_data(
	    CHERI_CAP_USER_DATA_PERMS, (vaddr_t)uaddr, len, 0), kaddr, len));
}

int
copyout_implicit_cap(const void *kaddr, void *uaddr, size_t len)
{

	return (copyout_c(kaddr,
	    cheri_capability_build_user_data(CHERI_CAP_USER_DATA_PERMS,
	    (vaddr_t)uaddr, len, 0), len));
}
#else /* !( __has_feature(capabilities) && !defined(CHERI_IMPLICIT_USER_DDC)) */
int
copyin_implicit_cap(const void *uaddr, void *kaddr, size_t len)
{

	return (copyin(uaddr, kaddr, len));
}

int
copyout_implicit_cap(const void *kaddr, void *uaddr, size_t len)
{

	return (copyout(kaddr, uaddr, len));
}
#endif /* !(__has_feature(capabilities) && !defined(CHERI_IMPLICIT_USER_DDC)) */

#ifdef NO_FUEWORD
/*
 * XXXKIB The temporal implementation of fue*() functions which do not
 * handle usermode -1 properly, mixing it with the fault code.  Keep
 * this until MD code is written.  Currently sparc64 does not have a
 * proper implementation.
 */

int
fueword(volatile const void *base, long *val)
{
	long res;

	res = fuword(base);
	if (res == -1)
		return (-1);
	*val = res;
	return (0);
}

int
fueword32(volatile const void *base, int32_t *val)
{
	int32_t res;

	res = fuword32(base);
	if (res == -1)
		return (-1);
	*val = res;
	return (0);
}

#ifdef _LP64
int
fueword64(volatile const void *base, int64_t *val)
{
	int64_t res;

	res = fuword64(base);
	if (res == -1)
		return (-1);
	*val = res;
	return (0);
}
#endif

int
casueword32(volatile uint32_t *base, uint32_t oldval, uint32_t *oldvalp,
    uint32_t newval)
{
	int32_t ov;

	ov = casuword32(base, oldval, newval);
	if (ov == -1)
		return (-1);
	*oldvalp = ov;
	return (0);
}


int
casueword(volatile u_long *p, u_long oldval, u_long *oldvalp, u_long newval)
{
	u_long ov;

	ov = casuword(p, oldval, newval);
	if (ov == -1)
		return (-1);
	*oldvalp = ov;
	return (0);
}
#else /* NO_FUEWORD */
int32_t
fuword32(volatile const void *addr)
{
	int rv;
	int32_t val;

	rv = fueword32(addr, &val);
	return (rv == -1 ? -1 : val);
}

#ifdef _LP64
int64_t
fuword64(volatile const void *addr)
{
	int rv;
	int64_t val;

	rv = fueword64(addr, &val);
	return (rv == -1 ? -1 : val);
}
#endif /* _LP64 */

long
fuword(volatile const void *addr)
{
	long val;
	int rv;

	rv = fueword(addr, &val);
	return (rv == -1 ? -1 : val);
}

uint32_t
casuword32(volatile uint32_t *addr, uint32_t old, uint32_t new)
{
	int rv;
	uint32_t val;

	rv = casueword32(addr, old, &val, new);
	return (rv == -1 ? -1 : val);
}

u_long
casuword(volatile u_long *addr, u_long old, u_long new)
{
	int rv;
	u_long val;

	rv = casueword(addr, old, &val, new);
	return (rv == -1 ? -1 : val);
}

#endif /* NO_FUEWORD */

#if __has_feature(capabilities)
long
fuword_c(volatile const void * __capability base)
{
	long val;

	if (fueword_c(base, &val) == -1)
		return (-1);
	return (val);
}

int
fuword32_c(volatile const void * __capability base)
{
	int32_t val;

	if (fueword32_c(base, &val) == -1)
		return (-1);
	return (val);
}

int64_t
fuword64_c(volatile const void * __capability base)
{
	int64_t val;

	if (fueword64_c(base, &val) == -1)
		return (-1);
	return (val);
}

uint32_t
casuword32_c(volatile uint32_t * __capability base, uint32_t oldval,
    uint32_t newval)
{
	int32_t ov;

	if (casueword32_c(base, oldval, &ov, newval) == -1)
		return (-1);
	return (ov);
}
#endif
// CHERI CHANGES START
// {
//   "updated": 20191025,
//   "target_type": "kernel",
//   "changes": [
//     "iovec-macros",
//     "user_capabilities"
//   ]
// }
// CHERI CHANGES END
