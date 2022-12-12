/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1988 University of Utah.
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * Copyright (c) 2016 SRI International
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department.
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
 * from: Utah $Hdr: vm_mmap.c 1.6 91/10/21$
 *
 *	@(#)vm_mmap.c	8.4 (Berkeley) 1/12/94
 */

/*
 * Mapped file (mmap) interface to VM
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_hwpmc_hooks.h"
#include "opt_ktrace.h"
#include "opt_vm.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/capsicum.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sysproto.h>
#include <sys/elf.h>
#include <sys/filedesc.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/procctl.h>
#include <sys/racct.h>
#include <sys/resource.h>
#include <sys/resourcevar.h>
#include <sys/rwlock.h>
#include <sys/signal.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/syscallsubr.h>
#include <sys/sysent.h>
#include <sys/syslog.h>
#include <sys/uio.h>
#include <sys/ktrace.h>		/* Requires sys/signal.h, sys/uio.h */
#include <sys/vmmeter.h>
#if defined(__amd64__) || defined(__i386__) /* for i386_read_exec */
#include <machine/md_var.h>
#endif

#include <cheri/cheric.h>

#include <security/audit/audit.h>
#include <security/mac/mac_framework.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>
#include <vm/vm_pageout.h>
#include <vm/vm_extern.h>
#include <vm/vm_page.h>
#include <vm/vnode_pager.h>

#ifdef HWPMC_HOOKS
#include <sys/pmckern.h>
#endif

#if __has_feature(capabilities)
#include <cheri/cheric.h>
#endif

int old_mlock = 0;
SYSCTL_INT(_vm, OID_AUTO, old_mlock, CTLFLAG_RWTUN, &old_mlock, 0,
    "Do not apply RLIMIT_MEMLOCK on mlockall");
static int mincore_mapped = 1;
SYSCTL_INT(_vm, OID_AUTO, mincore_mapped, CTLFLAG_RWTUN, &mincore_mapped, 0,
    "mincore reports mappings, not residency");
static int imply_prot_max = 1;
SYSCTL_INT(_vm, OID_AUTO, imply_prot_max, CTLFLAG_RWTUN, &imply_prot_max, 0,
    "Imply maximum page protections in mmap() when none are specified");
static int log_wxrequests = 0;
SYSCTL_INT(_vm, OID_AUTO, log_wxrequests, CTLFLAG_RWTUN, &log_wxrequests, 0,
    "Log requests for PROT_WRITE and PROT_EXEC");

#ifdef MAP_32BIT
#define	MAP_32BIT_MAX_ADDR	((vm_offset_t)1 << 31)
#endif

_Static_assert(MAXPAGESIZES <= 4, "MINCORE_SUPER too narrow");

#if __has_feature(capabilities)
static int
cap_covers_pages(const void * __capability cap, size_t size)
{
	const char * __capability addr;
	size_t pageoff;

	addr = cap;
	pageoff = ((__cheri_addr ptraddr_t)addr & PAGE_MASK);
	addr -= pageoff;
	size += pageoff;
	size = (vm_size_t)round_page(size);

	return (__CAP_CHECK(__DECONST_CAP(void * __capability, addr), size));
}

static uintcap_t
mmap_retcap(struct thread *td, vm_pointer_t addr,
    const struct mmap_req *mrp)
{
	uintcap_t newcap;
#ifndef __CHERI_PURE_CAPABILITY__
	ptraddr_t cap_base __diagused;
	size_t cap_len __diagused;
#endif
	register_t perms, cap_prot;

	/*
	 * Return the original capability when MAP_CHERI_NOSETBOUNDS is set.
	 *
	 * NB: This means no permission changes.
	 * The assumption is that the larger capability has the correct
	 * permissions and we're only interested in adjusting page mappings.
	 */
	if (mrp->mr_flags & MAP_CHERI_NOSETBOUNDS)
		return ((uintcap_t)mrp->mr_source_cap);

	/*
	 * The purecap kernel returns a properly bounded capability
	 * from the vm_map API.  Hybrid kernels need to use the
	 * address 'addr' to derive a valid capability.
	 */
#ifdef __CHERI_PURE_CAPABILITY__
	KASSERT(cheri_gettag(addr), ("Expected valid capability"));
	newcap = addr;
	/* Enforce per-thread mmap capability permission */
	newcap = cheri_andperm(newcap, cheri_getperm(mrp->mr_source_cap));
#else
	newcap = (uintcap_t)mrp->mr_source_cap;
	if (mrp->mr_flags & MAP_FIXED) {
		/*
		 * If hint was under aligned, we need to return a
		 * capability to the whole, properly-aligned region
		 * with the offset pointing to hint.
		 */
		newcap = cheri_setaddress(newcap, rounddown2(addr, PAGE_SIZE));
		newcap = cheri_setbounds(newcap,
		    roundup2(mrp->mr_len + (addr - rounddown2(addr, PAGE_SIZE)),
		    PAGE_SIZE));
		/* Shift address up if required */
		newcap = cheri_setaddress(newcap, addr);
	} else {
		cap_base = cheri_getbase(newcap);
		cap_len = cheri_getlen(newcap);
		KASSERT(addr >= cap_base &&
		    addr + mrp->mr_len <= cap_base + cap_len,
		    ("Allocated range (%zx - %zx) is not within source "
		    "capability (%zx - %zx)", addr, addr + mrp->mr_len,
		    cap_base, cap_base + cap_len));
		newcap = cheri_setbounds(
		    cheri_setaddress(newcap, addr),
		    roundup2(mrp->mr_len, PAGE_SIZE));
	}
#endif

	/*
	 * If PROT_MAX() was not passed, use the prot value to derive
	 * capability permissions.
	 */
	cap_prot = PROT_MAX_EXTRACT(mrp->mr_prot);
	if (cap_prot == 0)
		cap_prot = PROT_EXTRACT(mrp->mr_prot);
	/*
	 * Set the permissions to PROT_MAX to allow a full
	 * range of access subject to page permissions.
	 */
	perms = ~CHERI_PROT2PERM_MASK | vm_map_prot2perms(cap_prot);
	newcap = cheri_andperm(newcap, perms);

	return (newcap);
}
#endif

#ifndef _SYS_SYSPROTO_H_
struct sbrk_args {
	int incr;
};
#endif

int
sys_sbrk(struct thread *td, struct sbrk_args *uap)
{
	/* Not yet implemented */
	return (EOPNOTSUPP);
}

#ifndef _SYS_SYSPROTO_H_
struct sstk_args {
	int incr;
};
#endif

int
sys_sstk(struct thread *td, struct sstk_args *uap)
{
	/* Not yet implemented */
	return (EOPNOTSUPP);
}

#if defined(COMPAT_43)
int
ogetpagesize(struct thread *td, struct ogetpagesize_args *uap)
{

	td->td_retval[0] = PAGE_SIZE;
	return (0);
}
#endif				/* COMPAT_43 */

static inline int
vm_wxcheck(struct proc *p, char *call)
{
	if (log_wxrequests)
		log(LOG_NOTICE, "%s(%d): W^X requested from %s\n",
		    p->p_comm, p->p_pid, call);
	return (0);
}

/*
 * Memory Map (mmap) system call.  Note that the file offset
 * and address are allowed to be NOT page aligned, though if
 * the MAP_FIXED flag it set, both must have the same remainder
 * modulo the PAGE_SIZE (POSIX 1003.1b).  If the address is not
 * page-aligned, the actual mapping starts at trunc_page(addr)
 * and the return value is adjusted up by the page offset.
 *
 * Generally speaking, only character devices which are themselves
 * memory-based, such as a video framebuffer, can be mmap'd.  Otherwise
 * there would be no cache coherency between a descriptor and a VM mapping
 * both to the same character device.
 */
#ifndef _SYS_SYSPROTO_H_
struct mmap_args {
	void *addr;
	size_t len;
	int prot;
	int flags;
	int fd;
	long pad;
	off_t pos;
};
#endif

int
sys_mmap(struct thread *td, struct mmap_args *uap)
{
#if !__has_feature(capabilities)
	return (kern_mmap(td, &(struct mmap_req){
		.mr_hint = (uintptr_t)uap->addr,
		.mr_len = uap->len,
		.mr_prot = uap->prot,
		.mr_flags = uap->flags,
		.mr_fd = uap->fd,
		.mr_pos = uap->pos,
	    }));
#else
	int flags = uap->flags, kern_flags = 0;
	void * __capability source_cap;
	register_t perms, reqperms;
	vm_offset_t hint;

	if (flags & MAP_32BIT) {
		SYSERRCAUSE("MAP_32BIT not supported in CheriABI");
		return (EINVAL);
	}

	/*
	 * Allow existing mapping to be replaced using the MAP_FIXED
	 * flag IFF the addr argument is a valid capability with the
	 * VMMAP user permission.  In this case, the new capability is
	 * derived from the passed capability.  In all other cases, the
	 * new capability is derived from the per-thread mmap capability.
	 *
	 * If MAP_FIXED specified and addr does not meet the above
	 * requirements, then MAP_EXCL is implied to prevent changing
	 * page contents without permission.
	 *
	 * XXXBD: The fact that using valid a capability to a currently
	 * unmapped region with and without the VMMAP permission will
	 * yield different results (and even failure modes) is potentially
	 * confusing and incompatible with non-CHERI code.  One could
	 * potentially check if the region contains any mappings and
	 * switch to using userspace_root_cap as the source
	 * capability if this pattern proves common.
	 */
	hint = cheri_getaddress(uap->addr);

	if (cheri_gettag(uap->addr)) {
		if ((flags & MAP_FIXED) == 0)
			return (EPROT);
		else if ((cheri_getperm(uap->addr) & CHERI_PERM_SW_VMEM))
			source_cap = uap->addr;
		else
			return (EACCES);
	} else {
		if (!cheri_is_null_derived(uap->addr))
			return (EINVAL);

		/*
		 * When a capability is not provided, we implicitly
		 * request the creation of a reservation.
		 */
		kern_flags |= MAP_RESERVATION_CREATE;

		if (flags & MAP_FIXED)
			flags |= MAP_EXCL;

		if (flags & MAP_CHERI_NOSETBOUNDS) {
			SYSERRCAUSE("MAP_CHERI_NOSETBOUNDS without a valid "
			    "addr capability");
			return (EINVAL);
		}

		source_cap = userspace_root_cap;
	}
	KASSERT(cheri_gettag(source_cap),
	    ("td->td_cheri_mmap_cap is untagged!"));

	/*
	 * If MAP_FIXED is specified, make sure that that the reqested
	 * address range fits within the source capability.
	 */
	if ((flags & MAP_FIXED) &&
	    (rounddown2(hint, PAGE_SIZE) < cheri_getbase(source_cap) ||
	    roundup2(hint + uap->len, PAGE_SIZE) >
	    cheri_getaddress(source_cap) + cheri_getlen(source_cap))) {
		SYSERRCAUSE("MAP_FIXED and too little space in "
		    "capablity (0x%zx < 0x%zx)",
		    cheri_getlen(source_cap) - cheri_getoffset(source_cap),
		    roundup2(uap->len, PAGE_SIZE));
		return (EPROT);
	}

	perms = cheri_getperm(source_cap);
	reqperms = vm_map_prot2perms(uap->prot);
#ifdef CHERI_PERM_EXECUTIVE
	if ((flags & MAP_FIXED) && (perms & CHERI_PERM_EXECUTIVE) == 0)
		/*
		 * Don't implicity require CHERI_PERM_EXECUTIVE if it's
		 * not available in source capability.
		 */
		reqperms &= ~CHERI_PERM_EXECUTIVE;
#endif
	if ((perms & reqperms) != reqperms) {
		SYSERRCAUSE("capability has insufficient perms (0x%lx)"
		    "for request (0x%lx)", perms, reqperms);
		return (EPROT);
	}

	if ((flags & MAP_ALIGNMENT_MASK) == MAP_ALIGNED_SUPER) {
#if VM_NRESERVLEVEL > 0
		/*
		 * pmap_align_superpage() is a no-op for allocations
		 * less than a super page so request data alignment
		 * in that case.
		 *
		 * In practice this is a no-op as super-pages are
		 * precisely representable.
		 */
		if (uap->len < (1UL << (VM_LEVEL_0_ORDER + PAGE_SHIFT)) &&
		    CHERI_REPRESENTABLE_ALIGNMENT(uap->len) > (1UL << PAGE_SHIFT)) {
			flags &= ~MAP_ALIGNMENT_MASK;
			flags |= MAP_ALIGNED_CHERI;
		}
#endif
	}
	else if ((flags & MAP_ALIGNMENT_MASK) != MAP_ALIGNED(0) &&
		 (flags & MAP_ALIGNMENT_MASK) != MAP_ALIGNED_CHERI &&
		 (flags & MAP_ALIGNMENT_MASK) != MAP_ALIGNED_CHERI_SEAL) {
		/* Reject nonsensical sub-page alignment requests */
		if ((flags >> MAP_ALIGNMENT_SHIFT) < PAGE_SHIFT) {
			SYSERRCAUSE("subpage alignment request");
			return (EINVAL);
		}
	}

	/*
	 * NOTE: If this architecture requires an alignment constraint, it is
	 * set at this point.  A simple assert is not easy to contruct...
	 */

	return (kern_mmap(td, &(struct mmap_req){
		.mr_hint = hint,
		.mr_max_addr = cheri_gettop(source_cap),
		.mr_len = uap->len,
		.mr_prot = uap->prot,
		.mr_flags = flags,
		.mr_kern_flags = kern_flags,
		.mr_fd = uap->fd,
		.mr_pos = uap->pos,
		.mr_source_cap = source_cap,
	    }));
#endif
}

int
kern_mmap_maxprot(struct proc *p, int prot)
{

#if __has_feature(capabilities)
	if (SV_PROC_FLAG(p, SV_CHERI))
		return (prot);
#endif
	if ((p->p_flag2 & P2_PROTMAX_DISABLE) != 0 ||
	    (p->p_fctl0 & NT_FREEBSD_FCTL_PROTMAX_DISABLE) != 0)
		return (_PROT_ALL);
	if (((p->p_flag2 & P2_PROTMAX_ENABLE) != 0 || imply_prot_max) &&
	    prot != PROT_NONE)
		 return (prot);
	return (_PROT_ALL);
}

int
kern_mmap(struct thread *td, const struct mmap_req *mrp)
{
	struct vmspace *vms;
	struct file *fp;
	struct proc *p;
	off_t pos;
	vm_offset_t addr_mask = PAGE_MASK;
	vm_pointer_t addr, orig_addr;
	vm_offset_t max_addr;
	vm_size_t len, pageoff, size;
	vm_prot_t cap_maxprot;
	int align, error, fd, flags, max_prot, prot;
	cap_rights_t rights;
	mmap_check_fp_fn check_fp_fn;
	int cap_prot;

	orig_addr = addr = mrp->mr_hint;
	max_addr = mrp->mr_max_addr;
	len = mrp->mr_len;
	prot = mrp->mr_prot;
	flags = mrp->mr_flags;
	fd = mrp->mr_fd;
	pos = mrp->mr_pos;
	check_fp_fn = mrp->mr_check_fp_fn;

	p = td->td_proc;

	if ((prot & ~(_PROT_ALL | PROT_MAX(_PROT_ALL))) != 0) {
		SYSERRCAUSE(
		    "%s: invalid bits in prot %x", __func__,
		    (prot & ~(_PROT_ALL | PROT_MAX(_PROT_ALL))));
		return (EINVAL);
	}
	max_prot = PROT_MAX_EXTRACT(prot);
	prot = PROT_EXTRACT(prot);
	if (max_prot != 0 && (max_prot & prot) != prot) {
		SYSERRCAUSE(
		    "%s: requested page permissions exceed requested maximum",
		    __func__);
		return (ENOTSUP);
	}
	if ((prot & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC) &&
	    (error = vm_wxcheck(p, "mmap")))
		return (error);

	/*
	 * Always honor PROT_MAX if set.  If not, default to all
	 * permissions unless we're implying maximum permissions.
	 */
	if (max_prot == 0) {
		max_prot = kern_mmap_maxprot(p, prot);
		cap_prot = prot;
	} else
		cap_prot = max_prot;

	vms = p->p_vmspace;
	fp = NULL;
	AUDIT_ARG_FD(fd);

	/*
	 * Ignore old flags that used to be defined but did not do anything.
	 */
	if (!SV_CURPROC_FLAG(SV_CHERI))
		flags &= ~(MAP_RESERVED0020 | MAP_RESERVED0040);
	
	/*
	 * Enforce the constraints.
	 * Mapping of length 0 is only allowed for old binaries.
	 * Anonymous mapping shall specify -1 as filedescriptor and
	 * zero position for new code. Be nice to ancient a.out
	 * binaries and correct pos for anonymous mapping, since old
	 * ld.so sometimes issues anonymous map requests with non-zero
	 * pos.
	 */
	if (!SV_CURPROC_FLAG(SV_AOUT)) {
		if ((len == 0 && p->p_osrel >= P_OSREL_MAP_ANON) ||
		    ((flags & MAP_ANON) != 0 && (fd != -1 || pos != 0))) {
			SYSERRCAUSE("%s: len == 0", __func__);
			return (EINVAL);
		}
	} else {
		if ((flags & MAP_ANON) != 0)
			pos = 0;
	}

	if (flags & MAP_STACK) {
		if (fd != -1) {
			SYSERRCAUSE("%s: MAP_STACK with fd", __func__);
			return (EINVAL);
		}

		if ((prot & (PROT_READ | PROT_WRITE)) !=
		    (PROT_READ | PROT_WRITE)) {
			SYSERRCAUSE("%s: MAP_STACK without both PROT_READ "
			    "and PROT_WRITE", __func__);
			return (EINVAL);
		}
		flags |= MAP_ANON;
		pos = 0;
	}
	unsigned int extra_flags =
	    (flags & ~(MAP_SHARED | MAP_PRIVATE | MAP_FIXED | MAP_HASSEMAPHORE |
	    MAP_STACK | MAP_NOSYNC | MAP_ANON | MAP_EXCL | MAP_NOCORE |
	    MAP_PREFAULT_READ | MAP_GUARD |
	    MAP_CHERI_NOSETBOUNDS |
#ifdef MAP_32BIT
	    MAP_32BIT |
#endif
	    MAP_ALIGNMENT_MASK));
	if (extra_flags != 0) {
		SYSERRCAUSE("%s: Unhandled flag(s) 0x%x", __func__,
		    extra_flags);
		return (EINVAL);
	}
	flags |= mrp->mr_kern_flags;
	if ((flags & (MAP_EXCL | MAP_FIXED)) == MAP_EXCL) {
		SYSERRCAUSE("%s: MAP_EXCL without MAP_FIXED", __func__);
		return (EINVAL);
	}
	if ((flags & (MAP_SHARED | MAP_PRIVATE)) == (MAP_SHARED | MAP_PRIVATE)) {
		SYSERRCAUSE("%s: both MAP_SHARED and MAP_PRIVATE", __func__);
		return (EINVAL);
	}
	if (prot != PROT_NONE &&
	    (prot & ~(PROT_READ | PROT_WRITE | PROT_EXEC)) != 0) {
		SYSERRCAUSE("%s: Unexpected protections 0x%x", __func__,
		    (prot & ~(PROT_READ | PROT_WRITE | PROT_EXEC)));
		return (EINVAL);
	}
	if ((flags & MAP_GUARD) != 0 && (prot != PROT_NONE || fd != -1 ||
	    pos != 0 || (flags & ~(MAP_FIXED | MAP_GUARD | MAP_EXCL |
	    MAP_CHERI_NOSETBOUNDS | MAP_RESERVATION_CREATE |
#ifdef MAP_32BIT
	    MAP_32BIT |
#endif
	    MAP_ALIGNMENT_MASK)) != 0)) {
		SYSERRCAUSE("%s: Invalid arguments with MAP_GUARD", __func__);
		return (EINVAL);
	}

	/*
	 * Align the file position to a page boundary,
	 * and save its page offset component.
	 */
	pageoff = (pos & PAGE_MASK);
	pos -= pageoff;

	/* Compute size from len by rounding (on both ends). */
	size = len + pageoff;			/* low end... */
	size = round_page(size);		/* hi end */
	/* Check for rounding up to zero. */
	if (len > size)
		return (ENOMEM);

	align = flags & MAP_ALIGNMENT_MASK;
#if !__has_feature(capabilities)
	/* In the non-CHERI case, remove the alignment request. */
	if (align == MAP_ALIGNED_CHERI || align == MAP_ALIGNED_CHERI_SEAL) {
		flags &= ~MAP_ALIGNMENT_MASK;
		align = 0;
	}
#else /* __has_feature(capabilities) */
	/*
	 * Convert MAP_ALIGNED_CHERI(_SEAL) into explicit alignment
	 * requests and pad lengths.  The combination of alignment (via
	 * the updated, explicit alignment flags) and padding is required
	 * for any request that would otherwise be unrepresentable due
	 * to compressed capability bounds.
	 *
	 * XXX: With CHERI Concentrate, there is no difference in
	 * precision between sealed and unsealed capabilities.  We
	 * retain the duplicate code paths in case other otype tradeoffs
	 * are made at a later date.
	 */
	if (align == MAP_ALIGNED_CHERI) {
		flags &= ~MAP_ALIGNMENT_MASK;
		if (CHERI_REPRESENTABLE_ALIGNMENT(size) > PAGE_SIZE) {
			flags |= MAP_ALIGNED(CHERI_ALIGN_SHIFT(size));

			if (size != CHERI_REPRESENTABLE_LENGTH(size))
				size = CHERI_REPRESENTABLE_LENGTH(size);

			if (CHERI_ALIGN_MASK(size) != 0)
				addr_mask = CHERI_ALIGN_MASK(size);
		}
		align = flags & MAP_ALIGNMENT_MASK;
	} else if (align == MAP_ALIGNED_CHERI_SEAL) {
		flags &= ~MAP_ALIGNMENT_MASK;
		if (CHERI_SEALABLE_ALIGNMENT(size) > (1UL << PAGE_SHIFT)) {
			flags |= MAP_ALIGNED(CHERI_SEAL_ALIGN_SHIFT(size));

			if (size != CHERI_SEALABLE_LENGTH(size))
				size = CHERI_SEALABLE_LENGTH(size);

			if (CHERI_SEAL_ALIGN_MASK(size) != 0)
				addr_mask = CHERI_SEAL_ALIGN_MASK(size);
		}
		align = flags & MAP_ALIGNMENT_MASK;
	}
#endif

	/* Ensure alignment is at least a page and fits in a pointer. */
	if (align != 0 && align != MAP_ALIGNED_SUPER &&
	    (align >> MAP_ALIGNMENT_SHIFT >= sizeof(void *) * NBBY ||
	    align >> MAP_ALIGNMENT_SHIFT < PAGE_SHIFT)) {
		SYSERRCAUSE("%s: nonsensical alignment (2^%d)",
		    __func__, align >> MAP_ALIGNMENT_SHIFT);
		return (EINVAL);
	}

	/*
	 * Check for illegal addresses.  Watch out for address wrap... Note
	 * that VM_*_ADDRESS are not constants due to casts (argh).
	 */
	if (flags & MAP_FIXED) {
		/*
		 * The specified address must have the same remainder
		 * as the file offset taken modulo PAGE_SIZE, so it
		 * should be aligned after adjustment by pageoff.
		 */
		addr -= pageoff;
		if (addr & addr_mask) {
			SYSERRCAUSE("%s: addr (%p) is underaligned "
			    "(mask 0x%zx)", __func__, (void *)addr, addr_mask);
			return (EINVAL);
		}

		/* Address range must be all in user VM space. */
		if (!vm_map_range_valid(&vms->vm_map, addr, addr + size))
			return (EINVAL);
#ifdef MAP_32BIT
		if (flags & MAP_32BIT) {
			KASSERT(!SV_CURPROC_FLAG(SV_CHERI),
			    ("MAP_32BIT on a CheriABI process"));
			max_addr = MAP_32BIT_MAX_ADDR;
			if (addr + size > MAP_32BIT_MAX_ADDR) {
				SYSERRCAUSE("%s: addr (%p) + size (0x%zx) is "
				    "> 0x%zx (MAP_32BIT_MAX_ADDR)", __func__,
				    (void *)addr, size, MAP_32BIT_MAX_ADDR);
				return (EINVAL);
			}
		}
#ifdef __CHERI_PURE_CAPABILITY__
		/*
		 * This makes sure we use the correct source capability and hint
		 * address for hybrid userland and for MAP_FIXED.
		 * If MAP_RESERVATION_CREATE is requested, addr is just the hint
		 * virtual address and will not be a valid capability.
		 */
		if ((flags & MAP_RESERVATION_CREATE) == 0)
			addr = cheri_setaddress((uintcap_t)mrp->mr_source_cap,
			    addr);
#endif
	} else if (flags & MAP_32BIT) {
		KASSERT(!SV_CURPROC_FLAG(SV_CHERI),
		    ("MAP_32BIT on a CheriABI process"));
		max_addr = MAP_32BIT_MAX_ADDR;
		/*
		 * For MAP_32BIT, override the hint if it is too high and
		 * do not bother moving the mapping past the heap (since
		 * the heap is usually above 2GB).
		 */
		if (addr + size > MAP_32BIT_MAX_ADDR)
			addr = 0;
#endif
	} else {
		/*
		 * XXX for non-fixed mappings where no hint is provided or
		 * the hint would fall in the potential heap space,
		 * place it after the end of the largest possible heap.
		 *
		 * There should really be a pmap call to determine a reasonable
		 * location.
		 */
		if (addr == 0 ||
		    (addr >= round_page((vm_offset_t)vms->vm_taddr) &&
		    addr < round_page((vm_offset_t)vms->vm_daddr +
		    lim_max(td, RLIMIT_DATA))))
			addr = round_page((vm_offset_t)vms->vm_daddr +
			    lim_max(td, RLIMIT_DATA));
	}

	if (len == 0) {
		/*
		 * Return success without mapping anything for old
		 * binaries that request a page-aligned mapping of
		 * length 0.  For modern binaries, this function
		 * returns an error earlier.
		 */
		error = 0;
	} else if ((flags & MAP_GUARD) != 0) {
		error = vm_mmap_object(&vms->vm_map, &addr, max_addr, size,
		    VM_PROT_NONE, max_prot, flags, NULL, pos, FALSE, td);
	} else if ((flags & MAP_ANON) != 0) {
		/*
		 * Mapping blank space is trivial.
		 *
		 * This relies on VM_PROT_* matching PROT_*.
		 */
		error = vm_mmap_object(&vms->vm_map, &addr, max_addr, size,
		    VM_PROT_ADD_CAP(prot), VM_PROT_ADD_CAP(max_prot), flags,
		    NULL, pos, FALSE, td);
	} else {
		/*
		 * Mapping file, get fp for validation and don't let the
		 * descriptor disappear on us if we block. Check capability
		 * rights, but also return the maximum rights to be combined
		 * with maxprot later.
		 */
		cap_rights_init_one(&rights, CAP_MMAP);
		if (cap_prot & PROT_READ)
			cap_rights_set_one(&rights, CAP_MMAP_R);
		if ((flags & MAP_SHARED) != 0) {
			if (cap_prot & PROT_WRITE)
				cap_rights_set_one(&rights, CAP_MMAP_W);
		}
		if (cap_prot & PROT_EXEC)
			cap_rights_set_one(&rights, CAP_MMAP_X);
		error = fget_mmap(td, fd, &rights, &cap_maxprot, &fp);
		if (error != 0)
			goto done;
		if ((flags & (MAP_SHARED | MAP_PRIVATE)) == 0 &&
		    p->p_osrel >= P_OSREL_MAP_FSTRICT) {
			error = EINVAL;
			goto done;
		}
		if ((cap_prot & cap_maxprot) != cap_prot) {
			SYSERRCAUSE("%s: unable to map file with "
			    "requested permissions", __func__);
			error = EINVAL;
			goto done;
		}
		max_prot &= cap_maxprot;
		if (check_fp_fn != NULL) {
			error = check_fp_fn(fp, prot, max_prot, flags);
			if (error != 0)
				goto done;
		}
		if (fp->f_ops == &shm_ops && shm_largepage(fp->f_data))
			addr = orig_addr;
		/* This relies on VM_PROT_* matching PROT_*. */
		error = fo_mmap(fp, &vms->vm_map, &addr, max_addr, size,
		    prot, max_prot, flags, pos, td);
	}

	if (error == 0) {
#if __has_feature(capabilities)
		if (SV_CURPROC_FLAG(SV_CHERI))
			td->td_retval[0] = mmap_retcap(td, addr + pageoff, mrp);
		else
#endif
			td->td_retval[0] = addr + pageoff;
	}
done:
	if (fp)
		fdrop(fp, td);

	return (error);
}

#if defined(COMPAT_FREEBSD6)
int
freebsd6_mmap(struct thread *td, struct freebsd6_mmap_args *uap)
{
	return (kern_mmap(td, &(struct mmap_req){
		.mr_hint = (uintptr_t)uap->addr,
		.mr_len = uap->len,
		.mr_prot = uap->prot,
		.mr_flags = uap->flags,
		.mr_fd = uap->fd,
		.mr_pos = uap->pos,
	    }));
}
#endif

#ifdef COMPAT_43
#ifndef _SYS_SYSPROTO_H_
struct ommap_args {
	caddr_t addr;
	int len;
	int prot;
	int flags;
	int fd;
	long pos;
};
#endif
int
ommap(struct thread *td, struct ommap_args *uap)
{
	return (kern_ommap(td, (uintptr_t)uap->addr, uap->len, uap->prot,
	    uap->flags, uap->fd, uap->pos));
}

int
kern_ommap(struct thread *td, uintptr_t hint, int len, int oprot,
    int oflags, int fd, long pos)
{
	static const char cvtbsdprot[8] = {
		0,
		PROT_EXEC,
		PROT_WRITE,
		PROT_EXEC | PROT_WRITE,
		PROT_READ,
		PROT_EXEC | PROT_READ,
		PROT_WRITE | PROT_READ,
		PROT_EXEC | PROT_WRITE | PROT_READ,
	};
	int flags, prot;

	if (len < 0)
		return (EINVAL);

#define	OMAP_ANON	0x0002
#define	OMAP_COPY	0x0020
#define	OMAP_SHARED	0x0010
#define	OMAP_FIXED	0x0100

	prot = cvtbsdprot[oprot & 0x7];
#if (defined(COMPAT_FREEBSD32) && defined(__amd64__)) || defined(__i386__)
	if (i386_read_exec && SV_PROC_FLAG(td->td_proc, SV_ILP32) &&
	    prot != 0)
		prot |= PROT_EXEC;
#endif
	flags = 0;
	if (oflags & OMAP_ANON)
		flags |= MAP_ANON;
	if (oflags & OMAP_COPY)
		flags |= MAP_COPY;
	if (oflags & OMAP_SHARED)
		flags |= MAP_SHARED;
	else
		flags |= MAP_PRIVATE;
	if (oflags & OMAP_FIXED)
		flags |= MAP_FIXED;
	return (kern_mmap(td, &(struct mmap_req){
		.mr_hint = hint,
		.mr_len = len,
		.mr_prot = prot,
		.mr_flags = flags,
		.mr_fd = fd,
		.mr_pos = pos,
	    }));
}
#endif				/* COMPAT_43 */

#ifndef _SYS_SYSPROTO_H_
struct msync_args {
	void *addr;
	size_t len;
	int flags;
};
#endif
int
sys_msync(struct thread *td, struct msync_args *uap)
{

#if __has_feature(capabilities)
	/*
	 * FreeBSD msync() has a non-standard behavior that a len of 0
	 * effects the whole vm entry.  We allow this because it is used
	 * and we currently think there is little attack value in
	 * msync calls.
	 *
	 * XXX-BD: Revisit with co-processes...
	 */
	if (uap->len != 0 && cap_covers_pages(uap->addr, uap->len) == 0)
		return (EINVAL);
#endif

	return (kern_msync(td, (uintptr_t)(uintcap_t)uap->addr, uap->len,
	    uap->flags));
}

int
kern_msync(struct thread *td, uintptr_t addr0, size_t size, int flags)
{
	vm_offset_t addr;
	vm_size_t pageoff;
	vm_map_t map;
	int rv;

	addr = addr0;
	pageoff = (addr & PAGE_MASK);
	addr -= pageoff;
	size += pageoff;
	size = (vm_size_t) round_page(size);
	if (addr + size < addr)
		return (EINVAL);

	if ((flags & ~(MS_ASYNC | MS_INVALIDATE | MS_PAGEOUT)) != 0)
		return (EINVAL);
	if ((flags & (MS_ASYNC|MS_INVALIDATE)) == (MS_ASYNC|MS_INVALIDATE))
		return (EINVAL);
	if ((flags & MS_PAGEOUT) != 0 && (flags & ~MS_PAGEOUT) != 0)
		return (EINVAL);

	map = &td->td_proc->p_vmspace->vm_map;

	/*
	 * Clean the pages and interpret the return value.
	 */
	rv = vm_map_sync(map, addr, addr + size, (flags & MS_ASYNC) == 0,
	    (flags & MS_INVALIDATE) != 0, (flags & MS_PAGEOUT) != 0);
	switch (rv) {
	case KERN_SUCCESS:
		return (0);
	case KERN_INVALID_ADDRESS:
		return (ENOMEM);
	case KERN_INVALID_ARGUMENT:
		return (EBUSY);
	case KERN_FAILURE:
		return (EIO);
	default:
		return (EINVAL);
	}
}

#ifndef _SYS_SYSPROTO_H_
struct munmap_args {
	void *addr;
	size_t len;
};
#endif
int
sys_munmap(struct thread *td, struct munmap_args *uap)
{

#if __has_feature(capabilities)
	if (cap_covers_pages(uap->addr, uap->len) == 0)
		return (EPROT);
	if ((cheri_getperm(uap->addr) & CHERI_PERM_SW_VMEM) == 0)
		return (EPROT);
#endif

	return (kern_munmap(td, (uintptr_t)(uintcap_t)uap->addr, uap->len));
}

int
kern_munmap(struct thread *td, uintptr_t addr0, size_t size)
{
#ifdef HWPMC_HOOKS
	struct pmckern_map_out pkm;
	bool pmc_handled;
	vm_map_entry_t entry;
#endif
	vm_offset_t addr, end;
	vm_size_t pageoff;
	vm_map_t map;
	int rv = KERN_SUCCESS;

	if (size == 0)
		return (EINVAL);

	addr = addr0;
	pageoff = (addr & PAGE_MASK);
	addr -= pageoff;
	size += pageoff;
	size = (vm_size_t) round_page(size);
	end = addr + size;
	map = &td->td_proc->p_vmspace->vm_map;
	if (!vm_map_range_valid(map, addr, end))
		return (EINVAL);

	vm_map_lock(map);
#ifdef HWPMC_HOOKS
	pmc_handled = false;
	if (PMC_HOOK_INSTALLED(PMC_FN_MUNMAP)) {
		pmc_handled = true;
		/*
		 * Inform hwpmc if the address range being unmapped contains
		 * an executable region.
		 */
		pkm.pm_address = (uintptr_t) NULL;
		if (vm_map_lookup_entry(map, addr, &entry)) {
			for (; entry->start < end;
			    entry = vm_map_entry_succ(entry)) {
				if (vm_map_check_protection(map, entry->start,
					entry->end, VM_PROT_EXECUTE) == TRUE) {
					pkm.pm_address = (uintptr_t) addr;
					pkm.pm_size = (size_t) size;
					break;
				}
			}
		}
	}
#endif
	rv = vm_map_remove_locked(map, addr, addr + size);

#ifdef HWPMC_HOOKS
	if (rv == KERN_SUCCESS && __predict_false(pmc_handled)) {
		/* downgrade the lock to prevent a LOR with the pmc-sx lock */
		vm_map_lock_downgrade(map);
		if (pkm.pm_address != (uintptr_t) NULL)
			PMC_CALL_HOOK(td, PMC_FN_MUNMAP, (void *) &pkm);
		vm_map_unlock_read(map);
	} else
#endif
		vm_map_unlock(map);

	return (vm_mmap_to_errno(rv));
}

#ifndef _SYS_SYSPROTO_H_
struct mprotect_args {
	const void *addr;
	size_t len;
	int prot;
};
#endif
int
sys_mprotect(struct thread *td, struct mprotect_args *uap)
{

#if __has_feature(capabilities)
	if (cap_covers_pages(uap->addr, uap->len) == 0)
		return (EPROT);
	if ((cheri_getperm(uap->addr) & CHERI_PERM_SW_VMEM) == 0)
		return (EPROT);
#endif

	return (kern_mprotect(td, (uintptr_t)(uintcap_t)uap->addr, uap->len,
	    uap->prot));
}

int
kern_mprotect(struct thread *td, uintptr_t addr0, size_t size, int prot)
{
	vm_offset_t addr;
	vm_size_t pageoff;
	int vm_error, max_prot;
	int flags;

	addr = addr0;
	if ((prot & ~(_PROT_ALL | PROT_MAX(_PROT_ALL))) != 0)
		return (EINVAL);
	max_prot = PROT_MAX_EXTRACT(prot);
	prot = PROT_EXTRACT(prot);
	pageoff = (addr & PAGE_MASK);
	addr -= pageoff;
	size += pageoff;
	size = (vm_size_t) round_page(size);
#ifdef COMPAT_FREEBSD32
	if (SV_PROC_FLAG(td->td_proc, SV_ILP32)) {
		if (((addr + size) & 0xffffffff) < addr)
			return (EINVAL);
	} else
#endif
	if (addr + size < addr)
		return (EINVAL);

	if ((prot & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC) &&
	    (vm_error = vm_wxcheck(td->td_proc, "mprotect")))
		goto out;

	flags = VM_MAP_PROTECT_SET_PROT | VM_MAP_PROTECT_KEEP_CAP;
	if (max_prot != 0) {
		if ((max_prot & prot) != prot)
			return (ENOTSUP);
		flags |= VM_MAP_PROTECT_SET_MAXPROT;
	}
	if (vm_error == KERN_SUCCESS)
		vm_error = vm_map_protect(&td->td_proc->p_vmspace->vm_map,
		    addr, addr + size, prot, max_prot, flags);

out:
	switch (vm_error) {
	case KERN_SUCCESS:
		return (0);
	case KERN_PROTECTION_FAILURE:
		return (EACCES);
	case KERN_RESOURCE_SHORTAGE:
		return (ENOMEM);
	case KERN_OUT_OF_BOUNDS:
		return (ENOTSUP);
	}
	return (EINVAL);
}

#ifndef _SYS_SYSPROTO_H_
struct minherit_args {
	void *addr;
	size_t len;
	int inherit;
};
#endif
int
sys_minherit(struct thread *td, struct minherit_args *uap)
{

#if __has_feature(capabilities)
	if (cap_covers_pages(uap->addr, uap->len) == 0)
		return (EPROT);
	if ((cheri_getperm(uap->addr) & CHERI_PERM_SW_VMEM) == 0)
		return (EPROT);
#endif
	return (kern_minherit(td, (uintptr_t)(uintcap_t)uap->addr, uap->len,
	    uap->inherit));
}

int
kern_minherit(struct thread *td, uintptr_t addr0, size_t len, int inherit0)
{
	vm_offset_t addr;
	vm_size_t size, pageoff;
	vm_inherit_t inherit;

	addr = (vm_offset_t)addr0;
	size = len;
	inherit = inherit0;

	pageoff = (addr & PAGE_MASK);
	addr -= pageoff;
	size += pageoff;
	size = (vm_size_t) round_page(size);
	if (addr + size < addr)
		return (EINVAL);

	switch (vm_map_inherit(&td->td_proc->p_vmspace->vm_map, addr,
	    addr + size, (vm_inherit_t)inherit)) {
	case KERN_SUCCESS:
		return (0);
	case KERN_PROTECTION_FAILURE:
		return (EACCES);
	}
	return (EINVAL);
}

#ifndef _SYS_SYSPROTO_H_
struct madvise_args {
	void *addr;
	size_t len;
	int behav;
};
#endif

int
sys_madvise(struct thread *td, struct madvise_args *uap)
{

#if __has_feature(capabilities)
	if (cap_covers_pages(uap->addr, uap->len) == 0)
		return (EPROT);

	/*
	 * MADV_FREE may change the page contents so require
	 * CHERI_PERM_SW_VMEM.
	 */
	if (uap->behav == MADV_FREE &&
	    (cheri_getperm(uap->addr) & CHERI_PERM_SW_VMEM) == 0)
		return (EPROT);
#endif

	return (kern_madvise(td, (uintptr_t)(uintcap_t)uap->addr, uap->len,
	    uap->behav));
}

int
kern_madvise(struct thread *td, uintptr_t addr0, size_t len, int behav)
{
	vm_map_t map;
	vm_offset_t addr, end, start;
	int flags;

	/*
	 * Check for our special case, advising the swap pager we are
	 * "immortal."
	 */
	if (behav == MADV_PROTECT) {
		flags = PPROT_SET;
		return (kern_procctl(td, P_PID, td->td_proc->p_pid,
		    PROC_SPROTECT, &flags));
	}

	/*
	 * Check for illegal addresses.  Watch out for address wrap... Note
	 * that VM_*_ADDRESS are not constants due to casts (argh).
	 */
	map = &td->td_proc->p_vmspace->vm_map;
	addr = addr0;
	if (!vm_map_range_valid(map, addr, addr + len))
		return (EINVAL);

	/*
	 * Since this routine is only advisory, we default to conservative
	 * behavior.
	 */
	start = trunc_page(addr);
	end = round_page(addr + len);

	/*
	 * vm_map_madvise() checks for illegal values of behav.
	 */
	return (vm_map_madvise(map, start, end, behav));
}

#ifndef _SYS_SYSPROTO_H_
struct mincore_args {
	const void *addr;
	size_t len;
	char *vec;
};
#endif

int
sys_mincore(struct thread *td, struct mincore_args *uap)
{

#if __has_feature(capabilities)
	/*
	 * Since this is a read-only query that does not modify any mappings
	 * or raise faults, we do not require the cap to cover
	 * the full page, just to overlap at least part of the page.
	 */
	if (__CAP_CHECK(uap->addr, uap->len) == 0)
		return (EPROT);
#endif

	return (kern_mincore(td, (uintptr_t)(uintcap_t)uap->addr, uap->len,
	    uap->vec));
}

int
kern_mincore(struct thread *td, uintptr_t addr0, size_t len,
    char * __capability vec)
{
	pmap_t pmap;
	vm_map_t map;
	vm_map_entry_t current, entry;
	vm_object_t object;
	vm_offset_t addr, cend, end, first_addr;
	vm_paddr_t pa;
	vm_page_t m;
	vm_pindex_t pindex;
	int error, lastvecindex, mincoreinfo, vecindex;
	unsigned int timestamp;

	/*
	 * Make sure that the addresses presented are valid for user
	 * mode.
	 */
	first_addr = addr = trunc_page(addr0);
	end = round_page(addr0 + len);
	map = &td->td_proc->p_vmspace->vm_map;
	if (end > vm_map_max(map) || end < addr)
		return (ENOMEM);

	pmap = vmspace_pmap(td->td_proc->p_vmspace);

	vm_map_lock_read(map);
RestartScan:
	timestamp = map->timestamp;

	if (!vm_map_lookup_entry(map, addr, &entry)) {
		vm_map_unlock_read(map);
		return (ENOMEM);
	}

	/*
	 * Do this on a map entry basis so that if the pages are not
	 * in the current processes address space, we can easily look
	 * up the pages elsewhere.
	 */
	lastvecindex = -1;
	while (entry->start < end) {
		/*
		 * check for contiguity
		 */
		current = entry;
		entry = vm_map_entry_succ(current);
		if (current->end < end &&
		    entry->start > current->end) {
			vm_map_unlock_read(map);
			return (ENOMEM);
		}

		/*
		 * ignore submaps (for now) or null objects
		 */
		if ((current->eflags & MAP_ENTRY_IS_SUB_MAP) ||
		    current->object.vm_object == NULL)
			continue;

		/*
		 * limit this scan to the current map entry and the
		 * limits for the mincore call
		 */
		if (addr < current->start)
			addr = current->start;
		cend = current->end;
		if (cend > end)
			cend = end;

		for (; addr < cend; addr += PAGE_SIZE) {
			/*
			 * Check pmap first, it is likely faster, also
			 * it can provide info as to whether we are the
			 * one referencing or modifying the page.
			 */
			m = NULL;
			object = NULL;
retry:
			pa = 0;
			mincoreinfo = pmap_mincore(pmap, addr, &pa);
			if (mincore_mapped) {
				/*
				 * We only care about this pmap's
				 * mapping of the page, if any.
				 */
				;
			} else if (pa != 0) {
				/*
				 * The page is mapped by this process but not
				 * both accessed and modified.  It is also
				 * managed.  Acquire the object lock so that
				 * other mappings might be examined.  The page's
				 * identity may change at any point before its
				 * object lock is acquired, so re-validate if
				 * necessary.
				 */
				m = PHYS_TO_VM_PAGE(pa);
				while (object == NULL || m->object != object) {
					if (object != NULL)
						VM_OBJECT_WUNLOCK(object);
					object = atomic_load_ptr(&m->object);
					if (object == NULL)
						goto retry;
					VM_OBJECT_WLOCK(object);
				}
				if (pa != pmap_extract(pmap, addr))
					goto retry;
				KASSERT(vm_page_all_valid(m),
				    ("mincore: page %p is mapped but invalid",
				    m));
			} else if (mincoreinfo == 0) {
				/*
				 * The page is not mapped by this process.  If
				 * the object implements managed pages, then
				 * determine if the page is resident so that
				 * the mappings might be examined.
				 */
				if (current->object.vm_object != object) {
					if (object != NULL)
						VM_OBJECT_WUNLOCK(object);
					object = current->object.vm_object;
					VM_OBJECT_WLOCK(object);
				}
				if ((object->flags & OBJ_SWAP) != 0 ||
				    object->type == OBJT_VNODE) {
					pindex = OFF_TO_IDX(current->offset +
					    (addr - current->start));
					m = vm_page_lookup(object, pindex);
					if (m != NULL && vm_page_none_valid(m))
						m = NULL;
					if (m != NULL)
						mincoreinfo = MINCORE_INCORE;
				}
			}
			if (m != NULL) {
				VM_OBJECT_ASSERT_WLOCKED(m->object);

				/* Examine other mappings of the page. */
				if (m->dirty == 0 && pmap_is_modified(m))
					vm_page_dirty(m);
				if (m->dirty != 0)
					mincoreinfo |= MINCORE_MODIFIED_OTHER;

				/*
				 * The first test for PGA_REFERENCED is an
				 * optimization.  The second test is
				 * required because a concurrent pmap
				 * operation could clear the last reference
				 * and set PGA_REFERENCED before the call to
				 * pmap_is_referenced(). 
				 */
				if ((m->a.flags & PGA_REFERENCED) != 0 ||
				    pmap_is_referenced(m) ||
				    (m->a.flags & PGA_REFERENCED) != 0)
					mincoreinfo |= MINCORE_REFERENCED_OTHER;
			}
			if (object != NULL)
				VM_OBJECT_WUNLOCK(object);

			/*
			 * subyte may page fault.  In case it needs to modify
			 * the map, we release the lock.
			 */
			vm_map_unlock_read(map);

			/*
			 * calculate index into user supplied byte vector
			 */
			vecindex = atop(addr - first_addr);

			/*
			 * If we have skipped map entries, we need to make sure that
			 * the byte vector is zeroed for those skipped entries.
			 */
			while ((lastvecindex + 1) < vecindex) {
				++lastvecindex;
				error = subyte(vec + lastvecindex, 0);
				if (error) {
					error = EFAULT;
					goto done2;
				}
			}

			/*
			 * Pass the page information to the user
			 */
			error = subyte(vec + vecindex, mincoreinfo);
			if (error) {
				error = EFAULT;
				goto done2;
			}

			/*
			 * If the map has changed, due to the subyte, the previous
			 * output may be invalid.
			 */
			vm_map_lock_read(map);
			if (timestamp != map->timestamp)
				goto RestartScan;

			lastvecindex = vecindex;
		}
	}

	/*
	 * subyte may page fault.  In case it needs to modify
	 * the map, we release the lock.
	 */
	vm_map_unlock_read(map);

	/*
	 * Zero the last entries in the byte vector.
	 */
	vecindex = atop(end - first_addr);
	while ((lastvecindex + 1) < vecindex) {
		++lastvecindex;
		error = subyte(vec + lastvecindex, 0);
		if (error) {
			error = EFAULT;
			goto done2;
		}
	}

	/*
	 * If the map has changed, due to the subyte, the previous
	 * output may be invalid.
	 */
	vm_map_lock_read(map);
	if (timestamp != map->timestamp)
		goto RestartScan;
	vm_map_unlock_read(map);
done2:
	return (error);
}

#ifndef _SYS_SYSPROTO_H_
struct mlock_args {
	const void *addr;
	size_t len;
};
#endif
int
sys_mlock(struct thread *td, struct mlock_args *uap)
{

#if __has_feature(capabilities)
	if (cap_covers_pages(uap->addr, uap->len) == 0)
		return (EPROT);
#endif

	return (kern_mlock(td->td_proc, td->td_ucred,
	    (uintptr_t)__DECONST_CAP(uintcap_t, uap->addr), uap->len));
}

int
kern_mlock(struct proc *proc, struct ucred *cred, uintptr_t addr0, size_t len)
{
	vm_offset_t addr, end, last, start;
	vm_size_t npages, size;
	vm_map_t map;
	unsigned long nsize;
	int error;

	error = priv_check_cred(cred, PRIV_VM_MLOCK);
	if (error)
		return (error);
	addr = addr0;
	size = len;
	last = addr + size;
	start = trunc_page(addr);
	end = round_page(last);
	if (last < addr || end < addr)
		return (EINVAL);
	npages = atop(end - start);
	if (npages > vm_page_max_user_wired)
		return (ENOMEM);
	map = &proc->p_vmspace->vm_map;
	PROC_LOCK(proc);
	nsize = ptoa(npages + pmap_wired_count(map->pmap));
	if (nsize > lim_cur_proc(proc, RLIMIT_MEMLOCK)) {
		PROC_UNLOCK(proc);
		return (ENOMEM);
	}
	PROC_UNLOCK(proc);
#ifdef RACCT
	if (racct_enable) {
		PROC_LOCK(proc);
		error = racct_set(proc, RACCT_MEMLOCK, nsize);
		PROC_UNLOCK(proc);
		if (error != 0)
			return (ENOMEM);
	}
#endif
	error = vm_map_wire(map, start, end,
	    VM_MAP_WIRE_USER | VM_MAP_WIRE_NOHOLES);
#ifdef RACCT
	if (racct_enable && error != KERN_SUCCESS) {
		PROC_LOCK(proc);
		racct_set(proc, RACCT_MEMLOCK,
		    ptoa(pmap_wired_count(map->pmap)));
		PROC_UNLOCK(proc);
	}
#endif
	switch (error) {
	case KERN_SUCCESS:
		return (0);
	case KERN_INVALID_ARGUMENT:
		return (EINVAL);
	default:
		return (ENOMEM);
	}
}

#ifndef _SYS_SYSPROTO_H_
struct mlockall_args {
	int	how;
};
#endif

int
sys_mlockall(struct thread *td, struct mlockall_args *uap)
{
	vm_map_t map;
	int error;

	map = &td->td_proc->p_vmspace->vm_map;
	error = priv_check(td, PRIV_VM_MLOCK);
	if (error)
		return (error);

	if ((uap->how == 0) || ((uap->how & ~(MCL_CURRENT|MCL_FUTURE)) != 0))
		return (EINVAL);

	/*
	 * If wiring all pages in the process would cause it to exceed
	 * a hard resource limit, return ENOMEM.
	 */
	if (!old_mlock && uap->how & MCL_CURRENT) {
		if (map->size > lim_cur(td, RLIMIT_MEMLOCK))
			return (ENOMEM);
	}
#ifdef RACCT
	if (racct_enable) {
		PROC_LOCK(td->td_proc);
		error = racct_set(td->td_proc, RACCT_MEMLOCK, map->size);
		PROC_UNLOCK(td->td_proc);
		if (error != 0)
			return (ENOMEM);
	}
#endif

	if (uap->how & MCL_FUTURE) {
		vm_map_lock(map);
		vm_map_modflags(map, MAP_WIREFUTURE, 0);
		vm_map_unlock(map);
		error = 0;
	}

	if (uap->how & MCL_CURRENT) {
		/*
		 * P1003.1-2001 mandates that all currently mapped pages
		 * will be memory resident and locked (wired) upon return
		 * from mlockall(). vm_map_wire() will wire pages, by
		 * calling vm_fault_wire() for each page in the region.
		 */
		error = vm_map_wire(map, vm_map_min(map), vm_map_max(map),
		    VM_MAP_WIRE_USER|VM_MAP_WIRE_HOLESOK);
		if (error == KERN_SUCCESS)
			error = 0;
		else if (error == KERN_RESOURCE_SHORTAGE)
			error = ENOMEM;
		else
			error = EAGAIN;
	}
#ifdef RACCT
	if (racct_enable && error != KERN_SUCCESS) {
		PROC_LOCK(td->td_proc);
		racct_set(td->td_proc, RACCT_MEMLOCK,
		    ptoa(pmap_wired_count(map->pmap)));
		PROC_UNLOCK(td->td_proc);
	}
#endif

	return (error);
}

#ifndef _SYS_SYSPROTO_H_
struct munlockall_args {
	register_t dummy;
};
#endif

int
sys_munlockall(struct thread *td, struct munlockall_args *uap)
{
	vm_map_t map;
	int error;

	map = &td->td_proc->p_vmspace->vm_map;
	error = priv_check(td, PRIV_VM_MUNLOCK);
	if (error)
		return (error);

	/* Clear the MAP_WIREFUTURE flag from this vm_map. */
	vm_map_lock(map);
	vm_map_modflags(map, 0, MAP_WIREFUTURE);
	vm_map_unlock(map);

	/* Forcibly unwire all pages. */
	error = vm_map_unwire(map, vm_map_min(map), vm_map_max(map),
	    VM_MAP_WIRE_USER|VM_MAP_WIRE_HOLESOK);
#ifdef RACCT
	if (racct_enable && error == KERN_SUCCESS) {
		PROC_LOCK(td->td_proc);
		racct_set(td->td_proc, RACCT_MEMLOCK, 0);
		PROC_UNLOCK(td->td_proc);
	}
#endif

	return (error);
}

#ifndef _SYS_SYSPROTO_H_
struct munlock_args {
	const void *addr;
	size_t len;
};
#endif
int
sys_munlock(struct thread *td, struct munlock_args *uap)
{

#if __has_feature(capabilities)
	if (cap_covers_pages(uap->addr, uap->len) == 0)
		return (EPROT);
#endif

	return (kern_munlock(td, (uintptr_t)(uintcap_t)uap->addr, uap->len));
}

int
kern_munlock(struct thread *td, uintptr_t addr0, size_t size)
{
	vm_offset_t addr, end, last, start;
#ifdef RACCT
	vm_map_t map;
#endif
	int error;

	error = priv_check(td, PRIV_VM_MUNLOCK);
	if (error)
		return (error);
	addr = addr0;
	last = addr + size;
	start = trunc_page(addr);
	end = round_page(last);
	if (last < addr || end < addr)
		return (EINVAL);
	error = vm_map_unwire(&td->td_proc->p_vmspace->vm_map, start, end,
	    VM_MAP_WIRE_USER | VM_MAP_WIRE_NOHOLES);
#ifdef RACCT
	if (racct_enable && error == KERN_SUCCESS) {
		PROC_LOCK(td->td_proc);
		map = &td->td_proc->p_vmspace->vm_map;
		racct_set(td->td_proc, RACCT_MEMLOCK,
		    ptoa(pmap_wired_count(map->pmap)));
		PROC_UNLOCK(td->td_proc);
	}
#endif
	return (error == KERN_SUCCESS ? 0 : ENOMEM);
}

/*
 * vm_mmap_vnode()
 *
 * Helper function for vm_mmap.  Perform sanity check specific for mmap
 * operations on vnodes.
 */
int
vm_mmap_vnode(struct thread *td, vm_size_t objsize,
    vm_prot_t prot, vm_prot_t *maxprotp, int *flagsp,
    struct vnode *vp, vm_ooffset_t *foffp, vm_object_t *objp,
    boolean_t *writecounted)
{
	struct vattr va;
	vm_object_t obj;
	vm_ooffset_t foff;
	struct ucred *cred;
	int error, flags;
	bool writex;

	cred = td->td_ucred;
	writex = (*maxprotp & VM_PROT_WRITE) != 0 &&
	    (*flagsp & MAP_SHARED) != 0;
	if ((error = vget(vp, LK_SHARED)) != 0)
		return (error);
	AUDIT_ARG_VNODE1(vp);
	foff = *foffp;
	flags = *flagsp;
	obj = vp->v_object;
	if (vp->v_type == VREG) {
		/*
		 * Get the proper underlying object
		 */
		if (obj == NULL) {
			error = EINVAL;
			goto done;
		}
		if (obj->type == OBJT_VNODE && obj->handle != vp) {
			vput(vp);
			vp = (struct vnode *)obj->handle;
			/*
			 * Bypass filesystems obey the mpsafety of the
			 * underlying fs.  Tmpfs never bypasses.
			 */
			error = vget(vp, LK_SHARED);
			if (error != 0)
				return (error);
		}
		if (writex) {
			*writecounted = TRUE;
			vm_pager_update_writecount(obj, 0, objsize);
		}
	} else {
		error = EINVAL;
		goto done;
	}
	if ((error = VOP_GETATTR(vp, &va, cred)))
		goto done;
#ifdef MAC
	/* This relies on VM_PROT_* matching PROT_*. */
	error = mac_vnode_check_mmap(cred, vp, (int)prot, flags);
	if (error != 0)
		goto done;
#endif
	if ((flags & MAP_SHARED) != 0) {
		if ((va.va_flags & (SF_SNAPSHOT|IMMUTABLE|APPEND)) != 0) {
			if (prot & VM_PROT_WRITE) {
				error = EPERM;
				goto done;
			}
			*maxprotp &= ~VM_PROT_WRITE;
		}
	}
	/*
	 * If it is a regular file without any references
	 * we do not need to sync it.
	 * Adjust object size to be the size of actual file.
	 */
	objsize = round_page(va.va_size);
	if (va.va_nlink == 0)
		flags |= MAP_NOSYNC;
	if (obj->type == OBJT_VNODE) {
		obj = vm_pager_allocate(OBJT_VNODE, vp, objsize, prot, foff,
		    cred);
		if (obj == NULL) {
			error = ENOMEM;
			goto done;
		}
	} else {
		KASSERT((obj->flags & OBJ_SWAP) != 0, ("wrong object type"));
		vm_object_reference(obj);
#if VM_NRESERVLEVEL > 0
		if ((obj->flags & OBJ_COLORED) == 0) {
			VM_OBJECT_WLOCK(obj);
			vm_object_color(obj, 0);
			VM_OBJECT_WUNLOCK(obj);
		}
#endif
	}
	*objp = obj;
	*flagsp = flags;

	VOP_MMAPPED(vp);

done:
	if (error != 0 && *writecounted) {
		*writecounted = FALSE;
		vm_pager_update_writecount(obj, objsize, 0);
	}
	vput(vp);
	return (error);
}

/*
 * vm_mmap_cdev()
 *
 * Helper function for vm_mmap.  Perform sanity check specific for mmap
 * operations on cdevs.
 */
int
vm_mmap_cdev(struct thread *td, vm_size_t objsize, vm_prot_t *protp,
    vm_prot_t *maxprotp, int *flagsp, struct cdev *cdev, struct cdevsw *dsw,
    vm_ooffset_t *foff, vm_object_t *objp)
{
	vm_object_t obj;
	vm_prot_t prot;
	int error, flags;

	flags = *flagsp;
	prot = *protp;

	if (dsw->d_flags & D_MMAP_ANON) {
		*objp = NULL;
		*foff = 0;
		*maxprotp = VM_PROT_ALL;
		*protp = VM_PROT_ADD_CAP(*protp);
		*flagsp |= MAP_ANON;
		return (0);
	}
	/*
	 * cdevs do not provide private mappings of any kind.
	 */
	if ((*maxprotp & VM_PROT_WRITE) == 0 &&
	    (prot & VM_PROT_WRITE) != 0)
		return (EACCES);
	if (flags & (MAP_PRIVATE|MAP_COPY))
		return (EINVAL);
	/*
	 * Force device mappings to be shared.
	 */
	flags |= MAP_SHARED;
#ifdef MAC_XXX
	error = mac_cdev_check_mmap(td->td_ucred, cdev, (int)prot);
	if (error != 0)
		return (error);
#endif
	/*
	 * First, try d_mmap_single().  If that is not implemented
	 * (returns ENODEV), fall back to using the device pager.
	 * Note that d_mmap_single() must return a reference to the
	 * object (it needs to bump the reference count of the object
	 * it returns somehow).
	 *
	 * XXX assumes VM_PROT_* == PROT_*
	 */
	error = dsw->d_mmap_single(cdev, foff, objsize, objp, (int)prot);
	if (error != ENODEV)
		return (error);
	obj = vm_pager_allocate(OBJT_DEVICE, cdev, objsize, prot, *foff,
	    td->td_ucred);
	if (obj == NULL)
		return (EINVAL);
	*objp = obj;
	*flagsp = flags;
	return (0);
}

int
vm_mmap(vm_map_t map, vm_pointer_t *addr, vm_size_t size, vm_prot_t prot,
	vm_prot_t maxprot, int flags,
	objtype_t handle_type, void *handle,
	vm_ooffset_t foff)
{
	vm_object_t object;
	struct thread *td = curthread;
	int error;
	boolean_t writecounted;

	if (size == 0)
		return (EINVAL);

	size = round_page(size);
	object = NULL;
	writecounted = FALSE;

	KASSERT((prot & VM_PROT_CAP) == 0, ("VM_PROT_CAP set in prot"));
	KASSERT((maxprot & VM_PROT_CAP) == 0, ("VM_PROT_CAP set in maxprot"));

	switch (handle_type) {
	case OBJT_DEVICE: {
		struct cdevsw *dsw;
		struct cdev *cdev;
		int ref;

		cdev = handle;
		dsw = dev_refthread(cdev, &ref);
		if (dsw == NULL)
			return (ENXIO);
		error = vm_mmap_cdev(td, size, &prot, &maxprot, &flags, cdev,
		    dsw, &foff, &object);
		dev_relthread(cdev, ref);
		break;
	}
	case OBJT_VNODE:
		error = vm_mmap_vnode(td, size, prot, &maxprot, &flags,
		    handle, &foff, &object, &writecounted);
		break;
	default:
		error = EINVAL;
		break;
	}
	if (error)
		return (error);

	error = vm_mmap_object(map, addr, 0, size, prot, maxprot, flags,
	    object, foff, writecounted, td);
	if (error != 0 && object != NULL) {
		/*
		 * If this mapping was accounted for in the vnode's
		 * writecount, then undo that now.
		 */
		if (writecounted)
			vm_pager_release_writecount(object, 0, size);
		vm_object_deallocate(object);
	}
	return (error);
}

int
kern_mmap_racct_check(struct thread *td, vm_map_t map, vm_size_t size)
{
	int error;

	RACCT_PROC_LOCK(td->td_proc);
	if (map->size + size > lim_cur(td, RLIMIT_VMEM)) {
		RACCT_PROC_UNLOCK(td->td_proc);
		return (ENOMEM);
	}
	if (racct_set(td->td_proc, RACCT_VMEM, map->size + size)) {
		RACCT_PROC_UNLOCK(td->td_proc);
		return (ENOMEM);
	}
	if (!old_mlock && map->flags & MAP_WIREFUTURE) {
		if (ptoa(pmap_wired_count(map->pmap)) + size >
		    lim_cur(td, RLIMIT_MEMLOCK)) {
			racct_set_force(td->td_proc, RACCT_VMEM, map->size);
			RACCT_PROC_UNLOCK(td->td_proc);
			return (ENOMEM);
		}
		error = racct_set(td->td_proc, RACCT_MEMLOCK,
		    ptoa(pmap_wired_count(map->pmap)) + size);
		if (error != 0) {
			racct_set_force(td->td_proc, RACCT_VMEM, map->size);
			RACCT_PROC_UNLOCK(td->td_proc);
			return (error);
		}
	}
	RACCT_PROC_UNLOCK(td->td_proc);
	return (0);
}

/*
 * Internal version of mmap that maps a specific VM object into an
 * map.  Called by mmap for MAP_ANON, vm_mmap, shm_mmap, and vn_mmap.
 */
int
vm_mmap_object(vm_map_t map, vm_pointer_t *addr, vm_offset_t max_addr,
    vm_size_t size, vm_prot_t prot,
    vm_prot_t maxprot, int flags, vm_object_t object, vm_ooffset_t foff,
    boolean_t writecounted, struct thread *td)
{
	vm_pointer_t *reservp;
	int docow, error, findspace, rv;
	bool curmap, fitit;

#ifdef __CHERI_PURE_CAPABILITY__
	KASSERT(cheri_getlen(addr) == sizeof(void *),
	    ("Invalid bounds for pointer-sized object %zx",
	    (size_t)cheri_getlen(addr)));
#endif

	curmap = map == &td->td_proc->p_vmspace->vm_map;
	if (curmap) {
		error = kern_mmap_racct_check(td, map, size);
		if (error != 0)
			return (error);
	}

	/*
	 * We currently can only deal with page aligned file offsets.
	 * The mmap() system call already enforces this by subtracting
	 * the page offset from the file offset, but checking here
	 * catches errors in device drivers (e.g. d_single_mmap()
	 * callbacks) and other internal mapping requests (such as in
	 * exec).
	 */
	if (foff & PAGE_MASK)
		return (EINVAL);

	if ((flags & MAP_FIXED) == 0) {
		fitit = TRUE;
		*addr = round_page(*addr);
	} else {
		if (*addr != trunc_page(*addr))
			return (EINVAL);
		fitit = FALSE;
	}

	if (flags & MAP_ANON) {
		if (object != NULL || foff != 0)
			return (EINVAL);
		docow = 0;
	} else if (flags & MAP_PREFAULT_READ)
		docow = MAP_PREFAULT;
	else
		docow = MAP_PREFAULT_PARTIAL;

	if ((flags & (MAP_ANON|MAP_SHARED)) == 0)
		docow |= MAP_COPY_ON_WRITE;
	if (flags & MAP_NOSYNC)
		docow |= MAP_DISABLE_SYNCER;
	if (flags & MAP_NOCORE)
		docow |= MAP_DISABLE_COREDUMP;
	/* Shared memory is also shared with children. */
	if (flags & MAP_SHARED)
		docow |= MAP_INHERIT_SHARE;
	if (writecounted)
		docow |= MAP_WRITECOUNT;
	if (flags & MAP_STACK) {
		if (object != NULL)
			return (EINVAL);
		docow |= MAP_STACK_GROWS_DOWN;
	}
	if ((flags & MAP_EXCL) != 0)
		docow |= MAP_CHECK_EXCL;
	if ((flags & MAP_GUARD) != 0)
		docow |= MAP_CREATE_GUARD;

	if (fitit) {
		if ((flags & MAP_ALIGNMENT_MASK) == MAP_ALIGNED_SUPER)
			findspace = VMFS_SUPER_SPACE;
		else if ((flags & MAP_ALIGNMENT_MASK) != 0)
			findspace = VMFS_ALIGNED_SPACE(flags >>
			    MAP_ALIGNMENT_SHIFT);
		else
			findspace = VMFS_OPTIMAL_SPACE;
		if (curmap) {
			rv = vm_map_find_min(map, object, foff, addr, size,
			    round_page((vm_offset_t)td->td_proc->p_vmspace->
			    vm_daddr + lim_max(td, RLIMIT_DATA)), max_addr,
			    findspace, prot, maxprot, docow);
		} else {
			rv = vm_map_find(map, object, foff, addr, size,
			    max_addr, findspace, prot, maxprot, docow);
		}
	} else {
		if (max_addr != 0 && *addr + size > max_addr)
			return (ENOMEM);
		if (docow & MAP_GUARD)
			maxprot = PROT_NONE;
		if ((flags & MAP_RESERVATION_CREATE) != 0)
			reservp = addr;
		else
			reservp = NULL;
		rv = vm_map_fixed(map, object, foff, *addr, reservp, size,
		    prot, maxprot, docow);
	}

	if (rv == KERN_SUCCESS) {
		/*
		 * If the process has requested that all future mappings
		 * be wired, then heed this.
		 */
		if ((map->flags & MAP_WIREFUTURE) != 0) {
			vm_map_lock(map);
			if ((map->flags & MAP_WIREFUTURE) != 0)
				(void)vm_map_wire_locked(map, *addr,
				    *addr + size, VM_MAP_WIRE_USER |
				    ((flags & MAP_STACK) ? VM_MAP_WIRE_HOLESOK :
				    VM_MAP_WIRE_NOHOLES));
			vm_map_unlock(map);
		}
	}
	return (vm_mmap_to_errno(rv));
}

/*
 * Translate a Mach VM return code to zero on success or the appropriate errno
 * on failure.
 */
int
vm_mmap_to_errno(int rv)
{

	switch (rv) {
	case KERN_SUCCESS:
		return (0);
	case KERN_INVALID_ADDRESS:
	case KERN_NO_SPACE:
		return (ENOMEM);
	case KERN_PROTECTION_FAILURE:
		return (EACCES);
	case KERN_MEM_PROT_FAILURE:
		return (EPROT);
	default:
		return (EINVAL);
	}
}
// CHERI CHANGES START
// {
//   "updated": 20221212,
//   "target_type": "kernel",
//   "changes": [
//     "support",
//     "user_capabilities"
//   ],
//   "changes_purecap": [
//     "support",
//     "pointer_as_integer",
//     "bounds_compression"
//   ]
// }
// CHERI CHANGES END
