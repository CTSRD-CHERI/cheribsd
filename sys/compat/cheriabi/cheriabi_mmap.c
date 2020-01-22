/*-
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

#include <sys/param.h>
#include <sys/mman.h>
#include <sys/signal.h>
#include <sys/uio.h>
#include <sys/ktrace.h>		/* Must come after sys/signal.h */
#include <sys/syscallsubr.h>
#include <sys/user.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_extern.h>

#include <cheri/cheri.h>

#include <compat/cheriabi/cheriabi.h>
#include <compat/cheriabi/cheriabi_util.h>
#include <compat/cheriabi/cheriabi_proto.h>
#include <compat/cheriabi/cheriabi_syscall.h>

SYSCTL_NODE(_compat, OID_AUTO, cheriabi, CTLFLAG_RW, 0, "CheriABI mode");
SYSCTL_NODE(_compat_cheriabi, OID_AUTO, mmap, CTLFLAG_RW, 0, "mmap");

static int	cheriabi_mmap_honor_prot = 1;
SYSCTL_INT(_compat_cheriabi_mmap, OID_AUTO, honor_prot,
    CTLFLAG_RWTUN, &cheriabi_mmap_honor_prot, 0,
    "Reduce returned permissions to those requested by the prot argument.");
static int	cheriabi_mmap_setbounds = 1;
SYSCTL_INT(_compat_cheriabi_mmap, OID_AUTO, setbounds,
    CTLFLAG_RWTUN, &cheriabi_mmap_setbounds, 0,
    "Set bounds on returned capabilities.");

static register_t cheriabi_mmap_prot2perms(int prot);

static int
cap_covers_pages(const void * __capability cap, size_t size)
{
	const char * __capability addr;
	size_t pageoff;

	addr = cap;
	pageoff = ((__cheri_addr vaddr_t)addr & PAGE_MASK);
	addr -= pageoff;
	size += pageoff;
	size = (vm_size_t)round_page(size);

	return (__CAP_CHECK(__DECONST_CAP(void * __capability, addr), size));
}

int
cheriabi_msync(struct thread *td, struct cheriabi_msync_args *uap)
{

	/*
	 * FreeBSD msync() has a non-standard behavior that a len of 0
	 * effects the whole vm entry.  We allow this because it is used
	 * and we currently think there is little attack value in
	 * msync calls.
	 */
	if (uap->len != 0 && cap_covers_pages(uap->addr, uap->len) == 0)
		return (EINVAL);

	return (kern_msync(td, (__cheri_addr uintptr_t)uap->addr, uap->len,
	    uap->flags));
}

int
cheriabi_madvise(struct thread *td, struct cheriabi_madvise_args *uap)
{

	if (cap_covers_pages(uap->addr, uap->len) == 0)
		return (ENOMEM);	/* XXX EPROT? */

	/*
	 * MADV_FREE may change the page contents so require
	 * CHERI_PERM_CHERIABI_VMMAP.
	 */
	if (uap->behav == MADV_FREE) {
		if ((cheri_getperm(uap->addr) & CHERI_PERM_CHERIABI_VMMAP) == 0)
			return (EPROT);
	}

	return (kern_madvise(td, (__cheri_addr uintptr_t)uap->addr, uap->len,
	    uap->behav));
}

int
cheriabi_mmap(struct thread *td, struct cheriabi_mmap_args *uap)
{
	int flags = uap->flags;
	void * __capability source_cap;
	register_t perms, reqperms;
	vm_offset_t hint;
	struct mmap_req mr;

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
	 * switch to using the per-thread mmap capability as the source
	 * capability if this pattern proves common.
	 */
	hint = cheri_getaddress(uap->addr);
	if (cheri_gettag(uap->addr) &&
	    (cheri_getperm(uap->addr) & CHERI_PERM_CHERIABI_VMMAP) &&
	    (flags & MAP_FIXED))
		source_cap = uap->addr;
	else {
		if (flags & MAP_FIXED)
			flags |= MAP_EXCL;

		if (flags & MAP_CHERI_NOSETBOUNDS) {
			SYSERRCAUSE("MAP_CHERI_NOSETBOUNDS without a valid "
			    "addr capability");
			return (EINVAL);
		}

		/* Allocate from the per-thread capability. */
		source_cap = td->td_cheri_mmap_cap;
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
		    "capablity (0x%zx < 0x%zx)", cap_len - cap_offset,
		    roundup2(uap->len, PAGE_SIZE));
		return (EPROT);
	}

	perms = cheri_getperm(source_cap);
	reqperms = cheriabi_mmap_prot2perms(uap->prot);
	if ((perms & reqperms) != reqperms) {
		SYSERRCAUSE("capability has insufficient perms (0x%lx)"
		    "for request (0x%lx)", perms, reqperms);
		return (EPROT);
	}

	/*
	 * If alignment is specified, check that it is sufficent and
	 * increase as required.  If not, assume data alignment.
	 */
	switch (flags & MAP_ALIGNMENT_MASK) {
	case MAP_ALIGNED(0):
		flags &= ~MAP_ALIGNMENT_MASK;
		/*
		 * Request CHERI data alignment when no other request is made.
		 * However, do not request alignment if both MAP_FIXED and
		 * MAP_CHERI_NOSETBOUNDS is set since that means we are filling
		 * in reserved address space from a file or MAP_ANON memory.
		 */
		if (!((flags & MAP_FIXED) && (flags & MAP_CHERI_NOSETBOUNDS))) {
			flags |= MAP_ALIGNED_CHERI;
		}
		break;
	case MAP_ALIGNED_CHERI:
	case MAP_ALIGNED_CHERI_SEAL:
		break;
	case MAP_ALIGNED_SUPER:
#ifdef __mips_n64
		/*
		 * pmap_align_superpage() is a no-op for allocations
		 * less than a super page so request data alignment
		 * in that case.
		 *
		 * In practice this is a no-op as super-pages are
		 * precisely representable.
		 */
		if (uap->len < PDRSIZE &&
		    CHERI_REPRESENTABLE_ALIGNMENT(uap->len) > (1UL << PAGE_SHIFT)) {
			flags &= ~MAP_ALIGNMENT_MASK;
			flags |= MAP_ALIGNED_CHERI;
		}
#else
#error	MAP_ALIGNED_SUPER handling unimplemented for this architecture
#endif
		break;
	default:
		/* Reject nonsensical sub-page alignment requests */
		if ((flags >> MAP_ALIGNMENT_SHIFT) < PAGE_SHIFT) {
			SYSERRCAUSE("subpage alignment request");
			return (EINVAL);
		}

		/*
		 * Honor the caller's alignment request, if any unless
		 * it is too small.  If is, promote the request to
		 * MAP_ALIGNED_CHERI.
		 *
		 * However, do not request alignment if both MAP_FIXED and
		 * MAP_CHERI_NOSETBOUNDS is set since that means we are filling
		 * in reserved address space from a file or MAP_ANON memory.
		 *
		 * XXX: It seems likely a user passing too small an
		 * alignment will have also passed an invalid length,
		 * but upgrading the alignment is always safe and
		 * we'll catch the length later.
		 */
		if (!((flags & MAP_FIXED) && (flags & MAP_CHERI_NOSETBOUNDS))) {
			if ((1UL << (flags >> MAP_ALIGNMENT_SHIFT)) <
			    CHERI_REPRESENTABLE_ALIGNMENT(uap->len)) {
				flags &= ~MAP_ALIGNMENT_MASK;
				flags |= MAP_ALIGNED_CHERI;
			}
		}
		break;
	}
	/*
	 * NOTE: If this architecture requires an alignment constraint, it is
	 * set at this point.  A simple assert is not easy to contruct...
	 */

	memset(&mr, 0, sizeof(mr));
	mr.mr_hint = hint;
	mr.mr_max_addr = cheri_gettop(source_cap);
	mr.mr_len = uap->len;
	mr.mr_prot = uap->prot;
	mr.mr_flags = flags;
	mr.mr_fd = uap->fd;
	mr.mr_pos = uap->pos;
	mr.mr_source_cap = source_cap;

	return (kern_mmap_req(td, &mr));
}

int
cheriabi_munmap(struct thread *td, struct cheriabi_munmap_args *uap)
{

	if (cap_covers_pages(uap->addr, uap->len) == 0)
		return (ENOMEM);	/* XXX EPROT? */
	if ((cheri_getperm(uap->addr) & CHERI_PERM_CHERIABI_VMMAP) == 0)
		return (EPROT);

	return (kern_munmap(td, (__cheri_addr uintptr_t)uap->addr, uap->len));
}


int
cheriabi_mprotect(struct thread *td, struct cheriabi_mprotect_args *uap)
{
	register_t perms, reqperms;

	if (cap_covers_pages(uap->addr, uap->len) == 0)
		return (ENOMEM);	/* XXX EPROT? */
	/*
	 * XXX: should we require CHERI_PERM_CHERIABI_VMMAP?  On one
	 * hand we don't change the contents, on the other hand, denied
	 * access can turn into a fault...
	 */

	perms = cheri_getperm(uap->addr);
	/*
	 * Requested prot much be allowed by capability.
	 *
	 * XXX-BD: An argument could be made for allowing a union of the
	 * current page permissions with the capability permissions (e.g.
	 * allowing a writable cap to add write permissions to an RX
	 * region as required to match up objects with textrel sections.
	 */
	reqperms = cheriabi_mmap_prot2perms(uap->prot);
	if ((perms & reqperms) != reqperms)
		return (EPROT);

	return (kern_mprotect(td, (__cheri_addr vm_offset_t)uap->addr,
	    uap->len, uap->prot));
}

int
cheriabi_minherit(struct thread *td, struct cheriabi_minherit_args *uap)
{

	
	if (cap_covers_pages(uap->addr, uap->len) == 0)
		return (ENOMEM);	/* XXX EPROT? */
	/* XXX: require CHERI_PERM_CHERIABI_VMMAP? */

	return (kern_minherit(td, (__cheri_addr vm_offset_t)uap->addr,
	    uap->len, uap->inherit));
}

#define	PERM_READ	(CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP)
#define	PERM_WRITE	(CHERI_PERM_STORE | CHERI_PERM_STORE_CAP | \
			    CHERI_PERM_STORE_LOCAL_CAP)
#define	PERM_EXEC	CHERI_PERM_EXECUTE
#define	PERM_RWX	(PERM_READ | PERM_WRITE | PERM_EXEC)
/*
 * Given a starting set of CHERI permissions (operms), set (not AND) the load,
 * store, and execute permissions based on the mmap permissions (prot).
 *
 * This function is intended to be used when creating a capability to a
 * new region or rederiving a capability when upgrading a sub-region.
 */
static register_t
cheriabi_mmap_prot2perms(int prot)
{
	register_t perms = 0;

	if (prot & PROT_READ)
		perms |= CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP;
	if (prot & PROT_WRITE)
		perms |= CHERI_PERM_STORE | CHERI_PERM_STORE_CAP |
		CHERI_PERM_STORE_LOCAL_CAP;
	if (prot & PROT_EXEC)
		perms |= CHERI_PERM_EXECUTE;

	return (perms);
}

void * __capability
cheriabi_mmap_retcap(struct thread *td, vm_offset_t addr,
    const struct mmap_req *mrp)
{
	void * __capability newcap;
	size_t cap_base, cap_len;
	register_t perms, cap_prot;

	/*
	 * In the strong case (cheriabi_mmap_setbounds), return the original
	 * capability when MAP_CHERI_NOSETBOUNDS is set.
	 *
	 * In the weak case (!cheriabi_mmap_setbounds), return the original
	 * capability for *all* fixed requests.
	 *
	 * NB: This means no permission changes.
	 * The assumption is that the larger capability has the correct
	 * permissions and we're only intrested in adjusting page mappings.
	 */
	if (mrp->mr_flags & MAP_CHERI_NOSETBOUNDS ||
	    (!cheriabi_mmap_setbounds && mrp->mr_flags & MAP_FIXED)) {
		return (mrp->mr_source_cap);
	}

	newcap = mrp->mr_source_cap;
	if (cheriabi_mmap_honor_prot) {
		perms = cheri_getperm(newcap);
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
		newcap = cheri_andperm(newcap, ~PERM_RWX |
		    cheriabi_mmap_prot2perms(cap_prot));
	}

	if (mrp->mr_flags & MAP_FIXED) {
		KASSERT(cheriabi_mmap_setbounds,
		    ("%s: trying to set bounds on fixed map when disabled",
		    __func__));
		/*
		 * If hint was under aligned, we need to return a
		 * capability to the whole, properly aligned region
		 * with the offset pointing to hint.
		 */
		cap_base = cheri_getbase(newcap);
		/* TODO: use cheri_setaddress? */
		/* Set offset to vaddr of page */
		newcap = cheri_setoffset(newcap,
		    rounddown2(addr, PAGE_SIZE) - cap_base);
		newcap = cheri_csetbounds(newcap,
		    roundup2(mrp->mr_len + (addr - rounddown2(addr, PAGE_SIZE)),
		    PAGE_SIZE));
		/* Shift offset up if required */
		cap_base = cheri_getbase(newcap);
		newcap = cheri_setoffset(newcap, cap_base - addr);
	} else {
		cap_base = cheri_getbase(newcap);
		cap_len = cheri_getlen(newcap);
		KASSERT(addr >= cap_base &&
		    addr + mrp->mr_len <= cap_base + cap_len,
		    ("Allocated range (%zx - %zx) is not within source "
		    "capability (%zx - %zx)", addr, addr + mrp->mr_len,
		    cap_base, cap_base + cap_len));
		newcap = cheri_setoffset(newcap, addr - cap_base);
		if (cheriabi_mmap_setbounds)
			newcap = cheri_csetbounds(newcap,
			    roundup2(mrp->mr_len, PAGE_SIZE));
	}

	return (newcap);
}

int
cheriabi_mincore(struct thread *td, struct cheriabi_mincore_args *uap)
{

	if (cap_covers_pages(uap->addr, uap->len) == 0)
		return (ENOMEM);	/* XXX: EPROT? */

	return (kern_mincore(td, (__cheri_addr uintptr_t)uap->addr, uap->len,
	    uap->vec));
}

int
cheriabi_mlock(struct thread *td, struct cheriabi_mlock_args *uap)
{

	if (cap_covers_pages(uap->addr, uap->len) == 0)
		return (ENOMEM);	/* XXX: EPROT? */

	return (kern_mlock(td->td_proc, td->td_ucred,
	    (__cheri_addr uintptr_t)uap->addr, uap->len));
}

int
cheriabi_munlock(struct thread *td, struct cheriabi_munlock_args *uap)
{

	if (cap_covers_pages(uap->addr, uap->len) == 0)
		return (ENOMEM);	/* XXX: EPROT? */

	return (kern_munlock(td, (__cheri_addr uintptr_t)uap->addr, uap->len));
}
