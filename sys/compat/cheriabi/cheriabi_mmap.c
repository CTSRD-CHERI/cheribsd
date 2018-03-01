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

#include "opt_compat.h"

#include <sys/param.h>
#include <sys/mman.h>
#include <sys/signal.h>
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
#include <compat/cheriabi/cheriabi_sysargmap.h>

#include <sys/cheriabi.h>

SYSCTL_NODE(_compat, OID_AUTO, cheriabi, CTLFLAG_RW, 0, "CheriABI mode");
static SYSCTL_NODE(_compat_cheriabi, OID_AUTO, mmap, CTLFLAG_RW, 0, "mmap");

static int	cheriabi_mmap_honor_prot = 1;
SYSCTL_INT(_compat_cheriabi_mmap, OID_AUTO, honor_prot,
    CTLFLAG_RWTUN, &cheriabi_mmap_honor_prot, 0,
    "Reduce returned permissions to those requested by the prot argument.");
static int	cheriabi_mmap_setbounds = 1;
SYSCTL_INT(_compat_cheriabi_mmap, OID_AUTO, setbounds,
    CTLFLAG_RWTUN, &cheriabi_mmap_setbounds, 0,
    "Set bounds on returned capabilities.");
int	cheriabi_mmap_precise_bounds = 1;
SYSCTL_INT(_compat_cheriabi_mmap, OID_AUTO, precise_bounds,
    CTLFLAG_RWTUN, &cheriabi_mmap_precise_bounds, 0,
    "Require that bounds on returned capabilities be precise.");

static register_t cheriabi_mmap_prot2perms(int prot);

int
cheriabi_madvise(struct thread *td, struct cheriabi_madvise_args *uap)
{
	void * __capability addr_cap;
	register_t perms;

	/*
	 * MADV_FREE may change the page contents so require
	 * CHERI_PERM_CHERIABI_VMMAP.
	 */
	if (uap->behav == MADV_FREE) {
		cheriabi_fetch_syscall_arg(td, &addr_cap,
		    0, CHERIABI_SYS_cheriabi_madvise_PTRMASK);
		perms = cheri_getperm(addr_cap);
		if ((perms & CHERI_PERM_CHERIABI_VMMAP) == 0)
			return (EPROT);
	}

	return (kern_madvise(td, (uintptr_t)uap->addr, uap->len, uap->behav));
}

int
cheriabi_mmap(struct thread *td, struct cheriabi_mmap_args *uap)
{
	int flags = uap->flags;
	int usertag;
	size_t cap_base, cap_len, cap_offset;
	void * __capability addr_cap;
	register_t perms, reqperms;
	vm_offset_t reqaddr;

	if (flags & MAP_32BIT) {
		SYSERRCAUSE("MAP_32BIT not supported in CheriABI");
		return (EINVAL);
	}

	cheriabi_fetch_syscall_arg(td, &addr_cap,
	    0, CHERIABI_SYS_cheriabi_mmap_PTRMASK);
	usertag = cheri_gettag(addr_cap);
	if (!usertag) {
		if (flags & MAP_FIXED) {
			SYSERRCAUSE(
			    "MAP_FIXED without a valid addr capability");
			return (EINVAL);
		}
		if (flags & MAP_CHERI_NOSETBOUNDS) {
			SYSERRCAUSE("MAP_CHERI_NOSETBOUNDS without a valid"
			    "addr capability");
			return (EINVAL);
		}

		/* User didn't provide a capability so get one. */
		if (flags & MAP_CHERI_DDC) {
			if ((cheri_getperm(td->td_pcb->pcb_regs.ddc) &
			    CHERI_PERM_CHERIABI_VMMAP) == 0) {
				SYSERRCAUSE("DDC lacks "
				    "CHERI_PERM_CHERIABI_VMMAP");
				return (EPROT);
			}
			addr_cap = td->td_pcb->pcb_regs.ddc;
		} else {
			/* Use the per-thread one */
			addr_cap = td->td_md.md_cheri_mmap_cap;
			KASSERT(cheri_gettag(addr_cap),
			    ("td->td_md.md_cheri_mmap_cap is untagged!"));
		}
	} else {
		if (flags & MAP_CHERI_DDC) {
			SYSERRCAUSE("MAP_CHERI_DDC with non-NULL addr");
			return (EINVAL);
		}
	}
	cap_base = cheri_getbase(addr_cap);
	cap_len = cheri_getlen(addr_cap);
	if (usertag) {
		cap_offset = cheri_getoffset(addr_cap);
	} else {
		/*
		 * Ignore offset of default cap, it's only used to set bounds.
		 */
		cap_offset = 0;
	}
	if (cap_offset >= cap_len) {
		SYSERRCAUSE("capability has out of range offset");
		return (EPROT);
	}
	reqaddr = cap_base + cap_offset;
	if (reqaddr == 0)
		reqaddr = PAGE_SIZE;
	perms = cheri_getperm(addr_cap);
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
		/*
		 * Request CHERI data alignment when no other request
		 * is made.
		 */
		flags &= ~MAP_ALIGNMENT_MASK;
		flags |= MAP_ALIGNED_CHERI;
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
		    CHERI_ALIGN_SHIFT(uap->len) > PAGE_SHIFT) {
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
		 * XXX: It seems likely a user passing too small an
		 * alignment will have also passed an invalid length,
		 * but upgrading the alignment is always safe and
		 * we'll catch the length later.
		 */
		if ((flags >> MAP_ALIGNMENT_SHIFT) <
		    CHERI_ALIGN_SHIFT(uap->len)) {
			flags &= ~MAP_ALIGNMENT_MASK;
			flags |= MAP_ALIGNED_CHERI;
		}
		break;
	}
	/*
	 * NOTE: If this architecture requires an alignment constraint, it is
	 * set at this point.  A simple assert is not easy to contruct...
	 */

	if (flags & MAP_FIXED) {
		if (cap_len - cap_offset <
		    roundup2(uap->len, PAGE_SIZE)) {
			SYSERRCAUSE("MAP_FIXED and too little space in "
			    "capablity (0x%zx < 0x%zx)", cap_len - cap_offset,
			    roundup2(uap->len, PAGE_SIZE));
			return (EPROT);
		}

		/*
		 * If our address is under aligned, make sure
		 * we have room to shift it down to the page
		 * boundary.
		 */
		if ((reqaddr & PAGE_MASK) > cap_offset) {
			SYSERRCAUSE("insufficent space to shift addr (0x%lx) "
			    "down in capability (offset 0x%zx)",
			    reqaddr, cap_offset);
			return (EPROT);
		}

		/*
		 * NB: We defer alignment checks to kern_vm_mmap where we
		 * can account for file mappings with odd alignment
		 * that match the offset alignment.
		 */

	}

	return (kern_mmap(td, reqaddr, cap_base + cap_len, uap->len,
	    uap->prot, flags, uap->fd, uap->pos));
}


int
cheriabi_mprotect(struct thread *td, struct cheriabi_mprotect_args *uap)
{
	void * __capability addr_cap;
	register_t perms, reqperms;

	cheriabi_fetch_syscall_arg(td, &addr_cap,
	    0, CHERIABI_SYS_cheriabi_mprotect_PTRMASK);
	perms = cheri_getperm(addr_cap);
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

	return (kern_mprotect(td, (vm_offset_t)uap->addr, uap->len,
	    uap->prot));
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

int
cheriabi_mmap_set_retcap(struct thread *td, void * __capability *retcap,
   void * __capability *addrp, size_t len, int prot, int flags)
{
	register_t ret;
	size_t mmap_cap_base, mmap_cap_len;
	vm_map_t map;
	register_t perms;
	size_t addr_base;
	void * __capability addr;

	ret = td->td_retval[0];
	/* On failure, return a NULL capability with an offset of -1. */
	if ((void *)ret == MAP_FAILED) {
		/* XXX-BD: the return of -1 is in userspace, not here. */
		*retcap = (void * __capability)-1;
		return (0);
	}

	/*
	 * In the strong case (cheriabi_mmap_setbounds), leave addr untouched
	 * when MAP_CHERI_NOSETBOUNDS is set.
	 *
	 * In the weak case (!cheriabi_mmap_setbounds), return addr untouched
	 * for *all* fixed requests.
	 *
	 * NB: This means no permission changes.
	 * The assumption is that the larger capability has the correct
	 * permissions and we're only intrested in adjusting page mappings.
	 */
	if (flags & MAP_CHERI_NOSETBOUNDS ||
	    (!cheriabi_mmap_setbounds && flags & MAP_FIXED)) {
		*retcap = *addrp;
		return (0);
	}

	if (flags & MAP_FIXED) {
		addr = *addrp;
	} else if (flags & MAP_CHERI_DDC) {
		addr = td->td_pcb->pcb_regs.ddc;
	} else {
		addr = td->td_md.md_cheri_mmap_cap;
	}

	if (cheriabi_mmap_honor_prot) {
		perms = cheri_getperm(addr);
		/*
		 * Set the permissions to PROT_MAX to allow a full
		 * range of access subject to page permissions.
		 */
		addr = cheri_andperm(addr, ~PERM_RWX |
		    cheriabi_mmap_prot2perms(EXTRACT_PROT_MAX(prot)));
	}

	if (flags & MAP_FIXED) {
		KASSERT(cheriabi_mmap_setbounds,
		    ("%s: trying to set bounds on fixed map when disabled",
		    __func__));
		/*
		 * If addr was under aligned, we need to return a
		 * capability to the whole, properly aligned region
		 * with the offset pointing to addr.
		 */
		addr_base = cheri_getbase(addr);
		/* Set offset to vaddr of page */
		addr = cheri_setoffset(addr,
		    rounddown2(ret, PAGE_SIZE) - addr_base);
		addr = cheri_csetbounds(addr,
		    roundup2(len + (ret - rounddown2(ret, PAGE_SIZE)),
		    PAGE_SIZE));
		/* Shift offset up if required */
		addr_base = cheri_getbase(addr);
		addr = cheri_setoffset(addr, addr_base - ret);
	} else {
		mmap_cap_base = cheri_getbase(addr);
		mmap_cap_len = cheri_getlen(addr);
		if (ret < mmap_cap_base ||
		    ret + len > mmap_cap_base + mmap_cap_len) {
			map = &td->td_proc->p_vmspace->vm_map;
			vm_map_lock(map);
			vm_map_remove(map, ret, ret + len);
			vm_map_unlock(map);

			return (EPERM);
		}
		addr = cheri_setoffset(addr, ret - mmap_cap_base);
		if (cheriabi_mmap_setbounds)
			addr = cheri_csetbounds(addr, roundup2(len, PAGE_SIZE));
	}
	*retcap = addr;

	return (0);
}

int
cheriabi_mincore(struct thread *td, struct cheriabi_mincore_args *uap)
{

	/* XXX: check range of cap */
	return (kern_mincore(td, (__cheri_addr uintptr_t)uap->addr, uap->len,
	    uap->vec));
}
