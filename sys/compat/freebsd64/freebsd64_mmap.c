/*-
 * Copyright (c) 2015-2019 SRI International
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of
 * the DARPA SSITH research programme.
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
#include <sys/proc.h>
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

#include <compat/freebsd64/freebsd64_proto.h>

#if 0
int
freebsd64_sbrk(struct thread *td, struct freebsd64_sbrk_arg *uap)
{
	/* Never implemented, real implementation on sys_break */
	return (EOPNOTSUPP);
}

int
freebsd64_sstk(struct thread *td, struct freebsd64_sstk_args *uap)
{
	/* Never implemented */
	return (EOPNOTSUPP);
}
#endif

int
freebsd64_break(struct thread *td, struct freebsd64_break_args *uap)
{
#if !defined(__aarch64__) && !defined(__riscv)
	uintptr_t addr;
	int error;

	addr = (uintptr_t)uap->nsize;
	error = kern_break(td, &addr);
	if (error == 0)
		td->td_retval[0] = addr;
	return (error);
#else /* defined(__aarch64__) || defined(__riscv) */
	return (ENOSYS);
#endif /* defined(__aarch64__) || defined(__riscv) */
}

int
freebsd64_mmap(struct thread *td, struct freebsd64_mmap_args *uap)
{

	return (kern_mmap(td, &(struct mmap_req){
		.mr_hint = (uintptr_t)uap->addr,
		.mr_len = uap->len,
		.mr_prot = uap->prot,
		.mr_flags = uap->flags,
		.mr_fd = uap->fd,
		.mr_pos = uap->pos,
#ifdef __CHERI_PURE_CAPABILITY__
		/* Needed for fixed mappings */
		.mr_source_cap = userspace_root_cap
#endif
	    }));
}

#if defined(COMPAT_FREEBSD6)
int
freebsd6_freebsd64_mmap(struct thread *td,
    struct freebsd6_freebsd64_mmap_args *uap)
{
	return (kern_mmap(td, &(struct mmap_req){
		.mr_hint = (uintptr_t)uap->addr,
		.mr_len = uap->len,
		.mr_prot = uap->prot,
		.mr_flags = uap->flags,
		.mr_fd = uap->fd,
		.mr_pos = uap->pos,
#ifdef __CHERI_PURE_CAPABILITY__
		/* Needed for fixed mappings */
		.mr_source_cap = userspace_root_cap
#endif
	    }));
}
#endif

int
freebsd64_msync(struct thread *td, struct freebsd64_msync_args *uap)
{
	return (kern_msync(td, (uintptr_t)uap->addr, uap->len, uap->flags));
}

int
freebsd64_munmap(struct thread *td, struct freebsd64_munmap_args *uap)
{
	return (kern_munmap(td, (uintptr_t)uap->addr, uap->len));
}

int
freebsd64_mprotect(struct thread *td, struct freebsd64_mprotect_args *uap)
{
	return (kern_mprotect(td, (uintptr_t)uap->addr, uap->len, uap->prot));
}

int
freebsd64_minherit(struct thread *td, struct freebsd64_minherit_args *uap)
{
	return (kern_minherit(td, (uintptr_t)uap->addr, uap->len,
	    uap->inherit));
}

int
freebsd64_madvise(struct thread *td, struct freebsd64_madvise_args *uap)
{
	return (kern_madvise(td, (uintptr_t)uap->addr, uap->len, uap->behav));
}

int
freebsd64_mincore(struct thread *td, struct freebsd64_mincore_args *uap)
{
	return (kern_mincore(td, (uintptr_t)uap->addr, uap->len,
	    __USER_CAP(uap->vec, uap->len)));
}

int
freebsd64_mlock(struct thread *td, struct freebsd64_mlock_args *uap)
{
	return (kern_mlock(td->td_proc, td->td_ucred,
	    __DECONST(uintptr_t, uap->addr), uap->len));
}

int
freebsd64_munlock(struct thread *td, struct freebsd64_munlock_args *uap)
{
	return (kern_munlock(td, (uintptr_t)uap->addr, uap->len));
}
