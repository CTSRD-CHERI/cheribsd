/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Nathaniel Filardo
 * Copyright (c) 2020-2022 Microsoft Corp.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/signal.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/user.h>

#ifdef CHERI_CAPREVOKE

#include <cheri/cheric.h>

#include <sys/lock.h>
#include <sys/mutex.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>

#include <sys/aio.h>
#include <sys/event.h>
#include <sys/timers.h>

#include <cheri/revoke.h>
#include <cheri/revoke_kern.h>
#include <vm/vm_cheri_revoke.h>
#include <sys/syscallsubr.h>

/*
 * We reserve the FEATURE(cheri_revoke) and VM SYSCTL() namespace cheri_revoke
 * for the real implementation.
 */

FEATURE(cheri_revoke, "CHERI capability revocation support");

SYSCTL_NODE(_vm, OID_AUTO, cheri_revoke, CTLFLAG_RD | CTLFLAG_MPSAFE,  0,
    "CHERI capability revocation configuration");

/*
 * When revoking capabilities, we have to visit several kernel hoarders.
 *
 * XXX This gets exciting when these resources are shared.  For the moment,
 * we consider only the case where these are in 1:1 correspondence with
 * address spaces, but that's not going to be true in general (e.g., shared
 * file descriptor tables) even today, nevermind when we start doing things
 * like colocated processes.  Anyway, can we handwave away some of it and
 * say that "enough" of the world must be stopped?
 *
 * Since some stashes allow aliasing (e.g. dup2() for filedescs), we must
 * hold some locks for uncomfortably long.
 *
 * As kernel hoards are used by asynchronous systems (aio, kqueue, timers) and
 * might write to userspace, we ensure that all writes of unchecked
 * capabilities take place before we walk user memory.  By the time this
 * function returns, the hoards will be holding only checked capabilities that
 * are subsequently safe to write even while the revoker is doing its thing
 * and might not notice the stores.
 */
static void
cheri_revoke_hoarders(struct proc *p, struct vm_cheri_revoke_cookie *crc)
{
	/* aio */
	aio_cheri_revoke(p, crc);

	/* timers */
	ktimer_cheri_revoke(p, crc);

	/* kqueue: run last, because other systems might post here */
	kqueue_cheri_revoke(p->p_fd, crc);
}

static int
cheri_revoke_fini(struct cheri_revoke_syscall_info * __capability crsi,
    int res, struct cheri_revoke_stats *crst,
    struct cheri_revoke_epochs *crepochs)
{
	int res2 = 0;
	int res3 = 0;

	if (crsi != NULL) {
#ifdef CHERI_CAPREVOKE_STATS
		if (crst != NULL)
			res2 = copyout(crst, &crsi->stats, sizeof(*crst));
		else
#endif
			res2 = 0;
		res3 = copyout(crepochs, &crsi->epochs, sizeof(*crepochs));
	}
	if (res != 0)
		return (res);
	if (res2 != 0)
		return (res2);
	return (res3);
}

static int
sysctl_kern_proc_quarantining(SYSCTL_HANDLER_ARGS)
{
	struct vmspace *vm;
	int *name = (int *)arg1;
	u_int namelen = arg2;
	struct proc *p;
	int error = 0;
	pid_t pid;
	int is_quarantining;

	if (namelen != 1)
		return (EINVAL);

	pid = (pid_t)name[0];
	if (pid == curproc->p_pid || pid == 0) {
		if (SV_CURPROC_FLAG(SV_CHERI))
			is_quarantining = curproc->p_vmspace->
			    vm_map.vm_cheri_revoke_quarantining;
		else
			is_quarantining = -1;

		goto out;
	}

	error = pget(pid, PGET_WANTREAD, &p);
	if (error != 0)
		return (error);

	if (SV_PROC_FLAG(p, SV_CHERI)) {
		vm = vmspace_acquire_ref(p);
		if (vm == NULL)
			error = ESRCH;
		else {
			is_quarantining =
			     vm->vm_map.vm_cheri_revoke_quarantining;
			vmspace_free(vm);
		}
	} else
		is_quarantining = -1;

	PRELE(p);
out:
	if (error == 0)
		error = SYSCTL_OUT(req, &is_quarantining,
		    sizeof(is_quarantining));
	return (error);
}

static SYSCTL_NODE(_kern_proc, KERN_PROC_QUARANTINING, quarantining,
    CTLFLAG_RD | CTLFLAG_MPSAFE, sysctl_kern_proc_quarantining,
    "is this process quarantining for temporal safety");

static int
sysctl_kern_proc_revoker_state(SYSCTL_HANDLER_ARGS)
{
	struct vmspace *vm;
	int *name = (int *)arg1;
	u_int namelen = arg2;
	struct proc *p;
	int error = 0;
	pid_t pid;
	int state;

	if (namelen != 1)
		return (EINVAL);

	pid = (pid_t)name[0];
	if (pid == curproc->p_pid || pid == 0) {
		if (SV_CURPROC_FLAG(SV_CHERI))
			state = cheri_revoke_st_get_state(
			    curproc->p_vmspace->vm_map.vm_cheri_revoke_st);
		else
			state = -1;

		goto out;
	}

	error = pget(pid, PGET_WANTREAD, &p);
	if (error != 0)
		return (error);

	if (SV_PROC_FLAG(p, SV_CHERI)) {
		vm = vmspace_acquire_ref(p);
		if (vm == NULL)
			error = ESRCH;
		else {
			state = cheri_revoke_st_get_state(
			    vm->vm_map.vm_cheri_revoke_st);
			vmspace_free(vm);
		}
	} else
		state = -1;

	PRELE(p);
out:
	if (error == 0)
		error = SYSCTL_OUT(req, &state, sizeof(state));
	return (error);
}

static SYSCTL_NODE(_kern_proc, KERN_PROC_REVOKER_STATE, revoker_state,
    CTLFLAG_RD | CTLFLAG_MPSAFE, sysctl_kern_proc_revoker_state,
    "state of the in-kernel revoker");

static int
sysctl_kern_proc_revoker_epoch(SYSCTL_HANDLER_ARGS)
{
	struct vmspace *vm;
	int *name = (int *)arg1;
	u_int namelen = arg2;
	struct proc *p;
	int error = 0;
	pid_t pid;
	uint64_t epoch;

	if (namelen != 1)
		return (EINVAL);

	pid = (pid_t)name[0];
	if (pid == curproc->p_pid || pid == 0) {
		if (SV_CURPROC_FLAG(SV_CHERI))
			epoch = cheri_revoke_st_get_epoch(
			    curproc->p_vmspace->vm_map.vm_cheri_revoke_st);
		else
			epoch = -1;

		goto out;
	}

	error = pget(pid, PGET_WANTREAD, &p);
	if (error != 0)
		return (error);

	if (SV_PROC_FLAG(p, SV_CHERI)) {
		vm = vmspace_acquire_ref(p);
		if (vm == NULL)
			error = ESRCH;
		else {
			epoch = cheri_revoke_st_get_epoch(
			    vm->vm_map.vm_cheri_revoke_st);
			vmspace_free(vm);
		}
	} else
		epoch = -1;

	PRELE(p);
out:
	if (error == 0)
		error = SYSCTL_OUT(req, &epoch, sizeof(epoch));
	return (error);
}

static SYSCTL_NODE(_kern_proc, KERN_PROC_REVOKER_EPOCH, revoker_epoch,
    CTLFLAG_RD | CTLFLAG_MPSAFE, sysctl_kern_proc_revoker_epoch,
    "in-kernel revoker epoch");

#ifdef CHERI_CAPREVOKE_STATS
/* Here seems about as good a place as any */
_Static_assert(sizeof(struct cheri_revoke_stats) ==
    sizeof(((struct vm_map *)NULL)->vm_cheri_revoke_stats),
    "Caprevoke stats structure size mismatch");
#endif

static int
kern_cheri_revoke(struct thread *td, int flags,
    cheri_revoke_epoch_t start_epoch,
    struct cheri_revoke_syscall_info * __capability crsi)
{
	int res;
	cheri_revoke_epoch_t epoch;
	enum cheri_revoke_state entryst, myst;
	struct cheri_revoke_epochs crepochs = { 0 };
#ifdef CHERI_CAPREVOKE_STATS
	struct cheri_revoke_stats crst, *crstp;
#else
	struct cheri_revoke_stats *crstp = NULL;
#endif
	struct vmspace *vm;
	vm_map_t vmm;
	struct vm_cheri_revoke_cookie vmcrc;
	struct cheri_revoke_info_page * __capability info_page;

	vm = vmspace_acquire_ref(td->td_proc);
	vmm = &vm->vm_map;

	/*
	 * We need some value that's more or less "now", but we don't have
	 * to be too picky about it.  This value is not reported to
	 * userland, just used to guide the interlocking below.
	 */
	if ((flags & CHERI_REVOKE_IGNORE_START) != 0) {
		start_epoch = cheri_revoke_st_get_epoch(
		    vmm->vm_cheri_revoke_st);
	}

	/* Serialize and figure out what we're supposed to do */
	vm_map_lock(vmm);
	{
		int ires = 0;

		if (!vmm->vm_cheri_revoke_quarantining)
			vmm->vm_cheri_revoke_quarantining = true;

reentry:
		epoch = cheri_revoke_st_get_epoch(vmm->vm_cheri_revoke_st);
		entryst = cheri_revoke_st_get_state(vmm->vm_cheri_revoke_st);

		if (cheri_revoke_epoch_clears(epoch, start_epoch)) {
			/*
			 * An entire epoch has come and gone since the
			 * starting point of this request.  It is safe to
			 * return to userland with the request satiated.
			 *
			 * In case we queued, tho', go ahead and wake up the
			 * next would-be revoker first.
			 */
fast_out:
#ifdef CHERI_CAPREVOKE_STATS
			if (flags & CHERI_REVOKE_TAKE_STATS) {
				sx_xlock(&vmm->vm_cheri_revoke_stats_sx);
				crst = *(struct cheri_revoke_stats*)
				    &vmm->vm_cheri_revoke_stats;
				bzero(&vmm->vm_cheri_revoke_stats,
				    sizeof(vmm->vm_cheri_revoke_stats));
				sx_xunlock(&vmm->vm_cheri_revoke_stats_sx);
				crstp = &crst;
			} else {
				crstp = (struct cheri_revoke_stats*)
				    &vmm->vm_cheri_revoke_stats;
			}
#endif
			vm_map_unlock(vmm);
			cv_signal(&vmm->vm_cheri_revoke_cv);
			vmspace_free(vm);

			return (cheri_revoke_fini(crsi, ires, crstp,
			    &crepochs));
		}

		/*
		 * OK, the initial epoch clock isn't in the past.  Let's see
		 * what state we're in and what we can accomplish.
		 */
		switch (entryst) {
		case CHERI_REVOKE_ST_NONE:
			KASSERT((epoch & 1) == 0, ("Odd epoch NONE"));

			if (flags & CHERI_REVOKE_LAST_PASS) {
				myst = CHERI_REVOKE_ST_CLOSING;
			} else {
				myst = CHERI_REVOKE_ST_INITING;
			}
			break;
		case CHERI_REVOKE_ST_INITED:
			KASSERT((epoch & 1) == 1, ("Even epoch LS_INITED"));
			/*
			 * If a load-side epoch is already open, there's
			 * nothing to be done other than end it.
			 */
			if (flags & CHERI_REVOKE_LAST_PASS) {
				myst = CHERI_REVOKE_ST_CLOSING;
			} else {
				goto fast_out;
			}
			break;
		case CHERI_REVOKE_ST_CLOSING:
		case CHERI_REVOKE_ST_INITING:
			KASSERT(vmm->system_map == 0, ("System map?"));

			/* There is another revoker in progress.  Wait. */
			ires = cv_wait_sig(&vmm->vm_cheri_revoke_cv,
			    &vmm->lock);
			if (ires != 0) {
				vm_map_unlock(vmm);
				cv_signal(&vmm->vm_cheri_revoke_cv);
				vmspace_free(vm);
				return (ires);
			}

			goto reentry;
		}

		KASSERT((entryst == CHERI_REVOKE_ST_NONE) ||
			(entryst == CHERI_REVOKE_ST_INITED),
		    ("Beginning revocation with bad entry state"));
		KASSERT((myst == CHERI_REVOKE_ST_INITING) ||
			(myst == CHERI_REVOKE_ST_CLOSING),
		    ("Beginning revocation with bad current state"));

		if (entryst == CHERI_REVOKE_ST_NONE) {
			vm_map_entry_t entry;
			int test_flags =
			    VM_CHERI_REVOKE_CF_NO_COARSE_MEM |
			    VM_CHERI_REVOKE_CF_NO_OTYPES |
			    VM_CHERI_REVOKE_CF_NO_CIDS;
			if (!vm_map_entry_start_revocation(vmm, &entry))
				test_flags |= VM_CHERI_REVOKE_CF_NO_REV_ENTRY;
			vm_cheri_revoke_set_test(vmm, test_flags);
		}

#ifdef CHERI_CAPREVOKE_STATS
		crstp = (struct cheri_revoke_stats *)
		    &vmm->vm_cheri_revoke_stats;
#endif

		res = vm_cheri_revoke_cookie_init(&vm->vm_map, &vmcrc);
		if (res != KERN_SUCCESS) {
			vm_map_unlock(vmm);
			vmspace_free(vm);
			return (cheri_revoke_fini(crsi, vm_mmap_to_errno(res),
			    crstp, &crepochs));
		}

		/*
		 * Don't bump the epoch count here, just the state!  Wait
		 * until we're certain it's actually open, which we can only
		 * do below.
		 */
		cheri_revoke_st_set(&vmm->vm_cheri_revoke_st, epoch, myst);
	}
	vm_map_unlock(vmm);

	/*
	 * I am the revoker; expose an incremented epoch to userland
	 * for its enqueue side.  Use a store fence to ensure that this
	 * is visible before any of our subsequent loads (we can't use
	 * vm map lock to do this, because copyout might need the map).
	 */
	if ((entryst == CHERI_REVOKE_ST_NONE) &&
	    (myst == CHERI_REVOKE_ST_CLOSING)) {
		crepochs.enqueue = epoch + 2;
	} else {
		crepochs.enqueue = epoch + 1;
	}
	crepochs.dequeue = epoch;
	vm_cheri_revoke_info_page(vmm, td->td_proc->p_sysent, &info_page);
	vm_cheri_revoke_publish_epochs(info_page, &crepochs);
	wmb();

	/*
	 * If we've already begun the load-side work and are now just going
	 * to close it out, there's no need to do any thread singling, so
	 * don't.
	 */
	if ((entryst == CHERI_REVOKE_ST_INITED) &&
	    (myst == CHERI_REVOKE_ST_CLOSING))
		goto close_already_inited;

	KASSERT(myst == CHERI_REVOKE_ST_INITING ||
	    myst == CHERI_REVOKE_ST_CLOSING,
	    ("Bad target state in revoker."));

	/* Begin barrier phase! */

	{
		struct thread *ptd;

		PROC_LOCK(td->td_proc);
		if ((td->td_proc->p_flag & P_HADTHREADS) != 0) {
			if (thread_single(td->td_proc, SINGLE_BOUNDARY)) {
				PROC_UNLOCK(td->td_proc);

				vm_map_lock(vmm);
				cheri_revoke_st_set(&vmm->vm_cheri_revoke_st,
				    epoch, entryst);
				vm_map_unlock(vmm);

				/* XXX Don't signal other would-be revokers? */

				vm_cheri_revoke_cookie_rele(&vmcrc);
				vmspace_free(vm);

				/* XXX Don't copy out the stat structure? */

				return (ERESTART);
			}
		}

		/*
		 * Drop the process lock *then* iterate the threads in this
		 * process, which should either be "just us" or "just us
		 * running and everybody stopped at the syscall boundary".
		 *
		 * XXX This might not be safe, but we are PHOLD-ing this
		 * process, so it won't go anywhere without us.  As we're
		 * thread_single'd, too, we should be the only one futzing with
		 * the list of threads (I hope).
		 *
		 * What we should perhaps do instead is have each thread
		 * perform its own cleanup in a context without locks held
		 * (where it will be safe to read from the shadow bitmap) as
		 * soon as it's on core again.  This will require a barrier
		 * before we can increment the epoch counter or transition to
		 * the next state in the CHERI_REVOKE_ST state machine (i.e.,
		 * from CHERI_REVOKE_ST_CLOSING to CHERI_REVOKE_ST_NONE or
		 * from CHERI_REVOKE_ST_INITING to CHERI_REVOKE_ST_INITED).
		 * This also risks the use of ptrace() to expose to userspace
		 * the trap frame of a stalled thread that has not yet scanned
		 * itself.  Yick.
		 */

		_PHOLD(td->td_proc);
		PROC_UNLOCK(td->td_proc);

		/* Per-thread kernel hoarders */
		FOREACH_THREAD_IN_PROC (td->td_proc, ptd) {
			cheri_revoke_td_frame(ptd, &vmcrc);
			sigaltstack_cheri_revoke(ptd, &vmcrc);
		}
	}

	/* Per-process kernel hoarders */
	cheri_revoke_hoarders(td->td_proc, &vmcrc);

	KASSERT(myst == CHERI_REVOKE_ST_INITING ||
	    myst == CHERI_REVOKE_ST_CLOSING,
	    ("unexpected state %d in revoker", myst));
	if (entryst == CHERI_REVOKE_ST_NONE) {
		/*
		 * Increment the GCLG.  Immediately install for the
		 * current thread; any others are currently off-core
		 * and will be switched back to and so will call
		 * pmap_activate themselves.
		 *
		 * pmap_caploadgen_next also shoots down all TLBs
		 * with this AS possibly cached, ensuring that
		 * nobody continues to see a stale LCLG (from two
		 * epochs ago) as now suddenly valid again.
		 *
		 * Take a write lock on the address space around this
		 * so that we don't race any page faults from kernel
		 * worker threads; we won't race any page faults from
		 * userspace already since we're single-threaded.
		 *
		 * XXXMJ this statement is not quite true.  The map lock
		 * is acquired during page fault handing but may be
		 * dropped (and re-acquired) around calls into the
		 * pager.  In other words, it appears to be possible to
		 * increment the GCLG after a (kernel) thread has
		 * faulted but before it has installed a PTE for the new
		 * mapping.
		 */
		vm_map_lock(&vm->vm_map);
		pmap_caploadgen_next(vmm->pmap);
		pmap_activate(td);
		vm_map_unlock(&vm->vm_map);
	}

	PROC_LOCK(td->td_proc);
	_PRELE(td->td_proc);
	if ((td->td_proc->p_flag & P_HADTHREADS) != 0) {
		thread_single_end(td->td_proc, SINGLE_BOUNDARY);
	}
	PROC_UNLOCK(td->td_proc);

	/* Post barrier phase! */

	/*
	 * If we came in with no epoch open, we have just opened one.
	 * Bump the epoch count we will report to userland below.
	 */
	res = KERN_SUCCESS;
	if (entryst == CHERI_REVOKE_ST_NONE) {
		epoch++;

		KASSERT((myst == CHERI_REVOKE_ST_INITING) ||
			(myst == CHERI_REVOKE_ST_CLOSING),
			("Bad myst when finishing"));
		entryst = CHERI_REVOKE_ST_INITED;

		if (myst == CHERI_REVOKE_ST_CLOSING) {
close_already_inited:	/* (entryst == CHERI_REVOKE_ST_INITED) above */

			/* Walk the VM */
			res = vm_cheri_revoke_pass(&vmcrc);
		}
	}

	/* OK, that's that.  Where do we stand now? */
	if ((res == KERN_SUCCESS) &&
	    (myst == CHERI_REVOKE_ST_CLOSING)) {

#ifdef DIAGNOSTIC
		vm_cheri_assert_consistent_clg(&vm->vm_map);
#endif

		/* Signal the end of this revocation epoch */
		epoch++;
		crepochs.dequeue = epoch;
		vm_cheri_revoke_publish_epochs(info_page, &crepochs);
		entryst = CHERI_REVOKE_ST_NONE;

		vm_map_entry_end_revocation(&vm->vm_map);
	}

	vm_map_lock(vmm);
	cheri_revoke_st_set(&vmm->vm_cheri_revoke_st, epoch, entryst);
#ifdef CHERI_CAPREVOKE_STATS
	if (flags & CHERI_REVOKE_TAKE_STATS) {
		sx_xlock(&vmm->vm_cheri_revoke_stats_sx);
		crst = *(struct cheri_revoke_stats*)&vmm->vm_cheri_revoke_stats;
		crstp = &crst;
		bzero(&vmm->vm_cheri_revoke_stats,
		    sizeof(vmm->vm_cheri_revoke_stats));
		sx_xunlock(&vmm->vm_cheri_revoke_stats_sx);
	} else {
		crstp = (struct cheri_revoke_stats*)&vmm->vm_cheri_revoke_stats;
	}
#endif
	vm_map_unlock(vmm);

	/* Broadcast here: some sleepers may be able to take the fast out */
	cv_broadcast(&vmm->vm_cheri_revoke_cv);

	vm_cheri_revoke_cookie_rele(&vmcrc);
	vmspace_free(vm);

	return (cheri_revoke_fini(crsi, vm_mmap_to_errno(res), crstp,
	    &crepochs));
}

static int
kern_cheri_revoke_get_shadow(struct thread *td, int flags,
    void * __capability arena, void * __capability * __capability shadow)
{
	struct vmspace *vm;
	vm_map_t vmm;
	void * __capability cres;
	vm_offset_t base, size;
	int arena_perms, error;
	int sel = flags & CHERI_REVOKE_SHADOW_SPACE_MASK;

	if (!SV_CURPROC_FLAG(SV_CHERI)) {
		return (ENOSYS);
	}

	KASSERT(td == curthread, ("%s: called for other than curthread",
	    __func__));

	switch (sel) {
	case CHERI_REVOKE_SHADOW_NOVMEM:

		if (cheri_gettag(arena) == 0)
			return (EINVAL);

		arena_perms = cheri_getperm(arena);

		if ((arena_perms & CHERI_PERM_SW_VMEM) == 0)
			return (EPERM);

		base = cheri_getbase(arena);
		size = cheri_getlen(arena);

		cres = vm_cheri_revoke_shadow_cap(curproc->p_sysent,
			sel, base, size, arena_perms);

		break;

	case CHERI_REVOKE_SHADOW_OTYPE:
	    {
		int reqperms;

		if (cheri_gettag(arena) == 0)
			return (EINVAL);

		/* XXX Require all of SW_VMEM, SEAL, and UNSEAL permissions? */
		reqperms = CHERI_PERM_SEAL | CHERI_PERM_UNSEAL |
		    CHERI_PERM_SW_VMEM;
		arena_perms = cheri_getperm(arena);
		if ((arena_perms & reqperms) != reqperms)
			return (EPERM);

		base = cheri_getbase(arena);
		size = cheri_getlen(arena);

		cres = vm_cheri_revoke_shadow_cap(curproc->p_sysent,
			sel, base, size, 0);

		break;
	    }
	case CHERI_REVOKE_SHADOW_INFO_STRUCT:
	case CHERI_REVOKE_SHADOW_NOVMEM_ENTIRE: // XXX
	    {
		/* Anyone's allowed to ask, I guess; ->arena ignored. */
		cres = vm_cheri_revoke_shadow_cap(curproc->p_sysent,
			sel, 0, 0, 0);
		break;
	    }
	default:
		return (EINVAL);
	}

	if (!cheri_gettag(cres))
		return (EINVAL);

	vm = td->td_proc->p_vmspace;
	vmm = &vm->vm_map;
	vm_map_lock(vmm);
	if (!vmm->vm_cheri_revoke_quarantining) {
		vmm->vm_cheri_revoke_quarantining = true;
	}
	vm_map_unlock(vmm);

	error = copyoutcap(&cres, shadow, sizeof(cres));

	return (error);
}

int
sys_cheri_revoke(struct thread *td, struct cheri_revoke_args *uap)
{
	return (kern_cheri_revoke(td, uap->flags, uap->start_epoch, uap->crsi));
}

int
sys_cheri_revoke_get_shadow(struct thread *td,
    struct cheri_revoke_get_shadow_args *uap)
{
	return (kern_cheri_revoke_get_shadow(td, uap->flags, uap->arena,
	    uap->shadow));
}

#else /* CHERI_CAPREVOKE */

int
sys_cheri_revoke(struct thread *td, struct cheri_revoke_args *uap)
{
	static struct timeval lastfail;
	static int curfail;

	if (td->td_proc->p_pid == 1 || ppsratecheck(&lastfail, &curfail, 1))
		printf("%s: unsupported syscall (pid %d).  "
		    "A CAPREVOKE kernel is required.\n", __func__,
		    td->td_proc->p_pid);

	return (ENOSYS);
}

int
sys_cheri_revoke_get_shadow(struct thread *td,
    struct cheri_revoke_get_shadow_args *uap)
{
	static struct timeval lastfail;
	static int curfail;

	if (td->td_proc->p_pid == 1 || ppsratecheck(&lastfail, &curfail, 1))
		printf("%s: unsupported syscall (pid %d).  "
		    "A CAPREVOKE kernel is required.\n", __func__,
		    td->td_proc->p_pid);

	return (ENOSYS);
}

#endif /* CHERI_CAPREVOKE */
