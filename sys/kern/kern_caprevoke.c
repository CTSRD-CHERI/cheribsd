#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_compat.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/signal.h>
#include <sys/sysproto.h>
#include <sys/user.h>

#ifdef CHERI_CAPREVOKE

#include <cheri/cheric.h>

#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sysent.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>

#include <sys/aio.h>
#include <sys/event.h>
#include <sys/timers.h>

#include <sys/caprevoke.h>
#include <vm/vm_caprevoke.h>
#include <sys/syscallsubr.h>

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
caprevoke_hoarders(struct proc *p, struct vm_caprevoke_cookie *crc)
{
	/* aio */
	aio_caprevoke(p, crc);

	/* timers */
	ktimer_caprevoke(p, crc);

	/* kqueue: run last, because other systems might post here */
	kqueue_caprevoke(p->p_fd, crc);
}

static int
caprevoke_fini(struct caprevoke_syscall_info * __capability crsi,
    int res, struct caprevoke_stats *crst, struct caprevoke_epochs *crepochs)
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
		return res;
	if (res2 != 0)
		return res2;
	return res3;
}

#ifdef CHERI_CAPREVOKE_STATS
/* Here seems about as good a place as any */
_Static_assert(sizeof(struct caprevoke_stats) ==
    sizeof(((struct vm_map *)NULL)->vm_caprev_stats),
    "Caprevoke stats structure size mismatch");
#endif

int
kern_caprevoke(struct thread *td, int flags, caprevoke_epoch start_epoch,
    struct caprevoke_syscall_info * __capability crsi)
{
	int res;
	caprevoke_epoch epoch;
	enum caprevoke_state entryst, myst;
	struct caprevoke_epochs crepochs = { 0 };
#ifdef CHERI_CAPREVOKE_STATS
	struct caprevoke_stats crst, *crstp;
#else
	struct caprevoke_stats *crstp = NULL;
#endif
	struct vmspace *vm;
	vm_map_t vmm;
	struct vm_caprevoke_cookie vmcrc;
	struct caprevoke_info_page * __capability info_page;

	vm = vmspace_acquire_ref(td->td_proc);
	vmm = &vm->vm_map;

	/*
	 * We need some value that's more or less "now", but we don't have
	 * to be too picky about it.  This value is not reported to
	 * userland, just used to guide the interlocking below.
	 */
	if ((flags & CAPREVOKE_IGNORE_START) != 0) {
		start_epoch = caprevoke_st_epoch(vmm->vm_caprev_st);
	}

	/* Serialize and figure out what we're supposed to do */
	vm_map_lock(vmm);
	{
		static const int fast_out_flags = CAPREVOKE_NO_WAIT_OK |
		    CAPREVOKE_IGNORE_START | CAPREVOKE_LAST_NO_EARLY;
		int ires = 0;
		caprevoke_epoch first_epoch;

		epoch = caprevoke_st_epoch(vmm->vm_caprev_st);
		entryst = caprevoke_st_state(vmm->vm_caprev_st);
		first_epoch = epoch;

		if ((flags & (fast_out_flags | CAPREVOKE_LAST_PASS)) ==
		    fast_out_flags) {
			/* Apparently they really just wanted the time. */
			goto fast_out;
		}

reentry:
		if (caprevoke_epoch_clears(epoch, start_epoch)) {
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
			if (flags & CAPREVOKE_TAKE_STATS) {
				sx_xlock(&vmm->vm_caprev_stats_sx);
				crst = *(struct caprevoke_stats*)&vmm->vm_caprev_stats;
				bzero(&vmm->vm_caprev_stats, sizeof(vmm->vm_caprev_stats));
				sx_xunlock(&vmm->vm_caprev_stats_sx);
				crstp = &crst;
			} else {
				crstp = (struct caprevoke_stats*)&vmm->vm_caprev_stats;
			}
#endif
			vm_map_unlock(vmm);
			cv_signal(&vmm->vm_caprev_cv);
			vmspace_free(vm);

			return caprevoke_fini(crsi, ires, crstp, &crepochs);
		}

		/*
		 * OK, the initial epoch clock isn't in the past.  Let's see
		 * what state we're in and what we can accomplish.
		 */
		switch (entryst) {
		case CAPREVST_NONE:
			KASSERT((epoch & 1) == 0, ("Odd epoch NONE"));
			if (flags & CAPREVOKE_LOAD_SIDE) {
				if (flags & CAPREVOKE_LAST_PASS) {
					myst = CAPREVST_LS_CLOSING;
				} else {
					myst = CAPREVST_LS_INITING;
				}
			} else {
				if (flags & CAPREVOKE_LAST_PASS) {
					myst = CAPREVST_SS_LAST;
				} else {
					myst = CAPREVST_SS_INITING;
				}
			}
			break;
		case CAPREVST_SS_INITED:
			KASSERT((epoch & 1) == 1, ("Even epoch SS_INITED"));
			/*
			 * We could either be finishing up or doing just
			 * a(nother) pass and (re)entering the INIT state.
			 */
			if (flags & CAPREVOKE_LAST_PASS) {
				myst = CAPREVST_SS_LAST;
			} else {
				myst = CAPREVST_SS_INITING;
			}
			break;
		case CAPREVST_LS_INITED:
			KASSERT((epoch & 1) == 1, ("Even epoch LS_INITED"));
			/*
			 * If a load-side epoch is already open, there's
			 * nothing to be done other than end it.
			 */
			if (flags & CAPREVOKE_LAST_PASS) {
				myst = CAPREVST_LS_CLOSING;
			} else {
				goto fast_out;
			}
			break;
		case CAPREVST_SS_LAST:
		case CAPREVST_LS_CLOSING:
			/* There is another revoker in progress.  Wait? */
			if ((flags & CAPREVOKE_ONLY_IF_OPEN) != 0) {
				goto fast_out;
			}
			/* FALLTHROUGH */
		case CAPREVST_SS_INITING:
		case CAPREVST_LS_INITING:
			KASSERT(vmm->system_map == 0, ("System map?"));

			if ((flags & CAPREVOKE_NO_WAIT_OK) != 0) {
				goto fast_out;
			}

			/* There is another revoker in progress.  Wait. */
			ires = cv_wait_sig(&vmm->vm_caprev_cv, &vmm->lock);
			if (ires != 0) {
				cv_signal(&vmm->vm_caprev_cv);
				vmspace_free(vm);
				return ires;
			}

			epoch = caprevoke_st_epoch(vmm->vm_caprev_st);
			goto reentry;
		}

		KASSERT((entryst == CAPREVST_NONE) ||
			(entryst == CAPREVST_SS_INITED) ||
			(entryst == CAPREVST_LS_INITED),
		    ("Beginning revocation with bad entry state"));
		KASSERT((myst == CAPREVST_SS_INITING) ||
			(myst == CAPREVST_SS_LAST) ||
			(myst == CAPREVST_LS_INITING) ||
			(myst == CAPREVST_LS_CLOSING),
		    ("Beginning revocation with bad current state"));

		if (((flags & CAPREVOKE_ONLY_IF_OPEN) != 0) &&
		    ((epoch & 1) == 0)) {
			/*
			 * If we're requesting work only if an epoch is open
			 * and one isn't, then there's only one thing to do!
			 */
			goto fast_out;
		}

		if (entryst == CAPREVST_NONE) {
			/*
			 * XXX Right now, we know that there are no
			 * coarse-grain bits getting set, nor otypes nor
			 * anything else, since we don't do MPROT_QUARANTINE or
			 * anything of that sort.
			 *
			 * In the future, we should count the number of pages
			 * held in MPROT_QUARANTINE or munmap()'s quarantine or
			 * other such to decide whether to set _NO_COARSE.
			 * Similary for the others.
			 */
			vm_caprevoke_set_test(vmm,
			    VM_CAPREVOKE_CF_NO_COARSE_MEM |
			    VM_CAPREVOKE_CF_NO_OTYPES |
			    VM_CAPREVOKE_CF_NO_CIDS);
		}

#ifdef CHERI_CAPREVOKE_STATS
		crstp = (struct caprevoke_stats *)&vmm->vm_caprev_stats;
#endif

		res = vm_caprevoke_cookie_init(&vm->vm_map, &vmcrc);
		if (res != KERN_SUCCESS) {
			vm_map_unlock(vmm);
			vmspace_free(vm);
			return caprevoke_fini(crsi, vm_mmap_to_errno(res),
			    crstp, &crepochs);
		}

		/*
		 * Don't bump the epoch count here, just the state!  Wait
		 * until we're certain it's actually open, which we can only
		 * do below.
		 */
		caprevoke_st_set(&vmm->vm_caprev_st, epoch, myst);
	}
	vm_map_unlock(vmm);

	/*
	 * I am the revoker; expose an incremented epoch to userland
	 * for its enqueue side.  Use a store fence to ensure that this
	 * is visible before any of our subsequent loads (we can't use
	 * vm map lock to do this, because copyout might need the map).
	 */
	if ((entryst == CAPREVST_NONE) &&
	    ((myst == CAPREVST_SS_LAST) || (myst == CAPREVST_LS_CLOSING))) {
		crepochs.enqueue = epoch + 2;
	} else {
		crepochs.enqueue = epoch + 1;
	}
	crepochs.dequeue = epoch;
	vm_caprevoke_info_page(vmm, &info_page);
	vm_caprevoke_publish_epochs(info_page, &crepochs);
	wmb();

	/*
	 * If we've already begun the load-side work and are now just going
	 * to close it out, there's no need to do any thread singling, so
	 * don't.
	 */
	if ((entryst == CAPREVST_LS_INITED) && (myst == CAPREVST_LS_CLOSING))
		goto ls_close_already_inited;

	/* Pre-barrier store-side work */
	switch(myst) {
	default:
		panic("Bad target state in revoker");
	case CAPREVST_SS_INITING:
	case CAPREVST_SS_LAST:
		if ((myst == CAPREVST_SS_INITING) ||
		    (flags & CAPREVOKE_LAST_NO_EARLY) == 0) {
			int vmcflags = 0;

			    /* Userspace can ask us to avoid an IPI here */
			vmcflags |= (flags & CAPREVOKE_EARLY_SYNC)
					? VM_CAPREVOKE_SYNC_CD : 0;

			    /* If not first pass, only recently capdirty */
			vmcflags |= (entryst == CAPREVST_SS_INITED)
					? VM_CAPREVOKE_INCREMENTAL : 0;

			res = vm_caprevoke_pass(&vmcrc, vmcflags);

			if (res == KERN_SUCCESS) {
				/*
				 * That worked; the epoch is certainly open;
				 * when we set the state below, it's fine to
				 * advance the clock rather than revert it,
				 * even if something else goes wrong.
				 *
				 * Note that this is a purely local change even
				 * so; threads interlocking against us will not
				 * see it until we next publish the state
				 * below.
				 */
				if (entryst == CAPREVST_NONE) {
					epoch++;
					entryst = CAPREVST_SS_INITED;
				}
			} else {
				goto skip_last_pass;
			}
		}

		if (myst == CAPREVST_SS_INITING)
			goto skip_last_pass;

		break;
	case CAPREVST_LS_INITING:
	case CAPREVST_LS_CLOSING:
		break;
	}

	/* Begin barrier phase! */

	{
		struct thread *ptd;

		PROC_LOCK(td->td_proc);
		if ((td->td_proc->p_flag & P_HADTHREADS) != 0) {
			if (thread_single(td->td_proc, SINGLE_BOUNDARY)) {
				PROC_UNLOCK(td->td_proc);

				vm_map_lock(vmm);
				caprevoke_st_set(&vmm->vm_caprev_st, epoch,
				    entryst);
				vm_map_unlock(vmm);

				/* XXX Don't signal other would-be revokers? */

				vm_caprevoke_cookie_rele(&vmcrc);
				vmspace_free(vm);

				/* XXX Don't copy out the stat structure? */

				return ERESTART;
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
		 * the next state in the CAPREVST state machine (i.e., from
		 * CAPREVST_SS_LAST to CAPREV_NONE or from CAPREVST_LS_INITING
		 * to CAPREVST_LS_INITED).  This also risks the use of ptrace()
		 * to expose to userspace the trap frame of a stalled thread
		 * that has not yet scanned itself.  Yick.
		 */

		_PHOLD(td->td_proc);
		PROC_UNLOCK(td->td_proc);

		/* Per-thread kernel hoarders */
		FOREACH_THREAD_IN_PROC (td->td_proc, ptd) {
			caprevoke_td_frame(ptd, &vmcrc);
			sigaltstack_caprevoke(ptd, &vmcrc);
		}
	}

	/* Per-process kernel hoarders */
	caprevoke_hoarders(td->td_proc, &vmcrc);

	switch(myst) {
	default:
		panic("impossible");
	case CAPREVST_SS_LAST:
	    {
		/*
		 * The world is stopped; if we're on the store side path, do
		 * another pass through the VM now.
		 */
		int crflags = VM_CAPREVOKE_SYNC_CD | VM_CAPREVOKE_BARRIERED;

		/*
		 * This pass can be incremental if we had previously done an
		 * init pass, either just now or earlier.  In either case,
		 * entryst == CAPREVST_SS_INITED.
		 */
		crflags |= (entryst == CAPREVST_SS_INITED) ?
		    VM_CAPREVOKE_INCREMENTAL : 0;

		res = vm_caprevoke_pass(&vmcrc, crflags);
		break;
	    }
	case CAPREVST_LS_CLOSING:
	case CAPREVST_LS_INITING:
		if (entryst == CAPREVST_NONE) {
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
			 */
			vm_map_lock(&vm->vm_map);
			pmap_caploadgen_next(vmm->pmap);
			pmap_activate(td);
			vm_map_unlock(&vm->vm_map);
		}
		res = KERN_SUCCESS;
		break;
	}

	PROC_LOCK(td->td_proc);
	_PRELE(td->td_proc);
	if ((td->td_proc->p_flag & P_HADTHREADS) != 0) {
		thread_single_end(td->td_proc, SINGLE_BOUNDARY);
	}

	/* Post barrier phase! */

	if (res != KERN_SUCCESS) {
		PROC_UNLOCK(td->td_proc);

		vm_map_lock(vmm);
		caprevoke_st_set(&vmm->vm_caprev_st, epoch, entryst);
		vm_map_unlock(vmm);

		cv_signal(&vmm->vm_caprev_cv);

		vm_caprevoke_cookie_rele(&vmcrc);
		vmspace_free(vm);

		return caprevoke_fini(crsi, vm_mmap_to_errno(res), crstp,
		    &crepochs);
	}
	PROC_UNLOCK(td->td_proc);

	/*
	 * If we came in with no epoch open, we have just opened one.
	 * Bump the epoch count we will report to userland below.
	 */
	if (entryst == CAPREVST_NONE) {
		epoch++;

		if (myst == CAPREVST_SS_LAST) {
			entryst = CAPREVST_SS_INITED;
		} else {
			KASSERT((myst == CAPREVST_LS_INITING) ||
				(myst == CAPREVST_LS_CLOSING),
				("Bad myst when finishing loadside"));
			entryst = CAPREVST_LS_INITED;

			if (myst == CAPREVST_LS_CLOSING) {
				int crflags;
ls_close_already_inited:
				crflags = VM_CAPREVOKE_LOAD_SIDE;

				/* We're on the load side; walk the VM again. */
				res = vm_caprevoke_pass(&vmcrc, crflags);
			}
		}
	}

skip_last_pass:
	/* OK, that's that.  Where do we stand now? */
	if ((res == KERN_SUCCESS) &&
	     ((myst == CAPREVST_SS_LAST) || (myst == CAPREVST_LS_CLOSING))) {

		// XXX Assert all capdirty PTEs have LCLG equal to GCLG

		/* Signal the end of this revocation epoch */
		epoch++;
		crepochs.dequeue = epoch;
		vm_caprevoke_publish_epochs(info_page, &crepochs);
		entryst = CAPREVST_NONE;
	}

	vm_map_lock(vmm);
	caprevoke_st_set(&vmm->vm_caprev_st, epoch, entryst);
#ifdef CHERI_CAPREVOKE_STATS
	if (flags & CAPREVOKE_TAKE_STATS) {
		sx_xlock(&vmm->vm_caprev_stats_sx);
		crst = *(struct caprevoke_stats*)&vmm->vm_caprev_stats;
		crstp = &crst;
		bzero(&vmm->vm_caprev_stats, sizeof(vmm->vm_caprev_stats));
		sx_xunlock(&vmm->vm_caprev_stats_sx);
	} else {
		crstp = (struct caprevoke_stats*)&vmm->vm_caprev_stats;
	}
#endif
	vm_map_unlock(vmm);

	/* Broadcast here: some sleepers may be able to take the fast out */
	cv_broadcast(&vmm->vm_caprev_cv);

	vm_caprevoke_cookie_rele(&vmcrc);
	vmspace_free(vm);

	return caprevoke_fini(crsi, 0, crstp, &crepochs);
}

static int
kern_caprevoke_shadow(int flags, void * __capability arena,
    void * __capability * __capability shadow)
{
	int arena_perms, error;
	void * __capability cres;
	vm_offset_t base, size;
	int sel = flags & CAPREVOKE_SHADOW_SPACE_MASK;

	if (!SV_CURPROC_FLAG(SV_CHERI)) {
		return ENOSYS;
	}

	switch (sel) {
	case CAPREVOKE_SHADOW_NOVMMAP:

		if (cheri_gettag(arena) == 0)
			return EINVAL;

		arena_perms = cheri_getperm(arena);

		if ((arena_perms & CHERI_PERM_CHERIABI_VMMAP) == 0)
			return EPERM;

		base = cheri_getbase(arena);
		size = cheri_getlen(arena);

		cres = vm_caprevoke_shadow_cap(sel, base, size, arena_perms);

		break;

	case CAPREVOKE_SHADOW_OTYPE:
	    {
		int reqperms;

		if (cheri_gettag(arena) == 0)
			return EINVAL;

		/* XXX Require all of VMMAP, SEAL, and UNSEAL permissions? */
		reqperms = CHERI_PERM_SEAL | CHERI_PERM_UNSEAL |
		    CHERI_PERM_CHERIABI_VMMAP;
		arena_perms = cheri_getperm(arena);
		if ((arena_perms & reqperms) != reqperms)
			return EPERM;

		base = cheri_getbase(arena);
		size = cheri_getlen(arena);

		cres = vm_caprevoke_shadow_cap(sel, base, size, 0);

		break;
	    }
	case CAPREVOKE_SHADOW_INFO_STRUCT:
	case CAPREVOKE_SHADOW_NOVMMAP_ENTIRE: // XXX
	    {
		/* Anyone's allowed to ask, I guess; ->arena ignored. */
		cres = vm_caprevoke_shadow_cap(sel, 0, 0, 0);
		break;
	    }
	default:
		return EINVAL;
	}

	error = copyoutcap(&cres, shadow, sizeof(cres));

	return error;
}

int
sys_caprevoke(struct thread *td, struct caprevoke_args *uap)
{
	return kern_caprevoke(td, uap->flags, uap->start_epoch, uap->crsi);
}

int
sys_caprevoke_shadow(struct thread *td, struct caprevoke_shadow_args *uap)
{
	return kern_caprevoke_shadow(uap->flags, uap->arena, uap->shadow);
}

#else /* CHERI_CAPREVOKE */

int
sys_caprevoke(struct thread *td, struct caprevoke_args *uap)
{
	return (nosys(td, (struct nosys_args *)uap));
}

int
sys_caprevoke_shadow(struct thread *td, struct caprevoke_shadow_args *uap)
{
	void * __capability cres = NULL;

	copyoutcap(&cres, uap->shadow, sizeof(cres));

	return (nosys(td, (struct nosys_args *)uap));
}

#endif /* CHERI_CAPREVOKE */
