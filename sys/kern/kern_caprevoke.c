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

#include <sys/caprevoke.h>
#include <vm/vm_caprevoke.h>

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

	/* kqueue: run last, because other systems might post here */
	kqueue_caprevoke(p->p_fd, crc);
}

static int
caprevoke_fini(struct thread *td,
		struct caprevoke_stats * __capability statout,
		int res, struct caprevoke_stats *crst)
{
	int res2 = copyout(crst, statout, sizeof (*crst));
	if (res != 0)
		return res;
	return res2;
}

static void
caprevoke_just(struct thread *td, struct vm_caprevoke_cookie *vmcrc,
			struct caprevoke_stats *stats, int flags)
{
	/*
	 * Unlocked access is fine; this is advisory and, when it is
	 * relevant to userland, we expect that userland has already
	 * arranged for the bitmasks to carry the state it wants and
	 * wants to *now* wait for the clock to advance to be sure
	 * that time has elapsed.
	 *
	 * XXX But on ALPHA, we might need to explicitly add a read
	 * barrier, unless we've already done something that's
	 * implied a suitable one on syscall entry, which seems
	 * unlikely.
	 */
	stats->epoch_init =
		vmcrc->map->vm_caprev_st >> CAPREVST_EPOCH_SHIFT;

	if (flags & CAPREVOKE_JUST_MY_REGS) {
		/* XXX thread register file */
	}
	if (flags & CAPREVOKE_JUST_MY_STACK) {
		uintcap_t sp;
#if defined(__mips__)
		sp = (uintcap_t)td->td_frame->csp;
#else
#error "Can't get stack frame on this architecture"
#endif
		vm_caprevoke_one(vmcrc, 0,
			(vm_offset_t)sp);
	}
	if (flags & CAPREVOKE_JUST_HOARDERS) {
		caprevoke_hoarders(td->td_proc, vmcrc);
	}

	/* XXX unlocked read OK? */
	stats->epoch_fini =
		vmcrc->map->vm_caprev_st >> CAPREVST_EPOCH_SHIFT;
}

#define SET_ST(vp, e, st) \
	(vp)->vm_caprev_st = (((e) << CAPREVST_EPOCH_SHIFT) | (st))

static int
kern_caprevoke(struct thread *td, int flags, caprevoke_epoch start_epoch,
	       struct caprevoke_stats * __capability statout)
{
	int res;
	caprevoke_epoch epoch;
	enum caprevoke_state entryst, myst;
	struct caprevoke_info cri;
	struct caprevoke_stats stat = { 0 };
	struct vmspace *vm;
	vm_map_t vmm;
	struct vm_caprevoke_cookie vmcrc;

	vm = vmspace_acquire_ref(td->td_proc);
	res = vm_caprevoke_cookie_init(&vm->vm_map, &stat, &vmcrc);
	if (res != KERN_SUCCESS) {
		vmspace_free(vm);
		return caprevoke_fini(td, statout, vm_mmap_to_errno(res),
				      &stat);
	}

	if ((flags & CAPREVOKE_JUST_MASK) != 0) {
		caprevoke_just(td, &vmcrc, &stat, flags);
		vm_caprevoke_cookie_rele(&vmcrc);
		vmspace_free(vm);
		return caprevoke_fini(td, statout, 0, &stat);
	}
	/* Engaging the full state machine; here we go! */

	vmm = vmcrc.map;

	/*
	 * We need some value that's more or less "now", but we don't have
	 * to be too picky about it.  This value is not reported to
	 * userland, just used to guide the interlocking below.
	 */
	if ((flags & CAPREVOKE_IGNORE_START) != 0) {
		start_epoch = vmm->vm_caprev_st >> CAPREVST_EPOCH_SHIFT;
	}

	/*
	 * XXX We don't support late phases anyway, except as a placeholder,
	 * so act like the user asked us not to do one.
	 */
	flags |= CAPREVOKE_LAST_NO_LATE;

	/* Serialize and figure out what we're supposed to do */
	vm_map_lock(vmm);
	{
		static const int fast_out_flags = CAPREVOKE_NO_WAIT_OK
						| CAPREVOKE_IGNORE_START
						| CAPREVOKE_LAST_NO_EARLY;
		int ires = 0;
		caprevoke_epoch first_epoch;

		epoch = vmm->vm_caprev_st >> CAPREVST_EPOCH_SHIFT;
		first_epoch = epoch;

		/*
		 * Be optimistic about the outcome of any worker currently
		 * in progress.  We cannot truly claim that all writes to
		 * the revocation bitmap began prior to the epoch clock's
		 * current value if that value is in the process of being
		 * advanced by another thread: the writes may have happened
		 * after that thread began its work.  Therefore, bump the
		 * counter reported to userland appropriately.
		 *
		 * If the current epoch already clears the given
		 * start_epoch, this may result in epoch_init > epoch_fini!
		 *
		 * Similarly, if the thread advancing the clock fails to do
		 * so, we may find that our reported epoch_init is greater
		 * than the epoch clock and so we may end up attempting to
		 * advance only up to this report.  This is compensated for
		 * below, when we wake up from sleep and notice that the
		 * epoch has not advanced.
		 */

		switch(vmm->vm_caprev_st & CAPREVST_ST_MASK) {
		case CAPREVST_INIT_PASS:
			/*
			 * A revoker intends to open, but not close, this
			 * epoch.
			 */
			stat.epoch_init = epoch + 1;
			break;
		case CAPREVST_LAST_PASS:
			/*
			 * A revoker intends to close an epoch, which may
			 * be the one now open or the next one.  In either
			 * case, the resulting epoch is closed and advanced
			 * from its present value.
			 */
			stat.epoch_init = (epoch & ~1) + 2;
			break;
		case CAPREVST_NONE:
		case CAPREVST_INIT_DONE:
			/*
			 * There is no active worker; the epoch clock is
			 * a true reflection of the time.
			 */
			stat.epoch_init = epoch;
			break;
		}

		if ((flags & (fast_out_flags|CAPREVOKE_LAST_PASS))
		    == fast_out_flags) {
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
			vm_map_unlock(vmm);
			vm_caprevoke_cookie_rele(&vmcrc);
			cv_signal(&vmm->vm_caprev_cv);
			vmspace_free(vm);
			stat.epoch_fini = epoch;
			return caprevoke_fini(td, statout, ires, &stat);
		}

		/*
		 * OK, the initial epoch clock isn't in the past.  Let's see
		 * what state we're in and what we can accomplish.
		 */
		entryst = vmm->vm_caprev_st & CAPREVST_ST_MASK;
		switch(entryst) {
		case CAPREVST_NONE:
			/*
			 * Begin, non-incremental; advance clock.  We might
			 * also be ending the epoch at the same time.
			 */
			if (flags & CAPREVOKE_LAST_PASS) {
				myst = CAPREVST_LAST_PASS;
			} else {
				myst = CAPREVST_INIT_PASS;
			}
			KASSERT((epoch & 1) == 0, ("Odd epoch NONE"));
			break;
		case CAPREVST_INIT_DONE:
			/* We could either be finishing up or doing another pass */
			if (flags & CAPREVOKE_LAST_PASS) {
				myst = CAPREVST_LAST_PASS;
			} else {
				myst = CAPREVST_INIT_PASS;
			}
			KASSERT((epoch & 1) == 1, ("Even epoch INIT"));
			break;
		case CAPREVST_LAST_PASS:
			if ((flags & CAPREVOKE_ONLY_IF_OPEN) != 0) {
				goto fast_out;
			}
			/* FALLTHROUGH */
		case CAPREVST_INIT_PASS:
			if ((flags & CAPREVOKE_NO_WAIT_OK) != 0) {
				goto fast_out;
			}

			/* There is another revoker in progress.  Wait. */
			KASSERT(vmm->system_map == 0, ("System map?"));
			ires = cv_wait_sig(&vmm->vm_caprev_cv, &vmm->lock);
			if (ires != 0) {
				goto fast_out;
			}

			epoch = vmm->vm_caprev_st >> CAPREVST_EPOCH_SHIFT;
			if (epoch == first_epoch) {
				stat.epoch_init = epoch;
			}
			goto reentry;
		}

		KASSERT((entryst == CAPREVST_NONE)
			 || (entryst == CAPREVST_INIT_DONE),
			("Beginning revocation with bad entry state"));
		KASSERT((myst == CAPREVST_INIT_PASS)
			 || (myst == CAPREVST_LAST_PASS),
			("Beginning revocation with bad current state"));

		if (((flags & CAPREVOKE_ONLY_IF_OPEN) != 0)
		    && ((epoch & 1) == 0)) {
			/*
			 * If we're requesting work only if an epoch is open
			 * and one isn't, then there's only one thing to do!
			 */
			goto fast_out;
		}

		/*
		 * Don't bump the epoch count here, just the state!  Wait
		 * until we're certain it's actually open, which we can only
		 * do below.
		 */
		SET_ST(vmm, epoch, myst);
	}
	vm_map_unlock(vmm);

	/*
	 * I am the revoker; expose an incremented epoch to userland
	 * for its enqueue side.  Use a store fence to ensure that this
	 * is visible before any of our subsequent loads (we can't use
	 * vm map lock to do this, because copyout might need the map).
	 */
	if ((entryst == CAPREVST_NONE) && (myst == CAPREVST_LAST_PASS)) {
		cri.epoch_enqueue = epoch + 2;
	} else {
		cri.epoch_enqueue = epoch + 1;
	}
	cri.epoch_dequeue = epoch;
	vm_caprevoke_publish(&vmcrc, &cri);
	wmb();

	/* Walk the VM unless told not to */
	if ((flags & CAPREVOKE_LAST_NO_EARLY) == 0) {
		res = vm_caprevoke(&vmcrc,
			/* Userspace can ask us to avoid an IPI here */
		   (((flags & CAPREVOKE_EARLY_SYNC) != 0)
			? VM_CAPREVOKE_PMAP_SYNC : 0)
			/* If not first pass, only recently capdirty pages */
		   | ((entryst == CAPREVST_INIT_DONE)
			? VM_CAPREVOKE_INCREMENTAL : 0));

		if (res == KERN_SUCCESS) {
			/*
			 * That worked; the epoch is certainly open; when we
			 * set the state below, it's fine to advance the
			 * clock rather than revert it, even if something
			 * else goes wrong.
			 *
			 * Note that this is a purely local change even so;
			 * threads interlocking against us will not see it
			 * until we next publish the state below.
			 */
			if (entryst == CAPREVST_NONE) {
				epoch++;
				entryst = CAPREVST_INIT_DONE;
			}
		} else {
			goto skip_last_pass;
		}
	}

	/*
	 * If we are beginning the last pass, single-thread the world and
	 * expunge state that we want to ensure does not become visible
	 * during the body of the last pass.
	 */
	if (myst == CAPREVST_LAST_PASS) {
		PROC_LOCK(td->td_proc);
		if ((td->td_proc->p_flag & P_HADTHREADS) != 0) {
			if (thread_single(td->td_proc, SINGLE_BOUNDARY)) {
				PROC_UNLOCK(td->td_proc);

				vm_map_lock(vmm);
				SET_ST(vmm, epoch, entryst);
				vm_map_unlock(vmm);

				/* XXX Don't signal other would-be revokers? */

				vm_caprevoke_cookie_rele(&vmcrc);
				vmspace_free(vm);

				/* XXX Don't copy out the stat structure? */

				return ERESTART;
			}
		}

		/*
		 * XXX This cannot possibly be safe, but we're going with it
		 * for now.  I am so sorry.
		 *
		 * Drop the process lock *then* iterate the threads in this
		 * process, which should either be "just us" or "just us
		 * running and everybody stopped at the syscall boundary".
		 */
		PROC_UNLOCK(td->td_proc);

		/* XXX Per-thread kernel hoarders */

		/* Per-process kernel hoarders */
		caprevoke_hoarders(td->td_proc, &vmcrc);

		/*
		 * The world is stopped; do another pass through the VM.
		 *
		 * This pass can be incremental if we had previously done an
		 * init pass, either just now or earlier.  In either case,
		 * we'll have entryst == CAPREVST_INIT_DONE; there's no need
		 * to look at CAPREVOKE_LAST_NO_EARLY.
		 */
		res = vm_caprevoke(&vmcrc,
			((entryst == CAPREVST_INIT_DONE)
				? VM_CAPREVOKE_INCREMENTAL : 0)
			| VM_CAPREVOKE_LAST_INIT
			| VM_CAPREVOKE_PMAP_SYNC
			| (((flags & CAPREVOKE_LAST_NO_LATE) != 0)
				? VM_CAPREVOKE_LAST_FINI : 0));

		PROC_LOCK(td->td_proc);
		if ((td->td_proc->p_flag & P_HADTHREADS) != 0) {
			/* Un-single-thread the world */
			thread_single_end(td->td_proc, SINGLE_BOUNDARY);
		}

		if (res != KERN_SUCCESS) {
			PROC_UNLOCK(td->td_proc);

			vm_map_lock(vmm);
			SET_ST(vmm, epoch, entryst);
			vm_map_unlock(vmm);

			cv_signal(&vmm->vm_caprev_cv);

			vm_caprevoke_cookie_rele(&vmcrc);
			vmspace_free(vm);

			stat.epoch_fini = epoch;
			return caprevoke_fini(td, statout, 0, &stat);
		}
		PROC_UNLOCK(td->td_proc);

		if (entryst == CAPREVST_NONE) {
			/* That counts as our initial pass */
			epoch++;
			entryst = CAPREVST_INIT_DONE;
		}

		if ((flags & CAPREVOKE_LAST_NO_LATE) == 0) {
			/*
			 * Walk the VM again, now with the world running;
			 * as we must have done a pass before here, this is
			 * certain to be an incremental pass.
			 */
			res = vm_caprevoke(&vmcrc,
				VM_CAPREVOKE_INCREMENTAL
				| VM_CAPREVOKE_LAST_FINI);
		}
	}

skip_last_pass:
	/* OK, that's that.  Where do we stand now? */
	if ((res == KERN_SUCCESS) && (myst == CAPREVST_LAST_PASS)) {
		/* Signal the end of this revocation epoch */
		epoch++;
		cri.epoch_dequeue = epoch;
		vm_caprevoke_publish(&vmcrc, &cri);
		vm_map_lock(vmm);
		SET_ST(vmm, epoch, CAPREVST_NONE);
		vm_map_unlock(vmm);
	} else {
		/*
		 * Put the state back how we found it, modulo
		 * having perhaps finished the first pass.
		 */
		cri.epoch_dequeue = epoch;
		vm_caprevoke_publish(&vmcrc, &cri);
		vm_map_lock(vmm);
		SET_ST(vmm, epoch, entryst);
		vm_map_unlock(vmm);
	}

	/* Broadcast here: some sleepers may be able to take the fast out */
	cv_broadcast(&vmm->vm_caprev_cv);

	vm_caprevoke_cookie_rele(&vmcrc);
	vmspace_free(vm);

	/*
	 * Return the epoch as it was at the end of the run above,
	 * not necessarily as it is now.  This value is useful only
	 * for retroactive comparisons, i.e., to answer if
	 * particular epochs are in the past.
	 */
	stat.epoch_fini = epoch;

	return caprevoke_fini(td, statout, 0, &stat);
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

	case CAPREVOKE_SHADOW_OTYPE: {
		int reqperms;

		if (cheri_gettag(arena) == 0)
			return EINVAL;

		/* XXX Require all of VMMAP, SEAL, and UNSEAL permissions? */
		reqperms = CHERI_PERM_SEAL | CHERI_PERM_UNSEAL
			     | CHERI_PERM_CHERIABI_VMMAP;
		arena_perms = cheri_getperm(arena);
		if ((arena_perms & reqperms) != reqperms)
			return EPERM;

		base = cheri_getbase(arena);
		size = cheri_getlen(arena);

		cres = vm_caprevoke_shadow_cap(sel, base, size, 0);

		}
		break;

	case CAPREVOKE_SHADOW_INFO_STRUCT: {
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
	return kern_caprevoke(td, uap->flags, uap->start_epoch, uap->statout);
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
	struct caprevoke_stats stat = { 0 };

	copyout(&stat, uap->statout, sizeof (stat));

	return ENOSYS;
}

int
sys_caprevoke_shadow(struct thread *td, struct caprevoke_shadow_args *uap)
{
	void * __capability cres = NULL;

	copyoutcap(&cres, uap->shadow, sizeof(cres));

	return ENOSYS;
}

#endif /* CHERI_CAPREVOKE */
