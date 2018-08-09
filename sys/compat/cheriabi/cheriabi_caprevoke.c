#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_compat.h"

#define	EXPLICIT_USER_ACCESS

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/signal.h>
#include <sys/user.h>

#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_param.h>

#include <cheri/cheric.h>

#include <compat/cheriabi/cheriabi.h>
#include <compat/cheriabi/cheriabi_util.h>
#include <compat/cheriabi/cheriabi_proto.h>
#include <compat/cheriabi/cheriabi_syscall.h>

#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/caprevoke.h>

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
 */
static void
caprevoke_hoarders(struct proc *p)
{
	/* kqueue */
	{
		int fd;
		struct filedesc *fdp = p->p_fd;
		FILEDESC_SLOCK(fdp);
		for (fd = 0; fd <= fdp->fd_lastfile; fd++) {
			struct file * fp = fdp->fd_ofiles[fd].fde_file;
			if ((fp != NULL) && (fp->f_type == DTYPE_KQUEUE)) {

				/*
				 * We ignore errors from this function; they
				 * indicate either that the kq has yet to be
				 * born or that it's dying, and in either
				 * case, that should be fine.
				 */
				kqueue_caprevoke(fp);
			}
		}
		FILEDESC_SUNLOCK(fdp);
	}
}

static int
cheriabi_caprevoke_fini(struct thread *td, struct cheriabi_caprevoke_args *uap,
			struct caprevoke_stats *crst)
{
	return copyout(crst, uap->statout, sizeof (*crst));
}

static int
cheriabi_caprevoke_just(struct thread *td, struct cheriabi_caprevoke_args *uap)
{
	struct caprevoke_stats st = { 0 };

	/*
	 * XXX Should we do an unlocked epoch clock check?  A locked one?
	 * Only if we've been given a flag?
	 *
	 * At the moment we don't do any such thing because it seems like
	 * the common case will be that userland isn't accurately tracking
	 * the epoch where it wants to do partial scans like this.
	 */

	if (uap->flags & CAPREVOKE_JUST_MY_REGS) {
		/* XXX thread register file */
	}
	if (uap->flags & CAPREVOKE_JUST_MY_STACK) {
#if defined(CPU_CHERI)
		vm_caprevoke_one(td->td_proc, 0,
			(vm_offset_t)(__cheri_fromcap void *)
			(td->td_frame->csp), &st);
#else
		vm_caprevoke_one(td->td_proc, 0, td->td_frame.sp, &st);
#endif
	}
	if (uap->flags & CAPREVOKE_JUST_HOARDERS) {
		caprevoke_hoarders(td->td_proc);
	}

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
	st.epoch = td->td_proc->p_caprev_st >> CAPREVST_EPOCH_SHIFT;

	return cheriabi_caprevoke_fini(td, uap, &st);
}

#define SET_ST(p, e, st) \
	(p)->p_caprev_st = (((e) << CAPREVST_EPOCH_SHIFT) | (st))

int
cheriabi_caprevoke(struct thread *td, struct cheriabi_caprevoke_args *uap)
{
	uint64_t epoch;
	enum caprevoke_state entryst, myst;
	struct caprevoke_stats stat = { 0 };

	if ((uap->flags & CAPREVOKE_JUST_MASK) != 0) {
		return cheriabi_caprevoke_just(td, uap);
	}
	/* Engaging the full state machine; here we go! */

	/* Serialize and figure out what we're supposed to do */
	PROC_LOCK(td->td_proc);
reentry:
	{
		epoch = td->td_proc->p_caprev_st >> CAPREVST_EPOCH_SHIFT;

		if (caprevoke_epoch_ge(epoch,
		      uap->start_epoch + (uap->start_epoch & 1) + 2)) {
			/*
			 * An entire epoch has come and gone since the
			 * starting point of this request.  It is safe to
			 * return to userland with the request satiated.
			 *
			 * In case we queued, tho', go ahead and wake up the
			 * next would-be revoker first.
			 */
			PROC_UNLOCK(td->td_proc);
			cv_signal(&td->td_proc->p_caprev_cv);
			{
				struct caprevoke_stats st = { epoch, 0 };
				return cheriabi_caprevoke_fini(td, uap, &st);
			}
		}

		/*
		 * OK, the initial epoch clock isn't in the past.  Let's see
		 * what state we're in and what we can accomplish.
		 */
		entryst = td->td_proc->p_caprev_st & CAPREVST_ST_MASK;
		switch(entryst) {
		case CAPREVST_NONE:
			/*
			 * Begin, non-incremental; advance clock.  We might
			 * also be ending the epoch at the same time.
			 */
			if (uap->flags & CAPREVOKE_LAST_PASS) {
				myst = CAPREVST_LAST_PASS;
			} else {
				myst = CAPREVST_INIT_PASS;
			}
			KASSERT((epoch & 1) == 0, ("Odd epoch NONE"));
			break;
		case CAPREVST_INIT_DONE:
			/* We could either be finishing up or doing another pass */
			if (uap->flags & CAPREVOKE_LAST_PASS) {
				myst = CAPREVST_LAST_PASS;
			} else {
				myst = CAPREVST_INIT_PASS;
			}
			KASSERT((epoch & 1) == 1, ("Even epoch INIT"));
			break;
		case CAPREVST_INIT_PASS:
		case CAPREVST_LAST_PASS:
			/* There is another revoker in progress.  Wait. */
			KASSERT((epoch & 1) == 1, ("Even epoch PASS"));
			{
				int res;

				res = cv_wait_sig(&td->td_proc->p_caprev_cv,
					&td->td_proc->p_mtx);
				if (res != 0) {
					PROC_UNLOCK(td->td_proc);
					cv_signal(&td->td_proc->p_caprev_cv);
					return res;
				}
				goto reentry;
			}
		}

		KASSERT((entryst == CAPREVST_NONE)
			 || (entryst == CAPREVST_INIT_DONE),
			("Beginning revocation with bad entry state"));
		KASSERT((myst == CAPREVST_INIT_PASS)
			 || (myst == CAPREVST_LAST_PASS),
			("Beginning revocation with bad current state"));

		if (((td->td_proc->p_flag & P_HADTHREADS) != 0) &&
			(myst == CAPREVST_LAST_PASS)) {
			/*
			 * Single-thread the world, or at least the
			 * userland-visible parts of it.  In the current
			 * implementation, we will stay here for the
			 * duration of this last pass.
			 */
			if (thread_single(td->td_proc, SINGLE_BOUNDARY)) {
				PROC_UNLOCK(td->td_proc);
				cv_signal(&td->td_proc->p_caprev_cv);
				return ERESTART;
			}
		}

		/*
		 * At long last, we are in position to commit to being the
		 * next revocation pass.  This might mean opening a new
		 * epoch, but in either case update the state flag, hold the
		 * process, and drop the process lock.
		 */

		if (entryst == CAPREVST_NONE) {
			epoch++;
			SET_ST(td->td_proc, epoch, myst);
		} else {
			SET_ST(td->td_proc, epoch, myst);
		}

		/* XXX This hold might be superfluous? */
		_PHOLD(td->td_proc);
	}
	PROC_UNLOCK(td->td_proc);

	/*
	 * If we are beginning the last pass (and so, presently, are
	 * single-threaded), expunge state that we want to ensure does not
	 * become visible during the body of the last pass.
	 */
	if (myst == CAPREVST_LAST_PASS) {
		/* Kernel hoarders */
		caprevoke_hoarders(td->td_proc);

		/* XXX And thread register files */
	}

	/* Walk the VM */
	vm_caprevoke(td->td_proc,
		/* If not first pass, only recently capdirty pages */
	   (entryst == CAPREVST_INIT_DONE) ? VM_CAPREVOKE_INCREMENTAL : 0
		/*
		 * If last pass, loop until actually done.
		 *
		 * XXX Eventually _LAST_INIT and _LAST_FINI end up on
		 * opposite sides of the thread_single_end call, for when
		 * we want to do the load-side story.
		 */
	 | (myst == CAPREVST_LAST_PASS) ?
		(VM_CAPREVOKE_LAST_INIT | VM_CAPREVOKE_LAST_FINI) : 0,
	 &stat
	);

	/* OK, that's that.  Where do we stand now? */
	PROC_LOCK(td->td_proc);
	{
		_PRELE(td->td_proc);

		KASSERT(td->td_proc->p_caprev_st >> CAPREVST_EPOCH_SHIFT
			 == epoch,
			("Epoch value changed while revoking"));

		if (myst == CAPREVST_LAST_PASS) {
			if ((td->td_proc->p_flag & P_HADTHREADS) != 0) {
				/* Un-single-thread the world */
				thread_single_end(td->td_proc, SINGLE_BOUNDARY);
			}

			/*
			 * Advance the epoch clock and indicate that no
			 * revocation is pending.
			 */
			epoch++;
			SET_ST(td->td_proc, epoch, CAPREVST_NONE);
		} else {
			/*
			 * Do not advance the clock, but we have done at
			 * least one pass.
			 */
			SET_ST(td->td_proc, epoch, CAPREVST_INIT_DONE);
		}

	}
	PROC_UNLOCK(td->td_proc);

	/* Wake one would-be revoker to avoid thundering herds. */
	cv_signal(&td->td_proc->p_caprev_cv);

	stat.epoch = epoch;
	/*
	 * Return the epoch as it was at the end of the run above,
	 * not necessarily as it is now.  This value is useful only
	 * for retroactive comparisons, i.e., to answer if
	 * particular epochs are in the past.
	 */
	return cheriabi_caprevoke_fini(td, uap, &stat);
}

int
cheriabi_caprevoke_shadow(struct thread *td,
			    struct cheriabi_caprevoke_shadow_args *uap)
{
	int arena_perms, error;
	void * __capability cres;
	vm_offset_t base, size, shadow_base, shadow_size;

	if (!SV_CURPROC_FLAG(SV_CHERI))
		return ENOSYS;

	if (cheri_gettag(uap->arena) == 0)
		return EINVAL;

	switch (uap->flags & CAPREVOKE_SHADOW_SPACE_MASK) {
	case CAPREVOKE_SHADOW_NOVMMAP:

		arena_perms = cheri_getperm(uap->arena);

		if ((arena_perms & CHERI_PERM_CHERIABI_VMMAP) == 0)
			return EINVAL;

		/* Require at least byte granularity in the shadow space */
		base = cheri_getbase(uap->arena);
		if ((base & ((VM_CAPREVOKE_GSZ_MEM_NOMAP * 8) - 1)) != 0)
			return EINVAL;
		size = cheri_getlen(uap->arena);
		if ((size & ((VM_CAPREVOKE_GSZ_MEM_NOMAP * 8) - 1)) != 0)
			return EINVAL;

		shadow_base = VM_CAPREVOKE_BM_MEM_NOMAP
		            + (base / VM_CAPREVOKE_GSZ_MEM_NOMAP / 8);
		shadow_size = size / VM_CAPREVOKE_GSZ_MEM_NOMAP / 8;

		cres = cheri_capability_build_user_data(
			arena_perms & (CHERI_PERM_LOAD | CHERI_PERM_STORE)
				| CHERI_PERM_GLOBAL ,
			shadow_base, shadow_size, 0);

		break;

	case CAPREVOKE_SHADOW_OTYPE: {
		int reqperms;

		/* XXX Require all of VMMAP, SEAL, and UNSEAL permissions? */
		reqperms = CHERI_PERM_SEAL | CHERI_PERM_UNSEAL
			     | CHERI_PERM_CHERIABI_VMMAP;
		arena_perms = cheri_getperm(uap->arena);
		if ((arena_perms & reqperms) != reqperms)
			return EINVAL;

		/* Require at least byte granularity in the shadow space */
		base = cheri_getbase(uap->arena);
		if ((base & ((VM_CAPREVOKE_GSZ_OTYPE * 8) - 1)) != 0)
			return EINVAL;
		size = cheri_getlen(uap->arena);
		if ((size & ((VM_CAPREVOKE_GSZ_OTYPE * 8) - 1)) != 0)
			return EINVAL;

		shadow_base = VM_CAPREVOKE_BM_OTYPE
		            + (base / VM_CAPREVOKE_GSZ_OTYPE / 8);
		shadow_size = size / VM_CAPREVOKE_GSZ_OTYPE / 8;

		cres = cheri_capability_build_user_data(
			CHERI_PERM_LOAD | CHERI_PERM_STORE | CHERI_PERM_GLOBAL,
			shadow_base, shadow_size, 0);

		}
		break;
	default:
		return EINVAL;
	}

	error = copyoutcap(&cres, uap->shadow, sizeof(cres));

	return error;
}
