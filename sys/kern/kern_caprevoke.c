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

#include <sys/caprevoke.h>
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
}

static int
kern_caprevoke(struct thread *td, int flags, caprevoke_epoch start_epoch,
    struct caprevoke_syscall_info * __capability statout)
{
	return ENOSYS;
}

static int
kern_caprevoke_shadow(int flags, void * __capability arena,
    void * __capability * __capability shadow)
{
	return ENOSYS;
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

	return (nosys(td, (struct nosys_args *)uap));
}

int
sys_caprevoke_shadow(struct thread *td, struct caprevoke_shadow_args *uap)
{

	return (nosys(td, (struct nosys_args *)uap));
}

#endif /* CHERI_CAPREVOKE */
