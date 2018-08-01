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
static int
caprevoke_hoarders(struct thread *td)
{
	int error = 0;

	return error;
}

int
cheriabi_caprevoke(struct thread *td, struct cheriabi_caprevoke_args *uap)
{
	int error = ENOSYS;

	return error;
}

int
cheriabi_caprevoke_shadow(struct thread *td,
			    struct cheriabi_caprevoke_shadow_args *uap)
{

	return ENOSYS;
}
