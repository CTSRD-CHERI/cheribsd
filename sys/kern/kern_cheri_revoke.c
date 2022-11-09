#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_compat.h"

#include <sys/param.h>
#include <sys/sysproto.h>

/*
 * We reserve the FEATURE(cheri_revoke) and VM SYSCTL() namespace cheri_revoke
 * for the real implementation.  These are absent in this stub implementation.
 */

int
sys_cheri_revoke(struct thread *td, struct cheri_revoke_args *uap)
{

	return (ENOSYS);
}

int
sys_cheri_revoke_get_shadow(struct thread *td,
    struct cheri_revoke_get_shadow_args *uap)
{

	return (ENOSYS);
}
