/* Public domain. */

#ifndef __DRMCOMPAT_LINUX_CAPABILITY_H__
#define	__DRMCOMPAT_LINUX_CAPABILITY_H__

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/priv.h>

enum linux_capabilities {
	CAP_SYS_ADMIN = 1,
};

static inline bool
capable(enum linux_capabilities cap)
{

	KASSERT(cap == CAP_SYS_ADMIN, ("cap isn't CAP_SYS_ADMIN"));
	return (priv_check(curthread, PRIV_DRIVER) == 0);
}

#endif	/* __DRMCOMPAT_LINUX_CAPABILITY_H__ */
