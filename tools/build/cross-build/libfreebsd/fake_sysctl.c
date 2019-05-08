/* This file contains wrappers for sysctl that behave like the FreeBSD version */
#include <string.h>
#include <err.h>
#include <sysexits.h>

int
__freebsd_sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
	    void *newp, size_t newlen)
{
	if (strcmp(name, "kern.vm_guest") == 0) {
		if (!oldp || !oldlenp)
			errx(EX_USAGE, "Missing arguments for kern.vm_guest");

		if (newp || newlen)
			errx(EX_USAGE, "kern.vm_guest is read-only");
		strlcpy(oldp, "none",  *oldlenp);
		*oldlenp = strlen("none");
	}
	errx(EX_USAGE, "fatal: unknown sysctl %s\n", name);
}
