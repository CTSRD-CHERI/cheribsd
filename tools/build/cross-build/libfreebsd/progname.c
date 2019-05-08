#include <stdlib.h>

#ifdef __GLIBC__
extern const char *__progname;
const char *
getprogname(void)
{

	return (__progname);
}
void
setprogname(const char *progname)
{

	__progname = progname;
}
#endif /* __GLIBC__ */
