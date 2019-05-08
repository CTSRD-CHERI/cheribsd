#pragma once

#ifndef __USE_POSIX2
// Ensure that unistd.h pulls in getopt
#define __USE_POSIX2
#endif
#include_next <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/syscall.h>

#ifndef required_argument
#error"something went wrong including getopt"
#endif

__BEGIN_DECLS

#ifdef __GLIBC__
static inline int issetugid(void) {
	return 0;
}
#endif

static inline char *
fflagstostr(u_long flags)
{
	return strdup("");
}

static inline int
strtofflags(char **stringp, u_long *setp, u_long *clrp) {
	/* On linux just ignore the file flags for now */
	/*
	 * XXXAR: this will prevent makefs from setting noschg on libc, etc
	 * so we should really build the version from libc
	 */
	if (setp)
		*setp = 0;
	if (clrp)
		*clrp = 0;
	return 0; /* success */
}

#ifndef __GLIBC_PREREQ
#define __GLIBC_PREREQ(min, maj) 0
#endif

/* getentropy was added in glibc 2.25. Declare it for !glibc or older versions */
#if !__GLIBC_PREREQ(2, 25)
static inline int
getentropy(void *buf, size_t buflen) {

	return syscall(__NR_getrandom, buf, buflen, 0);
}
#endif

/* Used by elftoolchain: */
extern char *program_invocation_name;
extern char *program_invocation_short_name;

void	*setmode(const char *);
mode_t	 getmode(const void *, mode_t);

void	closefrom(int);

__END_DECLS
