/* We can't use #pragma once here since at least the version of time.h
 * shipped with glibc must be included more than once with different
 * defines set */
/* #pragma once*/

/* GLIBC sets this when multiple-including time.h */
#ifdef __need_time_t
#include_next <time.h>
#else
/* In addtion to time.h we also need to include sys/time.h and utime.h to
 * be compatible with FreeBSD */
#include_next <time.h>
/* On Linux utimes() is not defined in time.h */
#include <utime.h>
/* sys/types.h is needed for opensolaris compat */
#include <sys/types.h>
#include <sys/time.h>
#endif
