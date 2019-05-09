#ifdef _INCLUDING_USR_INCLUDE_LIMTITS
#if __has_include_next(<limits.h>)
#include_next <limits.h>
#endif
#else

#ifdef __STRICT_ANSI__
#warning __STRICT_ANSI__ defined
#endif

#include <sys/types.h>
#include <sys/uio.h> // For IOV_MAX

#if !defined(__clang__) && __has_include(</usr/include/limits.h>) && !defined(_INCLUDING_USR_INCLUDE_LIMTITS)
#define _INCLUDING_USR_INCLUDE_LIMTITS
/* For some reason GCC picks the wrong limits.h */
#include </usr/include/limits.h>
#undef _INCLUDING_USR_INCLUDE_LIMTITS
#endif

#include_next <limits.h>

#if __has_include(<linux/limits.h>)
#include <linux/limits.h>
#endif

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L
#if !defined(_GNU_SOURCE)
#warning "Attempting to use limits.h with -std=c89/without _GNU_SOURCE, many macros will be missing"
#endif

#else /* Not C89 */
/* Not C89 -> check that all macros that we expect are defined */
#ifndef __USE_XOPEN
#warning __USE_XOPEN should be defined (did you forget to set _GNU_SOURCE?)
#endif

#ifndef IOV_MAX
#error IOV_MAX should be defined
#endif
#endif /* C89 */

#ifndef MAXBSIZE
#define MAXBSIZE        65536   /* must be power of 2 */
#endif

#ifndef OFF_MAX
#define OFF_MAX UINT64_MAX
#endif

#ifndef QUAD_MAX
#define QUAD_MAX INT64_MAX
#endif

#ifndef GID_MAX
#define GID_MAX ((gid_t)-1)
#endif


#ifndef UID_MAX
#define UID_MAX ((uid_t)-1)
#endif


#ifdef __GLIBC__
#ifndef _LIBC_LIMITS_H_
#error "DIDN't include correct limits?"
#endif

/* Sanity checks for glibc */
#ifndef _GNU_SOURCE
#error _GNU_SOURCE not defined
#endif

#ifndef __USE_POSIX
#warning __USE_POSIX not defined
#endif

#if defined __GNUC__ && !defined _GCC_LIMITS_H_
#error "GCC limits not included"
#endif

#ifndef __OFF_T_MATCHES_OFF64_T
#error "Expected 64-bit off_t"
#endif

#endif

#ifndef _POSIX_PATH_MAX
#define _POSIX_PATH_MAX PATH_MAX
// #error _POSIX_PATH_MAX should be defined
#endif

#endif /* _INCLUDING_USR_INCLUDE_LIMTITS */
