#pragma once

/* one some version of glibc including string.h before stdlib.h won't work.
 * This happens when building anything that uses the libnetbsd stdlib.h override.
 * This is because string.h will include stdlib.h with a flag set to define
 * only a subset of the functions (which will then not set the _STDLIB_H
 * macro. libnetbsd stdlib.h can only be included once so this will not work.
 */
#include <stdlib.h>

/* Don't pull in the conflicting libbsd definition of strmode */
#define LIBBSD_STRING_H


__BEGIN_DECLS
size_t strlcpy(char *dst, const char *src, size_t siz);
size_t strlcat(char *dst, const char *src, size_t siz);
char *strnstr(const char *str, const char *find, size_t str_len);
void strmode(/* mode_t*/ int mode, char *str);

#if !defined(__GLIBC__) || \
    (defined(__GLIBC__) && (!__GLIBC_PREREQ(2, 25) || !defined(_GNU_SOURCE)))
void explicit_bzero(void *buf, size_t len);
#endif
__END_DECLS

#include_next <string.h>
