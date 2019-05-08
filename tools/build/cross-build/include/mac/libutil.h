#pragma once

#include <stdio.h>
#include <sys/socket.h>

#if __has_include_next(<libutil.h>)
#include_next <libutil.h>
#endif

/* Search for util.h only using the include paths after this file since
 * otherwise we end up including libnetbsd/util.h instead! */
#include_next <util.h>
