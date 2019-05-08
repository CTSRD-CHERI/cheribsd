#pragma once

#include_next <string.h>
/*
 * FreeBSD string.h #includes strings.h and all libmd code depends on
 * string.h providing explicit_bzero.
 */
#include <strings.h>
