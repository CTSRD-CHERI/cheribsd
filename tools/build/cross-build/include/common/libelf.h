#pragma once
/* Needed to get opensolaris stuff to compile */
#ifdef _OPENSOLARIS_SYS_TYPES_H_
#include <sys/endian.h>
#include_next <libelf.h>
#endif
