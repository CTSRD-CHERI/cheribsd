#pragma once


// <bits/fcntl.h> includes <bits/stat.h> which contains a member __unused
#include "__unused_workaround_start.h"
#include_next <fcntl.h>
#include "__unused_workaround_end.h"

#ifdef __unused_undefd
#undef __unused_undefd
#define __unused __attribute__((unused))
#endif

#include <sys/file.h>


#ifndef O_EXLOCK
#define O_EXLOCK (1 << 30)
#endif
#ifndef O_SHLOCK
#define O_SHLOCK (1 << 31)
#endif


#undef open
#define open(path, flags, ...) ({ \
    int __fd = (open)(path, flags, ##__VA_ARGS__); \
    if (flags & O_EXLOCK) flock(__fd, LOCK_EX); \
    if (flags & O_SHLOCK) flock(__fd, LOCK_SH); \
    __fd; })
