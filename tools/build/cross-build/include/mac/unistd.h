#pragma once

#include_next <unistd.h>
#include <fcntl.h>
#include <sys/signal.h>
#include <sys/time.h>
#include <sys/types.h>


static inline int
eaccess(const char *path, int mode) {
	return faccessat(AT_FDCWD, path, mode, AT_EACCESS);
}
/* Just needs to be declared, doesn't actually have to be implemented */
void closefrom(int lowfd);
