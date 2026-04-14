#ifndef SCAN_AND_STASH_H
#define SCAN_AND_STASH_H

#include <sys/conf.h>

// Dump this for now. I removed it from the source since FreeBSD doesn't seem
// to do this sort of thing and all other examples I've found of __user are
// removed via the preprocessor.

//#define __user      __attribute__((noderef, address_space(1)))

#endif /* SCAN_AND_STASH_H */
