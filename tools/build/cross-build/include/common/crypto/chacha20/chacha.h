#pragma once

#ifdef __linux__
#ifndef __isthreaded
#define __isthreaded 1
#endif
#define INHERIT_ZERO 0
static inline int
minherit(void *addr __unused, size_t len __unused, int inherit __unused)
{

	return 0;
}


#endif /* __linux__ */

#include "../../../../../../../sys/crypto/chacha20/chacha.h"
