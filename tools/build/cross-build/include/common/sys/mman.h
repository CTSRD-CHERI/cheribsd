#pragma once

#include_next <sys/mman.h>

#ifndef MAP_NOCORE
#define MAP_NOCORE 0
#endif

#ifndef MAP_NOSYNC
#define MAP_NOSYNC 0
#endif
