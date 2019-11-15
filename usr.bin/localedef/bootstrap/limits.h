#include_next <limits.h>

#ifndef COLL_WEIGHTS_MAX
#error "COLL_WEIGHTS_MAX missing"
#endif

#if COLL_WEIGHTS_MAX != 10
#pragma message("Changing value of COLL_WEIGHTS_MAX")
#undef COLL_WEIGHTS_MAX
#define COLL_WEIGHTS_MAX 10
#endif
