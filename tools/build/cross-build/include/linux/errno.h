#pragma once
#include_next <errno.h>

#ifndef EFTYPE
#define EFTYPE EINVAL
#endif

#ifndef EPROCLIM
#define EPROCLIM EAGAIN
#endif
