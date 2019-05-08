#pragma once

#include_next <sys/time.h>
#include <time.h>
/* Not quite the same but should be good enough */
#ifdef _OPENSOLARIS_SYS_TIME_H_
#define CLOCK_UPTIME CLOCK_BOOTTIME
#endif
