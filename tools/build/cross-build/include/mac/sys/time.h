#pragma once
#include <sys/stdint.h>
#include_next <sys/time.h>

#ifndef CLOCK_UPTIME
#define CLOCK_UPTIME CLOCK_UPTIME_RAW
#endif