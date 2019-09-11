#pragma once
/* The Linux sysctl struct has a member called __unused */
#undef __unused
#include_next <sys/sysctl.h>
#define __unused __attribute__((unused))
