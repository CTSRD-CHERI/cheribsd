#pragma once

#include_next <signal.h>

#define sys_signame sys_siglist
#define sys_nsig _NSIG
