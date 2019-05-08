#pragma once
#include_next <signal.h>

/* MacOS does not provide sys_nsig. It uses a NSIG/__DARWIN_NSIG macro instead */
#define sys_nsig NSIG
