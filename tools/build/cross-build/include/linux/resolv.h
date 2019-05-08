#pragma once
#include_next <resolv.h>

/* GLibc doesn't provide res_ndestroy */
#ifndef res_ndestroy
#define res_ndestroy res_nclose
#endif
