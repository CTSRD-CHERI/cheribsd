#pragma once

// <netdb.h> which contains a member called __unused
#include "__unused_workaround_start.h"
#include_next <netdb.h>
#include "__unused_workaround_end.h"

static inline void freehostent(void* arg __unused) {}
