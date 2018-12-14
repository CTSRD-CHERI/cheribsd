#pragma once

#if __has_include_next(<libutil.h>)
#include_next <libutil.h>
#endif

int	expand_number(const char *_buf, uint64_t *_num);
