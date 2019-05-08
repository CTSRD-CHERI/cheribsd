#pragma once
#include_next <ctype.h>
#include <stdlib.h>

#ifndef digittoint
static inline int digittoint(char c) {
	if (!isxdigit(c))
		return 0;
	char buffer[] = {c, '\0' };
	return strtol(buffer, 0, 16);
}
#endif
