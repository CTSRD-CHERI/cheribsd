#pragma once

#include_next <string.h>

/* strchrnul is not provided by macOS and the strchrnul.c implementation
 * can not be compiled on macOS so just provide it inline here */
static inline char *
strchrnul(const char *p, int ch)
{
	char c;

	c = ch;
	for (;; ++p) {
		if (*p == c || *p == '\0')
			return ((char *)p);
	}
	/* NOTREACHED */
}
