#pragma once
#include_next <unistd.h>
#include <getopt.h>

static inline int
check_utility_compat(const char *utility)
{
	/*
	 * The check_utility_compat() function returns zero if utility should
	 * implement strict IEEE Std 1003.1-2001 (“POSIX.1”) behavior, and
	 * nonzero otherwise.
	 *
	 * During bootstrapping from another host system always returning 1
	 * is probably the best.
	 */
	return (1);
}
