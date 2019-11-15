#pragma once
#include <sys/cdefs.h>
#include_next <ctype.h>

/*
 * On macOS isxdigit(), etc are defined in _ctype.h, but we have to include the
 * target _ctype.h so that localedef uses the correct values.
 * To fix macOS bootstrap, provide a declaration of isxdigit(), etc. here.
 * However, only do so if they are not already define as a macro (as is the
 * case on Linux).
 */
#ifndef isxdigit
__BEGIN_DECLS
int	isalpha(int);
int	isascii(int);
int	isdigit(int);
int	isgraph(int);
int	islower(int);
int	isxdigit(int);
__END_DECLS
#endif
