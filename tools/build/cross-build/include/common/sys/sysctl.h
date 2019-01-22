#pragma once

#include <sys/types.h>

#define sysctlbyname __freebsd_sysctlbyname
#define sysctl __freebsd_sysctl

int	sysctl(const int *, u_int, void *, size_t *, const void *, size_t);
int	sysctlbyname(const char *, void *, size_t *, const void *, size_t);
