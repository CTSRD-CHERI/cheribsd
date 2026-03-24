#include_next <sys/types.h>
#pragma once

/* XXX: belongs in stddef.h */
#ifndef _PTRADDR_T_DECLARED
typedef size_t     ptraddr_t;
#define	_PTRADDR_T_DECLARED
#endif

#ifndef _INT64PTR_T_DECLARED
#ifdef __ILP32_
typedef	long long	int64ptr_t;
#else
typedef	long		int64ptr_t;
#endif
#define	_INT64PTR_T_DECLARED
#endif

#ifndef _UINT64PTR_T_DECLARED
#ifdef __ILP32_
typedef	unsigned long long	uint64ptr_t;
#else
typedef	unsigned long	uint64ptr_t;
#endif
#define	_UINT64PTR_T_DECLARED
#endif

#ifndef __SIZEOF_INTCAP__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma clang diagnostic ignored "-Wtypedef-redefinition"
typedef	uintptr_t	__uintcap_t;
#pragma GCC diagnostic pop
#endif

#ifndef _KUINT64CAP_T_DECLARED
typedef uint64ptr_t		kuint64cap_t;
#define _KUINT64CAP_T_DECLARED
#endif
