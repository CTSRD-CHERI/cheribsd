
#pragma once

#include_next<fts.h>

#ifdef __GLIBC__
#define fts_open(path_argv, options, compar)				\
	fts_open(path_argv, options,					\
	    (int (*)(const FTSENT **, const FTSENT **))compar)
#endif
