#ifndef _CHERI_BENCH_MALLOC_H_
#define _CHERI_BENCH_MALLOC_H_

#include <stdio.h>

typedef int (*benchfn_t)(FILE *, int, char **);

/* capdirty.c */
int bench_capdirty_overhead(FILE *, int, char **);

/* malloc_comb.c */
int bench_malloc_comb(FILE *, int, char **);

#endif
