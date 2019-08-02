/*
 * Hammer malloc with short-lived objects of a comb of sizes
 */

#include <stdio.h>
#include <stdlib.h>

#include "cheri_bench_malloc.h"

static const int comb_sizes[] = { 32, 512, 8192, 131072, 2097152, 33554432 };
static const int comb_count[] = { 32,  16,    8,      4,       2,        1 };

_Static_assert(sizeof(comb_sizes) == sizeof(comb_count), "bad comb sizes");

int
bench_malloc_comb(FILE *out, int argc, char **argv)
{
  int iters = 1024;

  (void)out;
  (void)argc;
  (void)argv;

  for(; iters > 0; iters--)
  {
    for(size_t cpos = 0;
        cpos < sizeof(comb_sizes)/sizeof(comb_sizes[0]);
        cpos++)
    {
      for (int op = comb_count[cpos]; op > 0; op--)
      {
        char *p = malloc(comb_sizes[cpos]);
        p[0] = 1;
        free(p);
      }
    }
  }

  return 0;
}
