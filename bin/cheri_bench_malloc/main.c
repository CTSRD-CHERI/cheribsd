#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "cheri_bench_malloc.h"

typedef struct {
  const char *name;
  benchfn_t benchfn;
} benchdesc_t;

static const benchdesc_t benches[] = {
  { "capdirty_overhead", bench_capdirty_overhead },
  { "malloc_comb", bench_malloc_comb },
  { NULL, NULL },
};

static void
help(FILE *out)
{
  const benchdesc_t *b;
  fprintf(out, "Possible benchmarks:\n");
  for (b = benches; b->name != NULL; b++)
  {
    fprintf(out, "  %s\n", b->name);
  }
}

int
main(int argc, char **argv)
{
  int opt;
  FILE *benchout = stdout;

  while ((opt = getopt(argc, argv, "+h")) != -1)
  {
    switch(opt)
    {
    case 'h':
      help(stdout);
      return 0;
    }
  }

  if (optind >= argc)
  {
    fprintf(stderr, "Specify benchmark\n");
    help(stderr);
    return 1;
  }

  const benchdesc_t *b;
  for (b = benches; b->name != NULL; b++)
  {
    if (strcmp(b->name, argv[optind]) == 0)
    {
      break;
    }
  }
  if (b == NULL)
  {
    fprintf(stderr, "Unknown benchmark %s\n", argv[optind]);
    help(stderr);
  }

  return b->benchfn(benchout, argc-optind, &argv[optind]);
}
