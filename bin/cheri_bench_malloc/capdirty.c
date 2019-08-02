/*
 * A benchmark for stressing the capdirty tracking.
 *
 * Optional arguments:
 *
 *   flavor: specify as OR of:
 *     0x01 - read from each page
 *     0x02 - write data to each page
 *     0x04 - write capabilities to each page
 *
 *   npgs: arena size, in pages
 *
 *   iters: number of rounds of resetting the arena
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/mman.h>
#include <machine/param.h>

#include "cheri_bench_malloc.h"

int
bench_capdirty_overhead(FILE *out, int argc, char **argv)
{
	int iters = 32;
	int npgs = 512;
  int flavor = 0x7;
	char *arena = NULL;

  if (argc > 1)
  {
    flavor = atoi(argv[1]);
    argc--; argv++;
  }

  if (argc > 1)
  {
    npgs = atoi(argv[1]);
    argc--; argv++;
  }

  if (argc > 1)
  {
    iters = atoi(argv[1]);
    argc--; argv++;
  }

  fprintf(out, "# capdirty_overhead: flavor=0x%x npgs=%d iters=%d\n",
          flavor, npgs, iters);

	arena = mmap(arena, PAGE_SIZE*npgs, PROT_READ|PROT_WRITE,
               MAP_ANON|MAP_PRIVATE, -1, 0);
  if (arena == MAP_FAILED)
  {
    fprintf(out, "bail - initial mmap failed\n");
    return -1;
  }

	for (int i = 0; i < iters; i++)
  {
		char *pagep;
		void * __capability c = &pagep;
		int sum = 0;

		arena = mmap(arena, PAGE_SIZE*npgs,
				PROT_READ|PROT_WRITE,
				MAP_ANON|MAP_PRIVATE|MAP_FIXED, -1, 0);
    if (arena == MAP_FAILED)
    {
      fprintf(out, "bail - remap failed\n");
      return -2;
    }

		if (flavor & 0x1)
    {
			/* Read every page */
			pagep = arena;
			for (int j = 0; j < npgs; j++, pagep += PAGE_SIZE)
      {
				sum += *(int *)__builtin_assume_aligned(pagep, sizeof(int));
			}
      if (sum != 0)
      {
        fprintf(out, "bail - nonzero zero\n");
        return -3;
      }
		}

		if (flavor & 0x2)
    {	
			/* Write every page */
			pagep = arena;
			for (int j = 0; j < npgs; j++, pagep += PAGE_SIZE)
      {
				*(long *)__builtin_assume_aligned(pagep, sizeof(int))
					= 1;
			}
		}

		if (flavor & 0x4)
    {
			/* Capability-write every page */
			pagep = arena;
			for (int j = 0; j < npgs; j++, pagep += PAGE_SIZE)
      {
				*(void * __capability *)
					__builtin_assume_aligned(pagep,
						sizeof(void * __capability))
					= c;
			}
		}
	}

	munmap(arena, PAGE_SIZE*npgs);
  return 0;
}


