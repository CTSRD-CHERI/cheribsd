#include <stdlib.h>

/*
 * Perform a malloc in the earliest allowed non-system constructor.
 * If malloc is not initialized before this point it could fail.
 */
__attribute__((__constructor__(101)))
static void
foo(void)
{
	void * volatile ptr;

	ptr = malloc(1);
	free(ptr);
}

int
main(void)
{
	return (0);
}
