#include <sys/types.h>
#include <sys/systm.h>

#include "a.h"
#include "b/b.h"

void
a_funa(void)
{

	printf("b value = %d (should be %d)\n", b_funa(), B_VALUE);
}
