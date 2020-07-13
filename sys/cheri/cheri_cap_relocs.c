#include <cheri_init_globals.h>

/* Invoked from locore. */
extern void init_cap_relocs(void *data_cap, void *pc_cap);

void
init_cap_relocs(void *data_cap, void *pc_cap)
{
	cheri_init_globals_3(data_cap, pc_cap, data_cap);
}
