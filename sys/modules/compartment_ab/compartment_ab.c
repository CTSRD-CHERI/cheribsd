#include <sys/param.h>
#include <sys/compressor.h>
#include <sys/module.h>

#include "a.h"

static int
compartment_ab_modevent(module_t mod, int type, void *unused)
{

	switch (type) {
	case MOD_LOAD:
		a_funa();
		return (0);
	case MOD_UNLOAD:
		return (0);
	default:
		return (EINVAL);
	}
}

static moduledata_t compartment_ab_mod = {
	"compartment_ab",
	compartment_ab_modevent,
	0
};

MODULE_VERSION(compartment_ab, 1);
DECLARE_MODULE(compartment_ab, compartment_ab_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
