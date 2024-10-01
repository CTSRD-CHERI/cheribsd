/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Konrad Witaszczyk
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency (DARPA) Contract No. FA8750-24-C-B047 ("DEC").
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>

#include "sift_sa.h"
#include "sift_sa_public.h"
#include "sift_sa_private.h"

struct sift_sa_data sift_sa_data_public;
struct sift_sa_data sift_sa_data_private;

static int
sift_sa_modevent(module_t mod, int type, void *unused)
{
	int error;

	switch (type) {
	case MOD_LOAD:
		if (&sift_sa_data_private != &sift_sa_data_public + 1) {
		    printf("unexpected memory layout\n");
		    return (EINVAL);
		}

		error = sift_sa_public_load();
		if (error != 0)
			return (error);
		error = sift_sa_private_load();
		break;
	case MOD_UNLOAD:
		error = sift_sa_public_unload();
		if (error != 0)
			return (error);
		error = sift_sa_private_unload();
		break;
	default:
		error = EINVAL;
	}
	return (error);
}

static moduledata_t sift_sa_mod = {
	"sift_sa",
	sift_sa_modevent,
	0
};
DECLARE_MODULE(sift_sa, sift_sa_mod, SI_SUB_DRIVERS, SI_ORDER_FIRST);
MODULE_VERSION(sift_sa, 1);
