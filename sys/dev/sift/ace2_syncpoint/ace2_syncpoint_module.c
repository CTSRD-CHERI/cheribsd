/*-
 * Copyright (c) 2025 Capabilities Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency (DARPA) Contract No. FA8750-24-C-B047 ("DEC").
 */

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/module.h>

#include "ace2_syncpoint_internal.h"

/*
 * Module unload is not supported as we haven't implemented a pluggable
 * syncpoint mechanism.
 */
static int
ace2_syncpoint_modevent(module_t mod, int type, void *data)
{

	switch (type) {
	case MOD_LOAD:
		ace2_syncpoint_module_load();
		return (0);

	case MOD_UNLOAD:
		return (ace2_syncpoint_module_unload());

	default:
		return (EOPNOTSUPP);
	}
}

DEV_MODULE(ace2_syncpoint, ace2_syncpoint_modevent, NULL);
