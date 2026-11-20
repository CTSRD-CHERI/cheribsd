/*
 * SPDX-License-Identifier: CDDL 1.0
 *
 * Copyright (c) 2022 Christos Margiolis <christos@FreeBSD.org>
 * Copyright (c) 2022 Mark Johnston <markj@FreeBSD.org>
 * Copyright (c) 2023 The FreeBSD Foundation
 * Copyright (c) 2026 Konrad Witaszczyk
 *
 * Portions of this software were developed by Christos Margiolis
 * <christos@FreeBSD.org> under sponsorship from the FreeBSD Foundation.
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency / Air Force Research Laboratory (DARPA/AFRL) Contract
 * No. FA8750-24-C-B047 ("DEC").
 */

/*
 * The cbt provider's skeleton is based on the implementation of dtrace_kinst(4)
 * and dtrace_fbt(4) but its actual profiling logic is independent of them.
 */

#include <sys/param.h>

#include "cbt.h"

bool
cbt_md_excluded_function(const char *name)
{
	if (strcmp(name, "handle_el1h_sync") == 0 ||
	    strcmp(name, "do_el1h_sync") == 0 ||
	    strcmp(name, "handle_el1t_sync") == 0 ||
	    strcmp(name, "do_el1t_sync") == 0)
                return (true);

	return (false);
}
