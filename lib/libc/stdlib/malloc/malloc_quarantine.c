/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 SRI International
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency (DARPA) Contract No. FA8750-24-C-B047 ("DEC").
 */

#include <sys/errno.h>

#include <stdbool.h>
#include <stdlib.h>
#include <malloc_np.h>

bool
malloc_revoke_enabled(void)
{
	return (false);
}

int
malloc_revoke_quarantine_force_flush(void)
{
	return (ENOTSUP);
}
