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
#include <sys/proc.h>
#include <sys/queue.h>

#include "ace2_syncpoint.h"
#include "ace2_syncpoint_internal.h"

/*
 * These are the kernel portions of syncpoint test cases.
 */

static int
syncpoint_example1(SYSCTL_HANDLER_ARGS)
{
	uint64_t id;
	int error, v = 0;

	error = sysctl_handle_int(oidp, &v, 0, req);
	if (error)
		return (error);
	if (v == 0)
		return (0);
	id = ace2_syncpoint("example1", "example %d\n", 1);
	ace2_observe(id, "example1", "%d", 1);
	return (0);
}

SYSCTL_PROC(_dev_ace2_syncpoint_test, OID_AUTO, example1,
    CTLTYPE_INT | CTLFLAG_RWTUN | CTLFLAG_PRISON | CTLFLAG_MPSAFE, 0, 0,
    syncpoint_example1, "I", "ACE2 syncpoint test case");

static int
syncpoint_example2(SYSCTL_HANDLER_ARGS)
{
	uint64_t id;
	int error, v = 0;

	error = sysctl_handle_int(oidp, &v, 0, req);
	if (error)
		return (error);
	if (v == 0)
		return (0);
	id = ace2_syncpoint("example2", "example %d\n", 2);
	ace2_observe(id, "example2", "%d", 2);
	return (0);
}

SYSCTL_PROC(_dev_ace2_syncpoint_test, OID_AUTO, example2,
    CTLTYPE_INT | CTLFLAG_RWTUN | CTLFLAG_PRISON | CTLFLAG_MPSAFE, 0, 0,
    syncpoint_example2, "I", "ACE2 syncpoint test case");
