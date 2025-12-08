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
#include <sys/sbuf.h>
#include <sys/sysctl.h>

#include "ace2_syncpoint_internal.h"

SYSCTL_NODE(_dev, OID_AUTO, ace2, CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, "ace2");
SYSCTL_NODE(_dev_ace2, OID_AUTO, syncpoint, CTLFLAG_RD | CTLFLAG_MPSAFE,
    NULL, "ace2_syncpoint");
SYSCTL_NODE(_dev_ace2_syncpoint, OID_AUTO, test, CTLFLAG_RD | CTLFLAG_MPSAFE,
    NULL, "ace2_syncpoint tests");

int ace2_syncpoint_enabled = 1;
SYSCTL_INT(_dev_ace2_syncpoint, OID_AUTO, enabled, CTLFLAG_RW,
    &ace2_syncpoint_enabled, 0, "Enable ACE2 syncpoints");

uint64_t ace2_syncpoint_nextid;
SYSCTL_U64(_dev_ace2_syncpoint, OID_AUTO, nextid, CTLFLAG_RW,
    &ace2_syncpoint_nextid, 0, "Next syncpoint ID");

uint64_t ace2_syncpoint_count;
SYSCTL_U64(_dev_ace2_syncpoint, OID_AUTO, count, CTLFLAG_RW,
    &ace2_syncpoint_count, 0, "In-flight syncpoints");

/*
 * XXXRW: Do something better here.  Value not exposed to userlevel so that
 * it doesn't become part of the ABI.
 */
#define	ACE2_SYNCPOINT_SYSCTL_MAXSIZE	1024

static int
sysctl_ace2_syncpoint_list(SYSCTL_HANDLER_ARGS)
{
	struct sbuf *sb;
	int error;

	sb = sbuf_new(NULL, NULL, ACE2_SYNCPOINT_SYSCTL_MAXSIZE,
	    SBUF_FIXEDLEN);
	ace2_syncpoint_list(sb);
	sbuf_finish(sb);
	error = sysctl_handle_string(oidp, sbuf_data(sb), sbuf_len(sb), req);
	sbuf_delete(sb);
	return (error);
}

SYSCTL_PROC(_dev_ace2_syncpoint, OID_AUTO, list,
    CTLTYPE_STRING | CTLFLAG_MPSAFE, NULL, 0,
    sysctl_ace2_syncpoint_list, "A", "ACE2 syncpoint test case");
