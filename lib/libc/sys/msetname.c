/*-
 * Copyright (c) 2026 Capabilities Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency (DARPA) Contract No. FA8750-24-C-B047 ("DEC").
 */

#define	_WANT_P_OSREL

#include <sys/param.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <errno.h>
#include "libc_private.h"

__weak_reference(__sys_msetname, __msetname);

int
msetname(void *addr, size_t len, const char *name)
{
	int error;

	/*
	 * If msetname(2) isn't present, just disregard.
	 */
	error = 0;
	if (__getosreldate() >= P_OSREL_MSETNAME)
		error = __sys_msetname(addr, len, name);
	return (error);
}
