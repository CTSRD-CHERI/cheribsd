/*-
 * Copyright (c) 2025 Dapeng Gao
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency (DARPA) Contract No. FA8750-24-C-B047 ("DEC").
 */

#include <sys/mman.h>

#include <cheri/cheric.h>

#include "libc_private.h"

void *
mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset)
{
	uint64_t perms;
	void *ret;

	perms = CHERI_PERM_SYSCALL;
#ifdef __aarch64__
	perms |= CHERI_PERM_EXECUTIVE;
#endif

	ret = __sys_mmap(addr, len, prot, flags, fd, offset);
	ret = cheri_clearperm(ret, perms);
	return (ret);
}
