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

__weak_reference(__mmap, mmap);
__weak_reference(__mmap, _mmap);

void *
__mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset)
{
	void *ret;

	ret = __sys_mmap(addr, len, prot, flags, fd, offset);
#ifdef CHERI_LIB_C18N
	if (ret != MAP_FAILED && _rtld_c18n_is_enabled()) {
		uint64_t perms;

		perms = CHERI_PERM_SYSCALL;
#ifdef __aarch64__
		perms |= CHERI_PERM_EXECUTIVE;
#endif
		ret = cheri_clearperm(ret, perms);
	}
#endif
	return (ret);
}
