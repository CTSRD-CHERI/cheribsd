/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/cdefs.h>

#include <errno.h>

#include "libc_private.h"

#ifdef CHERI_LIB_C18N
struct rtld_sigaction_result {
	int rs_ret;
	int rs_errno;
};

#pragma weak _rtld_sigaction
struct rtld_sigaction_result _rtld_sigaction(int, const struct sigaction *,
    struct sigaction *);
#endif

/*
 * RTLD's _rtld_sigaction() returns the syscall error separately because
 * __sys_sigaction() sets RTLD's private errno. Copy it to the caller's errno.
 */
int
__libsys_sigaction_c18n(int sig, const struct sigaction *act,
    struct sigaction *oact)
{
#ifdef CHERI_LIB_C18N
	struct rtld_sigaction_result res;

	if (_rtld_sigaction != NULL) {
		res = _rtld_sigaction(sig, act, oact);
		if (res.rs_ret != 0)
			errno = res.rs_errno;
		return (res.rs_ret);
	}
#endif
	return (__sys_sigaction(sig, act, oact));
}
