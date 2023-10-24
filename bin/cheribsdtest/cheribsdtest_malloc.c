/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 SRI International
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency (DARPA) Contract No. HR001122S0003 ("MTSS").
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/procctl.h>
#include <sys/wait.h>

#include <errno.h>
#include <malloc_np.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "cheribsdtest.h"

static const char *
skip_malloc_not_revoking(const char *name __unused)
{
	if (malloc_is_revoking())
		return (NULL);
	return ("malloc is not revoking");
}

CHERIBSDTEST(malloc_revoke_basic,
    "verify that a free'd pointer is revoked by malloc_revoke",
    .ct_check_skip = skip_malloc_not_revoking)
{
	volatile void *ptr __unused;

	ptr = malloc(1);

	free(__DEVOLATILE(void *, ptr));

	malloc_revoke();

	/* XXX: ask kernel what the revocation method is? */
	CHERIBSDTEST_VERIFY2(!cheri_gettag(ptr),
	    "free'd pointer not revoked %#lp", ptr);

	cheribsdtest_success();
}

CHERIBSDTEST(malloc_revoke_twice, "revoke twice back to back",
    .ct_check_skip = skip_malloc_not_revoking)
{
	malloc_revoke();
	malloc_revoke();

	cheribsdtest_success();
}

CHERIBSDTEST(malloc_zero_size,
    "Check that allocators return non-NULL for size=0")
{
	void *ptr, *ptr2;

	CHERIBSDTEST_VERIFY((ptr = malloc(0)) != NULL);
	free(ptr);

	CHERIBSDTEST_VERIFY((ptr = calloc(0, 1)) != NULL);
	free(ptr);
	CHERIBSDTEST_VERIFY((ptr = calloc(1, 0)) != NULL);
	free(ptr);
	CHERIBSDTEST_VERIFY((ptr = calloc(0, 0)) != NULL);
	free(ptr);

	CHERIBSDTEST_VERIFY((ptr = realloc(NULL, 0)) != NULL);
	CHERIBSDTEST_VERIFY((ptr2 = realloc(ptr, 0)) != NULL);
	/*
	 * XXX: POSIX requires that: "A pointer to the allocated space
	 * shall be returned, and the memory object pointed to by ptr
	 * shall be freed."  Unfortunately that's impractical to check as
	 * even with revocation the same storage could be allocated if
	 * revocation is triggered internally.
	 */
	free(ptr2);

	/*
	 * C/POSIX require that aligned_alloc/posix_memalign take
	 * alignements that are a power-of-2 multiple of sizeof(void *).
	 */
	CHERIBSDTEST_VERIFY((ptr = aligned_alloc(sizeof(void *), 0)) != NULL);
	free(ptr);

	CHERIBSDTEST_VERIFY2(posix_memalign(&ptr, sizeof(void *), 0) == 0,
	    "posix_memalign failed, errno %d", errno);
	CHERIBSDTEST_VERIFY2(ptr != NULL, "posix_memalign returned NULL");
	free(ptr);

	CHERIBSDTEST_VERIFY((ptr = memalign(sizeof(void *), 0)) != NULL);
	free(ptr);

	cheribsdtest_success();
}

static bool
child_is_revoking(int pid)
{
	int res;

	waitpid(pid, &res, 0);
	if (WIFEXITED(res)) {
		if (WEXITSTATUS(res) == 0)
			return (true);
		else
			return (false);
	} else
		cheribsdtest_failure_errx("child exec failed");
}

static void
malloc_revocation_ctl_common_procctl(const char *progname,
    bool should_be_revoking, int *procctl_arg)
{
	int pid;

	pid = fork();
	CHERIBSDTEST_VERIFY(pid >= 0);
	if (pid == 0) {
		char *progpath;
		char *argv[2];

		if (procctl_arg != NULL)
			CHERIBSDTEST_CHECK_SYSCALL(procctl(P_PID, getpid(),
			    PROC_CHERI_REVOKE_CTL, procctl_arg));

		asprintf(&progpath, "/usr/libexec/%s", progname);
		argv[0] = progpath;
		argv[1] = NULL;
		execve(argv[0], argv, NULL);
		abort();
	} else {
		if (child_is_revoking(pid) == should_be_revoking)
			cheribsdtest_success();
		else {
			if (should_be_revoking)
				cheribsdtest_failure_errx(
				    "child is not revoking and should be");
			else
				cheribsdtest_failure_errx(
				    "child is revoking and should not be");
		}
	}
}

static void
malloc_revocation_ctl_common(const char *progname, bool should_be_revoking)
{
	malloc_revocation_ctl_common_procctl(progname, should_be_revoking,
	    NULL);
}

CHERIBSDTEST(malloc_revocation_ctl_baseline,
    "A base binary reports revocation is enabled")
{
	malloc_revocation_ctl_common("malloc_is_revoking", true);
}

CHERIBSDTEST(malloc_revocation_ctl_elfnote_disable,
    "A binary with elfnote disabling reports revocation is disable")
{
	malloc_revocation_ctl_common("malloc_is_revoking_elfnote_disable",
	    false);
}

CHERIBSDTEST(malloc_revocation_ctl_elfnote_enable,
    "A binary with elfnote enabling reports revocation is enabled")
{
	malloc_revocation_ctl_common("malloc_is_revoking_elfnote_enable",
	    true);
}

CHERIBSDTEST(malloc_revocation_ctl_elfnote_disable_protctl_enable,
    "A binary with elfnote disabling reports revocation is disable")
{
	int arg = PROC_CHERI_REVOKE_FORCE_ENABLE;

	malloc_revocation_ctl_common_procctl(
	    "malloc_is_revoking_elfnote_disable", true, &arg);
}

CHERIBSDTEST(malloc_revocation_ctl_elfnote_enable_protctl_disable,
    "A binary with elfnote enabling reports revocation is enabled")
{
	int arg = PROC_CHERI_REVOKE_FORCE_DISABLE;

	malloc_revocation_ctl_common_procctl(
	    "malloc_is_revoking_elfnote_enable", false, &arg);
}

CHERIBSDTEST(malloc_revocation_ctl_suid_baseline,
    "A suid binary reports revocation is enabled")
{
	malloc_revocation_ctl_common("malloc_is_revoking_suid", true);
}

CHERIBSDTEST(malloc_revocation_ctl_suid_elfnote_disable,
    "A suid binary with elfnote disabling reports revocation is disable")
{
	malloc_revocation_ctl_common("malloc_is_revoking_elfnote_disable",
	    false);
}

CHERIBSDTEST(malloc_revocation_ctl_suid_elfnote_enable,
    "A suid binary with elfnote enabling reports revocation is enabled")
{
	malloc_revocation_ctl_common("malloc_is_revoking_elfnote_enable",
	    true);
}

CHERIBSDTEST(malloc_revocation_ctl_suid_elfnote_disable_protctl_enable,
    "A binary with elfnote disabling reports revocation is disable")
{
	int arg = PROC_CHERI_REVOKE_FORCE_ENABLE;

	malloc_revocation_ctl_common_procctl(
	    "malloc_is_revoking_suid_elfnote_disable", false, &arg);
}

CHERIBSDTEST(malloc_revocation_ctl_suid_elfnote_enable_protctl_disable,
    "A binary with elfnote enabling reports revocation is enabled")
{
	int arg = PROC_CHERI_REVOKE_FORCE_DISABLE;

	malloc_revocation_ctl_common_procctl(
	    "malloc_is_revoking_suid_elfnote_enable", true, &arg);
}
