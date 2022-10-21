/*-
 * Copyright (c) 2021 Robert N. M. Watson
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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

#include <sys/cdefs.h>

#if !__has_feature(capabilities)
#error "This code requires a CHERI-aware compiler"
#endif

#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/time.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "cheribsdtest.h"

/*
 * As a regression test, block the current thread in a pipe write using a
 * large write of a buffer containing a capability, and trigger a timer signal
 * to interrupt that write.
 *
 * This would previously panic the kernel with a fatal capability page fault as
 * uiomove_fromphys called from pipe_clone_write_buffer would use a plain bcopy
 * and so not strip tags, but the kernel buffer was allocated without
 * VM_PROT_WRITE_CAP.
 */

#define	BUFFER_SIZE	8192

CHERIBSDTEST(test_ipc_pipe_sleep_signal,
    "check that direct write pipe IPC of a capability can be interrupted",
    .ct_flags = CT_FLAG_SIGNAL,
    .ct_signum = SIGALRM)
{
	void * __capability buffer[BUFFER_SIZE / sizeof(void * __capability)];
	int fds[2];

	memset(buffer, 0, sizeof(buffer));
	buffer[0] = (__cheri_tocap void * __capability)buffer;

	CHERIBSDTEST_CHECK_SYSCALL(pipe(fds));
	CHERIBSDTEST_CHECK_SYSCALL(alarm(1));
	CHERIBSDTEST_CHECK_SYSCALL(write(fds[0], buffer, sizeof(buffer)));
	close(fds[0]);
	close(fds[1]);
	cheribsdtest_failure_errx("write didn't block");
}

CHERIBSDTEST(test_ipc_pipe_nocaps,
    "check that read/write of a pipe(2) strips tags")
{
	void * __capability *buffer;
	void * __capability *buffer2;
	size_t len;
	ssize_t rv;
	int fds[2];

	len = getpagesize();
	buffer = calloc(1, len);
	buffer2 = calloc(1, len);
	buffer[0] = (__cheri_tocap void * __capability)buffer;
	CHERIBSDTEST_VERIFY2(cheri_gettag(buffer[0]) != 0,
	    "pretest: tag missing");

	CHERIBSDTEST_CHECK_SYSCALL(pipe(fds));
	rv = CHERIBSDTEST_CHECK_SYSCALL(write(fds[1], buffer, len));
	CHERIBSDTEST_CHECK_EQ_SIZE(rv, len);
	rv = CHERIBSDTEST_CHECK_SYSCALL(read(fds[0], buffer2, len));
	CHERIBSDTEST_CHECK_EQ_SIZE(rv, len);

	CHERIBSDTEST_VERIFY2(cheri_gettag(buffer[0]) != 0,
	    "posttest: source tag missing");
	CHERIBSDTEST_VERIFY2(cheri_gettag(buffer2[0]) == 0,
	    "posttest: destination tag present");
	CHERIBSDTEST_VERIFY2(cheri_equal_exact(cheri_cleartag(buffer[0]),
	     buffer2[0]), "untagged value not copied");

	CHERIBSDTEST_CHECK_SYSCALL(close(fds[0]));
	CHERIBSDTEST_CHECK_SYSCALL(close(fds[1]));
	cheribsdtest_success();
}
