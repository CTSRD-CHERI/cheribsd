/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2022 SRI International
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency (DARPA) Contract No. HR001122C0110 ("ETC").
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

#if !__has_feature(capabilities)
#error "This code requires a CHERI-aware compiler"
#endif

#include <sys/ptrace.h>
#include <sys/wait.h>

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include <cheri/cheric.h>

#include "cheribsdtest.h"

/*
 * Fork a child process and attach to it in the parent.  The child
 * exits, but the parent returns the child pid to the caller after
 * attaching to the stopped child.
  */
static pid_t
fork_child(void)
{
	pid_t fpid, wpid;
	int status;

	fpid = fork();
	CHERIBSDTEST_VERIFY2(fpid != -1, "Could not fork: errno=%d", errno);

	if (fpid == 0) {
		/* child */
		CHERIBSDTEST_VERIFY(ptrace(PT_TRACE_ME, 0, NULL, 0) == 0);
		raise(SIGSTOP);

		exit(0);
	}

	/* parent */
	wpid = waitpid(fpid, &status, 0);
	CHERIBSDTEST_VERIFY(wpid == fpid);
	CHERIBSDTEST_VERIFY(WIFSTOPPED(status));

	return (fpid);
}

/* Continue the stopped child process and wait for it to exit. */
static void
finish_child(pid_t pid)
{
	pid_t wpid;
	int status;

	CHERIBSDTEST_VERIFY(ptrace(PT_CONTINUE, pid, (caddr_t)1, 0) == 0);

	wpid = waitpid(pid, &status, 0);
	CHERIBSDTEST_VERIFY(wpid == pid);
	CHERIBSDTEST_VERIFY(WIFEXITED(status));
}

CHERIBSDTEST(test_ptrace_readcap, "Basic tests of PIOD_READ_CHERI_CAP")
{
	struct ptrace_io_desc piod;
	pid_t pid;
	uintcap_t cap, *pp;
	char capbuf[2][sizeof(uintcap_t) + 1];

	pp = malloc(sizeof(*pp) * 2);
	pp[0] = (uintcap_t)(__cheri_tocap void * __capability)&piod;
	pp[1] = 42;

	CHERIBSDTEST_VERIFY(cheri_gettag(pp[0]) != 0);
	CHERIBSDTEST_VERIFY(cheri_gettag(pp[1]) == 0);

	pid = fork_child();

	piod.piod_op = PIOD_READ_CHERI_CAP;
	piod.piod_offs = pp;
	piod.piod_addr = capbuf;
	piod.piod_len = sizeof(capbuf);
	CHERIBSDTEST_VERIFY(ptrace(PT_IO, pid, (caddr_t)&piod, 0) == 0);

	CHERIBSDTEST_VERIFY(piod.piod_len == sizeof(capbuf));
	CHERIBSDTEST_VERIFY2(capbuf[0][0] == 1,
	    "Tag not set in returned buffer");
	memcpy(&cap, &capbuf[0][1], sizeof(cap));
	CHERIBSDTEST_VERIFY2(cheri_equal_exact(cheri_cleartag(pp[0]), cap),
	    "Mismatch in non-tag bits of first capability");
	CHERIBSDTEST_VERIFY2(capbuf[1][0] == 0,
	    "Tag set in returned buffer");
	memcpy(&cap, &capbuf[1][1], sizeof(cap));
	CHERIBSDTEST_VERIFY2(cheri_equal_exact(pp[1], cap),
	    "Mismatch in non-tag bits of second capability");

	finish_child(pid);

	cheribsdtest_success();
}

CHERIBSDTEST(test_ptrace_readtags, "Basic test of PIOD_READ_CHERI_TAGS")
{
	struct ptrace_io_desc piod;
	pid_t pid;
	uintcap_t pp[8] __attribute__((aligned(8*sizeof(uintcap_t)))) = { 0 };
	char tagbuf[1];

	pp[0] = (uintcap_t)(__cheri_tocap void * __capability)&piod;
	pp[2] = (uintcap_t)(__cheri_tocap void * __capability)tagbuf;

	CHERIBSDTEST_VERIFY(cheri_gettag(pp[0]) != 0);
	CHERIBSDTEST_VERIFY(cheri_gettag(pp[1]) == 0);
	CHERIBSDTEST_VERIFY(cheri_gettag(pp[2]) != 0);
	CHERIBSDTEST_VERIFY(cheri_gettag(pp[3]) == 0);
	CHERIBSDTEST_VERIFY(cheri_gettag(pp[4]) == 0);
	CHERIBSDTEST_VERIFY(cheri_gettag(pp[5]) == 0);
	CHERIBSDTEST_VERIFY(cheri_gettag(pp[6]) == 0);
	CHERIBSDTEST_VERIFY(cheri_gettag(pp[7]) == 0);

	pid = fork_child();

	piod.piod_op = PIOD_READ_CHERI_TAGS;
	piod.piod_offs = pp;
	piod.piod_addr = tagbuf;
	piod.piod_len = sizeof(tagbuf);
	CHERIBSDTEST_VERIFY(ptrace(PT_IO, pid, (caddr_t)&piod, 0) == 0);

	CHERIBSDTEST_VERIFY(piod.piod_len == sizeof(tagbuf));
	CHERIBSDTEST_VERIFY(tagbuf[0] == 0x05);

	finish_child(pid);

	cheribsdtest_success();
}

CHERIBSDTEST(test_ptrace_readcap_pageend,
    "Use PIOD_READ_CHERI_CAP to fetch capability at the end of a page")
{
	struct ptrace_io_desc piod;
	size_t page_size;
	pid_t pid;
	uintcap_t cap, *pp;
	u_int last_index;
	char capbuf[sizeof(uintcap_t) + 1];

	page_size = getpagesize();
	pp = aligned_alloc(page_size, page_size);
	memset(pp, 0, page_size);
	last_index = (page_size / sizeof(uintcap_t)) - 1;
	pp[last_index] = (uintcap_t)(__cheri_tocap void * __capability)&piod;

	CHERIBSDTEST_VERIFY(cheri_gettag(pp[last_index]) != 0);

	pid = fork_child();

	piod.piod_op = PIOD_READ_CHERI_CAP;
	piod.piod_offs = &pp[last_index];
	piod.piod_addr = capbuf;
	piod.piod_len = sizeof(capbuf);
	CHERIBSDTEST_VERIFY(ptrace(PT_IO, pid, (caddr_t)&piod, 0) == 0);

	CHERIBSDTEST_VERIFY(piod.piod_len == sizeof(capbuf));
	CHERIBSDTEST_VERIFY2(capbuf[0] == 1,
	    "Tag not set in returned buffer");
	memcpy(&cap, &capbuf[1], sizeof(cap));
	CHERIBSDTEST_VERIFY2(cheri_equal_exact(cheri_cleartag(pp[last_index]),
	    cap), "Mismatch in non-tag bits of first capability");

	finish_child(pid);

	cheribsdtest_success();
}
