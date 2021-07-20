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
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "cheribsdtest.h"

/*
 * A series of tests that ensure that tagged values aren't carried over
 * various streaming IPC mechanisms.
 *
 * TODO:
 * - POSIX and System V message queues
 * - Datagram local and inet sockets
 * - Possibly exercise more message sizes ..?
 */
static void
ipc_pipe_create(int *fds)
{
	int error;

	error = pipe(fds);
	if (error < 0)
		cheribsdtest_failure_err("pipe()");
}

static void
ipc_socket_local_stream_create(int *fds)
{
	int error;

	error = socketpair(PF_LOCAL, SOCK_STREAM, 0, fds);
	if (error < 0)
		cheribsdtest_failure_err("socketpair(PF_LOCAL, SOCK_STREAM)");
}

static void
ipc_socket_tcp_stream_create(int *fds)
{
	struct sockaddr_in sin;
	int accept_sock, conn_sock, listen_sock;
	socklen_t socklen;

	listen_sock = CHERIBSDTEST_CHECK_SYSCALL(socket(PF_INET, SOCK_STREAM,
	    0));

	/* Bind an automatically allocated port; query and connect to it. */
	bzero(&sin, sizeof(sin));
	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;
	sin.sin_port = 0;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	CHERIBSDTEST_CHECK_SYSCALL(bind(listen_sock, (struct sockaddr *)&sin,
	    sizeof(sin)));
	CHERIBSDTEST_CHECK_SYSCALL(listen(listen_sock, -1));
	socklen = sizeof(sin);
	CHERIBSDTEST_CHECK_SYSCALL(getsockname(listen_sock,
	    (struct sockaddr *)&sin, &socklen));
	CHERIBSDTEST_CHECK_EQ_SIZE(socklen, sizeof(sin));
	conn_sock = CHERIBSDTEST_CHECK_SYSCALL(socket(PF_INET, SOCK_STREAM,
	    0));
	CHERIBSDTEST_CHECK_SYSCALL(connect(conn_sock, (struct sockaddr *)&sin,
	    sizeof(sin)));
	accept_sock = CHERIBSDTEST_CHECK_SYSCALL(accept(listen_sock, NULL,
	    NULL));
	fds[0] = conn_sock;
	fds[1] = accept_sock;
	close(listen_sock);
}

/*
 * Perform a test, sending the tagged pointer over the provided file
 * descriptor pair and checking various properties on the other side.  Pad the
 * pointer out to various sizes, triggering (or not) various optimizations.
 *
 * Because we want to exercise pipe()'s VM optimisations, we have to use not
 * just blocking file-descriptor I/O, but also synchronous writes.
 * Specifically, the sender thread blocks until the receive has received, so
 * as to avoid needing copy-on-write -- but as a result we can't use the same
 * thread to send and receive despite buffering.
 *
 * To avoid utilising threading, which changes other aspects of the process
 * execution environment, we fork a process to perform the send, and then do
 * the receive in the parent process that is running the test.
 *
 * Doesn't return.
 */
static int pointed_to;
static void
ipc_test_tagsend_pointer(int *fds, size_t bufferlen)
{
	int * __capability pointer_tosend =
	    (__cheri_tocap void * __capability)&pointed_to;
	int * __capability pointer_received;
	void *buffer;
	ssize_t len;
	pid_t pid;
	int status;

	/* Quick self check to make sure we start with a tagged pointer. */
	if (!cheri_gettag(pointer_tosend))
		cheribsdtest_failure_errx(
		    "pointer_tosend untagged before write");

	/* Self check on minimum buffer size. */
	if (bufferlen < sizeof(pointer_tosend))
		cheribsdtest_failure_errx("buffer too small");

	buffer = malloc(bufferlen);
	if (buffer == NULL)
		cheribsdtest_failure_err("malloc");
	bzero(buffer, bufferlen);
	*(void * __capability *)buffer =
	    (__cheri_tocap void * __capability)pointer_tosend;

	pid = CHERIBSDTEST_CHECK_SYSCALL(fork());
	if (pid == 0) {
		/*
		 * Child process.  Perform the write and immediately exit.
		 * The parent will hold both pipe endpoints open.
		 */
		len = CHERIBSDTEST_CHECK_SYSCALL(write(fds[0], buffer,
		    bufferlen));
		CHERIBSDTEST_CHECK_EQ_SIZE(len, bufferlen);
		exit(0);
	}

	/*
	 * For simplicity, assume arrives in a single read.  Should be true
	 * in practice, but isn't really a correct assumption for IPC.
	 */
	len = CHERIBSDTEST_CHECK_SYSCALL(read(fds[1], buffer, bufferlen));
	CHERIBSDTEST_CHECK_EQ_SIZE(len, bufferlen);
	pointer_received = *(void * __capability *)buffer;

	/*
	 * Bytewise comparison of visible data.
	 */
	if (memcmp(&pointer_tosend, &pointer_received,
	    sizeof(pointer_tosend)))
		cheribsdtest_failure_errx("pointer value mismatch");

	/*
	 * Check tag.
	 */
	if (cheri_gettag(pointer_received))
		cheribsdtest_failure_errx("received tagged pointer value");

	close(fds[0]);
	close(fds[1]);
	free(buffer);

	/*
	 * Pick up the pieces from the child, which actually closes the IPC
	 * channel on exit.
	 */
	CHERIBSDTEST_CHECK_SYSCALL(waitpid(pid, &status, 0));
	if (!WIFEXITED(status))
		cheribsdtest_failure_errx("waitpid !WIFEXITED");
	if (WEXITSTATUS(status) != 0)
		cheribsdtest_failure_errx(
		    "child returned non-zero status (%d)",
		    WEXITSTATUS(status));

	/*
	 * Tag correctly stripped by IPC transit.
	 */
	cheribsdtest_success();
}

/*
 * In the following tests, 8KiB is selected because it is >= PIPE_MINDIRECT
 * while still <= PIPSIZ.  This means that pipe VM optimizations will trigger
 * in FreeBSD, but sockets won't overfill with default socket-buffer sizes.
 */
CHERIBSDTEST(test_ipc_pipe_capsize_tagstripped,
    "check that pipe IPC strips tags for a pointer-size write")
{
	int fds[2];

	ipc_pipe_create(fds);
	ipc_test_tagsend_pointer(fds, sizeof(int * __capability));
}

CHERIBSDTEST(test_ipc_pipe_8k_tagstripped,
    "check that pipe IPC strips tags for an 8k write")
{
	int fds[2];

	ipc_pipe_create(fds);
	ipc_test_tagsend_pointer(fds, 8192);
}

CHERIBSDTEST(test_ipc_socket_local_stream_capsize_tagstripped,
    "check that local socket IPC strips tags for a pointer-size write")
{
	int fds[2];

	ipc_socket_local_stream_create(fds);
	ipc_test_tagsend_pointer(fds, sizeof(int * __capability));
}

CHERIBSDTEST(test_ipc_socket_local_stream_8k_tagstripped,
    "check that local socket IPC strips tags for an 8k write")
{
	int fds[2];

	ipc_socket_local_stream_create(fds);
	ipc_test_tagsend_pointer(fds, 8192);
}

CHERIBSDTEST(test_ipc_socket_tcp_stream_capsize_tagstripped,
    "check that TCP socket IPC strips tags for a pointer-size write")
{
	int fds[2];

	ipc_socket_tcp_stream_create(fds);
	ipc_test_tagsend_pointer(fds, sizeof(int * __capability));
}

CHERIBSDTEST(test_ipc_socket_tcp_stream_8k_tagstripped,
    "check that TCP socket IPC strips tags for an 8k write")
{
	int fds[2];

	ipc_socket_tcp_stream_create(fds);
	ipc_test_tagsend_pointer(fds, 8192);
}
