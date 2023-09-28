/*-
 * Copyright (c) 2018 Edward Tomasz Napierala <trasz@FreeBSD.org>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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

/*
 * This is a trivial example of using coaccept(3) and cocall(3) between
 * two threads.  With processes it would work pretty much the same,
 * except it would require a mechanism to transfer the target capability
 * from service to the caller.
 */

#include <err.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

static pthread_t		service_thread;
static void * __capability	target;

static void *
service_function(void *dummy __unused)
{
	/*
	 * Can't use int here, because buffers need to be capability-aligned.
	 * This will happen naturally when using malloc(3), but for now lets keep
	 * it simple and use a capability-sized integer type instead.
	 */
	intcap_t buf = 0;
	ssize_t received;
	int error;

	/*
	 * Every thread needs to do this once before calling coaccept(2).
	 */
	error = cosetup(COSETUP_COACCEPT);
	if (error != 0)
		err(1, "cosetup");

	/*
	 * Ask kernel for the target capability to call into this thread;
	 * the `target` is a global variable, to be used by the calling thread.
	 */
	error = coregister(NULL, &target);
	if (error != 0)
		err(1, "coregister");

	/*
	 * Now loop until the process exits.
	 */
	for (;;) {
		/*
		 * Send back the response, if any, then wait for next caller.
		 */
		received = coaccept(NULL, &buf, sizeof(buf), &buf, sizeof(buf));
		if (received < 0)
			err(1, "cocall");

		/*
		 * Got a call, bump the counter and loop.
		 */
		printf("accepted, counter is %d\n", (int)buf);
		buf++;
	}
}

int
main(int argc __unused, char **argv __unused)
{
	intcap_t buf = 0;
	ssize_t received;
	int error, i;

	/*
	 * Create the thread to wait on coaccept(2).
	 */
	error = pthread_create(&service_thread, NULL, service_function, NULL);
	if (error != 0)
		err(1, "pthread_create");

	/*
	 * Give the service thread a moment to start coaccepting before we proceed;
	 * otherwise cocall(3) might fail with EAGAIN.
	 */
	usleep(1000);

	/*
	 * Every thread needs to do this once before calling cocall(2).
	 * Call it twice if it needs both coaccept(2) and cocall(2).
	 */
	error = cosetup(COSETUP_COCALL);
	if (error != 0)
		err(1, "cosetup");

	/*
	 * Do the thing a couple of times.
	 */
	for (i = 3; i > 0; i--) {
		printf("calling %lp...\n", target);
		received = cocall(target, &buf, sizeof(buf), &buf, sizeof(buf));
		if (received < 0)
			err(1, "cocall");
		printf("returned, counter is %d\n", (int)buf);
	}

	/*
	 * Exit.
	 */
	return (0);
}
