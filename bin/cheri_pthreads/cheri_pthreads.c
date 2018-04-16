/*-
 * Copyright (c) 2016 Alex Richardson
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

#include <sys/types.h>

#if !__has_feature(capabilities)
#error "This code requires a CHERI-aware compiler"
#endif

#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>


struct thread_args {
	int num;
};

static pthread_mutex_t global_mutex;

static inline vaddr_t
read_tls_register(void) {
	vaddr_t tls = 0;
	__asm__ volatile("rdhwr %0, $29\n" : "=r"(tls));
	return tls;
}

static __thread volatile int thread_local_var = -2;
static __thread volatile struct thread_args* thread_local_args = NULL;
static __thread volatile int thread_can_exit = 0;

static void *
thread_func(void *_arg)
{
	int result;
	int tlsval;
	struct thread_args *arg = _arg;

	fprintf(stderr, "Thread %d started!\n", arg->num);
	pthread_t self = pthread_self();
	fprintf(stderr, "Thread %d pthread_self() = %#p\n", arg->num, self);
	fprintf(stderr, " TLS register for thread %d: 0x%lx\n", arg->num,
	    read_tls_register());

	tlsval = thread_local_var;
	fprintf(stderr, "Value of thread local var for thread %d is %d (should"
	    " be -2)\n", arg->num, tlsval);
	// Store to the variable
	thread_local_var = arg->num;
	tlsval = thread_local_var;
	fprintf(stderr, "New value of thread local var for thread %d is %d"
	    " (should be %d)\n", arg->num, tlsval, arg->num);
	thread_local_args = arg;


	if ((result = pthread_mutex_lock(&global_mutex)) != 0) {
		errc(1, result, "pthread_mutex_lock");
	}
	fprintf(stderr, "Thread %d got mutex\n", arg->num);
	if ((result = pthread_mutex_unlock(&global_mutex)) != 0) {
		errc(1, result, "pthread_mutex_unlock");
	}


	fprintf(stderr, "Thread %d finished\n", arg->num);

	/* Wait up to 3 seconds for a signal to be delivered */
	unsigned waited = 0;
	while (waited < 3000) {
		if (thread_can_exit)
			break;
		usleep(50000);
		waited += 50;
		pthread_yield();
	}
	if (waited >= 3000) {
		fprintf(stderr, "Thread %d did not receive signal!\n", arg->num);
		pthread_exit(NULL);
	}
	errno = arg->num;
	fprintf(stderr, "Thread %d set errno to %d\n", arg->num, errno);
	fprintf(stderr, "Thread %d finished\n", arg->num);
	return arg;
}

static volatile int* segv_pointer = NULL;
static volatile _Bool signal_expected = 0;
static int good_value = 42;

#define sighandler_puts(str) write(STDERR_FILENO, str, strlen(str));

static void signal_handler(int sig) {
	(void)sig;
	sighandler_puts("Main thread signal handler triggered!\n")
	if (!signal_expected) {
		sighandler_puts("Signal was not expected!\n")
		abort();
	}
	signal_expected = 0;
	segv_pointer = &good_value;
}

static void thread_signal_handler(int sig) {
	if (sig != SIGUSR1)
		abort();
	/* We can't call snprintf() in a signal handler */
	char msg[] = "Thread ? SIGUSR1 handler triggered!\n";
	int num = thread_local_args ? thread_local_args->num : -1;
	if (num > 0 && num < 10)
		msg[strlen("Thread ")] = '0' + num;
	sighandler_puts(msg);
	thread_can_exit = 1;
}

int
main(void)
{
	pthread_t thread1;
	pthread_t thread2;
	pthread_t self;
	struct thread_args t1args;
	struct thread_args t2args;
        struct thread_args *retval;
	int result;

	t1args.num = 1;
	t2args.num = 2;
	fprintf(stderr, "About to start cheri_pthreads\n");
	self = pthread_self();
	fprintf(stderr, "Main thread is %p\n", self);
	fprintf(stderr, "TLS register for main thread: 0x%lx\n",
	    read_tls_register());

	if ((result = pthread_mutex_init(&global_mutex, NULL)) != 0) {
		errc(1, result, "pthread_mutex_init");
	}
	fprintf(stderr, "Global mutex initialized\n");
	if ((result = pthread_mutex_lock(&global_mutex)) != 0) {
		errc(1, result, "pthread_mutex_lock");
	}
	fprintf(stderr, "Main thread locked global mutex\n");
	if ((result = pthread_mutex_unlock(&global_mutex)) != 0) {
		errc(1, result, "pthread_mutex_unlock");
	}
	fprintf(stderr, "Main thread unlocked global mutex\n");
	fprintf(stderr, "About to spawn threads\n");
	if ((result = pthread_create(&thread1, NULL, thread_func, &t1args)) != 0) {
		errc(1, result, "pthread_create 1");
	}
	fprintf(stderr, "Thread 1 created: %#p\n", thread1);
	if ((result = pthread_create(&thread2, NULL, thread_func, &t2args)) != 0) {
		errc(1, result, "pthread_create 2");
	}
	fprintf(stderr, "Thread 2 created: %#p\n", thread2);
	/* TODO: pthread_cond_wait, etc... */


	fprintf(stderr, "Registering SIGUSR1 handler\n");
	if (signal(SIGUSR1, thread_signal_handler) == SIG_ERR)
		err(EX_OSERR, "signal() failed!");

#if 0
	pthread_yield(); /* give other threads a chance to run */
#endif

	/* wait for the first thread to finish */
	fprintf(stderr, "Main thread %p waiting for thread 1 (%p) to join\n",
		    self, thread1);
	if ((result = pthread_kill(thread1, SIGUSR1)) != 0) {
		errc(1, result, "pthread_kill(t1, SIGUSR1)");
	}
	if ((result = pthread_join(thread1, (void**)&retval)) != 0) {
		errc(1, result, "pthread_join t1");
	}
	fprintf(stderr, "Thread 1 joined!\n");
        if (retval != &t1args) {
		errx(EX_DATAERR, "pthread_join t1 returned wrong value: "
		    "%#p instead of %#p", retval, &t1args);
	}
	fprintf(stderr, "Main thread %p waiting for thread 2 (%p) to join\n",
	    self, thread2);
	if ((result = pthread_kill(thread2, SIGUSR1)) != 0) {
		errc(1, result, "pthread_kill(t2, SIGUSR1)");
	}
	if ((result = pthread_join(thread2, (void**)&retval)) != 0) {
		errc(1, result, "pthread_join t2");
	}
        if (retval != &t2args) {
		errx(EX_DATAERR, "pthread_join t2 returned wrong value: "
		    "%#p instead of %#p", retval, &t2args);
	}
	fprintf(stderr, "Thread 2 joined!\n");
	/* Check that malloc and free still work: */
	char* s = strdup("Hello, World!");
	if (strcmp(s, "Hello, World!") != 0) {
		errx(EX_DATAERR, "malloc broken!");
	}
	s = realloc(s, 100);
	if (strcmp(s, "Hello, World!") != 0) {
		errx(EX_DATAERR, "realloc broken!");
	}
	free((void*)s);
	fprintf(stderr, "Finished main thread %p\n", pthread_self());

	fprintf(stderr, "Triggering SIGHUP to test signal handlers:\n");
	signal_expected = 1;
	if (signal(SIGHUP, signal_handler) == SIG_ERR)
		err(EX_OSERR, "signal() failed!");
	raise(SIGHUP);
	/* The SIGHUP handler should update this value so that it is not NULL! */
	if (!segv_pointer || *segv_pointer != 42)
		err(EX_DATAERR, "Signal handler not triggered?");
	fprintf(stderr, "SIGHUP handled successfully.\n");
	return 0;
}
