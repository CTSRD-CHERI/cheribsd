/*-
 * Copyright (c) 2018 Jessica Clarke
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

#include <sys/cdefs.h>

#if !__has_feature(capabilities)
#error "This code requires a CHERI-aware compiler"
#endif

#include <sys/types.h>

#include <cheri/cheri.h>

#include <pthread.h>
#include <string.h>

#include "cheribsdtest.h"

/*
 * Tests to ensure that Thread-Local Storage (TLS) works as expected.
 */
#ifdef CHERIBSD_DYNAMIC_TESTS
extern __thread int tls_gd;
extern __thread int tls_ld;
__thread int tls_gd __attribute__((tls_model("global-dynamic"))) = 1;
__thread int tls_ld __attribute__((tls_model("local-dynamic"))) = 2;
#endif
extern __thread int tls_ie;
extern __thread int tls_le;
__thread int tls_ie __attribute__((tls_model("initial-exec"))) = 3;
__thread int tls_le __attribute__((tls_model("local-exec"))) = 4;

#ifdef CHERIBSD_DYNAMIC_TESTS
extern int *thr_tls_gd;
extern int *thr_tls_ld;
int *thr_tls_gd;
int *thr_tls_ld;
#endif
extern int *thr_tls_ie;
extern int *thr_tls_le;
int *thr_tls_ie;
int *thr_tls_le;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static int thread_done;

static void *
test_tls_threads_get_vars(void *arg __unused)
{
	int error;

#ifdef CHERIBSD_DYNAMIC_TESTS
	thr_tls_gd = &tls_gd;
	++tls_gd;
	thr_tls_ld = &tls_ld;
	++tls_ld;
#endif
	thr_tls_ie = &tls_ie;
	++tls_ie;
	thr_tls_le = &tls_le;
	++tls_le;

	error = pthread_mutex_lock(&lock);
	if (error != 0)
		cheribsdtest_failure_errc(error, "pthread_mutex_lock");
	thread_done = 1;
	error = pthread_cond_broadcast(&cond);
	if (error != 0)
		cheribsdtest_failure_errc(error, "pthread_cond_broadcast");

	// We have not yet released the lock, so no need to check before
	// waiting.
	do {
		error = pthread_cond_wait(&cond, &lock);
		if (error != 0)
			cheribsdtest_failure_errc(error, "pthread_cond_wait");
	} while (thread_done == 1);
	error = pthread_mutex_unlock(&lock);
	if (error != 0)
		cheribsdtest_failure_errc(error, "pthread_mutex_unlock");

	return NULL;
}

CHERIBSDTEST(tls_threads, "Test TLS across threads")
{
	pthread_t thread;
	int error;
#ifdef CHERIBSD_DYNAMIC_TESTS
	int *my_tls_gd, *my_tls_ld;
	int thr_tls_gd_val, thr_tls_ld_val;
#endif
	int *my_tls_ie, *my_tls_le;
	int thr_tls_ie_val, thr_tls_le_val;
#ifdef __CHERI_PURE_CAPABILITY__
	size_t my_bottom, my_top, thr_bottom, thr_top;
#endif

	error = pthread_create(&thread, NULL,
	    test_tls_threads_get_vars, NULL);
	if (error != 0)
		cheribsdtest_failure_errc(error, "pthread_create");

#ifdef CHERIBSD_DYNAMIC_TESTS
	my_tls_gd = &tls_gd;
	my_tls_ld = &tls_ld;
#endif
	my_tls_ie = &tls_ie;
	my_tls_le = &tls_le;

	error = pthread_mutex_lock(&lock);
	if (error != 0)
		cheribsdtest_failure_errc(error, "pthread_mutex_lock");
	while (thread_done == 0) {
		error = pthread_cond_wait(&cond, &lock);
		if (error != 0)
			cheribsdtest_failure_errc(error, "pthread_cond_wait");
	}

#ifdef CHERIBSD_DYNAMIC_TESTS
	thr_tls_gd_val = *thr_tls_gd;
	thr_tls_ld_val = *thr_tls_ld;
#endif
	thr_tls_ie_val = *thr_tls_ie;
	thr_tls_le_val = *thr_tls_le;

	thread_done = 2;
	error = pthread_cond_broadcast(&cond);
	if (error != 0)
		cheribsdtest_failure_errc(error, "pthread_cond_broadcast");
	error = pthread_mutex_unlock(&lock);
	if (error != 0)
		cheribsdtest_failure_errc(error, "pthread_mutex_unlock");

#ifdef CHERIBSD_DYNAMIC_TESTS
	if (*my_tls_gd != 1)
		cheribsdtest_failure_errx("Bad *my_tls_gd (got: %d; expected 1)",
		    *my_tls_gd);
	if (*my_tls_ld != 2)
		cheribsdtest_failure_errx("Bad *my_tls_ld (got: %d; expected 2)",
		    *my_tls_ld);
#endif
	if (*my_tls_ie != 3)
		cheribsdtest_failure_errx("Bad *my_tls_ie (got: %d; expected 3)",
		    *my_tls_ie);
	if (*my_tls_le != 4)
		cheribsdtest_failure_errx("Bad *my_tls_le (got: %d; expected 4)",
		    *my_tls_le);
#ifdef CHERIBSD_DYNAMIC_TESTS
	if (thr_tls_gd_val != 2)
		cheribsdtest_failure_errx("Bad *thr_tls_gd (got: %d; expected 2)",
		    thr_tls_gd_val);
	if (thr_tls_ld_val != 3)
		cheribsdtest_failure_errx("Bad *thr_tls_ld (got: %d; expected 3)",
		    thr_tls_ld_val);
#endif
	if (thr_tls_ie_val != 4)
		cheribsdtest_failure_errx("Bad *thr_tls_ie (got: %d; expected 4)",
		    thr_tls_ie_val);
	if (thr_tls_le_val != 5)
		cheribsdtest_failure_errx("Bad *thr_tls_le (got: %d; expected 5)",
		    thr_tls_le_val);

#ifdef __CHERI_PURE_CAPABILITY__
#define CHECK_DISJOINT(_var)						\
	my_bottom = __builtin_cheri_base_get(my_##_var);		\
	my_top = my_bottom + __builtin_cheri_length_get(my_##_var);	\
	thr_bottom = __builtin_cheri_base_get(thr_##_var);		\
	thr_top = thr_bottom + __builtin_cheri_length_get(thr_##_var);	\
	if ((thr_bottom <=  my_bottom &&  my_bottom <  thr_top) ||	\
	    (thr_bottom <   my_top    &&  my_top    <= thr_top) ||	\
	    ( my_bottom <= thr_bottom && thr_bottom <   my_top) ||	\
	    ( my_bottom <  thr_top    && thr_top    <=  my_top))	\
		cheribsdtest_failure_errx("Overlapping TLS "		\
		    "capabilities (my "#_var": %#p ; thread's "#_var	\
		    ": %#p)", my_##_var, thr_##_var);

#ifdef CHERIBSD_DYNAMIC_TESTS
	CHECK_DISJOINT(tls_gd);
	CHECK_DISJOINT(tls_ld);
#endif
	CHECK_DISJOINT(tls_ie);
	CHECK_DISJOINT(tls_le);

#ifdef TLS_EXACT_BOUNDS
#define	CHECK_BOUNDS(_var)						\
	if (__builtin_cheri_offset_get((_var)) != 0)			\
		cheribsdtest_failure_errx("TLS variable "#_var" with "	\
		    "non-zero offset: %#p", (_var));			\
	if (__builtin_cheri_length_get((_var)) != sizeof(*(_var)))	\
		cheribsdtest_failure_errx("TLS variable "#_var" (size " \
		    "%zu) with bad length: %#p", sizeof(*(_var)), (_var));

#ifdef CHERIBSD_DYNAMIC_TESTS
	CHECK_BOUNDS(my_tls_gd);
	CHECK_BOUNDS(my_tls_ld);
	CHECK_BOUNDS(thr_tls_gd);
	CHECK_BOUNDS(thr_tls_ld);
#endif
	CHECK_BOUNDS(my_tls_ie);
	CHECK_BOUNDS(my_tls_le);
	CHECK_BOUNDS(thr_tls_ie);
	CHECK_BOUNDS(thr_tls_le);
#endif
#endif

	cheribsdtest_success();
}
