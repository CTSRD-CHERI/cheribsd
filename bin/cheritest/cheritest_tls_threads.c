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

#include "cheritest.h"

/*
 * Tests to ensure that Thread-Local Storage (TLS) works as expected.
 */
#ifdef CHERI_DYNAMIC_TESTS
extern __thread int tls_gd;
extern __thread int tls_ld;
__thread int tls_gd __attribute__((tls_model("global-dynamic"))) = 1;
__thread int tls_ld __attribute__((tls_model("local-dynamic"))) = 2;
#endif
extern __thread int tls_ie;
extern __thread int tls_le;
__thread int tls_ie __attribute__((tls_model("initial-exec"))) = 3;
__thread int tls_le __attribute__((tls_model("local-exec"))) = 4;

#ifdef CHERI_DYNAMIC_TESTS
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
#ifdef CHERI_DYNAMIC_TESTS
	thr_tls_gd = &tls_gd;
	++tls_gd;
	thr_tls_ld = &tls_ld;
	++tls_ld;
#endif
	thr_tls_ie = &tls_ie;
	++tls_ie;
	thr_tls_le = &tls_le;
	++tls_le;

	if (pthread_mutex_lock(&lock) != 0)
		cheritest_failure_err("pthread_mutex_lock");
	thread_done = 1;
	if (pthread_cond_broadcast(&cond) != 0)
		cheritest_failure_err("pthread_cond_broadcast");

	// We have not yet released the lock, so no need to check before
	// waiting.
	do {
		if (pthread_cond_wait(&cond, &lock) != 0)
			cheritest_failure_err("pthread_cond_wait");
	} while (thread_done == 1);
	if (pthread_mutex_unlock(&lock) != 0)
		cheritest_failure_err("pthread_mutex_unlock");

	return NULL;
}

void
test_tls_threads(const struct cheri_test *ctp __unused)
{
	pthread_t thread;
#ifdef CHERI_DYNAMIC_TESTS
	int *my_tls_gd, *my_tls_ld;
	int thr_tls_gd_val, thr_tls_ld_val;
#endif
	int *my_tls_ie, *my_tls_le;
	int thr_tls_ie_val, thr_tls_le_val;
#ifdef __CHERI_PURE_CAPABILITY__
	size_t my_bottom, my_top, thr_bottom, thr_top;
#endif

	if (pthread_create(&thread, NULL,
	    test_tls_threads_get_vars, NULL) != 0)
		cheritest_failure_err("pthread_create");

#ifdef CHERI_DYNAMIC_TESTS
	my_tls_gd = &tls_gd;
	my_tls_ld = &tls_ld;
#endif
	my_tls_ie = &tls_ie;
	my_tls_le = &tls_le;

	if (pthread_mutex_lock(&lock) != 0)
		cheritest_failure_err("pthread_mutex_lock");
	while (thread_done == 0) {
		if (pthread_cond_wait(&cond, &lock) != 0)
			cheritest_failure_err("pthread_cond_wait");
	}

#ifdef CHERI_DYNAMIC_TESTS
	thr_tls_gd_val = *thr_tls_gd;
	thr_tls_ld_val = *thr_tls_ld;
#endif
	thr_tls_ie_val = *thr_tls_ie;
	thr_tls_le_val = *thr_tls_le;

	thread_done = 2;
	if (pthread_cond_broadcast(&cond) != 0)
		cheritest_failure_err("pthread_cond_broadcast");
	if (pthread_mutex_unlock(&lock) != 0)
		cheritest_failure_err("pthread_mutex_unlock");

#ifdef CHERI_DYNAMIC_TESTS
	if (*my_tls_gd != 1)
		cheritest_failure_errx("Bad *my_tls_gd (got: %d; expected 1)",
		    *my_tls_gd);
	if (*my_tls_ld != 2)
		cheritest_failure_errx("Bad *my_tls_ld (got: %d; expected 2)",
		    *my_tls_ld);
#endif
	if (*my_tls_ie != 3)
		cheritest_failure_errx("Bad *my_tls_ie (got: %d; expected 3)",
		    *my_tls_ie);
	if (*my_tls_le != 4)
		cheritest_failure_errx("Bad *my_tls_le (got: %d; expected 4)",
		    *my_tls_le);
#ifdef CHERI_DYNAMIC_TESTS
	if (thr_tls_gd_val != 2)
		cheritest_failure_errx("Bad *thr_tls_gd (got: %d; expected 2)",
		    thr_tls_gd_val);
	if (thr_tls_ld_val != 3)
		cheritest_failure_errx("Bad *thr_tls_ld (got: %d; expected 3)",
		    thr_tls_ld_val);
#endif
	if (thr_tls_ie_val != 4)
		cheritest_failure_errx("Bad *thr_tls_ie (got: %d; expected 4)",
		    thr_tls_ie_val);
	if (thr_tls_le_val != 5)
		cheritest_failure_errx("Bad *thr_tls_le (got: %d; expected 5)",
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
		cheritest_failure_errx("Overlapping TLS capabilities "	\
		    "(my "#_var": %#p ; thread's "#_var": %#p)",	\
		    my_##_var, thr_##_var);

#ifdef CHERI_DYNAMIC_TESTS
	CHECK_DISJOINT(tls_gd);
	CHECK_DISJOINT(tls_ld);
#endif
	CHECK_DISJOINT(tls_ie);
	CHECK_DISJOINT(tls_le);
#endif

	cheritest_success();
}
