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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <machine/param.h>
#include <machine/sysarch.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <err.h>
#include <pthread.h>
#include <pthread_np.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

pthread_t	service_thread;

#if 0
#define SHARED_PAGE	0x7ffffff000

static void
show_8_hex(char *p)
{
	int i;

	for (i = 0; i < 8; i++)
		fprintf(stderr, " %02x", (uint8_t)*(p + i));
}

static void
show_8_char(char *p)
{
	int i;

	for (i = 0; i < 8; i++) {
		if (isprint(p[i]))
			fprintf(stderr, "%c", p[i]);
		else
			fprintf(stderr, ".");
	}
}

static void
show_16(char *p, off_t off)
{
	fprintf(stderr, "%08lx ", off);
	show_8_hex(p);
	fprintf(stderr, " ");
	show_8_hex(p + 8);
	fprintf(stderr, "  |");
	show_8_char(p);
	show_8_char(p + 8);
	fprintf(stderr, "|\n");
}

static void
show_chunk(void *ptr, off_t off, int len)
{
	char *p;
	int i, j;
	bool just_zeroes, just_zeroes_last_time;

	p = ptr;
	just_zeroes_last_time = false;
	for (i = 0; i < len; i += 16) {
		just_zeroes = true;
		for (j = 0; j < 16; j++) {
			if (p[i + j] != 0) {
				just_zeroes = false;
				break;
			}
		}
		if (just_zeroes) {
			if (!just_zeroes_last_time)
				fprintf(stderr, "*\n");
		} else {
			show_16(p + i, off + i);
		}
		just_zeroes_last_time = just_zeroes;
	}
}
#endif

static void
call(void)
{
	void * __capability switcher_code;
	void * __capability switcher_data;
	void * __capability lookedup;
	int error;

	fprintf(stderr, "%s: setting up...\n", __func__);
	error = cosetup(COSETUP_COCALL, &switcher_code, &switcher_data);
	if (error != 0)
		err(1, "cosetup");

	fprintf(stderr, "%s: colookingup...\n", __func__);
	error = colookup("kopytko", &lookedup);
	if (error != 0)
		err(1, "colookup");

	fprintf(stderr, "%s: code %p, data %p, calling %p, we are thread %d...\n",
	    __func__, (__cheri_fromcap void *)switcher_code, (__cheri_fromcap void *)switcher_data, (__cheri_fromcap void *)lookedup, pthread_getthreadid_np());
	error = cocall(switcher_code, switcher_data, lookedup);
	fprintf(stderr, "%s: done, cocall returned %d, we are thread %d\n",
	    __func__, error, pthread_getthreadid_np());

	fprintf(stderr, "%s: code %p, data %p, calling %p, we are thread %d...\n",
	    __func__, (__cheri_fromcap void *)switcher_code, (__cheri_fromcap void *)switcher_data, (__cheri_fromcap void *)lookedup, pthread_getthreadid_np());
	error = cocall(switcher_code, switcher_data, lookedup);
	fprintf(stderr, "%s: done, cocall returned %d, we are thread %d\n",
	    __func__, error, pthread_getthreadid_np());
}

static void *
service_proc(void *dummy __unused)
{
	void * __capability switcher_code;
	void * __capability switcher_data;
	int error;

	fprintf(stderr, "%s: setting up...\n", __func__);
	error = cosetup(COSETUP_COACCEPT, &switcher_code, &switcher_data);
	if (error != 0)
		err(1, "cosetup");

	fprintf(stderr, "%s: coregistering...\n", __func__);
	error = coregister("kopytko", NULL);
	if (error != 0)
		err(1, "coregister");

	fprintf(stderr, "%s: code %p, data %p, we are thread %d, accepting...\n",
	    __func__, (__cheri_fromcap void *)switcher_code, (__cheri_fromcap void *)switcher_data, pthread_getthreadid_np());
	while (coaccept(switcher_code, switcher_data)) {
		fprintf(stderr, "%s: accepted, we are thread %d, looping...\n",
		    __func__, pthread_getthreadid_np());
	}
	fprintf(stderr, "%s: we're not supposed to be here\n", __func__);
	return (NULL);
}

int
main(int argc __unused, char **argv __unused)
{
	int error;

#if 0
	fprintf(stderr, "memory at %p:\n", (void *)SHARED_PAGE);
	show_chunk((void *)SHARED_PAGE, SHARED_PAGE, PAGE_SIZE);
#endif

	error = pthread_create(&service_thread, NULL, service_proc, NULL);
	if (error != 0)
		err(1, "pthread_create");

	sleep(1);
	call();

	return (0);
}
