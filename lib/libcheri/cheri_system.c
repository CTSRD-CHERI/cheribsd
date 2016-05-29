/*-
 * Copyright (c) 2014-2016 Robert N. M. Watson
 * Copyright (c) 2014 SRI International
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

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "cheri_enter.h"
#define CHERI_SYSTEM_INTERNAL
#include "cheri_system.h"
#include "cheri_type.h"

#include "sandbox.h"
#include "sandbox_internal.h"

/*
 * This C file implements the CHERI system class.  Currently, pretty
 * minimalist.
 */
__capability void		*cheri_system_type;
__capability vm_offset_t	*cheri_system_vtable;

static struct cheri_object null_object;

static __attribute__ ((constructor)) void
cheri_system_init(void)
{

	cheri_system_type = cheri_type_alloc();
}

/*
 * Just a test function.
 */
int
cheri_system_helloworld(void)
{

	printf("hello world\n");
	return (123456);
}

/*
 * Implementation of puts(), but with a capability argument.  No persistent
 * state, so no recovery required if an exception is thrown due to a bad
 * capability being passed in.
 */
int
cheri_system_puts(__capability const char *str)
{

	for (; *str != '\0'; str++) {
		if (putchar(*str) == EOF)
			return (EOF);
	}
	putchar('\n');
	return (1);
}

int
cheri_system_putchar(int c)
{

	return (putchar(c));
}

int
cheri_system_clock_gettime(clockid_t clock_id, __capability struct timespec *tp)
{
	int ret;
	struct timespec ts;

		ret = clock_gettime(clock_id, &ts);
	if (ret == 0)
		/*
		 * XXX-BD: If we have a bad TP pointer the caller should fault
		 * not the cheri_system context.
		 */
		*tp = ts;
	return (ret);
}

int
cheri_system_calloc(size_t count, size_t size,
    void __capability * __capability *ptrp)
{
	__capability void *ptr;

	if ((ptr = (__capability void *)calloc(count, size)) == NULL)
		return (-1);
	*ptrp = ptr;
	return (0);
}

int
cheri_system_free(__capability void *ptr)
{

	free((void *)ptr);
	return (0);
}

static cheri_system_user_fn_t	cheri_system_user_fn_ptr;

/*
 * Allow the application to register its own methods.
 */
void
cheri_system_user_register_fn(cheri_system_user_fn_t fn_ptr)
{

	cheri_system_user_fn_ptr = fn_ptr;
}

/*
 * Call a legacy user function.
 */
register_t
cheri_system_user_call_fn(register_t methodnum,
    register_t a0, register_t a1, register_t a2, register_t a3,
    register_t a4, register_t a5, register_t a6,
    __capability void *c3, __capability void *c4, __capability void *c5,
    __capability void *c6, __capability void *c7)
{

	if (methodnum >= CHERI_SYSTEM_USER_BASE &&
	    methodnum < CHERI_SYSTEM_USER_CEILING &&
	    cheri_system_user_fn_ptr != NULL)
		return (cheri_system_user_fn_ptr(null_object,
		    methodnum,
		    a0, a1, a2, a3, a4, a5, a6, 0,
		    c3, c4, c5, c6, c7));
	return (-1);
}
