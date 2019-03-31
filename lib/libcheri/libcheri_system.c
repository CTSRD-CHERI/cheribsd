/*-
 * Copyright (c) 2014-2017 Robert N. M. Watson
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

#include <sys/syscall.h>

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "libcheri_enter.h"
#define LIBCHERI_SYSTEM_INTERNAL
#include "libcheri_system.h"
#include "libcheri_type.h"

#include "libcheri_sandbox.h"
#include "libcheri_sandbox_internal.h"

/*
 * This C file implements the CHERI system class.  Currently, pretty
 * minimalist.  Sandbox object instances are created by sandbox_object_new()
 * as required, one per loaded sandbox object.
 */
static struct cheri_object null_object;

LIBCHERI_CLASS_DECL(libcheri_system);

/*
 * Construct a new CHERI system object for use with a specific sandbox object.
 */
int
libcheri_system_new(struct sandbox_object *sbop,
    struct sandbox_object **sbopp)
{
	void * __capability invoke_pcc;

	/*
	 * Construct an object capability for the system-class instance that
	 * will be passed into the sandbox.
	 *
	 * The private data pointer is to the sandbox object that this system
	 * object serves.
	 *
	 * The code capability will simply be our $pcc.
	 *
	 * XXXRW: For now, we will populate $c0 with $pcc on invocation, so we
	 * need to leave a full set of permissions on it.  Eventually, we
	 * would prefer to limit this to LOAD and EXECUTE.
	 *
	 * XXXRW: We should do this once per class .. or even just once
	 * globally, rather than on every object creation.
	 *
	 * XXXRW: Use cheri_codeptr() here in the future?
	 *
	 * XXXRW: Is this up-to-date?
	 *
	 * Set up vector pointer, remove sealing, point at tranpoline?
	 */
	invoke_pcc = cheri_getpcc();
	invoke_pcc = cheri_setaddress(
	    invoke_pcc, (register_t)LIBCHERI_CLASS_ENTRY(libcheri_system));

	return (sandbox_object_new_system_object(
	    (__cheri_tocap void * __capability)(void *)sbop, invoke_pcc,
	    libcheri_system_vtable, sbopp));
}

/*
 * Just a test function.
 */
int
libcheri_system_helloworld(void)
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
libcheri_system_puts(const char * __capability str)
{

	for (; *str != '\0'; str++) {
		if (putchar(*str) == EOF)
			return (EOF);
	}
	putchar('\n');
	return (1);
}

int
libcheri_system_putchar(int c)
{

	return (putchar(c));
}

int
libcheri_system_clock_gettime(clockid_t clock_id,
    struct timespec * __capability tp)
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
libcheri_system_calloc(size_t count, size_t size,
    void * __capability * __capability ptrp)
{
	void * __capability ptr;

	if ((ptr = calloc_c(count, size)) == NULL)
		return (-1);
	*ptrp = ptr;
	return (0);
}

int
libcheri_system_free(void * __capability ptr)
{

	free_c(ptr);
	return (0);
}

static libcheri_system_user_fn_t	libcheri_system_user_fn_ptr;

/*
 * Allow the application to register its own methods.
 */
void
libcheri_system_user_register_fn(libcheri_system_user_fn_t fn_ptr)
{

	libcheri_system_user_fn_ptr = fn_ptr;
}

/*
 * Call a legacy user function.
 */
register_t
libcheri_system_user_call_fn(register_t methodnum,
    register_t a0, register_t a1, register_t a2, register_t a3,
    register_t a4, register_t a5, register_t a6,
    void * __capability c3, void * __capability c4, void * __capability c5,
    void * __capability c6, void * __capability c7)
{

	if (methodnum >= CHERI_SYSTEM_USER_BASE &&
	    methodnum < CHERI_SYSTEM_USER_CEILING &&
	    libcheri_system_user_fn_ptr != NULL)
		return (libcheri_system_user_fn_ptr(null_object,
		    methodnum,
		    a0, a1, a2, a3, a4, a5, a6, 0,
		    c3, c4, c5, c6, c7));
	return (-1);
}

static int
libcheri_syscall_allow(void)
{

	return (1);
}

libcheri_syscall_check_t libcheri_syscall_checks[SYS_MAXSYSCALL] = {
	[SYS_issetugid] = (libcheri_syscall_check_t)libcheri_syscall_allow,
};

/*
 * Generate stubs for all syscalls with stub macros.
 */
#define SYS_STUB(_num, _ret, _sys, \
    _protoargs, _protoargs_chk, _protoargs_err,				\
    _callargs, _callargs_chk, _callargs_err, _localcheck)		\
_ret _sys _protoargs;							\
_ret									\
__libcheri_system_sys_##_sys _protoargs_err				\
{									\
	_ret ret;							\
	int(*checkfunc)_protoargs_chk;					\
									\
	checkfunc = (int(*)_protoargs_chk)libcheri_syscall_checks[_num];\
	if (checkfunc == NULL) {					\
		*stub_errno = ENOSYS;					\
		return ((_ret)-1);					\
	} else {							\
		if (checkfunc _callargs_chk != 0)			\
			return ret;					\
	}								\
									\
	errno = *stub_errno;						\
	ret = _sys _callargs;						\
	*stub_errno = errno;						\
									\
	return (ret);							\
}

#ifdef __CHERI_PURE_CAPABILITY__
#define SYS_STUB_ARGHASPTRS(...)	SYS_STUB(__VA_ARGS__)
#else
#define SYS_STUB_ARGHASPTRS(_num, _ret, _sys,				\
   _protoargs, _protoargs_chk, _protoargs_err,				\
   _callargs, _callargs_chk, _callargs_err, _localcheck)		\
_ret _sys _protoargs;							\
_ret									\
__libcheri_system_sys_##_sys _protoargs_err				\
{									\
									\
	*stub_errno = ENOSYS;						\
									\
	return (-1);							\
}
#endif

/*
 * Varargs syscalls must declare an _v<sys> stub that takes a va_list.
 */
#define SYS_STUB_VA(_num, _ret, _sys, _lastarg,				\
    _protoargs, _vprotoargs, _protoargs_chk,  _protoargs_err,		\
    _callargs, _callargs_chk, _callargs_err, _localcheck)		\
_ret __sys_##_sys _protoargs;						\
_ret									\
__libcheri_system_sys_##_sys _protoargs_err				\
{									\
	_ret ret;							\
	int(*checkfunc)_protoargs_chk;					\
									\
	checkfunc = (int(*)_protoargs_chk)libcheri_syscall_checks[_num];\
	if (checkfunc == NULL) {					\
		*stub_errno = ENOSYS;					\
		return ((_ret)-1);					\
	} else {							\
		if (checkfunc _callargs_chk != 0)			\
			return ret;					\
	}								\
									\
	errno = *stub_errno;						\
	ret = __sys_##_sys _callargs;					\
	*stub_errno = errno;						\
									\
	return (ret);							\
}

#ifndef __CHERI_PURE_CAPABILITY__
/* Suppress complaints about unused parameters in noop SYS_STUB_ARGHASPTRS */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#endif

#include <compat/cheriabi/cheriabi_sysstubs.h>

#ifndef __CHERI_PURE_CAPABILITY__
#pragma clang diagnostic pop
#endif

#undef SYS_STUB
#undef SYS_STUB_ARGHASPTRS
#undef SYS_STUB_VA
