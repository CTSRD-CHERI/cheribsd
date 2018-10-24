/*-
 * Copyright (c) 2014, 2017 Robert N. M. Watson
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

#ifndef _LIBCHERI_SYSTEM_H_
#define	_LIBCHERI_SYSTEM_H_

#include <sys/syscall.h>

#include <stdarg.h>

#include <cheri/libcheri_system_md.h>

#if !__has_feature(capabilities)
#error "This code requires a CHERI-aware compiler"
#endif

/*
 * For now, expose the symbol for the system-object reference in each sandbox
 * as a public symbol.  At some point we will want to find a better way to do
 * this.
 */
extern struct cheri_object _libcheri_system_object;

#ifdef LIBCHERI_SYSTEM_INTERNAL
#define LIBCHERI_SYSTEM_CCALL					\
    __attribute__((cheri_ccallee))				\
    __attribute__((cheri_method_class(_libcheri_system_object)))
#else
#define LIBCHERI_SYSTEM_CCALL					\
    __attribute__((cheri_ccall))				\
    __attribute__((cheri_method_suffix("_cap")))		\
    __attribute__((cheri_method_class(_libcheri_system_object)))
#endif

/*
 * This header defines the interface for the libcheri system class.
 * Currently, it is a bit catch-all, and provides a few key service that make
 * it easy to implement (and debug) sandboxed code.  In the future, we
 * anticipate the system class being an entry point to a number of other
 * classes -- e.g., providing an open() method that returns file-descriptor
 * objects.  We are definitely not yet at that point.
 */

/*
 * Interface used to allocate system objects for specific sandboxes.
 *
 * XXXRW: This should probably be private to libcheri.
 */
struct sandbox_object;
int	libcheri_system_new(struct sandbox_object *sbop,
	    struct sandbox_object **sbopp);

/*
 * Methods themselves.
 */
LIBCHERI_SYSTEM_CCALL
int	libcheri_system_helloworld(void);
LIBCHERI_SYSTEM_CCALL
int	libcheri_system_puts(const char * __capability str);
LIBCHERI_SYSTEM_CCALL
int	libcheri_system_putchar(int c);
LIBCHERI_SYSTEM_CCALL
int	libcheri_system_clock_gettime(clockid_t clock_id,
	    struct timespec * __capability tp);
LIBCHERI_SYSTEM_CCALL
int	libcheri_system_calloc(size_t number, size_t size,
	    void * __capability * __capability ptrp);
LIBCHERI_SYSTEM_CCALL
int	libcheri_system_free(void * __capability ptr);
LIBCHERI_SYSTEM_CCALL
register_t	libcheri_system_user_call_fn(register_t methodnum,
		    register_t a0, register_t a1, register_t a2,
		    register_t a3, register_t a4, register_t a5,
		    register_t a6,
		    void * __capability c3, void * __capability c4,
		    void * __capability c5, void * __capability c6,
		    void * __capability c7);

/*
 * XXXRW: Probably should be library-private: the CHERI type of the system
 * library.
 */
extern void * __capability	libcheri_system_type;

typedef int(*libcheri_syscall_check_t)(int *ret, int * __capability stub_errno);
extern libcheri_syscall_check_t libcheri_syscall_checks[SYS_MAXSYSCALL];

/*
 * Vtable for cheri_system methods.
 */
extern vm_offset_t * __capability	libcheri_system_vtable;

#define SYS_STUB(_num, _ret, _sys,					\
    _protoargs, _protoargs_chk, _protoargs_err,				\
    _callargs, _callargs_chk, _callargs_err, _localcheck)		\
    LIBCHERI_SYSTEM_CCALL _ret __libcheri_system_sys_##_sys _protoargs_err;
#define SYS_STUB_ARGHASPTRS	SYS_STUB
#define SYS_STUB_VA(_num, _ret, _sys, _lastarg,				\
    _protoargs, _vprotoargs, _protoargs_chk, _protoargs_err,		\
    _callargs, _callargs_chk, _callargs_err, _localcheck)		\
    LIBCHERI_SYSTEM_CCALL _ret __libcheri_system_sys_##_sys _protoargs_err;

#include <compat/cheriabi/cheriabi_sysstubs.h>

#undef SYS_STUB
#undef SYS_STUB_ARGHASPTRS
#undef SYS_STUB_VA

#endif /* !_LIBCHERI_SYSTEM_H_ */
