/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 1998 John D. Polstra
 * All rights reserved.
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

#if !defined(IN_LIBDL) || defined(PIC)

/*
 * Linkage to services provided by the dynamic linker.
 */
#include <sys/mman.h>
#ifdef __CHERI_PURE_CAPABILITY__
#include <cheri/cheric.h>
#endif
#include <assert.h>
#include <dlfcn.h>
#include <link.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "namespace.h"
#include <pthread.h>
#include "un-namespace.h"
#include "libc_private.h"

static char sorry[] = "Service unavailable";

void _rtld_thread_init(void *);
void _rtld_atfork_pre(int *);
void _rtld_atfork_post(int *);

/*
 * For ELF, the dynamic linker directly resolves references to its
 * services to functions inside the dynamic linker itself.  These
 * weak-symbol stubs are necessary so that "ld" won't complain about
 * undefined symbols.  The stubs are executed only when the program is
 * linked statically, or when a given service isn't implemented in the
 * dynamic linker.  They must return an error if called, and they must
 * be weak symbols so that the dynamic linker can override them.
 */

#pragma weak _rtld_error
void
_rtld_error(const char *fmt __unused, ...)
{
	va_list ap;

	va_start(ap, fmt);
	/*
	 * XXXAR: Don't print these messages during kyua tests since it
	 * breaks tests that assume empty stderr
	*/
	if (!getenv("__RUNNING_INSIDE_ATF_RUN")) {
		vfprintf(stderr, fmt, ap);
		fputc('\n', stderr);
	}
	va_end(ap);
}

#if 0
#define PRINT_FUNCTION_NOT_AVAILABLE()	\
	_rtld_error("%s: %s is not available when statically linked.", \
	    getprogname(), __func__)
#else
#define PRINT_FUNCTION_NOT_AVAILABLE()	dlerror()
#endif

#pragma weak dladdr
int
dladdr(const void *addr __unused, Dl_info *dlip __unused)
{

	PRINT_FUNCTION_NOT_AVAILABLE();
	return (0);
}

#pragma weak dlclose
int
dlclose(void *handle __unused)
{

	PRINT_FUNCTION_NOT_AVAILABLE();
	return (-1);
}

#pragma weak dlerror
char *
dlerror(void)
{

	return (sorry);
}

#pragma weak dllockinit
void
dllockinit(void *context,
    void *(*lock_create)(void *context) __unused,
    void (*rlock_acquire)(void *lock) __unused,
    void (*wlock_acquire)(void *lock) __unused,
    void (*lock_release)(void *lock) __unused,
    void (*lock_destroy)(void *lock) __unused,
    void (*context_destroy)(void *context) __unused)
{

	if (context_destroy != NULL)
		context_destroy(context);
}

#pragma weak dlopen
void *
dlopen(const char *name __unused, int mode __unused)
{

	PRINT_FUNCTION_NOT_AVAILABLE();
	return (NULL);
}

#pragma weak dlsym
void *
dlsym(void * __restrict handle __unused, const char * __restrict name __unused)
{

	PRINT_FUNCTION_NOT_AVAILABLE();
	return (NULL);
}

#pragma weak dlfunc
dlfunc_t
dlfunc(void * __restrict handle __unused, const char * __restrict name __unused)
{

	PRINT_FUNCTION_NOT_AVAILABLE();
	return (NULL);
}

#pragma weak dlvsym
void *
dlvsym(void * __restrict handle __unused, const char * __restrict name __unused,
    const char * __restrict version __unused)
{

	PRINT_FUNCTION_NOT_AVAILABLE();
	return (NULL);
}

#pragma weak dlinfo
int
dlinfo(void * __restrict handle __unused, int request __unused,
    void * __restrict p __unused)
{

	PRINT_FUNCTION_NOT_AVAILABLE();
	return (0);
}

#pragma weak _rtld_thread_init
void
_rtld_thread_init(void *li __unused)
{

	/* Do nothing when linked statically. */
}

#ifndef IN_LIBDL
static pthread_once_t dl_phdr_info_once = PTHREAD_ONCE_INIT;
static struct dl_phdr_info phdr_info;

static void
dl_init_phdr_info(void)
{
	Elf_Auxinfo *auxp;
	unsigned int i;

	for (auxp = __elf_aux_vector; auxp->a_type != AT_NULL; auxp++) {
		switch (auxp->a_type) {
		case AT_BASE:
			phdr_info.dlpi_addr =
#ifdef __CHERI_PURE_CAPABILITY__
			    (uintptr_t)(Elf_Addr)auxp->a_un.a_ptr;
			assert(phdr_info.dlpi_addr == 0 &&
			    "Should be zero for static binaries");
#else
			    (Elf_Addr)auxp->a_un.a_ptr;
#endif
			break;
		case AT_EXECPATH:
			phdr_info.dlpi_name = (const char *)auxp->a_un.a_ptr;
			break;
		case AT_PHDR:
			phdr_info.dlpi_phdr =
#ifdef __CHERI_PURE_CAPABILITY__
			    /* XXXAR: currently needs load_cap for libunwind */
			    (const Elf_Phdr *)cheri_andperm(auxp->a_un.a_ptr,
			        CHERI_PERM_LOAD | CHERI_PERM_LOAD_CAP);
#else
			    (const Elf_Phdr *)auxp->a_un.a_ptr;
#endif
			break;
		case AT_PHNUM:
			phdr_info.dlpi_phnum = (Elf_Half)auxp->a_un.a_val;
			break;
		}
	}
	for (i = 0; i < phdr_info.dlpi_phnum; i++) {
		if (phdr_info.dlpi_phdr[i].p_type == PT_TLS) {
			phdr_info.dlpi_tls_modid = 1;
			phdr_info.dlpi_tls_data =
#ifndef __CHERI_PURE_CAPABILITY__
			    (void*)phdr_info.dlpi_phdr[i].p_vaddr;
#else
			    cheri_setbounds(cheri_setaddress(phdr_info.dlpi_phdr,
				phdr_info.dlpi_phdr[i].p_vaddr),
				phdr_info.dlpi_phdr[i].p_filesz);

#endif
		}
	}
	phdr_info.dlpi_adds = 1;
}
#endif

#pragma weak dl_iterate_phdr
int
dl_iterate_phdr(int (*callback)(struct dl_phdr_info *, size_t, void *) __unused,
    void *data __unused)
{

#ifndef IN_LIBDL
	__init_elf_aux_vector();
	if (__elf_aux_vector == NULL)
		return (1);
	_once(&dl_phdr_info_once, dl_init_phdr_info);
	return (callback(&phdr_info, sizeof(phdr_info), data));
#else
	return (0);
#endif
}

#pragma weak fdlopen
void *
fdlopen(int fd __unused, int mode __unused)
{

	PRINT_FUNCTION_NOT_AVAILABLE();
	return (NULL);
}

#pragma weak _rtld_atfork_pre
void
_rtld_atfork_pre(int *locks __unused)
{
}

#pragma weak _rtld_atfork_post
void
_rtld_atfork_post(int *locks __unused)
{
}

#pragma weak _rtld_addr_phdr
int
_rtld_addr_phdr(const void *addr __unused,
    struct dl_phdr_info *phdr_info_a __unused)
{

	return (0);
}

#pragma weak _rtld_get_stack_prot
int
_rtld_get_stack_prot(void)
{

	return (PROT_EXEC | PROT_READ | PROT_WRITE);
}

#pragma weak _rtld_is_dlopened
int
_rtld_is_dlopened(void *arg __unused)
{

	return (0);
}

#endif /* !defined(IN_LIBDL) || defined(PIC) */
