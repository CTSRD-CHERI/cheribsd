/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 Alex Richardson
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
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <machine/elf.h>
#include <stdbool.h>
#include <stdlib.h>
#include "libc_private.h"
#include "ignore_init.c"

/*
 * For -pie executables rtld will process the __cap_relocs, so we don't need
 * to include the code here.
 */
#ifndef PIC
#include "crt_init_globals.c"
#endif

struct Struct_Obj_Entry;
void _start(void *, void (*)(void), struct Struct_Obj_Entry *) __exported;

#ifdef GCRT
/* Profiling support. */
#error "GCRT should not be defined for purecap"
#endif

Elf_Auxinfo *__auxargs;

/*
 * The entry function, C part. This performs the bulk of program initialisation
 * before handing off to main().
 *
 * Note: If we want to support tight function bounds, it is important that
 * function calls and global variable accesses are only be made after
 * crt_init_globals() has completed (as this initializes the capabilities to
 * globals and functions in the captable, which is used for all function calls).
 * This restriction only applies to statically linked binaries since the dynamic
 * linker takes care of initialization otherwise.
 */
void
_start(void *auxv,
	void (*cleanup)(void),			/* from shared loader */
	struct Struct_Obj_Entry *obj)		/* from shared loader */
{
	int argc = 0;
	char **argv = NULL;
	char **env = NULL;
	const bool has_dynamic_linker = obj != NULL && cleanup != NULL;
#ifndef PIC
	const Elf_Phdr *at_phdr = NULL;
	long at_phnum = 0;
#else
	if (!has_dynamic_linker)
		__builtin_trap(); /* RTLD missing? Wrong *crt1.o linked? */
#endif

	if (cheri_getdefault() != NULL)
		__builtin_trap(); /* $ddc should be NULL */

	/*
	 * Digest the auxiliary vector for local use.
	 *
	 * Note: this file must be compile with -fno-jump-tables to avoid use
	 * of the captable before crt_init_globals() has been called.
	 */
	for (Elf_Auxinfo *auxp = auxv; auxp->a_type != AT_NULL;  auxp++) {
		if (auxp->a_type == AT_ARGV) {
			argv = (char **)auxp->a_un.a_ptr;
		} else if (auxp->a_type == AT_ENVV) {
			env = (char **)auxp->a_un.a_ptr;
		} else if (auxp->a_type == AT_ARGC) {
			argc = auxp->a_un.a_val;
#ifndef PIC
		} else if (auxp->a_type == AT_PHDR) {
			at_phdr = auxp->a_un.a_ptr;
		} else if (auxp->a_type == AT_PHNUM) {
			at_phnum = auxp->a_un.a_val;
#endif
		}
	}

	/* For -pie executables rtld will initialize the __cap_relocs */
#ifndef PIC
	/*
	 * crt_init_globals must be called before accessing any globals.
	 *
	 * Note: We parse the phdrs to ensure that the global data cap does
	 * not span the readonly segment or text segment.
	 */
	if (!has_dynamic_linker)
		crt_init_globals(at_phdr, at_phnum, NULL, NULL, NULL);
#endif
	/* We can access global variables/make function calls now. */

	__auxargs = auxv; /* Store the global auxargs pointer */

	handle_argv(argc, argv, env);

	if (cleanup != NULL)
		atexit(cleanup);
	else
		_init_tls();

	handle_static_init(argc, argv, env);

	exit(main(argc, argv, env));
}
