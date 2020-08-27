/* LINTLIBRARY */
/*-
 * Copyright 1996-1998 John D. Polstra.
 * Copyright 2014 Andrew Turner.
 * Copyright 2014-2015 The FreeBSD Foundation.
 * Copyright 2020 Brett F. Gutstein.
 * All rights reserved.
 *
 * Portions of this software were developed by Andrew Turner
 * under sponsorship from the FreeBSD Foundation.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <stdbool.h>
#include <stdlib.h>

#include "libc_private.h"
#include "crtbrand.c"
#include "ignore_init.c"

#ifdef GCRT
extern void _mcleanup(void);
extern void monstartup(void *, void *);
extern int eprol;
extern int etext;
#endif

extern long * _end;

/* The entry function. */
__asm("	.text			\n"
"	.align	0		\n"
"	.globl	_start		\n"
"	_start:			\n"
"	mov	x3, x2		\n" /* cleanup */
"	add	x1, x0, #8	\n" /* load argv */
"	ldr	x0, [x0]	\n" /* load argc */
"	add	x2, x1, x0, lsl #3 \n" /* env is after argv */
"	add	x2, x2, #8	\n" /* argv is null terminated */
"	b	 __start  ");

/*
 * For -pie executables rtld will process capability relocations, so we don't
 * need to include the code here.
 */
#if __has_feature(capabilities) && !defined(POSITION_INDEPENDENT_STARTUP)
#define SHOULD_PROCESS_CAP_RELOCS
#endif

#ifdef SHOULD_PROCESS_CAP_RELOCS
#define DONT_EXPORT_CRT_INIT_GLOBALS
#define CRT_INIT_GLOBALS_GDC_ONLY
#include "crt_init_globals.c"

void __start(int, char **, char **, void (*)(void), const Elf_Auxinfo * __capability);

/* The entry function. */
void
__start(int argc, char *argv[], char *env[], void (*cleanup)(void), const Elf_Auxinfo * __capability auxp)
{
	const Elf_Phdr * __capability phdr_cap = NULL;
	void *phdr = NULL;
	long phnum = 0;

	/* Digest the auxiliary vector to get information needed to init globals. */
	for (; auxp->a_type != AT_NULL; auxp++) {
		if (auxp->a_type == AT_PHDR) {
			phdr = auxp->a_un.a_ptr;
		} else if (auxp->a_type == AT_PHNUM) {
			phnum = auxp->a_un.a_val;
		}
	}

	/* Generate capability to init globals from DDC. */
	if (phdr != NULL && phnum != 0) {
		phdr_cap = cheri_setaddress(cheri_getdefault(), (vaddr_t)phdr);
		do_crt_init_globals(phdr_cap, phnum);
	}
#else
void __start(int, char **, char **, void (*)(void));

/* The entry function. */
void
__start(int argc, char *argv[], char *env[], void (*cleanup)(void))
{
#endif

	handle_argv(argc, argv, env);

	if (&_DYNAMIC != NULL)
		atexit(cleanup);
	else
		_init_tls();

#ifdef GCRT
	atexit(_mcleanup);
	monstartup(&eprol, &etext);
__asm__("eprol:");
#endif

	handle_static_init(argc, argv, env);
	exit(main(argc, argv, env));
}
