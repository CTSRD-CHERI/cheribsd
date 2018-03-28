/*-
 * Copyright 2015-2017 SRI International
 * Copyright 2013 Philip Withnall
 * Copyright 1996-1998 John D. Polstra.
 * All rights reserved.
 * Copyright (c) 1995 Christopher G. Demetriou
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Christopher G. Demetriou
 *    for the NetBSD Project.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
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
 *
 * $FreeBSD: head/lib/csu/mips/crt1_c.c 245133 2013-01-07 17:58:27Z kib $
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: head/lib/csu/mips/crt1_c.c 245133 2013-01-07 17:58:27Z kib $");

#ifndef __GNUC__
#error "GCC is needed to compile this file"
#endif

#include <sys/types.h>
#include <sys/cheriabi.h>

#include <machine/elf.h>

#include <stdlib.h>
#include "libc_private.h"
#include "crtbrand.c"
#include "ignore_init.c"
/* For -pie executables rtld will initialize the __cap_relocs */
#ifndef POSITION_INDEPENDENT_STARTUP
#define DONT_EXPORT_CRT_INIT_GLOBALS
#include "crt_init_globals.c"
#endif

struct Struct_Obj_Entry;

static void _start(void *, void (*)(void), struct Struct_Obj_Entry *) __used;
extern void crt_call_constructors(void);

#ifdef GCRT
/* Profiling support. */
extern void _mcleanup(void);
extern void monstartup(void *, void *);
extern int eprol;
extern int etext;
#endif

Elf_Auxinfo *__auxargs;

/* Define an assembly stub that sets up $cgp and jumps to _start */
#ifndef POSITION_INDEPENDENT_STARTUP
DEFINE_CHERI_START_FUNCTION(_start)
#else
/* RTLD takes care of initializing $cgp, and all the globals */
/* FIXME: we should probably just rename _start to __start instead of jumping */
asm(
	".text\n\t"
	".global __start\n\t"
	"__start:\n\t"
	".set noreorder\n\t"
	".set noat\n\t"
	".protected _start\n\t"
	/* Setup $c12 correctly in case we are inferring $cgp from $c12 */
	"lui $1, %pcrel_hi(_start - 8)\n\t"
	"daddiu $1, $1, %pcrel_lo(_start - 4)\n\t"
	"cgetpcc $c12\n\t"
	"cincoffset $c12, $c12, $1\n\t"
	"cjr $c12\n\t"
	"nop\n\t");
#endif

/* The entry function, C part. This performs the bulk of program initialisation
 * before handing off to main(). It is called by __start, which is defined in
 * crt1_s.s, and necessarily written in raw assembly so that it can re-align
 * the stack before setting up the first stack frame and calling _start1().
 *
 * It would be nice to be able to hide the _start1 symbol, but that's not
 * possible, since it must be present in the GOT in order to be resolvable by
 * the position independent code in __start.
 * See: http://stackoverflow.com/questions/8095531/mips-elf-and-partial-linking
 */
static void
_start(void *auxv,
	void (*cleanup)(void),			/* from shared loader */
	struct Struct_Obj_Entry *obj __unused)	/* from shared loader */
{
	Elf_Auxinfo *aux_info[AT_COUNT];
	int i;
	int argc = 0;
	char **argv = NULL;
	char **env = NULL;
	Elf_Auxinfo *auxp;

	/* For -pie executables rtld will initialize the __cap_relocs */
#ifndef POSITION_INDEPENDENT_STARTUP
	/* Must be called before accessing any globals */
	crt_init_globals();
#endif

	__auxargs = auxv;
	/* Digest the auxiliary vector. */
	for (i = 0;  i < AT_COUNT;  i++)
	    aux_info[i] = NULL;
	for (auxp = __auxargs;  auxp->a_type != AT_NULL;  auxp++) {
		if (auxp->a_type < AT_COUNT)
			aux_info[auxp->a_type] = auxp;
	}
	argc = aux_info[AT_ARGC]->a_un.a_val;
	argv = (char **)aux_info[AT_ARGV]->a_un.a_ptr;
	env = (char **)aux_info[AT_ENVV]->a_un.a_ptr;

	handle_argv(argc, argv, env);

	if (&_DYNAMIC != NULL)
		atexit(cleanup);
	else
		_init_tls();

	crt_call_constructors();

#ifdef GCRT
	/* Set up profiling support for the program, if we're being compiled
	 * with profiling support enabled (-DGCRT).
	 * See: http://sourceware.org/binutils/docs/gprof/Implementation.html
	 */
	atexit(_mcleanup);
	monstartup(&eprol, &etext);

	/* Create an 'eprol' (end of prologue?) label which delimits the start
	 * of the .text section covered by profiling. This must be before
	 * main(). */
__asm__("eprol:");
#endif

	handle_static_init(argc, argv, env);

	exit(main(argc, argv, env));
}
