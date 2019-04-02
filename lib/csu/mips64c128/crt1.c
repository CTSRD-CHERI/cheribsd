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

#include <stdbool.h>
#include <stdlib.h>
#include "libc_private.h"
#include "crtbrand.c"
#include "ignore_init.c"
/* For -pie executables rtld will initialize the __cap_relocs */
#ifndef POSITION_INDEPENDENT_STARTUP
#define DONT_EXPORT_CRT_INIT_GLOBALS
#define CRT_INIT_GLOBALS_GDC_ONLY
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

#ifndef POSITION_INDEPENDENT_STARTUP
/* This is __always_inline since it is called before globals have been set up */
static __always_inline void *
create_data_cap(const Elf_Phdr *phdr, long phnum)
{
	const Elf_Phdr *phlimit = phdr + phnum;
	Elf_Addr text_start = (Elf_Addr)-1l;
	Elf_Addr text_end = 0;
	Elf_Addr readonly_start = (Elf_Addr)-1l;
	Elf_Addr readonly_end = 0;
	Elf_Addr writable_start = (Elf_Addr)-1l;
	Elf_Addr writable_end = 0;

	bool have_rodata_segment = false;
	bool have_text_segment = false;
	bool have_data_segment = false;

	/* Attempt to bound the data capability to only the writable segment */
	for (const Elf_Phdr *ph = phdr; ph < phlimit; ph++) {
		if (ph->p_type != PT_LOAD) {
			/* Static binaries should not have a PT_DYNAMIC phdr */
			if (ph->p_type == PT_DYNAMIC) {
				__builtin_trap();
				break;
			}
			continue;
		}
		Elf_Addr seg_start = ph->p_vaddr;
		Elf_Addr seg_end = seg_start + ph->p_memsz;
		if ((ph->p_flags & PF_X)) {
			/* text segment */
			have_text_segment = true;
			text_start = MIN(text_start, seg_start);
			text_end = MAX(text_end, seg_end);
		} else if ((ph->p_flags & PF_W)) {
			/* data segment */
			have_data_segment = true;
			writable_start = MIN(writable_start, seg_start);
			writable_end = MAX(writable_end, seg_end);
		} else {
			have_rodata_segment = true;
			/* read-only segment (not always present) */
			readonly_start = MIN(readonly_start, seg_start);
			readonly_end = MAX(readonly_end, seg_end);
		}
	}

	if (!have_text_segment) {
		/* No text segment??? Must be an error somewhere else. */
		__builtin_trap();
	}

	/* No data segment -> should not need a writable cap -> use $pcc */
	if (!have_data_segment) {
		void* result = cheri_clearperm(cheri_getpcc(), CHERI_PERM_EXECUTE);
		Elf_Addr start = MIN(readonly_start, text_start);
		Elf_Addr end = MAX(readonly_end, text_end);
		result = cheri_setaddress(result, start);
		return cheri_csetbounds(result, end - start);
	}

	/*
	 * FIXME: For now, if we don't have a separate rodata segment we also
	 *  need to include the text segment in the data cap since we can't
	 *  initialize constant variables otherwise.
	 */
	if (!have_rodata_segment) {
		readonly_start = text_start;
		readonly_end = text_end;
	}

	/* Check that ranges are well-formed */
	if (writable_end < writable_start || readonly_end < readonly_start)
		__builtin_trap();
	/* Abort if readonly and writeable overlap: */
	if (MAX(writable_start, readonly_start) <=
	    MIN(writable_end, readonly_end)) {
		__builtin_trap();
	}

	/*
	 * For now we also must include the rodata segment in the RW cap since
	 * we don't yet have a flag in __cap_relocs for writable vs readonly
	 * data.
	 *
	 * TODO: we should really use a different capability for constant data!
	 */
	writable_start = MIN(writable_start, readonly_start);
	writable_end = MAX(writable_end, readonly_end);

	void* result = cheri_setaddress(phdr, writable_start);
	/* Bound the result and clear execute permissions. */
	result = cheri_clearperm(result, CHERI_PERM_EXECUTE);
	/* TODO: should we use exact setbounds? */
	result = cheri_csetbounds(result, writable_end - writable_start);
	return result;
}
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

	/*
	 * XXX: Clear DDC. Eventually the kernel should stop setting it in the
	 * first place.
	 */
#ifdef __CHERI_CAPABILITY_TABLE__
	__asm__ __volatile__ ("csetdefault %0" : : "C" (NULL));
#else
#pragma message("Not clearing $ddc since it is required for the legacy ABI")
#endif

	/* Digest the auxiliary vector for local use. */
	for (i = 0;  i < AT_COUNT;  i++)
	    aux_info[i] = NULL;
	for (auxp = auxv;  auxp->a_type != AT_NULL;  auxp++) {
		if (auxp->a_type < AT_COUNT)
			aux_info[auxp->a_type] = auxp;
	}

	/* For -pie executables rtld will initialize the __cap_relocs */
#ifndef POSITION_INDEPENDENT_STARTUP
	/*
	 * crt_init_globals_gdc must be called before accessing any globals.
	 *
	 * Note: We parse the phdrs to ensure that the global data cap does
	 * not span the readonly segment or text segment.
	 */
	crt_init_globals_gdc(create_data_cap(aux_info[AT_PHDR]->a_un.a_ptr, aux_info[AT_PHNUM]->a_un.a_val));
#endif
	__auxargs = auxv;
	argc = aux_info[AT_ARGC]->a_un.a_val;
	argv = (char **)aux_info[AT_ARGV]->a_un.a_ptr;
	env = (char **)aux_info[AT_ENVV]->a_un.a_ptr;

	handle_argv(argc, argv, env);

	if (&_DYNAMIC != NULL)
		atexit(cleanup);
	else
		_init_tls();

#ifndef POSITION_INDEPENDENT_STARTUP
	/*
	 * .ctors and .dtors are no longer supported for dynamically linked
	 * binaries. TODO: remove for statically linked ones too
	 */
	crt_call_constructors();
#endif

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
