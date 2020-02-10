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
#error "GCRT should not be defined for purecap"
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


static __always_inline bool
has_dynamic_linker(void) {
#ifdef PCREL_SYMBOL_ADDRESSES_WORK
	void* _pcc_after_daddui = 0;
	int64_t _dynamic_pcrel = 0;
	/*
	 * We can't get the address of _DYNAMIC in the purecap ABI before globals
	 * are initialized so we need to use dla here. If _DYNAMIC exists
	 * then the runtime-linker will have done the __cap_relocs already
	 * so we should be processing them here. Furthermore it will also have
	 * enforced relro so we will probably crash when attempting to write
	 * const pointers that are initialized to global addresses.
	 *
	 * TODO: Maybe clang should provide a __builtin_symbol_address() that is
	 * always filled in a static link time...
	 */
	__asm__ volatile(".global _DYNAMIC\n\t"
	    /*
	     * XXXAR: For some reason the attribute weak above is ignored if we
	     * don't also include it in the inline assembly
	     */
	    ".weak _DYNAMIC\n\t"
	    "lui %0, %%pcrel_hi(_DYNAMIC - 8)\n\t"
	    "daddiu %0, %0, %%pcrel_lo(_DYNAMIC - 4)\n\t"
	    "cgetpcc %1\n\t"
	    : "+r"(_dynamic_pcrel), "+C"(_pcc_after_daddui));

	/*
	 * If the address of _DYNAMIC is non-zero then we are dynamically linked
	 * and RTLD will be responsible for processing the capability relocs
	 * FIXME: MIPS only has 32-bit pcrelative relocations so this overflows
	 * For now just assume that if the pcrel value is greater than INT_MAX
	 * the value of _DYNAMIC is zero
	 */
	if ((vaddr_t)_pcc_after_daddui + _dynamic_pcrel != 0 &&
	    labs(_dynamic_pcrel) <= (int64_t)INT32_MAX)
		return true;
#else
	/*
	 * XXXAR: Since the MIPS %pcrel doesn't appear to work to get the value
	 * of _DYNAMIC without a text relocation I changed LLD to emit a symbol
	 * _HAS__DYNAMIC instead. This also has the advantage that it only needs
	 * a single instruction to load rather than the full dla/pcrel sequence.
	 */
	int64_t _has__DYNAMIC;
	__asm__ volatile("ori %0, $zero, %%lo(_HAS__DYNAMIC)\n\t"
	: "+r"(_has__DYNAMIC));
	/* If we are dynamically linked, the runtime linker takes care of this */
	if (_has__DYNAMIC)
		return true;
#endif
	return false;
}

/*
 * The entry function, C part. This performs the bulk of program initialisation
 * before handing off to main().
 *
 * It is important to note that function calls and global variable accesses
 * can only be made after do_crt_init_globals() has completed (as this
 * initializes the capabilities to globals and functions in the captable, which
 * is used for all function calls). This restriction only applies to statically
 * linked binaries since the dynamic linker takes care of initialization
 * otherwise.
 */
static void
_start(void *auxv,
	void (*cleanup)(void),			/* from shared loader */
	struct Struct_Obj_Entry *obj __unused)	/* from shared loader */
{
	int argc = 0;
	char **argv = NULL;
	char **env = NULL;
#ifndef POSITION_INDEPENDENT_STARTUP
	const Elf_Phdr *at_phdr = NULL;
	long at_phnum = 0;
#endif

	/*
	 * XXX: Clear DDC. Eventually the kernel should stop setting it in the
	 * first place.
	 */
#ifdef __CHERI_CAPABILITY_TABLE__
	__asm__ __volatile__ ("csetdefault %0" : : "C" (NULL));
#else
#pragma message("Not clearing $ddc since it is required for the legacy ABI")
#endif

	/*
	 * Digest the auxiliary vector for local use.
	 *
	 * Note: this file must be compile with -fno-jump-tables to avoid use
	 * of the captable before do_crt_init_globals() has been called.
	 */
	for (Elf_Auxinfo *auxp = auxv; auxp->a_type != AT_NULL;  auxp++) {
		if (auxp->a_type == AT_ARGV) {
			argv = (char **)auxp->a_un.a_ptr;
		} else if (auxp->a_type == AT_ENVV) {
			env = (char **)auxp->a_un.a_ptr;
		} else if (auxp->a_type == AT_ARGC) {
			argc = auxp->a_un.a_val;
#ifndef POSITION_INDEPENDENT_STARTUP
		} else if (auxp->a_type == AT_PHDR) {
			at_phdr = auxp->a_un.a_ptr;
		} else if (auxp->a_type == AT_PHNUM) {
			at_phnum = auxp->a_un.a_val;
#endif
		}
	}

	/* For -pie executables rtld will initialize the __cap_relocs */
#ifndef POSITION_INDEPENDENT_STARTUP
	/*
	 * crt_init_globals_3 must be called before accessing any globals.
	 *
	 * Note: We parse the phdrs to ensure that the global data cap does
	 * not span the readonly segment or text segment.
	 */
	if (!has_dynamic_linker())
		do_crt_init_globals(at_phdr, at_phnum);
#endif
	/* We can access global variables/make function calls now. */

	__auxargs = auxv;

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

#if defined(__CHERI_CAPABILITY_TABLE__) && __CHERI_CAPABILITY_TABLE__ != 3
	/* Store the $pcc with large bounds for __init_array/__fini_array */
	__initfini_base_cap = cheri_getpcc();
#endif
	handle_static_init(argc, argv, env);

	exit(main(argc, argv, env));
}
