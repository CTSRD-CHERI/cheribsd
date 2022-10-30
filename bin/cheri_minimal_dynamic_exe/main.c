/*-
 * Copyright (c) 2018 Alex Richardson
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
#include "simple_printf.h"

#include <stdlib.h>

void __cerror(int) __hidden;
#ifdef __CHERI_PURE_CAPABILITY__
void __libc_start1(int, char *[], char *[],
    void (*)(void), int (*)(int, char *[], char *[]), void *, 
    const void *) __hidden;
#else
void __libc_start1(int, char *[], char *[],
    void (*)(void), int (*)(int, char *[], char *[])) __hidden;
#endif

extern void _DYNAMIC __hidden;
#pragma weak _DYNAMIC
extern void __start___cap_relocs __hidden;
extern void _CHERI_CAPABILITY_TABLE_ __hidden;

#define PRINT_SYMBOL(sym) simple_printf("%25s = %#p\n", #sym, &sym);

int
main(int argc, char** argv)
{
	simple_putstr("Minimal CHERI dynamic exe started!\n");
	for (int i = 0; i < argc; i++) {
		simple_printf("\targv[%d] = %s\n", i, argv[i]);
	}

	simple_putchar('\n');

	/* Print out a few capabilities for debugging purposes */
	PRINT_SYMBOL(_DYNAMIC);
	PRINT_SYMBOL(__start___cap_relocs);
	PRINT_SYMBOL(_CHERI_CAPABILITY_TABLE_);
	// TODO: override a function from libsimple_printf to check that
	// the one in the main executable one gets called instead

	// TODO: compile as PIE

	// TODO: compile as plain MIPS
}


extern void _exit(int code);

// Add the functions needed by the startup code:
void
__libc_start1(int argc, char *argv[], char *env[], void (*cleanup)(void),
    int (*mainX)(int, char *[], char *[])
#ifdef __CHERI_PURE_CAPABILITY__
    , void *data_cap __unused, const void *code_cap __unused
#endif
	)
{
	int code;

	code = mainX(argc, argv, env);
	if (cleanup != NULL)
		cleanup();

	simple_printf("exit(%d)\n", code);
	_exit(code);
}

void
__cerror(int code)
{
	/* _exit should never return an error */
	simple_printf("__cerror(%d)\n", code);
	__builtin_trap();
}
