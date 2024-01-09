/* LINTLIBRARY */
/*-
 * Copyright 1996-1998 John D. Polstra.
 * Copyright 2014 Andrew Turner.
 * Copyright 2014-2015 The FreeBSD Foundation.
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

#include <machine/asm.h>

	.weak _DYNAMIC

	/*
	 * The program entry point
	 * void _start(char **ap, void (*cleanup)(void)) __dead2
	 */
ENTRY(_start)
	.cfi_undefined x30
	mov	x3, x2		/* cleanup */

	adrp	x2, :got:_DYNAMIC
	ldr	x2, [x2, :got_lo12:_DYNAMIC]
	cbnz	x2, 2f

	/*
	 * Statically linked binary; convert argc, argv, env and auxv to
	 * use 128-bit pointers since the kernel ABI is still 64-bit.
	 */
	add	x2, x0, #8	/* load argv */
	ldr	x4, [x0]	/* load argc */
	add	x2, x2, x4, lsl #3 /* env is after argv */
	add	x2, x2, #8	/* argv is null terminated */
1:
	ldr	x4, [x2], #8	/* load env[i++] */
	cbnz	x4, 1b		/* check if terminator */
1:
	ldr	x4, [x2], #16	/* load auxv[i++] */
	cbnz	x4, 1b		/* check if terminator */

	sub	x4, x2, x0	/* calculate current space used */
	sub	x5, x0, x4	/* calculate new start address */
	and	x5, x5, #~15	/* aligned to pointer alignment */
	add	x4, x4, #15	/* round up to multiple of stack alignment */
	and	x4, x4, #~15
	sub	sp, sp, x4	/* account for space being on stack */
	mov	x4, x0		/* get original base address */
	mov	x0, x5		/* save new base address */

1:
	ldr	x6, [x4], #8	/* load entry */
	stp	x6, xzr, [x5], #16 /* store padded entry */
	cmp	x4, x2		/* repeat until end */
	b.ne	1b

2:
	add	x1, x0, #16	/* load argv */
	ldr	x0, [x0]	/* load argc */
	add	x2, x1, x0, lsl #4 /* env is after argv */
	add	x2, x2, #16	/* argv is null terminated */
#if __has_feature(capabilities) && !defined(PIC)
	mov	x19, x0		/* save argc */
	mov	x20, x1		/* save argv */
	mov	x21, x2		/* save env */
	mov	x22, x3		/* save cleanup */
	/*
	 * __process_cap_relocs(env)
	 */
	mov	x0, x21
	bl	__process_cap_relocs
	mov	x0, x19		/* restore argc */
	mov	x1, x20		/* restore argv */
	mov	x2, x21		/* restore env */
	mov	x3, x22		/* restore cleanup */
#endif
#ifdef PIC
	adrp	x4, main
	add	x4, x4, :lo12:main
#else
	ldr	x4, =main
#endif
#ifdef GCRT
	ldr	x5, =eprol
	ldr	x6, =etext
	/*
	 * __libc_start1_gcrt(argc, argv, env, cleanup, main, &eprol, &etext)
	 */
	bl	__libc_start1_gcrt
eprol:
#else
	/* __libc_start1(argc, argv, env, cleanup, main) */
	bl	__libc_start1
#endif
END(_start)

	.section .note.GNU-stack,"",@progbits
