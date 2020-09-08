/*-
 * Copyright (c) 1996-1997 John D. Polstra.
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
 *
 * $FreeBSD$
 */

#ifndef	_MACHINE_ELF_H_
#define	_MACHINE_ELF_H_

/*
 * ELF definitions for the AArch64 architecture.
 */

#include <sys/elf32.h>	/* Definitions common to all 32 bit architectures. */
#include <sys/elf64.h>	/* Definitions common to all 64 bit architectures. */

#ifndef __ELF_WORD_SIZE
#define	__ELF_WORD_SIZE	64	/* Used by <sys/elf_generic.h> */
#endif

#include <sys/elf_generic.h>

/*
 * Auxiliary vector entries for passing information to the interpreter.
 */

typedef struct {	/* Auxiliary vector entry on initial stack */
	int	a_type;			/* Entry type. */
	union {
		int	a_val;		/* Integer value. */
	} a_un;
} Elf32_Auxinfo;

typedef struct {	/* Auxiliary vector entry on initial stack */
	long	a_type;			/* Entry type. */
	union {
		long	a_val;		/* Integer value. */
		void	*a_ptr;		/* Address. */
		void	(*a_fcn)(void);	/* Function pointer (not used). */
	} a_un;
} Elf64_Auxinfo;

__ElfType(Auxinfo);

#ifdef _MACHINE_ELF_WANT_32BIT
#define	ELF_ARCH	EM_ARM
#else
#define	ELF_ARCH	EM_AARCH64
#endif

#define	ELF_MACHINE_OK(x) ((x) == (ELF_ARCH))

/* Define "machine" characteristics */
#if __ELF_WORD_SIZE == 64
#define	ELF_TARG_CLASS	ELFCLASS64
#define	ELF_TARG_DATA	ELFDATA2LSB
#define	ELF_TARG_MACH	EM_AARCH64
#define	ELF_TARG_VER	1
#else
#define	ELF_TARG_CLASS	ELFCLASS32
#define	ELF_TARG_DATA	ELFDATA2LSB
#define	ELF_TARG_MACH	EM_ARM
#define	ELF_TARG_VER	1
#endif

#if __ELF_WORD_SIZE == 32
#define	ET_DYN_LOAD_ADDR 0x12000
#else
#define	ET_DYN_LOAD_ADDR 0x100000
#endif

/* HWCAP */

#define	HWCAP_FP	0x00000001
#define	HWCAP_ASIMD	0x00000002
#define	HWCAP_EVTSTRM	0x00000004
#define	HWCAP_AES	0x00000008
#define	HWCAP_PMULL	0x00000010
#define	HWCAP_SHA1	0x00000020
#define	HWCAP_SHA2	0x00000040
#define	HWCAP_CRC32	0x00000080
#define	HWCAP_ATOMICS	0x00000100
#define	HWCAP_FPHP	0x00000200
#define	HWCAP_CPUID	0x00000400
#define	HWCAP_ASIMDRDM	0x00000800
#define	HWCAP_JSCVT	0x00001000
#define	HWCAP_FCMA	0x00002000
#define	HWCAP_LRCPC	0x00004000
#define	HWCAP_DCPOP	0x00008000
#define	HWCAP_SHA3	0x00010000
#define	HWCAP_SM3	0x00020000
#define	HWCAP_SM4	0x00040000
#define	HWCAP_ASIMDDP	0x00080000
#define	HWCAP_SHA512	0x00100000
#define	HWCAP_SVE	0x00200000
#define	HWCAP_ASIMDFHM	0x00400000
#define	HWCAP_DIT	0x00800000
#define	HWCAP_USCAT	0x01000000
#define	HWCAP_ILRCPC	0x02000000
#define	HWCAP_FLAGM	0x04000000

#endif /* !_MACHINE_ELF_H_ */
