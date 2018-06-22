/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2001 David E. O'Brien
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

#ifndef _MACHINE_ELF_H_
#define	_MACHINE_ELF_H_ 1

/*
 * EABI ELF definitions for the PowerPC architecture.
 * See "PowerPC Embedded Application Binary Interface, 32-Bit Impliementation"
 * [ppc-eabi-1995-01.pdf] for details.
 */

#ifndef __ELF_WORD_SIZE
#ifdef __powerpc64__
#define	__ELF_WORD_SIZE	64	/* Used by <sys/elf_generic.h> */
#else
#define	__ELF_WORD_SIZE	32	/* Used by <sys/elf_generic.h> */
#endif
#endif

#include <sys/elf32.h>	/* Definitions common to all 32 bit architectures. */
#include <sys/elf64.h>	/* Definitions common to all 64 bit architectures. */
#include <sys/elf_generic.h>

#if __ELF_WORD_SIZE == 64
#define	ELF_ARCH	EM_PPC64
#define	ELF_MACHINE_OK(x) ((x) == EM_PPC64)
#else
#define	ELF_ARCH	EM_PPC
#define	ELF_ARCH32	EM_PPC
#define	ELF_MACHINE_OK(x) ((x) == EM_PPC)
#endif

/*
 * Auxiliary vector entries for passing information to the interpreter.
 *
 * The PowerPC supplement to the SVR4 ABI specification names this "auxv_t",
 * but POSIX lays claim to all symbols ending with "_t".
 */

typedef struct {	/* Auxiliary vector entry on initial stack */
	int	a_type;			/* Entry type. */
	union {
		long	a_val;		/* Integer value. */
		void	*a_ptr;		/* Address. */
		void	(*a_fcn)(void);	/* Function pointer (not used). */
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

/* Values for a_type. */
#define	AT_NULL		0	/* Terminates the vector. */
#define	AT_IGNORE	1	/* Ignored entry. */
#define	AT_EXECFD	2	/* File descriptor of program to load. */
#define	AT_PHDR		3	/* Program header of program already loaded. */
#define	AT_PHENT	4	/* Size of each program header entry. */
#define	AT_PHNUM	5	/* Number of program header entries. */
#define	AT_PAGESZ	6	/* Page size in bytes. */
#define	AT_BASE		7	/* Interpreter's base address. */
#define	AT_FLAGS	8	/* Flags (unused for PowerPC). */
#define	AT_ENTRY	9	/* Where interpreter should transfer control. */
#define	AT_DCACHEBSIZE	10	/* Data cache block size for the processor. */
#define	AT_ICACHEBSIZE	11	/* Instruction cache block size for the uP. */
#define	AT_UCACHEBSIZE	12	/* Cache block size, or `0' if cache not unified. */
#define	AT_EXECPATH	13	/* Path to the executable. */
#define	AT_CANARY	14	/* Canary for SSP */
#define	AT_CANARYLEN	15	/* Length of the canary. */
#define	AT_OSRELDATE	16	/* OSRELDATE. */
#define	AT_NCPUS	17	/* Number of CPUs. */
#define	AT_PAGESIZES	18	/* Pagesizes. */
#define	AT_PAGESIZESLEN	19	/* Number of pagesizes. */
#define	AT_STACKPROT	21	/* Initial stack protection. */
#define	AT_TIMEKEEP	22	/* Pointer to timehands. */
#define	AT_EHDRFLAGS	24	/* e_flags field from elf hdr */
#define	AT_HWCAP	25	/* CPU feature flags. */
#define	AT_HWCAP2	26	/* CPU feature flags 2. */

#define	AT_COUNT	27	/* Count of defined aux entry types. */

/*
 * Relocation types.
 */

#define	R_PPC_COUNT		37	/* Count of defined relocation types. */

					/* Count of defined relocation types. */
#define	R_PPC_EMB_COUNT		(R_PPC_EMB_RELSDA - R_PPC_EMB_NADDR32 + 1)

/* Define "machine" characteristics */
#if __ELF_WORD_SIZE == 64
#define	ELF_TARG_CLASS	ELFCLASS64
#define	ELF_TARG_DATA	ELFDATA2MSB
#define	ELF_TARG_MACH	EM_PPC64
#define	ELF_TARG_VER	1
#else
#define	ELF_TARG_CLASS	ELFCLASS32
#define	ELF_TARG_DATA	ELFDATA2MSB
#define	ELF_TARG_MACH	EM_PPC
#define	ELF_TARG_VER	1
#endif

#define	ET_DYN_LOAD_ADDR 0x01010000

#endif /* !_MACHINE_ELF_H_ */
