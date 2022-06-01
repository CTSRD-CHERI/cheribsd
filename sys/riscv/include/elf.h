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
 * ELF definitions for the RISC-V architecture.
 */

#ifndef __ELF_WORD_SIZE
#define	__ELF_WORD_SIZE	64
#if defined(__CHERI_PURE_CAPABILITY__) || \
    (__has_feature(capabilities) && defined(_KERNEL))
#define	__ELF_CHERI
#endif
#endif

#include <sys/elf32.h>	/* Definitions common to all 32 bit architectures. */
#include <sys/elf64.h>	/* Definitions common to all 64 bit architectures. */
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
	int64_t	a_type;			/* Entry type. */
	union {
		int64_t	a_val;		/* Integer value. */
#if __ELF_WORD_SIZE == 64 && !defined(__CHERI_PURE_CAPABILITY__)
		void	*a_ptr;		/* Address. */
		void	(*a_fcn)(void);	/* Function pointer (not used). */
#endif
	} a_un;
} Elf64_Auxinfo;

#if __has_feature(capabilities)
typedef struct {	/* Auxiliary vector entry on initial stack */
	int64_t	a_type;			/* Entry type. */
	union {
		int64_t	a_val;		/* Integer value. */
		void * __capability a_ptr; /* Address. */
		void	(* __capability a_fcn)(void); /* Function pointer (not used). */
	} a_un;
} Elf64C_Auxinfo;
#endif

#ifdef __ELF_CHERI
typedef Elf64C_Auxinfo Elf_Auxinfo;
#else
__ElfType(Auxinfo);
#endif

#define	ELF_ARCH	EM_RISCV

#define	ELF_MACHINE_OK(x) ((x) == (ELF_ARCH))

#define	ELF_IS_CHERI(hdr) (((hdr)->e_flags & EF_RISCV_CHERIABI) != 0)

#define	PT_MEMTAG_CHERI	PT_RISCV_MEMTAG_CHERI

/* Define "machine" characteristics */
#define	ELF_TARG_CLASS	ELFCLASS64
#define	ELF_TARG_DATA	ELFDATA2LSB
#define	ELF_TARG_MACH	EM_RISCV
#define	ELF_TARG_VER	1

/* TODO: set correct value */
#define	ET_DYN_LOAD_ADDR 0x100000

#define	DT_CHERI___CAPRELOCS	DT_RISCV_CHERI___CAPRELOCS
#define	DT_CHERI___CAPRELOCSSZ	DT_RISCV_CHERI___CAPRELOCSSZ

/* Flags passed in AT_HWCAP */
#define	HWCAP_ISA_BIT(c)	(1 << ((c) - 'A'))
#define	HWCAP_ISA_I		HWCAP_ISA_BIT('I')
#define	HWCAP_ISA_M		HWCAP_ISA_BIT('M')
#define	HWCAP_ISA_A		HWCAP_ISA_BIT('A')
#define	HWCAP_ISA_F		HWCAP_ISA_BIT('F')
#define	HWCAP_ISA_D		HWCAP_ISA_BIT('D')
#define	HWCAP_ISA_C		HWCAP_ISA_BIT('C')
#define	HWCAP_ISA_G		\
    (HWCAP_ISA_I | HWCAP_ISA_M | HWCAP_ISA_A | HWCAP_ISA_F | HWCAP_ISA_D)

#endif /* !_MACHINE_ELF_H_ */
