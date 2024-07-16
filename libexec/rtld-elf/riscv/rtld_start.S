/*-
 * Copyright (c) 2015-2018 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory as part of the CTSRD Project, with support from the UK Higher
 * Education Innovation Fund (HEIF).
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

#include <machine/asm.h>

#ifdef __CHERI_PURE_CAPABILITY__
#include <machine/riscvreg.h>
#endif

/*
 * Pure-capability:
 *
 * void
 * _rtld_relocate_nonplt_self(Elf_Dyn *dynp, Elf_Auxinfo *aux)
 *
 * func_ptr_type
 * _rtld(Elf_Auxinfo *aux, func_ptr_type *exit_proc, Obj_Entry **objp)
 */

/*
 * Plain:
 *
 * func_ptr_type
 * _rtld(Elf_Addr *sp, func_ptr_type *exit_proc, Obj_Entry **objp)
 */

#ifndef C18N_VARIANT

ENTRY(.rtld_start)
#ifdef __CHERI_PURE_CAPABILITY__
	cmove	cs0, ca0				/* Put aux in a callee-saved register */
	cmove	cs1, csp				/* And the stack pointer */

	cincoffset csp, csp, -(CLEN * 2)		/* Make room for obj_main & exit_proc */

	cllc	ca0, _DYNAMIC				/* dynp */
	cmove	ca1, cs0				/* aux */
	cjal	_rtld_relocate_nonplt_self		/* Relocate ourselves early, including __cap_relocs */

#if __CHERI_CAPABILITY_TABLE__ != 3
	/* TODO: CGP for PLT and FNDESC ABIs */
#error "Only the PC-relative ABI is currently supported"
#endif

	cmove	ca0, cs0				/* Restore aux */
	csetbounds	ca1, csp, CLEN			/* exit_proc */
	cincoffset	ca2, csp, CLEN
	csetbounds	ca2, ca2, CLEN			/* obj_main */
	cjal	_rtld					/* Call the loader */
	cmove	ct0, ca0				/* Backup the entry point */

	clc	ca1, (CLEN * 0)(csp)			/* Load cleanup */
	clc	ca2, (CLEN * 1)(csp)			/* Load obj_main */
	cmove	ca0, cs0				/* Restore aux */
	cmove	csp, cs1				/* Restore the stack pointer */
	cjr	ct0					/* Jump to the entry point */
#else /* defined(__CHERI_PURE_CAPABILITY__) */
	mv	s0, a0		/* Put ps_strings in a callee-saved register */
	mv	s1, sp		/* And the stack pointer */

	addi	sp, sp, -16	/* Make room for obj_main & exit proc */

	mv	a1, sp		/* exit_proc */
	addi	a2, a1, 8	/* obj_main */
	jal	_rtld		/* Call the loader */
	mv	t0, a0		/* Backup the entry point */

	ld	a2, 0(sp)	/* Load cleanup */
	ld	a1, 8(sp)	/* Load obj_main */
	mv	a0, s0		/* Restore ps_strings */
	mv	sp, s1		/* Restore the stack pointer */
	jr	t0		/* Jump to the entry point */
#endif /* defined(__CHERI_PURE_CAPABILITY__) */
END(.rtld_start)

#define	INT_SIZE	8
#define	INT(x)		x
#define	LOAD_INT	PTR(ld)
#define	STORE_INT	PTR(sd)

#ifdef __CHERI_PURE_CAPABILITY__
#define	LOAD_PTR	LOAD_CAP
#define	STORE_PTR	STORE_CAP
#define	ADD_PTR		cincoffset
#define	MV_PTR		cmove
#define	PTR_SIZE	CAP_SIZE
#define	PTR(x)		CAP(x)
#else
#define	LOAD_PTR	LOAD_INT
#define	STORE_PTR	STORE_INT
#define	ADD_PTR		add
#define	MV_PTR		mv
#define	PTR_SIZE	INT_SIZE
#define	PTR(x)		INT(x)
#endif

#define	JR_PTR		PTR(jr)

#if __has_feature(capabilities)
#define	LOAD_CAP	PTR(lc)
#define	STORE_CAP	PTR(sc)
#define	CAP_SIZE	16
#define	CAP(x)		c ## x
#else
#define	LOAD_CAP	ld
#define	STORE_CAP	sd
#define	CAP_SIZE	8
#define	CAP(x)		x
#endif

#ifdef __riscv_float_abi_double
#define	FLT_SIZE	8
#define	LOAD_FLT	PTR(fld)
#define	STORE_FLT	PTR(fsd)
#else
#define	FLT_SIZE	0
#endif

/*
 * t0 = obj pointer
 * t1 = reloc offset
 */
ENTRY(_rtld_bind_start)
#ifdef __CHERI_PURE_CAPABILITY__
	/* Currently unused and unimplemented for pure-capability code */
	unimp
#else /* defined(__CHERI_PURE_CAPABILITY__) */
	/* Save the arguments and (c)ra */
	/*
	 * We require 8 GP(C)Rs, 1 pointer and 8 FPRs, but the stack must be
	 * aligned to 16-bytes.
	 */
#define	FLT_OFFSET	(8 * CAP_SIZE + 1 * PTR_SIZE)
#define	FRAME_SIZE	(((FLT_OFFSET + 8 * FLT_SIZE) + 15) & ~15)

	ADD_PTR		PTR(sp), PTR(sp), -FRAME_SIZE
	STORE_CAP	CAP(a0), (CAP_SIZE * 0)(PTR(sp))
	STORE_CAP	CAP(a1), (CAP_SIZE * 1)(PTR(sp))
	STORE_CAP	CAP(a2), (CAP_SIZE * 2)(PTR(sp))
	STORE_CAP	CAP(a3), (CAP_SIZE * 3)(PTR(sp))
	STORE_CAP	CAP(a4), (CAP_SIZE * 4)(PTR(sp))
	STORE_CAP	CAP(a5), (CAP_SIZE * 5)(PTR(sp))
	STORE_CAP	CAP(a6), (CAP_SIZE * 6)(PTR(sp))
	STORE_CAP	CAP(a7), (CAP_SIZE * 7)(PTR(sp))
	STORE_PTR	PTR(ra), (CAP_SIZE * 8)(PTR(sp))

#if FLT_SIZE != 0
	/* Save any floating-point arguments */
	STORE_FLT	fa0, (FLT_OFFSET + FLT_SIZE * 0)(PTR(sp))
	STORE_FLT	fa1, (FLT_OFFSET + FLT_SIZE * 1)(PTR(sp))
	STORE_FLT	fa2, (FLT_OFFSET + FLT_SIZE * 2)(PTR(sp))
	STORE_FLT	fa3, (FLT_OFFSET + FLT_SIZE * 3)(PTR(sp))
	STORE_FLT	fa4, (FLT_OFFSET + FLT_SIZE * 4)(PTR(sp))
	STORE_FLT	fa5, (FLT_OFFSET + FLT_SIZE * 5)(PTR(sp))
	STORE_FLT	fa6, (FLT_OFFSET + FLT_SIZE * 6)(PTR(sp))
	STORE_FLT	fa7, (FLT_OFFSET + FLT_SIZE * 7)(PTR(sp))
#endif

	/* Reloc offset is 3x of the .got.plt offset */
	slli	a1, t1, 1	/* Mult items by 2 */
	add	a1, a1, t1	/* Plus item */

	/* Load obj */
	MV_PTR	PTR(a0), PTR(t0)

	/* Call into rtld */
	jal	_rtld_bind

	/* Backup the address to branch to */
	MV_PTR	PTR(t0), PTR(a0)

	/* Restore the arguments and ra */
	LOAD_CAP	CAP(a0), (CAP_SIZE * 0)(PTR(sp))
	LOAD_CAP	CAP(a1), (CAP_SIZE * 1)(PTR(sp))
	LOAD_CAP	CAP(a2), (CAP_SIZE * 2)(PTR(sp))
	LOAD_CAP	CAP(a3), (CAP_SIZE * 3)(PTR(sp))
	LOAD_CAP	CAP(a4), (CAP_SIZE * 4)(PTR(sp))
	LOAD_CAP	CAP(a5), (CAP_SIZE * 5)(PTR(sp))
	LOAD_CAP	CAP(a6), (CAP_SIZE * 6)(PTR(sp))
	LOAD_CAP	CAP(a7), (CAP_SIZE * 7)(PTR(sp))
	LOAD_PTR	PTR(ra), (CAP_SIZE * 8)(PTR(sp))

#if FLT_SIZE != 0
	/* Restore floating-point arguments */
	LOAD_FLT	fa0, (FLT_OFFSET + FLT_SIZE * 0)(PTR(sp))
	LOAD_FLT	fa1, (FLT_OFFSET + FLT_SIZE * 1)(PTR(sp))
	LOAD_FLT	fa2, (FLT_OFFSET + FLT_SIZE * 2)(PTR(sp))
	LOAD_FLT	fa3, (FLT_OFFSET + FLT_SIZE * 3)(PTR(sp))
	LOAD_FLT	fa4, (FLT_OFFSET + FLT_SIZE * 4)(PTR(sp))
	LOAD_FLT	fa5, (FLT_OFFSET + FLT_SIZE * 5)(PTR(sp))
	LOAD_FLT	fa6, (FLT_OFFSET + FLT_SIZE * 6)(PTR(sp))
	LOAD_FLT	fa7, (FLT_OFFSET + FLT_SIZE * 7)(PTR(sp))
#endif
	ADD_PTR		PTR(sp), PTR(sp), FRAME_SIZE

	/* Call into the correct function */
	JR_PTR	PTR(t0)
#endif /* defined(__CHERI_PURE_CAPABILITY__) */
END(_rtld_bind_start)

#endif /* C18N_VARIANT */
