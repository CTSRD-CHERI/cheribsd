/*	$NetBSD: SYS.h,v 1.19 2009/12/14 01:07:41 matt Exp $ */
/* $FreeBSD$ */

/*-
 * SPDX-License-Identifier: (BSD-4-Clause AND BSD-3-Clause)
 *
 * Copyright (c) 1996 Jonathan Stone
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Jonathan Stone for
 *      the NetBSD Project.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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

/*-
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Ralph Campbell.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from: @(#)SYS.h	8.1 (Berkeley) 6/4/93
 */
/*
 * CHERI CHANGES START
 * {
 *   "updated": 20181114,
 *   "target_type": "lib",
 *   "changes": [
 *     "support"
 *   ]
 * }
 * CHERI CHANGES END
 */

#include <sys/syscall.h>

#include <machine/asm.h>

/*
 * If compiling for shared libs, Emit sysV ABI PIC segment pseudo-ops.
 *
 * i)  Emit .abicalls before .LEAF entrypoint, and .cpload/.cprestore after.
 * ii) Do interprocedure jumps indirectly via t9, with the side-effect of
 *     preserving the callee's entry address in t9.
 */
#ifndef __CHERI_PURE_CAPABILITY__
#ifdef __ABICALLS__
	.abicalls
# if defined(__mips_o32) || defined(__mips_o64)
#  define PIC_PROLOGUE(x)	SETUP_GP
#  define PIC_TAILCALL(l)	PTR_LA t9, _C_LABEL(l); jr t9
#  define PIC_RETURN()		j ra
# else
#  define PIC_PROLOGUE(x)	SETUP_GP64(t3, x)
#  define PIC_TAILCALL(l)	PTR_LA t9, _C_LABEL(l); RESTORE_GP64; jr t9
#  define PIC_RETURN()		RESTORE_GP64; j ra
# endif
#else
# define PIC_PROLOGUE(x)
# define PIC_TAILCALL(l)	j  _C_LABEL(l)
# define PIC_RETURN()		j ra
#endif /* __ABICALLS__ */
#else /* defined(__CHERI_PURE_CAPABILITY__) */
#ifdef __PIC__
# define PIC_CHECK_GLOBALS_POINTER_VALID()			\
	.if PIC_GLOBALS_POINTER_CHANGED != 0;			\
	.error "must restore globals pointer before use";	\
	.endif
# if !defined(__CHERI_CAPABILITY_TABLE__)
#  undef t3
#  define t3 error dont use me
#  define GLOBALS_REG $15

/*
 * Legacy ABI: need to setup $t9 and $gp from $c12.
 * Note: since $gp is callee-save, we use $t3 instead
 */
#  define PIC_PROLOGUE(x)					\
	.abicalls;						\
	.set PIC_GLOBALS_POINTER_CHANGED, 0;			\
	.set PIC_GLOBALS_POINTER_SAVED, 0;			\
	cgetoffset	t9, $c12;				\
	lui	GLOBALS_REG, %hi(%neg(%gp_rel(x)));		\
	daddu	GLOBALS_REG, GLOBALS_REG, t9;			\
	daddiu	GLOBALS_REG, GLOBALS_REG, %lo(%neg(%gp_rel(x)))
#  define LEGACY_LOAD_DATA_CAP(capreg, gpr, l)		\
	PIC_CHECK_GLOBALS_POINTER_VALID();		\
	ld	gpr, %got_disp(l)(GLOBALS_REG);		\
	cfromddc	capreg, gpr;			\
	ld	gpr, %got_disp(.size.##l)(GLOBALS_REG);	\
	ld	gpr, 0(gpr)				\
	csetbounds	capreg, capreg, gpr
#  define LEGACY_LOAD_CODE_CAP(capreg, gpr, l)		\
	PIC_CHECK_GLOBALS_POINTER_VALID();		\
	ld	gpr, %got_disp(l)(GLOBALS_REG);		\
	cgetpccsetoffset	capreg, gpr
# elif __CHERI_CAPABILITY_TABLE__ == 3
#define GLOBALS_REG $cgp
/*
 * PC-relative: derive $cgp from $pcc.
 * Note: $cgp is caller-save so no need to save it.
 */
#  define PIC_PROLOGUE(x)				\
	.set push; .set noat;				\
	PCREL_LOAD_CODE_PTR(GLOBALS_REG, $1, _CHERI_CAPABILITY_TABLE_); \
	.set pop;					\
	.set PIC_GLOBALS_POINTER_CHANGED, 0;		\
	.set PIC_GLOBALS_POINTER_SAVED, 0;
# else
/*
 * PLT ABI: $cgp is live-in -> nothing to do in PIC_PROLOGUE()
 * However, for non-local calls we need to save/restore $cgp
 */
#  define GLOBALS_REG $cgp
#  define PIC_PROLOGUE(x)			\
	.set PIC_GLOBALS_POINTER_CHANGED, 0;	\
	.set PIC_GLOBALS_POINTER_SAVED, 0;
# endif /* !defined(__CHERI_CAPABILITY_TABLE__) */
# define PCREL_LOAD_CODE_PTR(capreg, gpr, l)		\
	lui		gpr, %pcrel_hi(l - 8);		\
	daddiu		gpr, gpr, %pcrel_lo(l - 4);	\
	cgetpcc		capreg;				\
	cincoffset	capreg, capreg, gpr

# define CAPTABLE_LOAD_PTR(capreg, cgp, l)		\
	PIC_CHECK_GLOBALS_POINTER_VALID();		\
	clcbi		capreg, %captab20(l)(cgp)
# define CAPTABLE_LOAD_CALL_PTR(capreg, cgp, l)		\
	PIC_CHECK_GLOBALS_POINTER_VALID();		\
	clcbi		capreg, %capcall20(l)(cgp)

# if defined(__CHERI_CAPABILITY_TABLE__)
/*
 * In the PLT ABI we cannot derive the target from $pcc with tight code bounds
 * so we have to use use captable. We could use pc-relative addresses in the
 * pc-relative ABI, but the breaks calls to preemptible symbols so we also use
 * the captable there
 */
#  define PIC_LOAD_CODE_PTR(capreg, gpr, l) CAPTABLE_LOAD_PTR(capreg, GLOBALS_REG, l)
#  define PIC_LOAD_CALL_PTR(capreg, gpr, l) CAPTABLE_LOAD_CALL_PTR(capreg, GLOBALS_REG, l)
#  define PIC_SAVE_GLOBALS_POINTER(offset) PIC_SAVE_GLOBALS_POINTER_IMPL(csc, offset)
#  define PIC_RESTORE_GLOBALS_POINTER(offset) PIC_RESTORE_GLOBALS_POINTER_IMPL(clc, offset)
/* TODO: remove this once we drop the legacy ABI: */
#  define PIC_SAVE_LEGACY_GP(offset)
#  define PIC_RESTORE_LEGACY_GP(offset)
# else
/* Legacy ABI -> Load from the GOT (assuming that $gp points there) */
#  define PIC_LOAD_CODE_PTR(capreg, gpr, l) LEGACY_LOAD_CODE_CAP(capreg, gpr, l)
#  define PIC_LOAD_CALL_PTR(capreg, gpr, l) LEGACY_LOAD_CODE_CAP(capreg, gpr, l)
#  define PIC_SAVE_GLOBALS_POINTER(offset) PIC_SAVE_GLOBALS_POINTER_IMPL(csd, offset)
#  define PIC_RESTORE_GLOBALS_POINTER(offset) PIC_RESTORE_GLOBALS_POINTER_IMPL(cld, offset)
#  define PIC_SAVE_LEGACY_GP(offset) PIC_SAVE_GLOBALS_POINTER_IMPL(csd, offset)
#  define PIC_RESTORE_LEGACY_GP(offset) PIC_RESTORE_GLOBALS_POINTER_IMPL(cld, offset)
# endif
# define PIC_SAVE_GLOBALS_POINTER_IMPL(op, offset)	\
	op GLOBALS_REG, zero, (offset)($csp);		\
	.set PIC_GLOBALS_POINTER_SAVED, 1;
# define PIC_RESTORE_GLOBALS_POINTER_IMPL(op, offset)				\
	.if PIC_GLOBALS_POINTER_SAVED == 0;					\
	.error "PIC_RESTORE_GLOBALS_POINTER without PIC_SAVE_GLOBALS_POINTER";	\
	.endif;									\
	op GLOBALS_REG, zero, (offset)($csp);					\
	.set PIC_GLOBALS_POINTER_CHANGED, 0;

# define PIC_TAILCALL(l)				\
	PIC_CHECK_GLOBALS_POINTER_VALID();		\
	PIC_LOAD_CALL_PTR($c12, t9, _C_LABEL(l));	\
	cjr $c12; nop
# define PIC_CALL(l)					\
	_PIC_CALL_IMPL(l)				\
	.set PIC_GLOBALS_POINTER_CHANGED, 1;
# define PIC_CALL_LOCAL(l)	\
	.protected _C_LABEL(l);	\
	_PIC_CALL_IMPL(l)
# define _PIC_CALL_IMPL(l)				\
	PIC_SAVE_LEGACY_GP(CALLFRAME_CGP)		\
	PIC_LOAD_CALL_PTR($c12, t9, _C_LABEL(l));	\
	cjalr $c12, $c17;				\
	nop;						\
	PIC_RESTORE_LEGACY_GP(CALLFRAME_CGP)

# define PIC_RETURN()						\
	PIC_CHECK_GLOBALS_POINTER_VALID(); cjr $c17; nop
#else
#ifdef __CHERI_CAPABILITY_TABLE
#error THIS IS WRONG
#endif
# define PIC_PROLOGUE(x)
# define PIC_TAILCALL(l)	j _C_LABEL(l)
# define PIC_CALL(l)				\
	dla			t9, l;		\
	cgetpccsetoffset	$c12, t9;	\
	cjalr			$c12, $c17;	\
	nop
# define PIC_RETURN()		cjr $c17
#endif
#endif /* defined(__CHERI_PURE_CAPABILITY__) */

#ifndef PIC_CALL_LOCAL
#define PIC_CALL_LOCAL(l) PIC_CALL(l)
#endif

# define SYSTRAP(x)	li v0,SYS_ ## x; syscall;

/*
 * Do a syscall that cannot fail (sync, get{p,u,g,eu,eg)id)
 */
#define RSYSCALL_NOERROR(x)						\
LEAF(__sys_ ## x);							\
	.weak _C_LABEL(x);						\
	_C_LABEL(x) = _C_LABEL(__CONCAT(__sys_,x));			\
	.weak _C_LABEL(__CONCAT(_,x));					\
	_C_LABEL(__CONCAT(_,x)) = _C_LABEL(__CONCAT(__sys_,x));		\
	PIC_PROLOGUE(__sys_ ## x);					\
	SYSTRAP(x);							\
	PIC_RETURN();							\
END(__sys_ ## x)

/*
 * Do a normal syscall.
 */
#define RSYSCALL(x)							\
LEAF(__sys_ ## x);							\
	.weak _C_LABEL(x);						\
	_C_LABEL(x) = _C_LABEL(__CONCAT(__sys_,x));			\
	.weak _C_LABEL(__CONCAT(_,x));					\
	_C_LABEL(__CONCAT(_,x)) = _C_LABEL(__CONCAT(__sys_,x));		\
	PIC_PROLOGUE(__sys_ ## x);					\
	SYSTRAP(x);							\
	bne a3,zero,err;						\
	PIC_RETURN();							\
err:									\
	PIC_TAILCALL(__cerror);						\
END(__sys_ ## x)

/*
 * Do a renamed or pseudo syscall (e.g., _exit()), where the entrypoint
 * and syscall name are not the same.
 */
#define PSEUDO_NOERROR(x)						\
LEAF(__sys_ ## x);							\
	.weak _C_LABEL(__CONCAT(_,x));					\
	_C_LABEL(__CONCAT(_,x)) = _C_LABEL(__CONCAT(__sys_,x));		\
	SYSTRAP(x);							\
	j ra;								\
END(__sys_ ## x)

#define PSEUDO(x)							\
LEAF(__sys_ ## x);							\
	.weak _C_LABEL(__CONCAT(_,x));					\
	_C_LABEL(__CONCAT(_,x)) = _C_LABEL(__CONCAT(__sys_,x));		\
	PIC_PROLOGUE(__sys_ ## x);					\
	SYSTRAP(x);							\
	bne a3,zero,err;						\
	PIC_RETURN();							\
err:									\
	PIC_TAILCALL(__cerror);						\
END(__sys_ ## x)

/* Do a system call where the _ioctl() is also custom */
#define NO_UNDERSCORE(x)						\
LEAF(__sys_ ## x);							\
	PIC_PROLOGUE(__sys_ ## x);					\
	SYSTRAP(x);							\
	bne a3,zero,err;						\
	PIC_RETURN();							\
err:									\
	PIC_TAILCALL(__cerror);						\
END(__sys_ ## x)
