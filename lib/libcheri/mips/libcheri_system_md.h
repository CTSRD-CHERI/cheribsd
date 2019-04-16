/*-
 * Copyright (c) 2012-2017 Robert N. M. Watson
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

#ifndef _LIBCHERI_SYSTEM_MD_H_
#define	_LIBCHERI_SYSTEM_MD_H_

/* XXXRW: Needed temporarily for CHERI_ASM_CMOVE(). */
#define	_CHERI_INTERNAL
#define	zero	$zero
#include <machine/cheriasm.h>
#undef _CHERI_INTERNAL

/*
 * CHERI system class CCall landing pad code: catches CCalls inbound from
 * sandboxes seeking system services, and bootstraps C code.  A number of
 * differences from sandboxed code, including how $c0 is handled, and not
 * setting up the C heap.
 *
 * Temporary ABI conventions for the hybrid ABI:
 *    $sp contains a pointer to the top of the stack; capability aligned
 *    $fp contains a pointer to the top of the stack; capability aligned
 *
 *    Or for the pure-capability ABI:
 *
 *    $csp contains a pointer to the top of the stack; capability aligned
 *
 *    $a0-$a7 contain user arguments
 *    $v0, $v1 contain user return values
 *
 *    $c0, $pcc contain access to (100% overlapped) sandbox code and data
 *
 *    $c1, $c2 contain the invoked object capability
 *    $c3-$c10 contain user capability arguments
 *
 *    $c26 contains the invoked data capability installed by CCall; unlike
 *      sandboxed versions of this code, this points at the sandbox_object,
 *      which a suitable $ddc can be loaded from.
 *
 * For now, assume:
 * (1) The caller has not set up the general-purpose register context, that's
 *     our job.
 * (2) That there is no concurrent sandbox use -- we have a single stack on
 *     the inbound path, which can't be the long-term solution.
 */

#ifdef __CHERI_PURE_CAPABILITY__

#ifdef __CHERI_CAPABILITY_TABLE__

/* TODO: Support other captable ABIs that aren't pcrel */

#define	LIBCHERI_CLASS_ASM(class)					\
	.text;								\
	.option pic0;							\
	.global __libcheri_ ## class ## _entry;				\
	.type __libcheri_ ## class ## _entry,@function;			\
	.ent __libcheri_ ## class ## _entry;				\
__libcheri_ ## class ## _entry:						\
	/*								\
	 * Load sandbox object's DDC via IDC.				\
	 */								\
	clc	$c12, zero, (4*CHERICAP_SIZE)($c26);			\
	csetdefault	$c12;						\
									\
	/*								\
	 * Install global invocation stack.  NB: this means we can't	\
	 * support recursion or concurrency.  Further note: this is	\
	 * shared by all classes outside of the sandbox.		\
	 */								\
	lui $t0, %hi(%neg(%captab_rel(0f)));				\
	daddiu $t0, $t0, %lo(%neg(%captab_rel(0f)));			\
0:	cgetpcc	$c12;							\
	cincoffset	$c12, $c12, $t0;				\
	clcbi	$c12, %captab20(__libcheri_enter_stack_csp)($c12);	\
	clc	$csp, zero, 0($c12);					\
									\
	/*								\
	 * Set up global pointer.					\
	 */								\
	dla	$gp, _gp;						\
									\
	/*								\
	 * The fourth entry of $idc is a method vtable.  If it is a	\
	 * valid capability, then load the address at offset $v0	\
	 * rather than using the "enter" functions.			\
	 */								\
	clc	$c12, zero, (3*CHERICAP_SIZE)($c26);			\
	cld	$t9, $v0, 0($c12);					\
	dla	$ra, 1f;						\
	cgetpcc	$c12;							\
	csetoffset	$c12, $c12, $t9;				\
	cjalr	$c12, $c17;						\
	nop;			/* Branch-delay slot */			\
									\
1:									\
	/*								\
	 * Return to caller - load creturn capability from		\
	 * __libcheri_object_creturn into $c1, $c2, and then ccall.	\
	 */								\
	lui $t0, %hi(%neg(%captab_rel(2f)));				\
	daddiu $t0, $t0, %lo(%neg(%captab_rel(2f)));			\
2:	cgetpcc	$c2;							\
	cincoffset	$c2, $c2, $t0;					\
	clcbi	$c2, %captab20(__libcheri_object_creturn)($c2);		\
	clc	$c1, zero, 0($c2);					\
	clc	$c2, zero, CHERICAP_SIZE($c2);				\
	CCALL($c1, $c2);						\
									\
$__libcheri_ ## class ## _entry_end:					\
	.end __libcheri_## class ## _entry;				\
	.size __libcheri_ ## class ## _entry,$__libcheri_ ## class ## _entry_end - __libcheri_ ## class ## _entry

#else /* !__CHERI_CAPABILITY_TABLE__ */

#define	LIBCHERI_CLASS_ASM(class)					\
	.text;								\
	.option pic0;							\
	.global __libcheri_ ## class ## _entry;				\
	.type __libcheri_ ## class ## _entry,@function;			\
	.ent __libcheri_ ## class ## _entry;				\
__libcheri_ ## class ## _entry:						\
									\
	/*								\
	 * Load sandbox object's DDC via IDC.				\
	 */								\
	clc	$c12, zero, (4*CHERICAP_SIZE)($c26);			\
	csetdefault	$c12;						\
									\
	/*								\
	 * Install global invocation stack.  NB: this means we can't	\
	 * support recursion or concurrency.  Further note: this is	\
	 * shared by all classes outside of the sandbox.		\
	 */								\
	dla	$t0, __libcheri_enter_stack_csp;			\
	clc	$csp, $t0, 0($c12);					\
									\
	/*								\
	 * Set up global pointer.					\
	 */								\
	dla	$gp, _gp;						\
									\
	/*								\
	 * The fourth entry of $idc is a method vtable.  If it is a	\
	 * valid capability, then load the address at offset $v0	\
	 * rather than using the "enter" functions.			\
	 */								\
	clc	$c12, zero, (3*CHERICAP_SIZE)($c26);			\
	cld	$t9, $v0, 0($c12);					\
	dla	$ra, 0f;						\
	cgetpcc	$c12;							\
	csetoffset	$c12, $c12, $t9;				\
	cjalr	$c12, $c17;						\
	nop;			/* Branch-delay slot */			\
									\
0:									\
	/*								\
	 * Return to caller - load creturn capability from		\
	 * __libcheri_object_creturn into $c1, $c2, and then ccall.	\
	 */								\
	dla	$t0, __libcheri_object_creturn;				\
	cgetdefault	$c2;						\
	clc	$c1, $t0, 0($c2);					\
	clc	$c2, $t0, CHERICAP_SIZE($c2);				\
	CCALL($c1, $c2);						\
									\
$__libcheri_ ## class ## _entry_end:					\
	.end __libcheri_## class ## _entry;				\
	.size __libcheri_ ## class ## _entry,$__libcheri_ ## class ## _entry_end - __libcheri_ ## class ## _entry

#endif /* !__CHERI_CAPABILITY_TABLE__ */

#else /* !__CHERI_PURE_CAPABILITY__ */

#define	LIBCHERI_CLASS_ASM(class)					\
	.text;								\
	.option pic0;							\
	.global __libcheri_ ## class ## _entry;				\
	.type __libcheri_ ## class ## _entry,@function;			\
	.ent __libcheri_ ## class ## _entry;				\
__libcheri_ ## class ## _entry:						\
									\
	/*								\
	 * Load sandbox object's DDC via IDC.				\
	 */								\
	clc	$c12, zero, (4*CHERICAP_SIZE)($c26);			\
	csetdefault	$c12;						\
									\
	/*								\
	 * Install global invocation stack.  NB: this means we can't	\
	 * support recursion or concurrency.  Further note: this is	\
	 * shared by all classes outside of the sandbox.		\
	 */								\
	dla	$sp, __libcheri_enter_stack_cap;				\
	clc	$c11, $sp, 0($c12);					\
	dla	$sp, __libcheri_enter_stack_sp;				\
	cld	$sp, $sp, 0($c12);					\
	move	$fp, $sp;						\
									\
	/*								\
	 * Set up global pointer.					\
	 */								\
	dla	$gp, _gp;						\
									\
	/*								\
	 * The fourth entry of $idc is a method vtable.  If it is a	\
	 * valid capability, then load the address at offset $v0	\
	 * rather than using the "enter" functions.			\
	 */								\
	clc	$c12, zero, (3*CHERICAP_SIZE)($c26);			\
	cld	$t9, $v0, 0($c12);					\
	dla	$ra, 0f;						\
	cgetpcc	$c12;							\
	csetoffset	$c12, $c12, $t9;				\
	cjalr	$c12, $c17;						\
	nop;			/* Branch-delay slot */			\
									\
0:									\
	/*								\
	 * Return to caller - load creturn capability from		\
	 * __cheri_object_creturn into $c1, $c2, and then ccall.	\
	 */								\
	dla	$t0, __libcheri_object_creturn;				\
	cgetdefault	$c2;						\
	clc	$c1, $t0, 0($c2);					\
	clc	$c2, $t0, CHERICAP_SIZE($c2);				\
	CCALL($c1, $c2);						\
									\
$__libcheri_ ## class ## _entry_end:					\
	.end __libcheri_## class ## _entry;				\
	.size __libcheri_ ## class ## _entry,$__libcheri_ ## class ## _entry_end - __libcheri_ ## class ## _entry

#endif /* !__CHERI_PURE_CAPABILITY__ */

#define	LIBCHERI_CLASS_DECL(class)					\
	extern void (__libcheri_## class ## _entry)(void);

#define	LIBCHERI_CLASS_ENTRY(class)					\
	(__libcheri_## class ## _entry)

#endif /* _LIBCHERI_SYSTEM_MD_H_ */
