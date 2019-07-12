/*-
 * Copyright (c) 2011-2017 Robert N. M. Watson
 * Copyright (c) 2015 SRI International
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

#ifndef _MIPS_INCLUDE_CHERI_H_
#define	_MIPS_INCLUDE_CHERI_H_

#ifdef _KERNEL
#include <sys/sysctl.h>		/* SYSCTL_DECL() */
#endif

#include <machine/cherireg.h>

#include <sys/types.h>

/*
 * In the past, struct cheri_frame was the in-kernel and kernel<->user
 * structure holding CHERI register state for context switching.  It is now a
 * public structure for kernel<->user interaction (e.g., signals), and struct
 * trapframe is used within the kernel.  Regardless, correct preservation of
 * state in this structure is critical to both correctness and security.
 */
struct cheri_frame {
	/* DDC has special properties for MIPS load/store instructions. */
	void * __capability	cf_ddc;

	/*
	 * General-purpose capabilities -- note, numbering is from v1.17 of
	 * the CHERI ISA spec (ISAv5 draft).
	 */
	void * __capability	cf_c1;
	void * __capability	cf_c2;
	void * __capability	cf_c3;
	void * __capability	cf_c4;
	void * __capability	cf_c5;
	void * __capability	cf_c6;
	void * __capability	cf_c7;
	void * __capability	cf_c8;
	void * __capability	cf_c9;
	void * __capability	cf_c10;
	void * __capability	cf_csp;
	void * __capability	cf_c12;
	void * __capability	cf_c13;
	void * __capability	cf_c14;
	void * __capability	cf_c15;
	void * __capability	cf_c16;
	void * __capability	cf_c17;
	void * __capability	cf_c18;
	void * __capability	cf_c19;
	void * __capability	cf_c20;
	void * __capability	cf_c21;
	void * __capability	cf_c22;
	void * __capability	cf_c23;
	void * __capability	cf_c24;
	void * __capability	cf_c25;
	void * __capability	cf_idc;
	void * __capability	cf_c27;
	void * __capability	cf_c28;
	void * __capability	cf_c29;
	void * __capability	cf_c30;
	void * __capability	cf_c31;

	/*
	 * Program counter capability -- extracted from exception frame EPCC.
	 */
	void * __capability	cf_pcc;

	/*
	 * Padded out non-capability registers.
	 *
	 * XXXRW: The comment below on only updating for CP2 exceptions is
	 * incorrect, but should be made correct.
	 */
	register_t	cf_capcause;	/* Updated only on CP2 exceptions. */
	register_t	cf_capvalid;
#if (defined(CPU_CHERI) && !defined(CPU_CHERI128)) || (defined(_MIPS_SZCAP) && (_MIPS_SZCAP == 256))
	register_t	_cf_pad1[2];
#endif
};

#ifdef _KERNEL
/*
 * Data structure defining kernel per-thread caller-save state used in
 * voluntary context switches.  This is morally equivalent to pcb_context[].
 */
struct cheri_kframe {
	void * __capability	ckf_c17;
	void * __capability	ckf_c18;
	void * __capability	ckf_c19;
	void * __capability	ckf_c20;
	void * __capability	ckf_c21;
	void * __capability	ckf_c22;
	void * __capability	ckf_c23;
	void * __capability	ckf_c24;
};
#endif


#ifdef _KERNEL
#define _INLINE_CHERI_ASM_OPTIONS		\
	".set noreorder\n.set cheri_sysregs_accessible\n"
#else
#define _INLINE_CHERI_ASM_OPTIONS		\
	".set noreorder\n"
#endif


/*
 * CHERI capability register manipulation macros.
 */
#define	CHERI_CGETBASE(v, cb) do {					\
	__asm__ __volatile__ (						\
	    ".set push\n"						\
	  _INLINE_CHERI_ASM_OPTIONS					\
	    "cgetbase %0, $c%1\n"					\
	    ".set pop\n"						\
	    : "=r" (v) : "i" (cb));					\
} while (0)

#define	CHERI_CGETLEN(v, cb) do {					\
	__asm__ __volatile__ (						\
	    ".set push\n"						\
	  _INLINE_CHERI_ASM_OPTIONS					\
	    "cgetlen %0, $c%1\n"					\
	    ".set pop\n"						\
	    : "=r" (v) :"i" (cb));					\
} while (0)

#define	CHERI_CGETOFFSET(v, cb) do {					\
	__asm__ __volatile__ (						\
	    ".set push\n"						\
	    _INLINE_CHERI_ASM_OPTIONS					\
	    "cgetoffset %0, $c%1\n"					\
	    ".set pop\n"						\
	    : "=r" (v) : "i" (cb));					\
} while (0)

#define	CHERI_CGETTAG(v, cb) do {					\
	__asm__ __volatile__ (						\
	    ".set push\n"						\
	    _INLINE_CHERI_ASM_OPTIONS					\
	    "cgettag %0, $c%1\n"					\
	    ".set pop\n"						\
	    : "=r" (v) : "i" (cb));					\
} while (0)

#define	CHERI_CGETSEALED(v, cb) do {					\
	__asm__ __volatile__ (						\
	    ".set push\n"						\
	    _INLINE_CHERI_ASM_OPTIONS					\
	    "cgetsealed %0, $c%1\n"					\
	    ".set pop\n"						\
	    : "=r" (v) : "i" (cb));					\
} while (0)

#define	CHERI_CGETPERM(v, cb) do {					\
	__asm__ __volatile__ (						\
	    ".set push\n"						\
	    _INLINE_CHERI_ASM_OPTIONS					\
	    "cgetperm %0, $c%1\n"					\
	    ".set pop\n"						\
	    : "=r" (v) : "i" (cb));					\
} while (0)

#define	CHERI_CGETTYPE(v, cb) do {					\
	__asm__ __volatile__ (						\
	    ".set push\n"						\
	    _INLINE_CHERI_ASM_OPTIONS					\
	    "cgettype %0, $c%1\n"					\
	    ".set pop\n"						\
	    : "=r" (v) : "i" (cb));					\
} while (0)

#define	CHERI_CGETCAUSE(v) do {						\
	__asm__ __volatile__ (						\
	    ".set push\n"						\
	    _INLINE_CHERI_ASM_OPTIONS					\
	    "cgetcause %0\n"						\
	    ".set pop\n"						\
	    : "=r" (v));						\
} while (0)

#define	CHERI_CTOPTR(v, cb, ct) do {					\
	__asm__ __volatile__ (						\
	    ".set push\n"						\
	    _INLINE_CHERI_ASM_OPTIONS					\
	    "ctoptr %0, $c%1, $c%2\n"					\
	    ".set pop\n"						\
	    : "=r" (v) : "i" (cb), "i" (ct));				\
} while (0)

/*
 * Note that despite effectively being a CMove, CGetDefault doesn't require a
 * memory clobber: if it's writing to $ddc, it's a nop; otherwise, it's not
 * writing to $ddc so no clobber is needed.
 */
#define	CHERI_CGETDEFAULT(cd) do {					\
	__asm__ __volatile__ (						\
	    ".set push\n"						\
	    _INLINE_CHERI_ASM_OPTIONS					\
	    "cgetdefault $c%0\n"					\
	    ".set pop\n"						\
	    : : "i" (cd));						\
} while (0)

#define	CHERI_CGETEPCC(cd) do {						\
	__asm__ __volatile__ (						\
	    ".set push\n"						\
	    _INLINE_CHERI_ASM_OPTIONS					\
	    "cgetepcc $c%0\n"						\
	    ".set pop\n"						\
	    : : "i" (cd));						\
} while (0)

/*
 * Instructions that check capability values and could throw exceptions; no
 * capability-register value changes, so no clobbers required.
 */
#define	CHERI_CCHECKPERM(cs, v) do {					\
	__asm__ __volatile__ (						\
	    ".set push\n"						\
	    _INLINE_CHERI_ASM_OPTIONS					\
	    "ccheckperm $c%0, %1\n" 					\
	    ".set pop\n"						\
	    : : "i" (cd), "r" (v));					\
} while (0)

#define	CHERI_CCHECKTYPE(cs, cb) do {					\
	__asm__ __volatile__ (						\
	    ".set push\n"						\
	    _INLINE_CHERI_ASM_OPTIONS					\
	    "cchecktype $c%0, $c%1\n"					\
	    ".set pop\n"						\
	    : : "i" (cs), "i" (cb));					\
} while (0)

/*
 * Instructions relating to capability invocation, return, sealing, and
 * unsealing.  Memory clobbers are required for register manipulation when
 * targeting $ddc.  They are also required for both CCall and CReturn to
 * ensure that any memory write-back is done before invocation.
 *
 * XXXRW: Is the latter class of cases required?
 */
#define	CHERI_CSEAL(cd, cs, ct) do {					\
	if ((cd) == 0)							\
		__asm__ __volatile__ (					\
		    ".set push\n"					\
		    _INLINE_CHERI_ASM_OPTIONS				\
		    "cseal $c%0, $c%1, $c%2\n"				\
		    ".set pop\n"					\
		    : : "i" (cd), "i" (cs), "i" (ct) : "memory");	\
	else								\
		__asm__ __volatile__ (					\
		    ".set push\n"					\
		    _INLINE_CHERI_ASM_OPTIONS				\
		    "cseal $c%0, $c%1, $c%2\n"				\
		    ".set pop\n"					\
		    : : "i" (cd), "i" (cs), "i" (ct));			\
} while (0)

#define CHERI_CUNSEAL(cd, cb, ct) do {					\
	if ((cd) == 0)							\
		__asm__ __volatile__ (					\
		    ".set push\n"					\
		    _INLINE_CHERI_ASM_OPTIONS				\
		    "cunseal $c%0, $c%1, $c%2\n"			\
		    ".set pop\n"					\
		    : : "i" (cd), "i" (cb), "i" (ct) : "memory");	\
	else								\
		__asm__ __volatile__ (					\
		    ".set push\n"					\
		    _INLINE_CHERI_ASM_OPTIONS				\
		    "cunseal $c%0, $c%1, $c%2\n"			\
		    ".set pop\n"					\
		    : : "i" (cd), "i" (cb), "i" (ct));			\
} while (0)

#define	CHERI_CCALL_TRAP(cs, cb) do {					\
	__asm__ __volatile__ (						\
	    ".set push\n"						\
	    _INLINE_CHERI_ASM_OPTIONS					\
	    "CCallTrap $c%0, $c%1\n" /* no branch delay slot */		\
	    ".set pop\n"						\
	    : :	"i" (cs), "i" (cb) : "memory");				\
} while (0)

#define	CHERI_CRETURN() do {						\
	__asm__ __volatile__ (						\
	    ".set push\n"						\
	    _INLINE_CHERI_ASM_OPTIONS					\
	    "creturn\n"							\
	    ".set pop\n"						\
	    : : : "memory");						\
} while (0)

/*
 * Capability store; while this doesn't muck with $ddc, it does require a
 * memory clobber.
 */
#define	CHERI_CSC(cs, cb, regbase, offset) do {				\
	__asm__ __volatile__ (						\
	    ".set push\n"						\
	    _INLINE_CHERI_ASM_OPTIONS					\
	    "csc $c%0, %1, %2($c%3)\n"					\
	    ".set pop\n"						\
	    : : "i" (cs), "r" (regbase), "i" (offset), "i" (cb) :	\
	    "memory");							\
} while (0)

/*
 * Data stores; while these don't muck with $ddc, they do require memory
 * clobbers.
 */
#define	CHERI_CSB(rs, rt, offset, cb) do {				\
	__asm__ __volatile__ (						\
	    ".set push\n"						\
	    _INLINE_CHERI_ASM_OPTIONS					\
	    "csb %0, %1, %2($c%3)\n"					\
	    ".set pop\n"						\
	    : : "r" (rs), "r" (rt), "i" (offset), "i" (cb) : "memory");	\
} while (0)

#define	CHERI_CSH(rs, rt, offset, cb) do {				\
	__asm__ __volatile__ (						\
	    ".set push\n"						\
	    _INLINE_CHERI_ASM_OPTIONS					\
	    "csh %0, %1, %2($c%3)\n"					\
	    ".set pop\n"						\
	    : : "r" (rs), "r" (rt), "i" (offset), "i" (cb) : "memory");	\
} while (0)

#define	CHERI_CSW(rs, rt, offset, cb) do {				\
	__asm__ __volatile__ (						\
	    ".set push\n"						\
	    _INLINE_CHERI_ASM_OPTIONS					\
	    "csw %0, %1, %2($c%3)\n"					\
	    ".set pop\n"						\
	    : : "r" (rs), "r" (rt), "i" (offset), "i" (cb) : "memory");	\
} while (0)

#define	CHERI_CSD(rs, rt, offset, cb) do {				\
	__asm__ __volatile__ (						\
	    ".set push\n"						\
	    _INLINE_CHERI_ASM_OPTIONS					\
	    "csd %0, %1, %2($c%3)\n"					\
	    ".set pop\n"						\
	    : : "r" (rs), "r" (rt), "i" (offset), "i" (cb) : "memory");	\
} while (0)

/*
 * Data loads: while these don't much with $ddc, they do require memory
 * clobbers.
 */
#define	CHERI_CLB(rd, rt, offset, cb) do {				\
	__asm__ __volatile__ (						\
	    ".set push\n"						\
	    _INLINE_CHERI_ASM_OPTIONS					\
	    "clb %0, %1, %2($c%3)\n"					\
	    ".set pop\n"						\
	     : "=r" (rd) : "r" (rt), "i" (offset),"i" (cb) : "memory");	\
} while (0)

#define	CHERI_CLH(rd, rt, offset, cb) do {				\
	__asm__ __volatile__ (						\
	    ".set push\n"						\
	    _INLINE_CHERI_ASM_OPTIONS					\
	    "clh %0, %1, %2($c%3)\n"					\
	    ".set pop\n"						\
	    : "=r" (rd) : "r" (rt), "i" (offset), "i" (cb) : "memory");	\
} while (0)

#define	CHERI_CLW(rd, rt, offset, cb) do {				\
	__asm__ __volatile__ (						\
	    ".set push\n"						\
	    _INLINE_CHERI_ASM_OPTIONS					\
	    "clw %0, %1, %2($c%3)\n"					\
	    ".set pop\n"						\
	    : "=r" (rd) : "r" (rt), "i" (offset), "i" (cb) : "memory");	\
} while (0)

#define	CHERI_CLD(rd, rt, offset, cb) do {				\
	__asm__ __volatile__ (						\
	    ".set push\n"						\
	    _INLINE_CHERI_ASM_OPTIONS					\
	    "cld %0, %1, %2($c%3)\n"					\
	    ".set pop\n"						\
	    : "=r" (rd) : "r" (rt), "i" (offset), "i" (cb) : "memory");	\
} while (0)

#define	CHERI_CLBU(rd, rt, offset, cb) do {				\
	__asm__ __volatile__ (						\
	    ".set push\n"						\
	    _INLINE_CHERI_ASM_OPTIONS					\
	    "clbu %0, %1, %2($c%3)\n"					\
	    ".set pop\n"						\
	    : "=r" (rd) : "r" (rt), "i" (offset), "i" (cb) : "memory");	\
} while (0)

#define	CHERI_CLHU(rd, rt, offset, cb) do {				\
	__asm__ __volatile__ (						\
	    ".set push\n"						\
	    _INLINE_CHERI_ASM_OPTIONS					\
	    "clhu %0, %1, %2($c%3)\n"					\
	    ".set pop\n"						\
	    : "=r" (rd) : "r" (rt), "i" (offset), "i" (cb) : "memory");	\
} while (0)

#define	CHERI_CLWU(rd, rt, offset, cb) do {				\
	__asm__ __volatile__ (						\
	    ".set push\n"						\
	    _INLINE_CHERI_ASM_OPTIONS					\
	    "clwu %0, %1, %2($c%3)\n"					\
	    ".set pop\n"						\
	    : "=r" (rd) : "r" (rt), "i" (offset), "i" (cb) : "memory");	\
} while (0)

/*
 * Routines that modify or replace values in capability registers, and that if
 * if used on $ddc, require the compiler to write registers back to memory,
 * and reload afterwards, since we may effectively be changing the compiler-
 * visible address space.  This is also necessary for permissions changes as
 * well, to ensure that write-back occurs before a possible loss of store
 * permission.
 */
#define	CHERI_CGETPCC(v, cd) do {					\
	if ((cd) == 0)							\
		__asm__ __volatile__ (					\
		    ".set push\n"					\
		    _INLINE_CHERI_ASM_OPTIONS				\
		    "cgetpcc %0, $c%1\n"				\
		    ".set pop\n"					\
		    : "=r" (v) : "i" (cd) : "memory");			\
	else								\
		__asm__ __volatile__ (					\
		    ".set push\n"					\
		    _INLINE_CHERI_ASM_OPTIONS				\
		    "cgetpcc %0, $c%1\n"				\
		    ".set pop\n"					\
		    : "=r" (v) : "i" (cd));				\
} while (0)

#define	CHERI_CINCBASE(cd, cb, v) do {					\
	if ((cd) == 0)							\
		__asm__ __volatile__ (					\
		    ".set push\n"					\
		    _INLINE_CHERI_ASM_OPTIONS				\
		    "cincbase $c%0, $c%1, %2\n"				\
		    ".set pop\n"					\
		    : :	"i" (cd), "i" (cb), "r" (v) : "memory");	\
	else								\
		__asm__ __volatile__ (					\
		    ".set push\n"					\
		    _INLINE_CHERI_ASM_OPTIONS				\
		    "cincbase $c%0, $c%1, %2\n"				\
		    ".set pop\n"					\
		    : :	"i" (cd), "i" (cb), "r" (v));			\
} while (0)

#define	CHERI_CINCOFFSET(cd, cb, v) do {				\
	if ((cd) == 0)							\
		__asm__ __volatile__ (					\
		    ".set push\n"					\
		    _INLINE_CHERI_ASM_OPTIONS				\
		    "cincoffset $c%0, $c%1, %2\n"			\
		    ".set pop\n"					\
		    : :	"i" (cd), "i" (cb), "r" (v) : "memory");	\
	else								\
		__asm__ __volatile__ (					\
		    ".set push\n"					\
		    _INLINE_CHERI_ASM_OPTIONS				\
		    "cincoffset $c%0, $c%1, %2\n"			\
		    ".set pop\n"					\
		    : :	"i" (cd), "i" (cb), "r" (v));			\
} while (0)

#if (defined(CPU_CHERI) && !defined(CPU_CHERI128)) || (defined(_MIPS_SZCAP) && (_MIPS_SZCAP == 256))
#define	CHERI_CMOVE(cd, cb) do {					\
	if ((cd) == 0)							\
		__asm__ __volatile__ (					\
		    ".set push\n"					\
		    _INLINE_CHERI_ASM_OPTIONS				\
		    "cmove $c%0, $c%1\n"				\
		    ".set pop\n"					\
		    : : "i" (cd), "i" (cb) : "memory");			\
	else								\
		__asm__ __volatile__ (					\
		    ".set push\n"					\
		    _INLINE_CHERI_ASM_OPTIONS				\
		    "cmove $c%0, $c%1\n"				\
		    ".set pop\n"					\
		    : : "i" (cd), "i" (cb));				\
} while (0)
#else /* 128-bit CHERI */
#define	CHERI_CMOVE(cd, cb)	CHERI_CINCOFFSET(cd, cb, 0)
#endif /* 128-bit CHERI */

#define	CHERI_CSETDEFAULT(cb) do {					\
	__asm__ __volatile__ (						\
	    ".set push\n"						\
	    _INLINE_CHERI_ASM_OPTIONS					\
	    "csetdefault %c%0\n"					\
	    ".set pop\n"						\
	    : : "i" (cb) : "memory");					\
} while (0)

#define	CHERI_CSETLEN(cd, cb, v) do {					\
	if ((cd) == 0)							\
		__asm__ __volatile__ (					\
		    ".set push\n"					\
		    _INLINE_CHERI_ASM_OPTIONS				\
		    "csetlen $c%0, $c%1, %2\n"				\
		    ".set pop\n"					\
		    : :	"i" (cd), "i" (cb), "r" (v) : "memory");	\
	else								\
		__asm__ __volatile__ (					\
		    ".set push\n"					\
		    _INLINE_CHERI_ASM_OPTIONS				\
		    "csetlen $c%0, $c%1, %2\n"				\
		    ".set pop\n"					\
		    : :	"i" (cd), "i" (cb), "r" (v));			\
} while (0)

#define	CHERI_CSETOFFSET(cd, cb, v) do {				\
	if ((cd) == 0)							\
		__asm__ __volatile__ (					\
		    ".set push\n"					\
		    _INLINE_CHERI_ASM_OPTIONS				\
		    "csetoffset $c%0, $c%1, %2\n"			\
		    ".set pop\n"					\
		    : :	"i" (cd), "i" (cb), "r" (v) : "memory");	\
	else								\
		__asm__ __volatile__ (					\
		    ".set push\n"					\
		    _INLINE_CHERI_ASM_OPTIONS				\
		    "csetoffset $c%0, $c%1, %2\n"			\
		    ".set pop\n"					\
		    : :	"i" (cd), "i" (cb), "r" (v));			\
} while (0)

#define	CHERI_CCLEARTAG(cd, cb) do {					\
	if ((cd) == 0)							\
		__asm__ __volatile__ (					\
		    ".set push\n"					\
		    _INLINE_CHERI_ASM_OPTIONS				\
		    "ccleartag $c%0, $c%1\n"				\
		    ".set pop\n"					\
		    : : "i" (cd), "i" (cb) : "memory");			\
	else								\
		__asm__ __volatile__ (					\
		    ".set push\n"					\
		    _INLINE_CHERI_ASM_OPTIONS				\
		    "ccleartag $c%0, $c%1\n"				\
		    ".set pop\n"					\
		    : :	"i" (cd), "i" (cb));				\
} while (0)

#define	CHERI_CANDPERM(cd, cb, v) do {					\
	if ((cd) == 0)							\
		__asm__ __volatile__ (					\
		    ".set push\n"					\
		    _INLINE_CHERI_ASM_OPTIONS				\
		    "candperm $c%0, $c%1, %2\n"				\
		    ".set pop\n"					\
		    : :	"i" (cd), "i" (cb), "r" (v) : "memory");	\
	else								\
		__asm__ __volatile__ (					\
		    ".set push\n"					\
		    _INLINE_CHERI_ASM_OPTIONS				\
		    "candperm $c%0, $c%1, %2\n"				\
		    ".set pop\n"					\
		    : :	"i" (cd), "i" (cb), "r" (v));			\
} while (0)

#define	CHERI_CSETBOUNDS(cd, cb, v) do {				\
	if ((cd) == 0)							\
		__asm__ __volatile__ (					\
		    ".set push\n"					\
		    _INLINE_CHERI_ASM_OPTIONS				\
		    "csetbounds $c%0, $c%1, %2\n"			\
		    ".set pop\n"					\
		    : :	"i" (cd), "i" (cb), "r" (v) : "memory");	\
	else								\
		__asm__ __volatile__ (					\
		    ".set push\n"					\
		    _INLINE_CHERI_ASM_OPTIONS				\
		    "csetbounds $c%0, $c%1, %2\n"			\
		    ".set pop\n"					\
		    : :	"i" (cd), "i" (cb), "r" (v));			\
} while (0)

#define	CHERI_CFROMPTR(cd, cb, v) do {					\
	if ((cd) == 0)							\
		__asm__ __volatile__ (					\
		    ".set push\n"					\
		    _INLINE_CHERI_ASM_OPTIONS				\
		    "cfromptr $c%0, $c%1, %2\n"				\
		    ".set pop\n"					\
		    : :	"i" (cd), "i" (cb), "r" (v) : "memory");	\
	else								\
		__asm__ __volatile__ (					\
		    ".set push\n"					\
		    _INLINE_CHERI_ASM_OPTIONS				\
		    "cfromptr $c%0, $c%1, %2\n"				\
		    ".set pop\n"					\
		    : :	"i" (cd), "i" (cb), "r" (v));			\
} while (0)

#define	CHERI_CLC(cd, cb, regbase, offset) do {				\
	if ((cd) == 0)							\
		__asm__ __volatile__ (					\
		    ".set push\n"					\
		    _INLINE_CHERI_ASM_OPTIONS				\
		    "clc $c%0, %1, %2($c%3)\n"				\
		    ".set pop\n"					\
		    : :	"i" (cd), "r" (regbase), "i" (offset), "i" (cb)	\
		    : "memory");					\
	else								\
		__asm__ __volatile__ (					\
		    ".set push\n"					\
		    _INLINE_CHERI_ASM_OPTIONS				\
		    "clc $c%0, %1, %2($c%3)\n"				\
		    ".set pop\n"					\
		    : : "i" (cd), "r" (regbase), "i" (offset),		\
		    "i" (cb));						\
} while (0)

/*
 * CHERI-MIPS-specific kernel utility functions.
 */
#ifdef _KERNEL
struct sysentvec;
void	cheri_capability_set_user_sealcap(void * __capability *);
void	cheri_capability_set_user_sigcode(void * __capability *,
	    struct sysentvec *);
int	cheri_capcause_to_sicode(register_t capcause);

void	hybridabi_exec_setregs(struct thread *td, unsigned long entry_addr);
void	hybridabi_newthread_setregs(struct thread *td,
	    unsigned long entry_addr);
#endif

/*
 * Routines for measuring time -- depends on a later MIPS userspace cycle
 * counter.
 */
static __inline uint32_t
cheri_get_cyclecount(void)
{
	uint64_t _time;

	__asm__ __volatile__ (
	    ".set push\n"
	    ".set noreorder\n"
	    "rdhwr %0, $2\n"
	   ".set pop\n"
	    : "=r" (_time));
	return (_time & 0xffffffff);
}

/*
 * Special marker NOPs recognised by analyse_trace.py to start / stop region
 * of interest in trace.
 */
#define	CHERI_START_TRACE	do {					\
	__asm__ __volatile__("li $0, 0xbeef");				\
} while(0)
#define	CHERI_STOP_TRACE	do {					\
	__asm__ __volatile__("li $0, 0xdead");				\
} while(0)

#ifdef _KERNEL
/*
 * Special marker NOP to log messages in instruction traces.
 */
void cheri_trace_log(void *buf, size_t len, int format);

#define	CHERI_TRACE_STRING(s)						\
	cheri_trace_log((s), strlen((s)), 0);
#define CHERI_TRACE_MEM(buf, len)					\
	cheri_trace_log((buf), (len), 1);

#endif /* !_KERNEL */

#endif /* _MIPS_INCLUDE_CHERI_H_ */
