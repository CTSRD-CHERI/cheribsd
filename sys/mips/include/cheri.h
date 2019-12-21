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

#include <sys/types.h>
#include <machine/cherireg.h>

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

/*
 * CHERI-MIPS-specific kernel utility functions.
 */
struct sysentvec;
void	cheri_capability_set_user_sealcap(void * __capability *);
void	cheri_capability_set_user_sigcode(void * __capability *,
	    struct sysentvec *);
int	cheri_capcause_to_sicode(register_t capcause);

int	cheriabi_fetch_syscall_args(struct thread *td);
void	cheriabi_newthread_init(struct thread *td);

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
