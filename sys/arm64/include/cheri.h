/*-
 * Copyright (c) 2016 Andrew Turner
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
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
 *
 * $FreeBSD$
 */

#ifndef _MACHINE_CHERI_H_
#define _MACHINE_CHERI_H_

#ifdef __CHERI_PURE_CAPABILITY__
#define	ASM_PTR_CONSTR "C"
#else
#define	ASM_PTR_CONSTR "r"
#endif

#ifdef _KERNEL
#define	__USER_DDC	((void * __capability)curthread->td_frame->tf_ddc)
#define	__USER_PCC	((void * __capability)curthread->td_frame->tf_elr)

struct thread;

/* Used to set DDC_EL0 in psci call functions. */
extern void * __capability smccc_ddc_el0;

/*
 * Morello specific kernel utility functions.
 */
void		cheri_init_capabilities(void * __capability kroot);
void		hybridabi_thread_setregs(struct thread *td, unsigned long entry_addr);
int		cheri_esr_to_sicode(uint64_t esr);
const char	*cheri_fsc_string(uint8_t fsc);
#endif

#endif /* _MACHINE_CHERI_H_ */
