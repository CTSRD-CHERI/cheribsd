/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 John Baldwin
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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

#ifndef _MACHINE_CHERI_H_
#define	_MACHINE_CHERI_H_

#ifdef _KERNEL
/* Return userspace DDC and PCC of current thread. */
#define	__USER_DDC	((void * __capability)curthread->td_frame->tf_ddc)
#define	__USER_PCC	((void * __capability)curthread->td_frame->tf_sepc)

/* RISC-V always adds the base in CToPtr */
#define	__USER_DDC_OFFSET_ENABLED	1
#define	__USER_PCC_OFFSET_ENABLED	1

/*
 * CHERI-RISC-V-specific kernel utility functions.
 */
void	cheri_init_capabilities(void * __capability kroot);
int	cheri_stval_to_sicode(register_t stval);
void	hybridabi_thread_setregs(struct thread *td, unsigned long entry_addr);
#endif

/*
 * Special marker NOPs for QEMU to start / stop region
 * of interest in trace.
 */
#define	CHERI_START_TRACE	do {					\
	__asm__ __volatile__("slti zero, zero, 0x1b");                  \
} while(0)
#define	CHERI_STOP_TRACE	do {					\
	__asm__ __volatile__("slti zero, zero, 0x1e");                  \
} while(0)

#define	CHERI_START_USER_TRACE	do {					\
	__asm__ __volatile__("slti zero, zero, 0x2b");			\
} while(0)

#define	CHERI_STOP_USER_TRACE	do {					\
	__asm__ __volatile__("slti zero, zero, 0x2e");			\
} while(0)

#endif /* !_MACHINE_CHERI_H_ */
