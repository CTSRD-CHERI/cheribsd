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

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/proc.h>

#include <cheri/cheri.h>

#include <machine/frame.h>
#include <machine/riscvreg.h>
#include <machine/vmparam.h>

/* XXX: CHERI TODO: Probably should init this in locore on the BSP. */
extern void * __capability userspace_cap;

static void
cheri_cpu_startup(void)
{

	userspace_cap = scr_read(ddc);
}
SYSINIT(cheri_cpu_startup, SI_SUB_CPU, SI_ORDER_FIRST, cheri_cpu_startup,
    NULL);

void
hybridabi_thread_setregs(struct thread *td, unsigned long entry_addr)
{
	struct trapframe *tf;

	tf = td->td_frame;

	/* Set DDC to full user privilege. */
	tf->tf_ddc = (uintcap_t)cheri_capability_build_user_data(
	    CHERI_CAP_USER_DATA_PERMS, CHERI_CAP_USER_DATA_BASE,
	    CHERI_CAP_USER_DATA_LENGTH, CHERI_CAP_USER_DATA_OFFSET);

	/* Use 'entry_addr' as offset of PCC. */
	tf->tf_sepc = (uintcap_t)cheri_capability_build_user_code(
	    CHERI_CAP_USER_CODE_PERMS, CHERI_CAP_USER_CODE_BASE,
	    CHERI_CAP_USER_CODE_LENGTH, entry_addr);
}
