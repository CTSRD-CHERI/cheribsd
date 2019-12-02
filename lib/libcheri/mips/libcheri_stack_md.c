/*-
 * Copyright (c) 2014-2017 Robert N. M. Watson
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

#include <sys/cdefs.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/ucontext.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <machine/cpuregs.h>
#define	_WANT_MIPS_REGNUM
#include <machine/regnum.h>
#include <machine/sysarch.h>

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>

#include "libcheri_stack.h"
#include "libcheri_stack_internal.h"

/*
 * Unwind the trusted stack by the specified number of frames (or all) --
 * machine-dependent portion.
 */
int
libcheri_stack_unwind_md(ucontext_t *uap, struct libcheri_stack_frame *lcsfp,
    register_t ret)
{
	struct cheri_frame *cfp;
	register_t saved_mcreg0;

#ifdef __CHERI_PURE_CAPABILITY__
	cfp = &uap->uc_mcontext.mc_cheriframe;
#else
	cfp = (struct cheri_frame *)uap->uc_mcontext.mc_cp2state;
	if (cfp == NULL || uap->uc_mcontext.mc_cp2state_len != sizeof(*cfp)) {
		errno = ERANGE;
		return (-1);
	}
#endif

	/*
	 * Zero the capability register file, explicitly restoring $pcc and
	 * $csp from the last trusted-stack frame.
	 */
	memset(cfp, 0, sizeof(*cfp));
	cfp->cf_csp =  lcsfp->lcsf_caller_csp;
	cfp->cf_pcc = lcsfp->lcsf_caller_pcc;

	/*
	 * Zero the general-purpose register file.  restore not only $pc, but
	 * also the slot for $zero, which will hold a magic number across
	 * sigcode and sigreturn().  Also set a return value.
	 *
	 * XXXRW: The kernel unwinder sets V1 to the signal number?
	 */
	saved_mcreg0 = uap->uc_mcontext.mc_regs[0];
	memset(uap->uc_mcontext.mc_regs, 0, sizeof(uap->uc_mcontext.mc_regs));
	uap->uc_mcontext.mc_regs[0] = saved_mcreg0;
	uap->uc_mcontext.mc_pc = cheri_getoffset(cfp->cf_pcc);
	uap->uc_mcontext.mc_regs[V0] = ret;

	return (0);
}
