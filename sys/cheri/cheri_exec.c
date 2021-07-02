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
#include <sys/elf.h>
#include <sys/exec.h>
#include <sys/imgact.h>
#include <sys/proc.h>
#include <sys/sysent.h>
#include <sys/systm.h>
#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

FEATURE(cheriabi, "CheriABI process support");
#ifdef __CHERI_PURE_CAPABILITY__
FEATURE(cheri_kernel, "Pure-capability ABI kernel");
#endif

/*
 * Helper routines to construct initial capabilities for CheriABI
 * programs.
 */

void * __capability
cheri_exec_pcc(struct thread *td, struct image_params *imgp)
{
	vm_offset_t code_start, code_end;
	size_t code_length;

	/*
	 * If we are executing a static binary we use end_addr as the
	 * end of the text segment. If $pcc is the start of rtld we
	 * use interp_end.  If we are executing rtld directly we can
	 * use end_addr to find the end of the rtld mapping.
	 */
	if (imgp->interp_end != 0) {
		code_start = imgp->interp_start;
		code_end = imgp->interp_end;
	} else {
		code_start = imgp->start_addr;
		code_end = imgp->end_addr;
	}

	code_length = code_end - code_start;
	/* Check that imgact_elf enforced capability representability. */
	MPASS(code_start == CHERI_REPRESENTABLE_BASE(code_start, code_length));
	MPASS(code_length == CHERI_REPRESENTABLE_LENGTH(code_length));
	KASSERT(code_start < code_end, ("%s: truncated PCC", __func__));
	return (cheri_capability_build_user_code(td, CHERI_CAP_USER_CODE_PERMS,
	    code_start, code_length, imgp->entry_addr - code_start));
}

void * __capability
cheri_sigcode_capability(struct thread *td)
{
	void * __capability tmpcap;
	struct proc *p = td->td_proc;
	struct sysentvec *sv;

	sv = p->p_sysent;
	KASSERT(PROC_HAS_SHP(p),
	    ("CheriABI requires shared page for sigcode"));

	tmpcap = (void * __capability)cheri_setboundsexact(
	    cheri_andperm(PROC_SIGCODE(p), CHERI_CAP_USER_CODE_PERMS),
	    *sv->sv_szsigcode);

	if (SV_PROC_FLAG(td->td_proc, SV_CHERI))
		tmpcap = cheri_capmode(tmpcap);

	return (cheri_sealentry(tmpcap));
}
