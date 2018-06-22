/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2005, Joseph Koshy
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/pmc.h>
#include <sys/proc.h>
#include <sys/systm.h>

#include <machine/cpu.h>
#include <machine/md_var.h>
#include <machine/pmc_mdep.h>
#include <machine/stack.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>

/* XXX: Userland code compiled with gcc will need an heuristic
 * to be correctly detected. 
 */
#ifdef __clang__
#define PC_OFF 1
#define FP_OFF 0
#else
#define PC_OFF -1
#define FP_OFF -3
#endif

struct pmc_mdep *
pmc_md_initialize()
{
#ifdef CPU_XSCALE_IXP425
	if (cpu_class == CPU_CLASS_XSCALE)
		return pmc_xscale_initialize();
#endif
#ifdef CPU_CORTEXA
	if (cpu_class == CPU_CLASS_CORTEXA)
		return pmc_armv7_initialize();
#endif
	return NULL;
}

void
pmc_md_finalize(struct pmc_mdep *md)
{
#ifdef CPU_XSCALE_IXP425
	if (cpu_class == CPU_CLASS_XSCALE)
		pmc_xscale_finalize(md);
	else
		KASSERT(0, ("[arm,%d] Unknown CPU Class 0x%x", __LINE__,
		    cpu_class));
#endif
#ifdef CPU_CORTEXA
	if (cpu_class == CPU_CLASS_CORTEXA)
		pmc_armv7_finalize(md);
#endif
}

int
pmc_save_kernel_callchain(uintptr_t *cc, int maxsamples,
    struct trapframe *tf)
{
	uintptr_t pc, r, stackstart, stackend, fp;
	struct thread *td;
	int count;

	KASSERT(TRAPF_USERMODE(tf) == 0,("[arm,%d] not a kernel backtrace",
	    __LINE__));

	td = curthread;
	pc = PMC_TRAPFRAME_TO_PC(tf);
	*cc++ = pc;

	if (maxsamples <= 1)
		return (1);

	stackstart = (uintptr_t) td->td_kstack;
	stackend = (uintptr_t) td->td_kstack + td->td_kstack_pages * PAGE_SIZE;
	fp = PMC_TRAPFRAME_TO_FP(tf);

	if (!PMC_IN_KERNEL(pc) ||
	    !PMC_IN_KERNEL_STACK(fp, stackstart, stackend))
		return (1);

	for (count = 1; count < maxsamples; count++) {
		/* Use saved lr as pc. */
		r = fp + PC_OFF * sizeof(uintptr_t);
		if (!PMC_IN_KERNEL_STACK(r, stackstart, stackend))
			break;
		pc = *(uintptr_t *)r;
		if (!PMC_IN_KERNEL(pc))
			break;

		*cc++ = pc;

		/* Switch to next frame up */
		r = fp + FP_OFF * sizeof(uintptr_t);
		if (!PMC_IN_KERNEL_STACK(r, stackstart, stackend))
			break;
		fp = *(uintptr_t *)r;
		if (!PMC_IN_KERNEL_STACK(fp, stackstart, stackend))
			break;
	}

	return (count);
}

int
pmc_save_user_callchain(uintptr_t *cc, int maxsamples,
    struct trapframe *tf)
{
	uintptr_t pc, r, oldfp, fp;
	struct thread *td;
	int count;

	KASSERT(TRAPF_USERMODE(tf), ("[x86,%d] Not a user trap frame tf=%p",
	    __LINE__, (void *) tf));

	td = curthread;
	pc = PMC_TRAPFRAME_TO_PC(tf);
	*cc++ = pc;

	if (maxsamples <= 1)
		return (1);

	oldfp = fp = PMC_TRAPFRAME_TO_FP(tf);

	if (!PMC_IN_USERSPACE(pc) ||
	    !PMC_IN_USERSPACE(fp))
		return (1);

	for (count = 1; count < maxsamples; count++) {
		/* Use saved lr as pc. */
		r = fp + PC_OFF * sizeof(uintptr_t);
		if (copyin((void *)r, &pc, sizeof(pc)) != 0)
			break;
		if (!PMC_IN_USERSPACE(pc))
			break;

		*cc++ = pc;

		/* Switch to next frame up */
		oldfp = fp;
		r = fp + FP_OFF * sizeof(uintptr_t);
		if (copyin((void *)r, &fp, sizeof(fp)) != 0)
			break;
		if (fp < oldfp || !PMC_IN_USERSPACE(fp))
			break;
	}

	return (count);
}
