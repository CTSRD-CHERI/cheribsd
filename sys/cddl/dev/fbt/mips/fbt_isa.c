/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * Portions Copyright 2006-2008 John Birrell jb@freebsd.org
 * Portions Copyright 2013 Justin Hibbits jhibbits@freebsd.org
 * Portions Copyright 2013 Howard Su howardsu@freebsd.org
 * Portions Copyright 2015-2016 Ruslan Bukin <br@bsdpad.com>
 *
 * $FreeBSD$
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/dtrace.h>
#include <sys/sysent.h>

#include <machine/cpuregs.h>
#include <machine/cache.h>

#include <sys/param.h>
#include <sys/sysctl.h>

#include "fbt.h"

#define	FBT_PATCHVAL		(MIPS_BREAK_INSTR)
#define	FBT_ENTRY		"entry"
#define	FBT_RETURN		"return"

#define FBT_PARAMETER_CAPABILITY 0x1
#define FBT_PARAMETER_FLOAT 0x2
#define FBT_PARAMETER_OTHERS 0x3
#define FBT_PARAMETER_UNKNOWN 0x4


extern int dtrace_cap_parameters;


static int
fbt_get_params_type(fbt_probe_t *probe, int inx)
{
	dtrace_argdesc_t desc;
	desc.dtargd_ndx = inx;

	fbt_getargdesc(NULL, 0, probe, &desc);
	// TODO(nicomazz): in a hybrid kernel, a pointer isn't always a
	//     capability. This check will change when we can distinguish them.
	if (strstr(desc.dtargd_native, "*"))
		return FBT_PARAMETER_CAPABILITY;

	if (strstr(desc.dtargd_native, "float"))
		return FBT_PARAMETER_FLOAT;

	return FBT_PARAMETER_OTHERS;
}

static void
fbt_get_params(struct trapframe *frame, fbt_probe_t *fbt, uintcap_t *params)
{
	void *__capability *cap_registers;
	register_t *normal_registers;
	int n_inx, c_inx;

	cap_registers = &frame->c3;
	normal_registers = &frame->a0;

	n_inx = 0;
	c_inx = 0;

	if (fbt->pointer_args == -1) {
		fbt->pointer_args = 0;
		for (int i = 0; i < 5; i++)
			if (fbt_get_params_type(fbt, i) ==
			    FBT_PARAMETER_CAPABILITY)
				fbt->pointer_args |= (1 << i);
	}

	for (int i = 0; i < 5; i++) {
		if ((fbt->pointer_args >> i) & 1)
			params[i] = (uintcap_t)cap_registers[c_inx++];
		else
			params[i] = normal_registers[n_inx++];

	}
}

int
fbt_invop(uintptr_t addr, struct trapframe *frame, uintptr_t rval)
{
	solaris_cpu_t *cpu;
	fbt_probe_t *fbt;

	cpu = &solaris_cpu[curcpu];
	fbt = fbt_probetab[FBT_ADDR2NDX(addr)];

	for (; fbt != NULL; fbt = fbt->fbtp_hashnext) {
		if ((uintptr_t)fbt->fbtp_patchpoint == addr) {
			cpu->cpu_dtrace_caller = addr;

			if (!SV_CURPROC_FLAG(SV_CHERI) || !dtrace_cap_parameters) {
				dtrace_probe(fbt->fbtp_id, frame->a0, frame->a1,
				    frame->a2, frame->a3, frame->a4);
			} else {
				uintcap_t params[5];

				fbt_get_params(frame, fbt, params);

				dtrace_probe(fbt->fbtp_id, params[0], params[1],
				    params[2], params[3], params[4]);
			}

			cpu->cpu_dtrace_caller = 0;
			return (fbt->fbtp_savedval);
		}
	}

	return (0);
}

void
fbt_patch_tracepoint(fbt_probe_t *fbt, fbt_patchval_t val)
{

	*fbt->fbtp_patchpoint = val;
	mips_icache_sync_range((vm_offset_t)fbt->fbtp_patchpoint, 4);
}

int
fbt_provide_module_function(linker_file_t lf, int symindx,
    linker_symval_t *symval, void *opaque)
{
	fbt_probe_t *fbt, *retfbt;
	uint32_t *instr, *limit;
	const char *name;
	char *modname;

	modname = opaque;
	name = symval->name;

	/* Check if function is excluded from instrumentation */
	if (fbt_excluded(name))
		return (0);

	instr = (uint32_t *)(symval->value);
	limit = (uint32_t *)(symval->value + symval->size);

	/* Look for store double to ra register */
	for (; instr < limit; instr++) {
		if ((*instr & LDSD_RA_SP_MASK) == SD_RA_SP)
			break;
	}

	if (instr >= limit)
		return (0);

	fbt = malloc(sizeof (fbt_probe_t), M_FBT, M_WAITOK | M_ZERO);
	fbt->fbtp_name = name;
	fbt->fbtp_id = dtrace_probe_create(fbt_id, modname,
	    name, FBT_ENTRY, 3, fbt);
	fbt->fbtp_patchpoint = instr;
	fbt->fbtp_ctl = lf;
	fbt->fbtp_loadcnt = lf->loadcnt;
	fbt->fbtp_savedval = *instr;
	fbt->fbtp_patchval = FBT_PATCHVAL;
	fbt->fbtp_rval = DTRACE_INVOP_SD;
	fbt->fbtp_symindx = symindx;

	fbt->fbtp_hashnext = fbt_probetab[FBT_ADDR2NDX(instr)];
	fbt_probetab[FBT_ADDR2NDX(instr)] = fbt;

	fbt->pointer_args = -1;
	lf->fbt_nentries++;

	retfbt = NULL;
again:
	for (; instr < limit; instr++) {
		if ((*instr & LDSD_RA_SP_MASK) == LD_RA_SP) {
			break;
		}
	}

	if (instr >= limit)
		return (0);

	/*
	 * We have a winner!
	 */
	fbt = malloc(sizeof (fbt_probe_t), M_FBT, M_WAITOK | M_ZERO);
	fbt->fbtp_name = name;
	if (retfbt == NULL) {
		fbt->fbtp_id = dtrace_probe_create(fbt_id, modname,
		    name, FBT_RETURN, 3, fbt);
	} else {
		retfbt->fbtp_probenext = fbt;
		fbt->fbtp_id = retfbt->fbtp_id;
	}
	retfbt = fbt;

	fbt->fbtp_patchpoint = instr;
	fbt->fbtp_ctl = lf;
	fbt->fbtp_loadcnt = lf->loadcnt;
	fbt->fbtp_symindx = symindx;
	fbt->fbtp_rval = DTRACE_INVOP_LD;
	fbt->fbtp_savedval = *instr;
	fbt->fbtp_patchval = FBT_PATCHVAL;
	fbt->fbtp_hashnext = fbt_probetab[FBT_ADDR2NDX(instr)];
	fbt_probetab[FBT_ADDR2NDX(instr)] = fbt;

	lf->fbt_nentries++;

	instr++;
	goto again;
}
