/*
 * SPDX-License-Identifier: CDDL 1.0
 *
 * Copyright (c) 2022 Christos Margiolis <christos@FreeBSD.org>
 * Copyright (c) 2023 The FreeBSD Foundation
 * Copyright (c) 2026 Konrad Witaszczyk
 *
 * Portions of this software were developed by Christos Margiolis
 * <christos@FreeBSD.org> under sponsorship from the FreeBSD Foundation.
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency / Air Force Research Laboratory (DARPA/AFRL) Contract
 * No. FA8750-24-C-B047 ("DEC").
 */

/*
 * The cbt provider's skeleton is based on the implementation of dtrace_kinst(4)
 * and dtrace_fbt(4) but its actual profiling logic is independent of them.
 */

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/compartment.h>
#include <sys/dtrace.h>
#include <sys/dtrace_bsd.h>
#include <sys/tree.h>

#include "linker_if.h"

#include "dtrace_excluded.h"
#include "cbt.h"

extern cbt_probe_func_t cbt_probe_func;

static void cbt_provide_module(void *arg, modctl_t *lf);
static void cbt_enable(void *arg __unused, dtrace_id_t id, void *parg);
static void cbt_disable(void *arg __unused, dtrace_id_t id, void *parg);
static void cbt_destroy(void *arg __unused, dtrace_id_t id, void *parg);

static dtrace_provider_id_t cbt_id;

static dtrace_pattr_t cbt_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
};

static const dtrace_pops_t cbt_pops = {
	.dtps_provide		= NULL,
	.dtps_provide_module	= cbt_provide_module,
	.dtps_enable		= cbt_enable,
	.dtps_disable		= cbt_disable,
	.dtps_suspend		= NULL,
	.dtps_resume		= NULL,
	.dtps_getargdesc	= NULL,
	.dtps_getargval		= NULL,
	.dtps_usermode		= NULL,
	.dtps_destroy		= cbt_destroy
};

static void
cbt_probe(dtrace_id_t id, elf_compartment_t elf_compartment)
{

	dtrace_probe(id, (uintptr_t)(void *)elf_compartment, 0, 0, 0, 0);
}

static bool
cbt_excluded_function(const char *name)
{
	if (dtrace_excluded_function(name))
		return (true);
	if (cbt_md_excluded_function(name))
		return (true);
#ifndef _KLD_MODULE
	if (strncmp(name, "cbt_", strlen("cbt_")) == 0)
		return (true);
#endif
	return (false);
}

static void
cbt_toggle(struct compartment_trampoline *trampoline, dtrace_id_t id,
    bool enabled)
{
	char namebuf[64];
	elf_compartment_t elf_compartment;
	long offset;
	ptraddr_t addr;
	bool isentry;

	elf_compartment = compartment_trampoline_get_elf_compartment(
	    trampoline);
	if (id != elf_compartment->entry_probe &&
	    id != elf_compartment->return_probe)
		return;

	isentry = (id == elf_compartment->entry_probe);
	addr = compartment_trampoline_get_target_address(trampoline);
	if (linker_ddb_search_symbol_name(addr, namebuf,
	    sizeof(namebuf), &offset) != 0)
		return;
	if (offset == 0 && cbt_excluded_function(namebuf))
		return;

	if (isentry)
		compartment_trampoline_toggle_entry_probe(trampoline,
		    enabled);
	else
		compartment_trampoline_toggle_return_probe(trampoline,
		    enabled);
}

static int
cbt_enable_probe(struct compartment_trampoline *trampoline, void *arg)
{
	cbt_toggle(trampoline, *(dtrace_id_t *)arg, true);
	return (0);
}

static int
cbt_disable_probe(struct compartment_trampoline *trampoline, void *arg)
{
	cbt_toggle(trampoline, *(dtrace_id_t *)arg, false);
	return (0);
}

static void
cbt_enable(void *arg __unused, dtrace_id_t id, void *parg)
{
	elf_compartment_t elf_compartment = parg;
	struct compartment_trampoline_tree *tree;

	tree = LINKER_COMPARTMENT_TRAMPOLINES(
	    (linker_file_t)elf_compartment->file);
	(void)compartment_trampoline_tree_foreach(tree, cbt_enable_probe,
	    &id);
}

static void
cbt_disable(void *arg __unused, dtrace_id_t id, void *parg)
{
	elf_compartment_t elf_compartment = parg;
	struct compartment_trampoline_tree *tree;

	tree = LINKER_COMPARTMENT_TRAMPOLINES(
	    (linker_file_t)elf_compartment->file);
	(void)compartment_trampoline_tree_foreach(tree, cbt_disable_probe,
	    &id);
}

static void
cbt_destroy(void *arg __unused, dtrace_id_t id, void *parg)
{
	elf_compartment_t elf_compartment = parg;

	ASSERT(id == elf_compartment->entry_probe ||
	    id == elf_compartment->return_probe);

	if (id == elf_compartment->entry_probe)
		elf_compartment->entry_probe = 0;
	else
		elf_compartment->return_probe = 0;
}

static int
cbt_provide_compartment(elf_compartment_t elf_compartment, void *arg)
{
	void *modname = arg;

	elf_compartment->entry_probe = dtrace_probe_create(cbt_id, modname,
	    elf_compartment->name, CBT_ENTRY, 0, elf_compartment);
	elf_compartment->return_probe = dtrace_probe_create(cbt_id, modname,
	    elf_compartment->name, CBT_RETURN, 0, elf_compartment);
	return (0);
}

static void
cbt_provide_module(void *arg, modctl_t *lf)
{
	if (dtrace_excluded_module(lf))
		return;

	(void)LINKER_EACH_COMPARTMENT(lf, cbt_provide_compartment,
	    lf->filename);

}

static int
cbt_linker_file_cb(linker_file_t lf, void *arg)
{
	cbt_provide_module(arg, lf);
	return (0);
}

static int
cbt_load(void *dummy)
{
	int error;

	error = dtrace_register("cbt", &cbt_attr, DTRACE_PRIV_USER, NULL,
	    &cbt_pops, NULL, &cbt_id);
	if (error != 0)
		return (error);
	error = linker_file_foreach(cbt_linker_file_cb, NULL);
	if (error != 0)
		return (error);
	cbt_probe_func = cbt_probe;
	return (0);
}

static int
cbt_unload(void *dummy)
{
	cbt_probe_func = NULL;
	return (dtrace_unregister(cbt_id));
}

static int
cbt_modevent(module_t mod __unused, int type, void *data __unused)
{
	int error = 0;

	switch (type) {
	case MOD_LOAD:
		break;
	case MOD_UNLOAD:
		break;
	case MOD_SHUTDOWN:
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

SYSINIT(cbt_load, SI_SUB_DTRACE_PROVIDER, SI_ORDER_ANY, cbt_load, NULL);
SYSUNINIT(cbt_unload, SI_SUB_DTRACE_PROVIDER, SI_ORDER_ANY, cbt_unload,
    NULL);

DEV_MODULE(cbt, cbt_modevent, NULL);
MODULE_VERSION(cbt, 1);
MODULE_DEPEND(cbt, dtrace, 1, 1, 1);
MODULE_DEPEND(cbt, opensolaris, 1, 1, 1);
MODULE_DEPEND(cbt, fbt, 1, 1, 1);
