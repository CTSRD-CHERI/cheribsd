/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Robert N. M. Watson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/sysctl.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_param.h>

#include "tagscan.h"

struct tagscan_stats ts;

static void
tagscan_page_process(vm_page_t m)
{
	vm_object_t obj;
	uintcap_t c, *cp;
	vm_paddr_t pa;
	u_int i, tags, seals, readables, writables;

	tags = seals = readables = writables = 0;

	/*
	 * Skip pages that don't correspond to actual resources.
	 */
	pa = VM_PAGE_TO_PHYS(m);
	if (pa == 0) {
		ts.ts_without_pa_count++;
		return;
	}

	/*
	 * Handle counters purely related to the page-level metadata.
	 */
	if (m->oflags & VPO_UNMANAGED)
		ts.ts_unmanaged_count++;
	if (m->a.flags & PGA_REFERENCED)
		ts.ts_referenced_count++;
	if (m->a.flags & PGA_CAPSTORE)
		ts.ts_capstore_count++;
	if (m->a.flags & PGA_CAPDIRTY)
		ts.ts_capdirty_count++;
	if (m->flags & PG_PCPU_CACHE)
		ts.ts_pcpu_count++;
	if (m->flags & PG_FICTITIOUS)
		ts.ts_fict_count++;
	if (m->flags & PG_ZERO)
		ts.ts_zero_count++;
	if (m->flags & PG_NODUMP)
		ts.ts_nodump_count++;
	if (m->flags & PG_NOFREE)
		ts.ts_nofree_count++;

	/*
	 * Handle counters relating to the VM object for the page, if present.
	 */
	obj = m->object;
	if (obj != NULL) {
		ts.ts_obj_count++;
		if (obj->flags & OBJ_HASCAP)
			ts.ts_obj_flag_hascap_count++;
		if (obj->flags & OBJ_NOCAP)
			ts.ts_obj_flag_nocap_count++;

		if (obj == kernel_object)
			ts.ts_obj_kernel_count++;

		ts.ts_obj_type_all_count++;
		switch (obj->type) {
		case OBJT_PHYS:
			ts.ts_obj_type_phys_count++;
			break;

		case OBJT_SWAP:
			ts.ts_obj_type_swap_count++;
			break;

		case OBJT_VNODE:
			ts.ts_obj_type_vnode_count++;
			break;

		default:
			ts.ts_obj_type_misc_count++;
			break;
		}
	} else {
		ts.ts_noobj_count++;
	}

	/*
	 * Next scan the page itself to identify capability-related contents.
	 */
	cp = (uintcap_t *)PHYS_TO_DMAP_PAGE(pa);
	for (i = 0; i < PAGE_SIZE / sizeof(*cp); i++) {
		c = cp[i];
		if (!(cheri_gettag(c)))
			continue;
		tags++;
		if (cheri_getsealed(c))
			seals++;
		if (cheri_getperm(c) & CHERI_PERM_LOAD)
			readables++;
		if (cheri_getperm(c) & CHERI_PERM_STORE)
			writables++;
	}

	/*
	 * Handle counters that depend on the results of the page scan.
	 */
	ts.ts_tag_count += tags;
	if (tags)
		ts.ts_pageswithcaps_count++;
	ts.ts_seal_count += seals;
	if (seals)
		ts.ts_withseals_count++;
	ts.ts_read_count += readables;
	ts.ts_write_count += writables;

	/*
	 * Now update various context-specific counters, particularly relating
	 * to object properties.  None of these relating to sealing [yet].
	 */
	if (tags == 0)	/* All stats here relate only to tagged values. */
		return;
	if (obj != NULL) {
		if (obj == kernel_object) {
			ts.ts_obj_kernel_pageswithcaps_count++;
			ts.ts_obj_kernel_caps_count += tags;
		}
		if (obj->flags & OBJ_HASCAP) {
			ts.ts_obj_flag_hascap_pageswithcaps_count++;
			ts.ts_obj_flag_hascap_caps_count += tags;
		}
		if (obj->flags & OBJ_NOCAP) {
			ts.ts_obj_flag_nocap_pageswithcaps_count++;
			ts.ts_obj_flag_nocap_caps_count += tags;
		}

		ts.ts_obj_type_all_pageswithcaps_count++;
		ts.ts_obj_type_all_caps_count += tags;
		switch (obj->type) {
		case OBJT_PHYS:
			ts.ts_obj_type_phys_pageswithcaps_count++;
			ts.ts_obj_type_phys_caps_count += tags;
			break;

		case OBJT_SWAP:
			ts.ts_obj_type_swap_pageswithcaps_count++;
			ts.ts_obj_type_swap_caps_count += tags;
			break;

		case OBJT_VNODE:
			ts.ts_obj_type_vnode_pageswithcaps_count++;
			ts.ts_obj_type_vnode_caps_count += tags;
			break;

		default:
			ts.ts_obj_type_misc_pageswithcaps_count++;
			ts.ts_obj_type_misc_caps_count += tags;
			break;
		}
	} else {
		/* No object found. */
		ts.ts_noobj_pageswithcaps_count++;
		ts.ts_noobj_caps_count += tags;
	}
}

static void
tagscan_recaculate(void)
{

	/* Stats with total page count as denominator. */
	ts.ts_obj_percent = (100 * ts.ts_obj_count) / ts.ts_total;
	ts.ts_unmanaged_percent = (100 * ts.ts_unmanaged_count) /
	    ts.ts_unmanaged_count;
	ts.ts_referenced_percent = (100 * ts.ts_referenced_count) /
	    ts.ts_referenced_count;
	ts.ts_capstore_percent = (100 * ts.ts_capstore_count) /
	    ts.ts_total;
	ts.ts_capdirty_percent = (100 * ts.ts_capdirty_count) /
	    ts.ts_total;
	ts.ts_pcpu_percent = (100 * ts.ts_pcpu_count) / ts.ts_total;
	ts.ts_fict_percent = (100 * ts.ts_fict_count) / ts.ts_total;
	ts.ts_zero_percent = (100 * ts.ts_zero_count) / ts.ts_total;
	ts.ts_nodump_percent = (100 * ts.ts_nodump_count) / ts.ts_total;
	ts.ts_nofree_percent = (100 * ts.ts_nofree_count) / ts.ts_total;

	ts.ts_obj_flag_hascap_percent = (100 * ts.ts_obj_flag_hascap_count) /
	    ts.ts_total;
	ts.ts_obj_flag_nocap_percent = (100 * ts.ts_obj_flag_nocap_count) /
	    ts.ts_total;
	ts.ts_noobj_percent = (100 * ts.ts_noobj_count) / ts.ts_total;

	ts.ts_without_pa_percent = (100 * ts.ts_without_pa_count) /
	    ts.ts_total;
	ts.ts_pageswithcaps_percent = (100 * ts.ts_pageswithcaps_count) /
	    ts.ts_total;
	ts.ts_withseals_percent = (100 * ts.ts_withseals_count) /
	    ts.ts_total;

	/*
	 * Calculate proportions of 'all' pages that each object type
	 * represents.
	 */
        ts.ts_obj_kernel_ofall_percent =
	    (100 * ts.ts_obj_kernel_count) / ts.ts_obj_type_all_count;
        ts.ts_obj_type_phys_ofall_percent =
	    (100 * ts.ts_obj_type_phys_count) / ts.ts_obj_type_all_count;
        ts.ts_obj_type_vnode_ofall_percent =
	    (100 *  ts.ts_obj_type_vnode_count) / ts.ts_obj_type_all_count;
        ts.ts_obj_swap_ofall_percent =
	    (100 *  ts.ts_obj_type_swap_count) / ts.ts_obj_type_all_count;
        ts.ts_obj_misc_ofall_percent =
	    (100 *  ts.ts_obj_type_misc_count) / ts.ts_obj_type_all_count;

	/*
	 * Calculate, for each object type, the percentage of its pages that
	 * contain at least one tagged value.
	 */
	ts.ts_obj_kernel_pageswithcaps_percent = (100 *
	    ts.ts_obj_kernel_pageswithcaps_count) / ts.ts_obj_kernel_count;

        ts.ts_obj_type_phys_pageswithcaps_percent = (100 *
	    ts.ts_obj_type_phys_pageswithcaps_count) /
	    ts.ts_obj_type_phys_count;
	ts.ts_obj_type_vnode_pageswithcaps_percent = (100 *
	    ts.ts_obj_type_vnode_pageswithcaps_count) /
	    ts.ts_obj_type_vnode_count;
	ts.ts_obj_type_swap_pageswithcaps_percent = (100 *
	    ts.ts_obj_type_swap_pageswithcaps_count) /
	    ts.ts_obj_type_swap_count;
	ts.ts_obj_type_misc_pageswithcaps_percent = (100 *
	    ts.ts_obj_type_misc_pageswithcaps_count) /
	    ts.ts_obj_type_misc_count;
	ts.ts_obj_type_all_pageswithcaps_percent = (100 *
	    ts.ts_obj_type_all_pageswithcaps_count) /
	    ts.ts_obj_type_all_count;
	ts.ts_noobj_pageswithcaps_percent = (100 *
	    ts.ts_noobj_pageswithcaps_count) /
	    ts.ts_noobj_count;

        ts.ts_obj_flag_hascap_pageswithcaps_percent = (100 *
	    ts.ts_obj_flag_hascap_pageswithcaps_count) /
	    ts.ts_obj_flag_hascap_count;
        ts.ts_obj_flag_nocap_pageswithcaps_percent = (100 *
	    ts.ts_obj_flag_nocap_pageswithcaps_count) /
	    ts.ts_obj_flag_nocap_count;

	/*
	 * Stats with object-type denominators: Work out the average
	 * capability density across all pages used for that object type,
	 * returned as a percentage.
	 */
	ts.ts_obj_kernel_caps_percent =
	    (100 * ts.ts_obj_kernel_caps_count * sizeof(void *)) /
	    (ts.ts_obj_kernel_count * PAGE_SIZE);

        ts.ts_obj_type_phys_caps_percent =
	    (100 * ts.ts_obj_type_phys_caps_count * sizeof(void *)) /
	    (ts.ts_obj_type_phys_count * PAGE_SIZE);
	ts.ts_obj_type_vnode_caps_percent =
	    (100 * ts.ts_obj_type_vnode_caps_count * sizeof(void *)) /
	    (ts.ts_obj_type_vnode_count * PAGE_SIZE);
	ts.ts_obj_type_swap_caps_percent =
	    (100 * ts.ts_obj_type_swap_caps_count * sizeof(void *)) /
	    (ts.ts_obj_type_swap_count * PAGE_SIZE);
	ts.ts_obj_type_misc_caps_percent =
	    (100 * ts.ts_obj_type_misc_caps_count * sizeof(void *)) /
	    (ts.ts_obj_type_misc_count * PAGE_SIZE);
	ts.ts_obj_type_all_caps_percent =
	    (100 * ts.ts_obj_type_all_caps_count * sizeof(void *)) /
	    (ts.ts_obj_type_all_count * PAGE_SIZE);
	ts.ts_noobj_caps_percent =
	    (100 * ts.ts_noobj_caps_count * sizeof(void *)) /
	    (ts.ts_noobj_count * PAGE_SIZE);

	ts.ts_obj_flag_hascap_caps_percent =
	    (100 * ts.ts_obj_flag_hascap_caps_count * sizeof(void *)) /
	    (ts.ts_obj_flag_hascap_count * PAGE_SIZE);
	ts.ts_obj_flag_nocap_caps_percent =
	    (100 * ts.ts_obj_flag_nocap_caps_count * sizeof(void *)) /
	    (ts.ts_obj_flag_nocap_count * PAGE_SIZE);

	/*
	 * Estimated overhead based on assuming that any tagged piece of
	 * memory doubled in size from adding CHERI.  Lots of assumptions
	 * there; too many to put in this comment.
	 */
	ts.ts_obj_kernel_overhead = ts.ts_obj_kernel_caps_percent/2;
	ts.ts_obj_type_phys_overhead = ts.ts_obj_type_phys_caps_percent/2;
	ts.ts_obj_type_vnode_overhead = ts.ts_obj_type_vnode_caps_percent/2;
	ts.ts_obj_type_swap_overhead = ts.ts_obj_type_swap_caps_percent/2;
	ts.ts_obj_type_misc_overhead = ts.ts_obj_type_misc_caps_percent/2;
	ts.ts_obj_type_all_overhead = ts.ts_obj_type_all_caps_percent/2;
	ts.ts_noobj_overhead = ts.ts_noobj_caps_percent/2;

	ts.ts_obj_flag_hascap_overhead = ts.ts_obj_flag_hascap_caps_percent/2;
	ts.ts_obj_flag_nocap_overhead = ts.ts_obj_flag_nocap_caps_percent/2;
}

static void
tagscan_update(void)
{
	long pi;

	bzero(&ts, sizeof(ts));
	ts.ts_size = sizeof (ts);
	ts.ts_page_size = PAGE_SIZE;
	ts.ts_total = vm_page_array_size;

	/* Race conditions be damned. */
	/* XXX: Or add more locking. */
	for (pi = 0; pi < vm_page_array_size; pi++) {
		tagscan_page_process(&vm_page_array[pi]);
	}
	tagscan_recaculate();
}

/*
 * Trigger a rescan of all physical pages by setting this sysctl to '1'.
 */
static int
sysctl_dev_tagscan_update(SYSCTL_HANDLER_ARGS)
{
	int error, value;

	value = 0;
	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error || !req->newptr)
		return (error);
	tagscan_update();
	return (0);
}

SYSCTL_NODE(_dev, OID_AUTO, tagscan, CTLFLAG_RW | CTLFLAG_MPSAFE, NULL,
    "Physical memory CHERI tag scanning");

SYSCTL_ULONG(_dev_tagscan, OID_AUTO, size, CTLFLAG_RD, &ts.ts_size, 0,
    "Identify struct layout");

SYSCTL_ULONG(_dev_tagscan, OID_AUTO, page_size, CTLFLAG_RD, &ts.ts_page_size,
    0, "Avoid confusion on units");

/*
 * Update all counters and stats.
 */
SYSCTL_PROC(_dev_tagscan, OID_AUTO, update,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, 0, 0,
    &sysctl_dev_tagscan_update, "I", "Trigger tag rescan");

/*
 * Extract various stats.  Don't allow writing; must be updated by using the
 * 'update' MIB.
 */
SYSCTL_NODE(_dev_tagscan, OID_AUTO, capability_counters,
    CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, "Global capability counters");

SYSCTL_ULONG(_dev_tagscan_capability_counters, OID_AUTO, tagged,
    CTLFLAG_RD, &ts.ts_tag_count, 0,
    "Number of tags globally");

SYSCTL_ULONG(_dev_tagscan_capability_counters, OID_AUTO, sealed,
    CTLFLAG_RD, &ts.ts_seal_count, 0,
    "Number of sealed capabilities globally");

SYSCTL_ULONG(_dev_tagscan_capability_counters, OID_AUTO, readable,
    CTLFLAG_RD, &ts.ts_read_count, 0,
    "Number of readable capabilities globally");

SYSCTL_ULONG(_dev_tagscan_capability_counters, OID_AUTO, writable,
    CTLFLAG_RD, &ts.ts_write_count, 0,
    "Number of writable capabilities globally");

/*
 * Counts of pages.
 */
SYSCTL_NODE(_dev_tagscan, OID_AUTO, page_counters,
    CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, "Per-page counters.");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, total, CTLFLAG_RD,
    &ts.ts_total, 0, "Number of vm_page_t's");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, obj, CTLFLAG_RD,
    &ts.ts_obj_count, 0, "Number of pages with non-NULL objects");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, unmanaged, CTLFLAG_RD,
    &ts.ts_unmanaged_count, 0, "Number of unmanaged pages");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, referenced, CTLFLAG_RD,
    &ts.ts_referenced_count, 0, "Number of referenced pages");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, capstore, CTLFLAG_RD,
    &ts.ts_capstore_count, 0, "Number of capstore pages");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, capdirty, CTLFLAG_RD,
    &ts.ts_capdirty_count, 0, "Number of capdirty pages");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, pcpu, CTLFLAG_RD,
    &ts.ts_pcpu_count, 0, "Number of pages from per-CPU cache");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, ficticious, CTLFLAG_RD,
    &ts.ts_fict_count, 0, "Number of ficticious pages");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, zeroed, CTLFLAG_RD,
    &ts.ts_zero_count, 0, "Number of zeroed pages");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, nodump, CTLFLAG_RD,
    &ts.ts_nodump_count, 0, "Number of nodump pages");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, nofree, CTLFLAG_RD,
    &ts.ts_nofree_count, 0, "Number of nofree pages");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, obj_kernel,
    CTLFLAG_RD, &ts.ts_obj_kernel_count, 0,
    "Number of pages for object type");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, type_phys,
    CTLFLAG_RD, &ts.ts_obj_type_phys_count, 0,
    "Number of pages for object type");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, type_vnode,
    CTLFLAG_RD, &ts.ts_obj_type_vnode_count, 0,
    "Number of pages for object type");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, type_swap,
    CTLFLAG_RD, &ts.ts_obj_type_swap_count, 0,
    "Number of pages for object type");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, type_misc,
    CTLFLAG_RD, &ts.ts_obj_type_misc_count, 0,
    "Number of pages for object type");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, type_all,
    CTLFLAG_RD, &ts.ts_obj_type_all_count, 0,
    "Number of pages for object type");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, noobj,
    CTLFLAG_RD, &ts.ts_noobj_count, 0,
    "Number of pages with no object type");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, obj_flag_hascap,
    CTLFLAG_RD, &ts.ts_obj_flag_hascap_count, 0,
    "Number of pages with HASCAP objects");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, obj_flag_nocap, CTLFLAG_RD,
    &ts.ts_obj_flag_nocap_count, 0, "Number of pages with NOCAP objects");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, without_pa,
    CTLFLAG_RD, &ts.ts_without_pa_count, 0,
    "Number of pages without valid physical addresses");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, page_pageswithcaps,
    CTLFLAG_RD, &ts.ts_pageswithcaps_count, 0,
    "Number of pages with tagged values in them");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, withseals, CTLFLAG_RD,
    &ts.ts_withseals_count, 0,
    "Number of pages with tagged and sealed values in them");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, obj_kernel_pageswithcaps,
    CTLFLAG_RD, &ts.ts_obj_kernel_pageswithcaps_count, 0,
    "Number of pages of object type with tags");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, obj_type_phys_pageswithcaps,
    CTLFLAG_RD, &ts.ts_obj_type_phys_pageswithcaps_count, 0,
    "Number of pages of object type with tags");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, obj_type_vnode_pageswithcaps,
    CTLFLAG_RD, &ts.ts_obj_type_vnode_pageswithcaps_count, 0,
    "Number of pages of object type with tags");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, obj_type_swap_pageswithcaps,
    CTLFLAG_RD, &ts.ts_obj_type_swap_pageswithcaps_count, 0,
    "Number of pages of object type with tags");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, obj_type_misc_pageswithcaps,
    CTLFLAG_RD, &ts.ts_obj_type_misc_pageswithcaps_count, 0,
    "Number of pages of object type with tags");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, obj_type_all_pageswithcaps,
    CTLFLAG_RD, &ts.ts_obj_type_all_pageswithcaps_count, 0,
    "Number of pages of object type with tags");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, noobj_pageswithcaps,
    CTLFLAG_RD, &ts.ts_noobj_pageswithcaps_count, 0,
    "Number of pages with no object type that have tags");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, obj_flag_hascap_pageswithcaps,
    CTLFLAG_RD, &ts.ts_obj_flag_hascap_pageswithcaps_count, 0,
    "Number of pages of object type with tags");

SYSCTL_ULONG(_dev_tagscan_page_counters, OID_AUTO, obj_flag_nocap_pageswithcaps,
    CTLFLAG_RD, &ts.ts_obj_flag_nocap_pageswithcaps_count, 0,
    "Number of pages of object type with tags");

/*
 * Counts of actual tags in pages, by type.
 */
SYSCTL_NODE(_dev_tagscan, OID_AUTO, tag_counters, CTLFLAG_RW | CTLFLAG_MPSAFE,
    NULL, "Tag counters.");

SYSCTL_ULONG(_dev_tagscan_tag_counters, OID_AUTO, obj_kernel_caps, CTLFLAG_RD,
    &ts.ts_obj_kernel_caps_count, 0,
    "Number of tags in pages of the object type");

SYSCTL_ULONG(_dev_tagscan_tag_counters, OID_AUTO, obj_type_phys_caps,
    CTLFLAG_RD, &ts.ts_obj_type_phys_caps_count, 0,
    "Number of tags in pages of the object type");

SYSCTL_ULONG(_dev_tagscan_tag_counters, OID_AUTO, obj_type_vnode_caps,
    CTLFLAG_RD, &ts.ts_obj_type_vnode_caps_count, 0,
    "Number of tags in pages of the object type");

SYSCTL_ULONG(_dev_tagscan_tag_counters, OID_AUTO, obj_type_swap_caps,
    CTLFLAG_RD, &ts.ts_obj_type_swap_caps_count, 0,
    "Number of tags in pages of the object type");

SYSCTL_ULONG(_dev_tagscan_tag_counters, OID_AUTO, obj_type_misc_caps,
    CTLFLAG_RD, &ts.ts_obj_type_misc_caps_count, 0,
    "Number of tags in pages of the object type");

SYSCTL_ULONG(_dev_tagscan_tag_counters, OID_AUTO, obj_type_all_caps,
    CTLFLAG_RD, &ts.ts_obj_type_all_caps_count, 0,
    "Number of tags in pages of the object type");

SYSCTL_ULONG(_dev_tagscan_tag_counters, OID_AUTO, noobj_caps,
    CTLFLAG_RD, &ts.ts_noobj_caps_count, 0,
    "Number of tags in pages without an object type");

SYSCTL_ULONG(_dev_tagscan_tag_counters, OID_AUTO, obj_flag_hascap_caps,
    CTLFLAG_RD, &ts.ts_obj_flag_hascap_caps_count, 0,
    "Number of tags in pages of the object type");

SYSCTL_ULONG(_dev_tagscan_tag_counters, OID_AUTO, obj_flag_nocap_caps,
    CTLFLAG_RD, &ts.ts_obj_flag_nocap_caps_count, 0,
    "Number of tags in pages of the object type");

/*
 * Summary statistics.
 */
SYSCTL_NODE(_dev_tagscan, OID_AUTO, page_global_percents,
    CTLFLAG_RW | CTLFLAG_MPSAFE, NULL,
    "Per-page stats percentages for tag scanning");

SYSCTL_ULONG(_dev_tagscan_global_page_percents, OID_AUTO, haveobj, CTLFLAG_RD,
    &ts.ts_obj_percent, 0, "Percentage of pages with non-NULL objects");

SYSCTL_ULONG(_dev_tagscan_global_page_percents, OID_AUTO, unmanaged, CTLFLAG_RD,
    &ts.ts_unmanaged_percent, 0, "Percent unmanaged pages");

SYSCTL_ULONG(_dev_tagscan_global_page_percents, OID_AUTO, referenced, CTLFLAG_RD,
    &ts.ts_referenced_percent, 0, "Percent referenced pages");

SYSCTL_ULONG(_dev_tagscan_global_page_percents, OID_AUTO, capstore, CTLFLAG_RD,
    &ts.ts_capstore_percent, 0, "Percent capstore pages");

SYSCTL_ULONG(_dev_tagscan_global_page_percents, OID_AUTO, capdirty, CTLFLAG_RD,
    &ts.ts_capdirty_percent, 0, "Percent capdirty pages");

SYSCTL_ULONG(_dev_tagscan_global_page_percents, OID_AUTO, pcpu, CTLFLAG_RD,
    &ts.ts_pcpu_percent, 0, "Percentage of pages from per-CPU cache");

SYSCTL_ULONG(_dev_tagscan_global_page_percents, OID_AUTO, ficticious, CTLFLAG_RD,
    &ts.ts_fict_percent, 0, "Percent ficticious pages");

SYSCTL_ULONG(_dev_tagscan_global_page_percents, OID_AUTO, zeroed, CTLFLAG_RD,
    &ts.ts_zero_percent, 0, "Percent zeroed pages");

SYSCTL_ULONG(_dev_tagscan_global_page_percents, OID_AUTO, nodump, CTLFLAG_RD,
    &ts.ts_nodump_percent, 0, "Percent nodump pages");

SYSCTL_ULONG(_dev_tagscan_global_page_percents, OID_AUTO, nofree, CTLFLAG_RD,
    &ts.ts_nofree_percent, 0, "Percent nofree pages");

SYSCTL_ULONG(_dev_tagscan_global_page_percents, OID_AUTO, obj_flag_hascap,
    CTLFLAG_RD, &ts.ts_obj_flag_hascap_percent, 0,
    "Percentage of pages with HASCAP objects");

SYSCTL_ULONG(_dev_tagscan_global_page_percents, OID_AUTO, obj_flag_nocap,
    CTLFLAG_RD, &ts.ts_obj_flag_nocap_percent, 0,
    "Percentage of pages with NOCAP objects");

SYSCTL_ULONG(_dev_tagscan_global_page_percents, OID_AUTO, without_pa,
    CTLFLAG_RD, &ts.ts_without_pa_percent, 0,
    "Percent of pages without valid physical addresses");

SYSCTL_ULONG(_dev_tagscan_global_page_percents, OID_AUTO, withcaps,
    CTLFLAG_RD, &ts.ts_pageswithcaps_percent, 0,
    "Percentage of pages with tagged values in them");

SYSCTL_ULONG(_dev_tagscan_global_page_percents, OID_AUTO, withseals,
    CTLFLAG_RD, &ts.ts_withseals_percent, 0,
    "Percentage of pages with tagged and sealed values in them");

/* Stats with total page count for 'all' objects as denominator. */
SYSCTL_NODE(_dev_tagscan, OID_AUTO, object_distribution,
    CTLFLAG_RW | CTLFLAG_MPSAFE, NULL,
    "Distribution of object-linked pages across object types");

SYSCTL_ULONG(_dev_tagscan_object_distribution, OID_AUTO, obj_kernel,
    CTLFLAG_RD, &ts.ts_obj_kernel_ofall_percent, 0,
    "Percentage of 'all' pages associated with object type");

SYSCTL_ULONG(_dev_tagscan_object_distribution, OID_AUTO, type_phys,
    CTLFLAG_RD, &ts.ts_obj_type_phys_ofall_percent, 0,
    "Percentage of 'all' pages associated with object type");

SYSCTL_ULONG(_dev_tagscan_object_distribution, OID_AUTO, type_vnode,
    CTLFLAG_RD, &ts.ts_obj_type_vnode_ofall_percent, 0,
    "Percentage of 'all' pages associated with object type");

SYSCTL_ULONG(_dev_tagscan_object_distribution, OID_AUTO, type_swap,
    CTLFLAG_RD, &ts.ts_obj_swap_ofall_percent, 0,
    "Percentage of 'all' pages associated with object type");

SYSCTL_ULONG(_dev_tagscan_object_distribution, OID_AUTO, type_misc,
    CTLFLAG_RD, &ts.ts_obj_misc_ofall_percent, 0,
    "Percentage of 'all' pages associated with object type");

/* Statistics with object-type denominators. */
SYSCTL_NODE(_dev_tagscan, OID_AUTO, object_page_percents,
    CTLFLAG_RW | CTLFLAG_MPSAFE, NULL,
    "Per-object-type stats percentages for tag scanning");

SYSCTL_ULONG(_dev_tagscan_object_page_percents, OID_AUTO,
    obj_kernel, CTLFLAG_RD,
    &ts.ts_obj_kernel_pageswithcaps_percent, 0,
    "Percentage of object-type pages with tagged values in them");

SYSCTL_ULONG(_dev_tagscan_object_page_percents, OID_AUTO,
    type_phys, CTLFLAG_RD,
    &ts.ts_obj_type_phys_pageswithcaps_percent, 0,
    "Percentage of object-type pages with tagged values in them");

SYSCTL_ULONG(_dev_tagscan_object_page_percents, OID_AUTO,
    type_vnode, CTLFLAG_RD,
    &ts.ts_obj_type_vnode_pageswithcaps_percent, 0,
    "Percentage of object-type pages with tagged values in them");

SYSCTL_ULONG(_dev_tagscan_object_page_percents, OID_AUTO,
    type_swap, CTLFLAG_RD,
    &ts.ts_obj_type_swap_pageswithcaps_percent, 0,
    "Percentage of object-type pages with tagged values in them");

SYSCTL_ULONG(_dev_tagscan_object_page_percents, OID_AUTO,
    type_misc, CTLFLAG_RD,
    &ts.ts_obj_type_misc_pageswithcaps_percent, 0,
    "Percentage of object-type pages with tagged values in them");

SYSCTL_ULONG(_dev_tagscan_object_page_percents, OID_AUTO,
    type_all, CTLFLAG_RD,
    &ts.ts_obj_type_all_pageswithcaps_percent, 0,
    "Percentage of object-type pages with tagged values in them");

SYSCTL_ULONG(_dev_tagscan_object_page_percents, OID_AUTO,
    noobj, CTLFLAG_RD,
    &ts.ts_noobj_pageswithcaps_percent, 0,
    "Percentage of object-type pages with tagged values in them");

SYSCTL_ULONG(_dev_tagscan_object_page_percents, OID_AUTO,
    flag_hascap, CTLFLAG_RD,
    &ts.ts_obj_flag_hascap_pageswithcaps_percent, 0,
    "Percentage of object-type pages with tagged values in them");

SYSCTL_ULONG(_dev_tagscan_object_page_percents, OID_AUTO,
    flag_nocap, CTLFLAG_RD,
    &ts.ts_obj_flag_nocap_pageswithcaps_percent, 0,
    "Percentage of object-type pages with tagged values in them");

SYSCTL_NODE(_dev_tagscan, OID_AUTO, object_cap_percents,
    CTLFLAG_RW | CTLFLAG_MPSAFE, NULL,
    "Per-object-type stats percentages for tag scanning");

SYSCTL_ULONG(_dev_tagscan_object_cap_percents, OID_AUTO, obj_kernel,
    CTLFLAG_RD, &ts.ts_obj_kernel_caps_percent, 0,
    "Density of tags across an object-type's pages");

SYSCTL_ULONG(_dev_tagscan_object_cap_percents, OID_AUTO, obj_type_phys,
    CTLFLAG_RD, &ts.ts_obj_type_phys_caps_percent, 0,
    "Density of tags across an object-type's pages");

SYSCTL_ULONG(_dev_tagscan_object_cap_percents, OID_AUTO, obj_type_vnode,
    CTLFLAG_RD, &ts.ts_obj_type_vnode_caps_percent, 0,
    "Density of tags across an object-type's pages");

SYSCTL_ULONG(_dev_tagscan_object_cap_percents, OID_AUTO, obj_type_swap,
    CTLFLAG_RD, &ts.ts_obj_type_swap_caps_percent, 0,
    "Density of tags across an object-type's pages");

SYSCTL_ULONG(_dev_tagscan_object_cap_percents, OID_AUTO, obj_type_misc,
    CTLFLAG_RD, &ts.ts_obj_type_misc_caps_percent, 0,
    "Density of tags across an object-type's pages");

SYSCTL_ULONG(_dev_tagscan_object_cap_percents, OID_AUTO, obj_type_all,
    CTLFLAG_RD, &ts.ts_obj_type_all_caps_percent, 0,
    "Density of tags across an object-type's pages");

SYSCTL_ULONG(_dev_tagscan_object_cap_percents, OID_AUTO, noobj,
    CTLFLAG_RD, &ts.ts_noobj_caps_percent, 0,
    "Density of tags in pages that have no object type");

SYSCTL_ULONG(_dev_tagscan_object_cap_percents, OID_AUTO, obj_flag_hascap,
    CTLFLAG_RD, &ts.ts_obj_flag_hascap_caps_percent, 0,
    "Density of tags across an object-type's pages");

SYSCTL_ULONG(_dev_tagscan_object_cap_percents, OID_AUTO, obj_flag_nocap,
    CTLFLAG_RD, &ts.ts_obj_flag_nocap_caps_percent, 0,
    "Density of tags across an object-type's pages");

/*
 * Estimated overheads based on capability density.
 */
SYSCTL_NODE(_dev_tagscan, OID_AUTO, object_memory_overhead,
    CTLFLAG_RW | CTLFLAG_MPSAFE, NULL,
    "Per-object-type stats estimated overheads for tag scanning");

SYSCTL_ULONG(_dev_tagscan_object_memory_overhead, OID_AUTO, obj_kernel,
    CTLFLAG_RD, &ts.ts_obj_kernel_overhead, 0,
    "Estimated memory overhead by object type");

SYSCTL_ULONG(_dev_tagscan_object_memory_overhead, OID_AUTO, obj_type_phys,
    CTLFLAG_RD, &ts.ts_obj_type_phys_overhead, 0,
    "Estimated memory overhead by object type");

SYSCTL_ULONG(_dev_tagscan_object_memory_overhead, OID_AUTO, obj_type_vnode,
    CTLFLAG_RD, &ts.ts_obj_type_vnode_overhead, 0,
    "Estimated memory overhead by object type");

SYSCTL_ULONG(_dev_tagscan_object_memory_overhead, OID_AUTO, obj_type_swap,
    CTLFLAG_RD, &ts.ts_obj_type_swap_overhead, 0,
    "Estimated memory overhead by object type");

SYSCTL_ULONG(_dev_tagscan_object_memory_overhead, OID_AUTO, obj_type_misc,
    CTLFLAG_RD, &ts.ts_obj_type_misc_overhead, 0,
    "Estimated memory overhead by object type");

SYSCTL_ULONG(_dev_tagscan_object_memory_overhead, OID_AUTO, obj_type_all,
    CTLFLAG_RD, &ts.ts_obj_type_all_overhead, 0,
    "Estimated memory overhead by object type");

SYSCTL_ULONG(_dev_tagscan_object_memory_overhead, OID_AUTO, noobj,
    CTLFLAG_RD, &ts.ts_noobj_overhead, 0,
    "Estimated memory overhead by object type");

SYSCTL_ULONG(_dev_tagscan_object_memory_overhead, OID_AUTO, obj_type_hascap,
    CTLFLAG_RD, &ts.ts_obj_flag_hascap_overhead, 0,
    "Estimated memory overhead by object type");

SYSCTL_ULONG(_dev_tagscan_object_memory_overhead, OID_AUTO, obj_type_nocap,
    CTLFLAG_RD, &ts.ts_obj_flag_nocap_overhead, 0,
    "Estimated memory overhead by object type");

/* ARGSUSED */
static int
tagscan_modevent(module_t mod __unused, int type, void *data __unused)
{
	switch(type) {
	case MOD_LOAD:
		tagscan_update();
		break;

	case MOD_UNLOAD:
	case MOD_SHUTDOWN:
		break;

	default:
		return (EOPNOTSUPP);
	}

	return (0);
}

DEV_MODULE(tagscan, tagscan_modevent, NULL);
MODULE_VERSION(tagscan, 1);
