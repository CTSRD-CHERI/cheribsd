/*-
 * Copyright (c) 2025-2026 Capabilities Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency / Air Force Research Laboratory (DARPA/AFRL) Contract
 * No. FA8750-24-C-B047 ("DEC").
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/sbuf.h>
#include <sys/sysctl.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_param.h>

#define	TS_INTERVAL_SECS_DEFAULT	10
#define	TS_INTERVAL_SECS_MIN		10
#define	TS_INTERVAL_SECS_MAX		120

/* static int	tps_interval_secs = TS_INTERVAL_SECS_DEFAULT; */

/*
 * Statistics structure decribing both direct measurements and summary stats +
 * overhead estimates for a set of pages.  Most (but not all) stats are
 * calculated relative to its own total pages/words/bytes counted.
 */
struct tagscan_pageset_stats {
	/*
	 * Stats at page granularity.
	 */
	uint64_t	tps_pages_count_scanned;		/* Measured. */
	uint64_t	tps_pages_count_with_tags;		/* Measured. */
	uint64_t	tps_pages_percent_with_tags_int;	/* Summary. */
	uint64_t	tps_pages_percent_with_tags_frac;	/* Summary. */
	uint64_t	tps_pages_tagstore_overhead_bytes;	/* Summary. */
	uint64_t	tps_pages_tagstore_overhead_percent_int;/* Summary. */
	uint64_t	tps_pages_tagstore_overhead_percent_frac;/* Summary. */

	/*
	 * Stats at (capability) word granularity.
	 */
	uint64_t	tps_words_count_scanned;		/* Measured. */
	uint64_t	tps_words_count_with_tags;		/* Measured. */
	uint64_t	tps_words_count_percent_with_tags_int;	/* Summary. */
	uint64_t	tps_words_count_percent_with_tags_frac;	/* Summary. */
	uint64_t	tps_words_memory_overhead_bytes;	/* Summary. */
	uint64_t	tps_words_memory_overhead_percent_int;	/* Summary. */
	uint64_t	tps_words_memory_overhead_percent_frac;	/* Summary. */

	/*
	 * Stats at byte granularity.
	 */
	uint64_t	tps_bytes_count_scanned;		/* Measured. */
	uint64_t	tps_bytes_count_in_capabilities;	/* Measured. */

	/*
	 * Misc.
	 */
	uint64_t	tps_percent_of_global_memory_int;	/* Summary. */
	uint64_t	tps_percent_of_global_memory_frac;	/* Summary. */
};

/*-
 * Various collections of pages for which we generate / maintain statistics:
 *
 * tps_global - All present pages
 * tps_allocated - All present pages allocated by the buddy allocator
 * tps_unallocated - All present pages unallocated by the buddy allocator
 * tps_object - All present allocated pages with an associated VM object
 * tps_no_object - All present allocated pages without an associated VM object
 * tps_vnode_object - All present allocated pages in vnode objects
 * tps_swap_object - All present allocated pages in swap objects
 * tps_anon_object - All present allocated pages in anonymous objects
 * tps_kernel_object - All present allocated pages in the kernel object
 * tps_phys_object - All present allocated pages consisting of physical pages
 * tps_device_object - All present allocated pages in device objects
 * tps_misc_object - All present allocated pages in other object types
 */
struct tagscan_pageset_stats	tps_global;
struct tagscan_pageset_stats	tps_allocated, tps_unallocated;
struct tagscan_pageset_stats	tps_object, tps_no_object;
struct tagscan_pageset_stats	tps_vnode_object, tps_swap_object;
struct tagscan_pageset_stats	tps_phys_object, tps_device_object;
struct tagscan_pageset_stats	tps_anon_object;
struct tagscan_pageset_stats	tps_kernel_object;
struct tagscan_pageset_stats	tps_misc_object;

SYSCTL_NODE(_dev, OID_AUTO, tagscan, CTLFLAG_RW | CTLFLAG_MPSAFE, NULL,
    "Physical memory CHERI tag scanning");

/*
 * Given a tag count associated with a scanned page, update a page collection
 * statistics block.  This may be called multiple times for each page as each
 * page may be associated with multiple statistics blocks.
 */
static void
tagscan_pageset_stats_update(struct tagscan_pageset_stats *tpsp,
    uint64_t tags)
{

	tpsp->tps_pages_count_scanned++;
	if (tags)
		tpsp->tps_pages_count_with_tags++;
	tpsp->tps_words_count_scanned += PAGE_SIZE / sizeof(uintcap_t);
	tpsp->tps_words_count_with_tags += tags;
}

static void
tagscan_rescan_page(vm_page_t m)
{
	uintcap_t c, *cp;
	vm_object_t obj;
	vm_paddr_t pa;
	uint64_t tags;
	int i;

	pa = VM_PAGE_TO_PHYS(m);
	if (pa == 0)
		return;

	tags = 0;
	cp = (uintcap_t *)PHYS_TO_DMAP_PAGE(pa);
	for (i = 0; i < PAGE_SIZE / sizeof(*cp); i++) {
		c = cp[i];
		if (cheri_gettag(c))
			tags++;
	}

	tagscan_pageset_stats_update(&tps_global, tags);

	/* If not allocated by the buddy allocator, don't analyse further. */
	if (m->order < VM_NFREEORDER) {
		tagscan_pageset_stats_update(&tps_unallocated, tags);
		return;
	}
	tagscan_pageset_stats_update(&tps_allocated, tags);
	obj = atomic_load_ptr(&m->object);
	if (obj != NULL) {
		tagscan_pageset_stats_update(&tps_object, tags);
		if (obj == kernel_object)
			tagscan_pageset_stats_update(&tps_kernel_object,
			    tags);

		switch (obj->type) {
		case OBJT_SWAP:
			tagscan_pageset_stats_update(&tps_swap_object, tags);
			break;

		case OBJT_VNODE:
			tagscan_pageset_stats_update(&tps_vnode_object, tags);
			break;

		case OBJT_PHYS:
			tagscan_pageset_stats_update(&tps_phys_object, tags);
			break;

		case OBJT_DEVICE:
			tagscan_pageset_stats_update(&tps_device_object,
			    tags);

		default:
			tagscan_pageset_stats_update(&tps_misc_object, tags);
		}

		if (obj->flags & OBJ_ANON)
			tagscan_pageset_stats_update(&tps_anon_object, tags);
	} else
		tagscan_pageset_stats_update(&tps_no_object, tags);
}

/*
 * Recalculate various derived metrics after a rescan.  Most derived metrics
 * are relative the pages scanned of a particular memory type; the only
 * exception is the % of overall system memory.
 *
 * XXX: Some values here use floor rather than proper rounding.
 */
static void
tagscan_pageset_stats_recalculate(struct tagscan_pageset_stats *tpsp)
{
	uint64_t percent;

	/*
	 * Overall percentage of system memory this type takes up.
	 *
	 * Note the absolute reference to tps_global here.
	 */
	percent = (1000 * tpsp->tps_pages_count_scanned) /
	    tps_global.tps_pages_count_scanned;
	tpsp->tps_percent_of_global_memory_int = percent / 10;
	tpsp->tps_percent_of_global_memory_frac = percent % 10;

	/*
	 * Calculate % of pages that contain one or more tagged values.
	 */
	percent = (1000 * tpsp->tps_pages_count_with_tags) /
	    tpsp->tps_pages_count_scanned;
	tpsp->tps_pages_percent_with_tags_int = percent / 10;
	tpsp->tps_pages_percent_with_tags_frac = percent % 10;

	/*
	 * Estimate of the size taken up by tag storage for pages with tagged
	 * values.
	 *
	 * 1. What is the tag storage cost for pages with tagged?
	 *
	 * 2. What overhead does that represent against the total memory size?
	 */
	tpsp->tps_pages_tagstore_overhead_bytes =
	    (tpsp->tps_pages_count_with_tags *
	    (PAGE_SIZE / sizeof(uintcap_t))) / NBBY;
	percent = (1000 * tpsp->tps_pages_tagstore_overhead_bytes) /
	    (tpsp->tps_pages_count_scanned * PAGE_SIZE);
	tpsp->tps_pages_tagstore_overhead_percent_int = percent / 10;
	tpsp->tps_pages_tagstore_overhead_percent_frac = percent % 10;

	/*
	 * Calculate % of capability-width words that contain tagged values.
	 */
	percent =
	    (1000 * tpsp->tps_words_count_with_tags) /
	    tpsp->tps_words_count_scanned;
	tpsp->tps_words_count_percent_with_tags_int = percent / 10;
	tpsp->tps_words_count_percent_with_tags_frac = percent % 10;

	/*
	 * Estimate bytes of memory overhead due to tagged values.
	 */
	tpsp->tps_words_memory_overhead_bytes =
	    tpsp->tps_words_count_with_tags * (sizeof(uintcap_t) / 2);

	/*
	 * Estimate percent of memory overhead due to tagged values.
	 *
	 * 1. What is the size in bytes of the total memory sacnned?
	 * 2. What is the size in bytes of the capabilities found?
	 * 3. What is the number of bytes overhead that represents if all
	 *    128-bit capabilities took up only 64 bits?
	 * 4. If we assume that all those 128-bit values became 64 bit,
	 *    what is the percentage overhead of the subtracted capability
	 *    metadata?
	 */
	tpsp->tps_bytes_count_scanned =
	    tpsp->tps_words_count_scanned * sizeof(uintcap_t);
	tpsp->tps_bytes_count_in_capabilities =
	    tpsp->tps_words_count_with_tags * sizeof(uintcap_t);
	tpsp->tps_words_memory_overhead_bytes =
	    tpsp->tps_bytes_count_in_capabilities / 2;

	percent = (1000 * tpsp->tps_words_memory_overhead_bytes) /
	    (tpsp->tps_bytes_count_scanned -
	    tpsp->tps_words_memory_overhead_bytes);
	tpsp->tps_words_memory_overhead_percent_int = percent / 10;
	tpsp->tps_words_memory_overhead_percent_frac = percent % 10;
}

static void
tagscan_rescan(void)
{
	long pi;

	/*
	 * XXXRW: One could do it into temporary structs and then swap in
	 * to prevent intermediate values being overly visible?
	 */
	bzero(&tps_global, sizeof(tps_global));
	bzero(&tps_allocated, sizeof(tps_allocated));
	bzero(&tps_unallocated, sizeof(tps_unallocated));
	bzero(&tps_object, sizeof(tps_object));
	bzero(&tps_kernel_object, sizeof(tps_kernel_object));
	bzero(&tps_swap_object, sizeof(tps_swap_object));
	bzero(&tps_anon_object, sizeof(tps_anon_object));
	bzero(&tps_vnode_object, sizeof(tps_vnode_object));
	bzero(&tps_phys_object, sizeof(tps_phys_object));
	bzero(&tps_device_object, sizeof(tps_device_object));
	bzero(&tps_no_object, sizeof(tps_misc_object));
	bzero(&tps_no_object, sizeof(tps_no_object));
	for (pi = 0; pi < vm_page_array_size; pi++)
		tagscan_rescan_page(&vm_page_array[pi]);
	tagscan_pageset_stats_recalculate(&tps_global);
	tagscan_pageset_stats_recalculate(&tps_allocated);
	tagscan_pageset_stats_recalculate(&tps_unallocated);
	tagscan_pageset_stats_recalculate(&tps_object);
	tagscan_pageset_stats_recalculate(&tps_kernel_object);
	tagscan_pageset_stats_recalculate(&tps_swap_object);
	tagscan_pageset_stats_recalculate(&tps_anon_object);
	tagscan_pageset_stats_recalculate(&tps_vnode_object);
	tagscan_pageset_stats_recalculate(&tps_phys_object);
	tagscan_pageset_stats_recalculate(&tps_device_object);
	tagscan_pageset_stats_recalculate(&tps_misc_object);
	tagscan_pageset_stats_recalculate(&tps_no_object);
}

static int
sysctl_dev_tagscan_rescan(SYSCTL_HANDLER_ARGS)
{
	int error, value;

	value = 0;
	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error || !req->newptr)
		return (error);
	tagscan_rescan();
	return (0);
}
SYSCTL_PROC(_dev_tagscan, OID_AUTO, rescan,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, 0, 0,
    &sysctl_dev_tagscan_rescan, "I", "Trigger tag rescan");

static void
tagscan_pageset_stats_dump(struct sbuf *sb,
    struct tagscan_pageset_stats *tpsp)
{

	sbuf_printf(sb, "  pages_count_scanned: %ju\n",
	    tpsp->tps_pages_count_scanned);
	sbuf_printf(sb, "  pages_count_with_tags: %ju\n",
	    tpsp->tps_pages_count_with_tags);
	sbuf_printf(sb, "  pages_percent_with_tags: %ju.%01ju\n",
	    tpsp->tps_pages_percent_with_tags_int,
	    tpsp->tps_pages_percent_with_tags_frac);
	sbuf_printf(sb, "  pages_tagstore_overhead_bytes: %ju\n",
	    tpsp->tps_pages_tagstore_overhead_bytes);
	sbuf_printf(sb, "  pages_tagstore_overhead_percent: %ju.%01ju\n",
	    tpsp->tps_pages_tagstore_overhead_percent_int,
	    tpsp->tps_pages_tagstore_overhead_percent_frac);
	sbuf_printf(sb, "  words_count_scanned: %ju\n",
	    tpsp->tps_words_count_scanned);
	sbuf_printf(sb, "  words_count_with_tags: %ju\n",
	    tpsp->tps_words_count_with_tags);
	sbuf_printf(sb, "  words_percent_with_tags: %ju.%01ju\n",
	    tpsp->tps_words_count_percent_with_tags_int,
	    tpsp->tps_words_count_percent_with_tags_frac);
	sbuf_printf(sb, "  words_memory_overhead_bytes: %ju\n",
	    tpsp->tps_words_memory_overhead_bytes);
	sbuf_printf(sb, "  words_memory_overhead_percent: %ju.%01ju\n",
	    tpsp->tps_words_memory_overhead_percent_int,
	    tpsp->tps_words_memory_overhead_percent_frac);
	sbuf_printf(sb, "  bytes_count_scanned: %ju\n",
	    tpsp->tps_bytes_count_scanned);
	sbuf_printf(sb, "  bytes_count_in_capabilities: %ju\n",
	    tpsp->tps_bytes_count_in_capabilities);
	sbuf_printf(sb, "  percent_of_global_memory: %ju.%01ju\n",
	    tpsp->tps_percent_of_global_memory_int,
	    tpsp->tps_percent_of_global_memory_frac);
}

static int
sysctl_dev_tagscan_dump(SYSCTL_HANDLER_ARGS)
{
	struct sbuf sb;
	int error;

	sbuf_new(&sb, NULL, 256, SBUF_AUTOEXTEND | SBUF_INCLUDENUL);
	sbuf_printf(&sb, "global:\n");
	tagscan_pageset_stats_dump(&sb, &tps_global);
	sbuf_printf(&sb, "allocated:\n");
	tagscan_pageset_stats_dump(&sb, &tps_allocated);
	sbuf_printf(&sb, "unallocated:\n");
	tagscan_pageset_stats_dump(&sb, &tps_unallocated);
	sbuf_printf(&sb, "object:\n");
	tagscan_pageset_stats_dump(&sb, &tps_object);
	sbuf_printf(&sb, "no_object:\n");
	tagscan_pageset_stats_dump(&sb, &tps_no_object);
	sbuf_printf(&sb, "phys_object:\n");
	tagscan_pageset_stats_dump(&sb, &tps_phys_object);
	sbuf_printf(&sb, "swap_object:\n");
	tagscan_pageset_stats_dump(&sb, &tps_swap_object);
	sbuf_printf(&sb, "anon_object:\n");
	tagscan_pageset_stats_dump(&sb, &tps_anon_object);
	sbuf_printf(&sb, "vnode_object:\n");
	tagscan_pageset_stats_dump(&sb, &tps_vnode_object);
	sbuf_printf(&sb, "device_object:\n");
	tagscan_pageset_stats_dump(&sb, &tps_device_object);
	sbuf_printf(&sb, "kernel_object:\n");
	tagscan_pageset_stats_dump(&sb, &tps_kernel_object);
	sbuf_printf(&sb, "misc_object:\n");
	tagscan_pageset_stats_dump(&sb, &tps_misc_object);
	error = sbuf_finish(&sb);
	if (error == 0)
		error = SYSCTL_OUT(req, sbuf_data(&sb), sbuf_len(&sb));
	sbuf_delete(&sb);
	return (error);
}

SYSCTL_PROC(_dev_tagscan, OID_AUTO, dump,
    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE, NULL, 0,
    sysctl_dev_tagscan_dump, "A", "Dump tagscan statistics");

/* ARGSUSED */
static int
tagscan_modevent(module_t mod __unused, int type, void *data __unused)
{
	switch(type) {
	case MOD_LOAD:
		tagscan_rescan();
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
