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

#ifndef _DEV_TAGSCAN_H_
#define	_DEV_TAGSCAN_H_

/*
 * Various stats, broken down into "# pages" and "# tags found in those
 * pages".
 *
 * Would be useful to break this down quite a bit in terms of object types,
 * capability types, and so on, in due course.  Of particular interest will
 * be differentiating control-flow from data capabilities, and also by VM 
 * object type.
 *
 * XXX: It's not clear that categorising by "kernel" and "user" are
 * meaningful.
 */
struct tagscan_stats {
	unsigned long	ts_size;		/* Identify struct layout. */
	unsigned long	ts_page_size;		/* Avoid confusion on units. */

	/* Global capability counters. */
	unsigned long	ts_tag_count;		/* # tags found globally. */
	unsigned long	ts_seal_count;		/* # sealed caps found glob. */
	unsigned long	ts_read_count;		/* # readable caps glob. */
	unsigned long	ts_write_count;		/* # writable caps glob. */

	/* Page counters, counted using various properties. */
	unsigned long	ts_total;		/* # pages globally. */
	unsigned long	ts_obj_count;		/* # pages with objects .*/
	unsigned long	ts_unmanaged_count;	/* # pages unmanaged. */
	unsigned long	ts_referenced_count;	/* # pages referenced. */
	unsigned long	ts_capstore_count;	/* # pages capstore. */
	unsigned long	ts_capdirty_count;	/* # pages capdirty. */
	unsigned long	ts_pcpu_count;		/* # pages from PCPU cache. */
	unsigned long	ts_fict_count;		/* # pages ficticious. */
	unsigned long	ts_zero_count;		/* # pages zeroed. */
	unsigned long	ts_nodump_count;	/* # pages nodump. */
	unsigned long	ts_nofree_count;	/* # pages nofree. */
	unsigned long	ts_obj_kernel_count;	/* # pages in kernel object. */
	unsigned long	ts_obj_type_phys_count;	/* # pages in a phys object. */
	unsigned long	ts_obj_type_vnode_count;/* # pages in a vnode object. */
	unsigned long	ts_obj_type_swap_count;	/* # pages in a swap object. */
	unsigned long	ts_obj_type_misc_count;	/* # pages in other objects. */
	unsigned long	ts_obj_type_all_count;	/* # pages in any object. */
	unsigned long	ts_obj_flag_hascap_count;/* # pages hascap obj. */
	unsigned long	ts_obj_flag_nocap_count;/* # pages nocap obj. */
	unsigned long	ts_noobj_count;		/* # pages w/o object. */
	unsigned long	ts_without_pa_count;	/* # pages with 0 addr */
	unsigned long	ts_pageswithcaps_count;	/* # pages with tags. */
	unsigned long	ts_withseals_count;	/* # pages with sealed caps. */

	/* Page counters but limited to pages with tags. */
	unsigned long	ts_obj_kernel_pageswithcaps_count;
	unsigned long	ts_obj_type_phys_pageswithcaps_count;
	unsigned long	ts_obj_type_vnode_pageswithcaps_count;
	unsigned long	ts_obj_type_swap_pageswithcaps_count;
	unsigned long	ts_obj_type_misc_pageswithcaps_count;
	unsigned long	ts_obj_type_all_pageswithcaps_count;
	unsigned long	ts_obj_flag_hascap_pageswithcaps_count;
	unsigned long	ts_obj_flag_nocap_pageswithcaps_count;
	unsigned long	ts_noobj_pageswithcaps_count;

	/* For pages of this object type, how many capabilities are there? */
	unsigned long	ts_obj_kernel_caps_count;
	unsigned long	ts_obj_type_phys_caps_count;
	unsigned long	ts_obj_type_vnode_caps_count;
	unsigned long	ts_obj_type_swap_caps_count;
	unsigned long	ts_obj_type_misc_caps_count;
	unsigned long	ts_obj_type_all_caps_count;
	unsigned long	ts_obj_flag_hascap_caps_count;
	unsigned long	ts_obj_flag_nocap_caps_count;
	unsigned long	ts_noobj_caps_count;

	/*
	 * Summary statistics across all of the above.
	 */

	/* Stats with total page count denominator. */
	unsigned long	ts_obj_percent;
	unsigned long	ts_unmanaged_percent;
	unsigned long	ts_referenced_percent;
	unsigned long	ts_capstore_percent;
	unsigned long	ts_capdirty_percent;
	unsigned long	ts_pcpu_percent;
	unsigned long	ts_fict_percent;
	unsigned long	ts_zero_percent;
	unsigned long	ts_nodump_percent;
	unsigned long	ts_nofree_percent;

	unsigned long	ts_obj_flag_hascap_percent;
	unsigned long	ts_obj_flag_nocap_percent;
	unsigned long	ts_noobj_percent;

	unsigned long	ts_without_pa_percent;
	unsigned long	ts_pageswithcaps_percent;
	unsigned long	ts_withseals_percent;

	/* Stats with total page count for 'all' objects as denominator. */
	unsigned long	ts_obj_kernel_ofall_percent;
	unsigned long	ts_obj_type_phys_ofall_percent;
	unsigned long	ts_obj_type_vnode_ofall_percent;
	unsigned long	ts_obj_swap_ofall_percent;
	unsigned long	ts_obj_misc_ofall_percent;

	/* Stats with object-type page-count denominator. */
	unsigned long	ts_obj_kernel_pageswithcaps_percent;
	unsigned long	ts_obj_type_phys_pageswithcaps_percent;
	unsigned long	ts_obj_type_vnode_pageswithcaps_percent;
	unsigned long	ts_obj_type_swap_pageswithcaps_percent;
	unsigned long	ts_obj_type_misc_pageswithcaps_percent;
	unsigned long	ts_obj_type_all_pageswithcaps_percent;
	unsigned long	ts_obj_flag_hascap_pageswithcaps_percent;
	unsigned long	ts_obj_flag_nocap_pageswithcaps_percent;
	unsigned long	ts_noobj_pageswithcaps_percent;

	/* Statistics with object-type word-count denominators. */
	unsigned long	ts_obj_kernel_caps_percent;
	unsigned long	ts_obj_type_phys_caps_percent;
	unsigned long	ts_obj_type_vnode_caps_percent;
	unsigned long	ts_obj_type_swap_caps_percent;
	unsigned long	ts_obj_type_misc_caps_percent;
	unsigned long	ts_obj_type_all_caps_percent;
	unsigned long	ts_obj_flag_hascap_caps_percent;
	unsigned long	ts_obj_flag_nocap_caps_percent;
	unsigned long	ts_noobj_caps_percent;

	/* Estimated overheads from pointer-size growth. */
	unsigned long	ts_obj_kernel_overhead;
	unsigned long	ts_obj_type_phys_overhead;
	unsigned long	ts_obj_type_vnode_overhead;
	unsigned long	ts_obj_type_swap_overhead;
	unsigned long	ts_obj_type_misc_overhead;
	unsigned long	ts_obj_type_all_overhead;
	unsigned long	ts_obj_flag_hascap_overhead;
	unsigned long	ts_obj_flag_nocap_overhead;
	unsigned long	ts_noobj_overhead;
};

#endif /* _DEV_TAGSCAN_H_ */
