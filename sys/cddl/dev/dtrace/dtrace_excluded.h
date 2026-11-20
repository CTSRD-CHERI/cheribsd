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
 *
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _DTRACE_EXCLUDED_H_
#define _DTRACE_EXCLUDED_H_

static inline int
dtrace_excluded_module(modctl_t *lf)
{
	int i;

	/*
	 * Employees of dtrace and their families are ineligible.  Void
	 * where prohibited.
	 */
	if (strncmp(lf->filename, "dtrace", sizeof("dtrace") - 1) == 0)
		return (1);

	/*
	 * To register with DTrace, a module must list 'dtrace' as a
	 * dependency in order for the kernel linker to resolve
	 * symbols like dtrace_register(). All modules with such a
	 * dependency are ineligible for FBT tracing.
	 */
	for (i = 0; i < lf->ndeps; i++)
		if (strncmp(lf->deps[i]->filename, "dtrace",
		    sizeof("dtrace") - 1) == 0)
			return (1);

	return (0);
}

static inline int
dtrace_excluded_function(const char *name)
{

	if (strncmp(name, "dtrace_", 7) == 0 &&
	    strncmp(name, "dtrace_safe_", 12) != 0) {
		/*
		 * Anything beginning with "dtrace_" may be called
		 * from probe context unless it explicitly indicates
		 * that it won't be called from probe context by
		 * using the prefix "dtrace_safe_".
		 */
		return (1);
	}

	/*
	 * Omit instrumentation of functions that are probably in DDB.  It
	 * makes it too hard to debug broken FBT.
	 *
	 * NB: kdb_enter() can be excluded, but its call to printf() can't be.
	 * This is generally OK since we're not yet in debugging context.
	 */
	if (strncmp(name, "db_", 3) == 0 ||
	    strncmp(name, "kdb_", 4) == 0)
		return (1);

	/*
	 * Lock owner methods may be called from probe context.
	 */
	if (strcmp(name, "owner_mtx") == 0 ||
	    strcmp(name, "owner_rm") == 0 ||
	    strcmp(name, "owner_rw") == 0 ||
	    strcmp(name, "owner_sx") == 0)
		return (1);

	/*
	 * The KMSAN runtime can't be instrumented safely.
	 */
	if (strncmp(name, "__msan", 6) == 0 ||
	    strncmp(name, "kmsan_", 6) == 0)
		return (1);

	/*
	 * Stack unwinders may be called from probe context on some
	 * platforms.
	 */
#if defined(__aarch64__) || defined(__riscv)
	if (strcmp(name, "unwind_frame") == 0)
		return (1);
#endif

#ifdef CHERI_COMPARTMENTALIZE_KERNEL
	/*
	 * The compartmentalization trampoline and its callees cannot be
	 * instrumented as the probe handling code can be compartmentalized.
	 * To simplify the assumptions, exclude the entire compartment API.
	 * This list should be kept in sync with the trampoline code in
	 * compartment.S and the functions it calls indirectly in
	 * kern_compartment.c.
	 */
	if (strncmp(name, "compartment_", sizeof("compartment_") - 1) == 0 ||
	    strcmp(name, "spinlock_enter") == 0 ||
	    strcmp(name, "spinlock_exit") == 0 ||
	    strncmp(name, "__pcpu_ptr_", sizeof("__pcpu_ptr_") - 1) == 0 ||
	    strncmp(name, "__dpcpu_ptr_", sizeof("__dpcpu_ptr_") - 1) == 0)
		return (1);
#endif

	return (0);
}

#endif /* _DTRACE_EXCLUDED_H_ */
