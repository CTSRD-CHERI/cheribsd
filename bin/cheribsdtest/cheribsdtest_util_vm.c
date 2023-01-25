/*-
 * Copyright (c) 2021, 2022 SRI International
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

#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <cheri/cheric.h>

#include <libprocstat.h>
#include <unistd.h>

#include "cheribsdtest.h"

/*
 * Find a region of address space unoccupied by any memory mappings.
 *
 * Caveats:
 * - This is not concurency safe and the found region could be disrupted
 *   by any non-MAP_FIXED mmap() call.  This includes anything that
 *   allocates heap memory.
 * - The region between PAGE_SIZE and the first mapping is not currently
 *   searched.
 * - The top of the address space will be searched due to the shared
 *   page at the topmost address.
 * - If an alignment of 0 is pased, the address of a region representable as a
 *   capability will be returned.  It a non-zero alignment is passed it
 *   will be honored even if that results in an address that is
 *   under-aligned relative to a representable capability.
 */
ptraddr_t
find_address_space_gap(size_t len, size_t align)
{
	struct procstat *psp;
	struct kinfo_proc *kipp;
	struct kinfo_vmentry *kivp;
	uint pcnt, vmcnt;
	ptraddr_t addr = 0;

	psp = procstat_open_sysctl();
	CHERIBSDTEST_VERIFY(psp != NULL);
	kipp = procstat_getprocs(psp, KERN_PROC_PID, getpid(), &pcnt);
	CHERIBSDTEST_VERIFY(kipp != NULL);
	CHERIBSDTEST_VERIFY(pcnt == 1);
	kivp = procstat_getvmmap(psp, kipp, &vmcnt);
	CHERIBSDTEST_VERIFY(kivp != NULL);

	if (align == 0) {
		len = CHERI_REPRESENTABLE_LENGTH(len);
		align = CHERI_REPRESENTABLE_ALIGNMENT(len) + 1;
	}

	for (u_int i = 1; i < vmcnt; i++) {
		ptraddr_t aligned_start = __align_up(kivp[i-1].kve_end, align);
		ptraddr_t end = kivp[i].kve_start;
		if (aligned_start > end)
			continue;
		if (end - aligned_start >= len) {
			addr = aligned_start;
			break;
		}
	}
	if (addr == 0) {
		cheribsdtest_failure_errx("no free region of length %#jx\n",
		    len);
	}

	procstat_freevmmap(psp, kivp);
	procstat_freeprocs(psp, kipp);
	procstat_close(psp);
	return (addr);
}
