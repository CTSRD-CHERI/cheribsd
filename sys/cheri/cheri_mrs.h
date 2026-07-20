/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025-2026 Capabilities Limited
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency (DARPA) Contract No. FA8750-24-C-B047 ("DEC").
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

#ifndef __SYS_CHERI_MRS_H__
#define	__SYS_CHERI_MRS_H__

#include <sys/_timespec.h>

#define CHERI_MRS_STATS_VERSION		1
#define CHERI_MRS_STATS_MAX_SIZE	256

#define	CHERI_MFS_FLAGS_INITIALIZED	0x00000001	/* Structure live. */
#define	CHERI_MRS_FLAGS_QUARANTINING	0x00000002	/* Quarantining. */
#define	CHERI_MRS_FLAGS_EVERYFREE	0x00000004	/* Revoke every free. */
#define	CHERI_MRS_FLAGS_ASYNCREVOKE	0x00000008	/* Async revocation. */
#define	CHERI_MRS_FLAGS_ABORTONFAIL	0x00000010	/* Abort on failure. */
#define	CHERI_MRS_FLAGS_BOUNDPTRS	0x00000020	/* Bound pointers. */

/*
 * Statistics gathered by the heap allocator and mrs.  The version field
 * doubles as a synchronisation flag where a non-zero value indicates that the
 * other fields have been initialised.
 */
struct cheri_mrs_stats {
	size_t		cms_size;
	_Atomic(size_t)	cms_version;

	/* Counts of events since inception. */
	_Atomic(size_t)	cms_mrs_count_allocated;
	_Atomic(size_t)	cms_mrs_count_freed;	/* .. by the caller. */
	_Atomic(size_t)	cms_mrs_count_returned;	/* .. to the allocator. */

	/* Running totals of outstanding and quarantined memory allocations. */
	_Atomic(size_t)	cms_mrs_count_inheap;	/* Allocated but not freed. */
	_Atomic(size_t)	cms_mrs_count_inquarantine; /* Freed but not revoked. */

	/* Byte totals for allocator since inception. */
	_Atomic(size_t)	cms_mrs_bytes_allocated;
	_Atomic(size_t)	cms_mrs_bytes_freed;	/* .. by the caller. */
	_Atomic(size_t)	cms_mrs_bytes_returned;	/* .. to the allocator. */

	/* Running totals of outstanding and quarantined memory in bytes. */
	_Atomic(size_t)	cms_mrs_bytes_inheap;	/* Allocated but not freed. */
	_Atomic(size_t)	cms_mrs_bytes_inquarantine; /* Freed but not revoked. */

	/* 32-bit mrs parameters. */
	uint32_t	cms_mrs_arenas;
	uint32_t	cms_mrs_quarantine_numerator;
	uint32_t	cms_mrs_quarantine_denominator;
	uint32_t	cms_mrs_revocation_minimum;

	/* Status flags. */
	uint32_t	cms_mrs_flags;
	uint32_t	_cms_mrs_pad0;

	/* 64-bit mrs global state. */
	_Atomic(size_t)	cms_mrs_allocated_size;
	_Atomic(size_t)	cms_mrs_max_allocated_size;

	/* 64-bit mrs parameters. */
	_Atomic(uint64_t)	cms_mrs_epoch;

	/* Timestamps associated with these stats. */
	struct timespec	cms_mrs_ts_start;	/* Earliest moment. */

	/* Padding to a sensible size for future non-disruptive growth. */
	size_t		_cms_pad1[4];
};

#ifndef _KERNEL
extern struct cheri_mrs_stats *rtld_cheri_mrs_statsp;
#endif

#endif /* __SYS_CHERI_MRS_H__ */
