/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Dapeng Gao
 * Copyright (c) 2024 Capabilities Limited
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency / Air Force Research Laboratory (DARPA/AFRL) Contract
 * No. FA8750-24-C-B047 ("DEC").
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

#ifndef __SYS_CHERI_STATS_H__
#define	__SYS_CHERI_STATS_H__

#include <sys/_timespec.h>

/*
 * Members fields do not need to be atomic outside of RTLD.
 */
#if !defined(IN_RTLD) && !defined(MRS_STATS)
#define	_Atomic(t)			t
#endif

#define RTLD_C18N_STATS_VERSION		1
#define RTLD_C18N_STATS_MAX_SIZE	256

/*
 * Statistics exposed by RTLD. The version field doubles as a synchronisation
 * flag where a non-zero value indicates that the other fields have been
 * initialised.
 */
struct rtld_c18n_stats {
	_Atomic(size_t) version;
	size_t rcs_compart;
	_Atomic(size_t) rcs_ustack;
	_Atomic(size_t) rcs_tramp;
	_Atomic(size_t) rcs_tramp_page;
	_Atomic(size_t) rcs_bytes_total;
	_Atomic(size_t) rcs_switch;
};

/*
 * Compartment information exposed by RTLD.
 */
struct rtld_c18n_compart {
	const char * __kerncap	rcc_name;
	size_t			rcc_id;
	uint8_t			rcc_dlopened_explicitly : 1;
	uint8_t			rcc_dlopened : 1;
};

#define CHERI_MRS_STATS_VERSION		1
#define CHERI_MRS_STATS_MAX_SIZE	256

#define	CHERI_MRS_FLAGS_INITIALIZED	0x00000001	/* Structure live. */
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
	size_t	cms_version;

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
	_Atomic(size_t)	cms_mrs_max_quarantine_size;

	/* 64-bit mrs parameters. */
	_Atomic(uint64_t)	cms_mrs_epoch;

	/* Timestamps associated with these stats. */
	struct timespec	cms_mrs_ts_start;	/* Earliest moment. */

	/* Padding to a sensible size for future non-disruptive growth. */
	size_t		_cms_pad1[4];
};

/*
 * The interface provided by the kernel for RTLD to supply compartmentalisation
 * information. The version field doubles as a synchronisation flag where a
 * non-zero value indicates that the other fields have been initialised.
 */
#define CHERI_C18N_INFO_VERSION	3

struct cheri_stats {
	size_t version;

	size_t c18n_stats_size;
	size_t mrs_stats_size;
	struct rtld_c18n_stats * __kerncap	c18n_stats;
	struct cheri_mrs_stats * __kerncap	mrs_stats;

	/*
	 * Since the `comparts` array may be reallocated or ortherwise change
	 * whilst the kernel is reading it, the generation counter allows the
	 * kernel to identify such races. An even value indicates that the
	 * array and size data are in a consistent state, and an odd value
	 * indicates that the data may be inconsistent.
	 */
	_Atomic(size_t) comparts_gen;
	size_t comparts_size;
	size_t comparts_entry_size;
	void * __kerncap	comparts;
};

/*
 * The interface provided by the kernel via sysctl for compartmentalization
 * monitoring tools such as procstat and vmstat.
 */
#define	CHERI_C18N_COMPART_MAXNAME	(PATH_MAX + NAME_MAX + 2)

/*
 * The last fields of kinfo_cheri_{,k}c18n_compart structures may be truncated.
 * The *_structsize fields contains the actual aligned size of the current
 * object.
 */

struct kinfo_cheri_c18n_compart {
	size_t		kccc_structsize;
	size_t		kccc_id;
	uint8_t		kccc_dlopened_explicitly : 1;
	uint8_t		kccc_dlopened : 1;
	char		kccc_name[CHERI_C18N_COMPART_MAXNAME];
};

struct kinfo_cheri_kc18n_compart {
	size_t		kckc_structsize;
	size_t		kckc_id;
	uint8_t		kckc_executive : 1;
	char		kckc_name[CHERI_C18N_COMPART_MAXNAME];
};

#if !defined(IN_RTLD) && !defined(MRS_STATS)
#undef _Atomic
#endif

#endif /* __SYS_CHERI_STATS_H__ */
