/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Dapeng Gao
 * Copyright (c) 2024 Capabilities Limited
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

#ifndef __SYS_CHERI_C18N_H__
#define	__SYS_CHERI_C18N_H__

/*
 * Members fields do not need to be atomic outside of RTLD.
 */
#ifndef IN_RTLD
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

/*
 * The interface provided by the kernel for RTLD to supply compartmentalisation
 * information. The version field doubles as a synchronisation flag where a
 * non-zero value indicates that the other fields have been initialised.
 */
#define CHERI_C18N_INFO_VERSION		2

struct cheri_c18n_info {
	_Atomic(size_t) version;

	size_t stats_size;
	struct rtld_c18n_stats * __kerncap	stats;

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
 * monitoring tools such as procstat.
 */
#define	CHERI_C18N_COMPART_MAXNAME	(PATH_MAX + NAME_MAX + 2)

struct kinfo_cheri_c18n_compart {
	/*
	 * The last field of this struct may be truncated. This field contains
	 * the actual aligned size of the current object.
	 */
	size_t		kccc_structsize;
	size_t		kccc_id;
	uint8_t		kccc_dlopened_explicitly : 1;
	uint8_t		kccc_dlopened : 1;
	char		kccc_name[CHERI_C18N_COMPART_MAXNAME];
};

#ifndef IN_RTLD
#undef _Atomic
#endif

#endif /* __SYS_CHERI_C18N_H__ */
