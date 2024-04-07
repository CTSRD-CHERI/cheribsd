/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Dapeng Gao
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
	_Atomic(uint8_t) version;
	size_t rcs_compart;
	_Atomic(size_t) rcs_ustack;
	_Atomic(size_t) rcs_tramp;
	_Atomic(size_t) rcs_tramp_page;
	_Atomic(size_t) rcs_bytes_total;
};

/*
 * The interface provided by the kernel for RTLD to supply compartmentalisation
 * information. The version field doubles as a synchronisation flag where a
 * non-zero value indicates that the other fields have been initialised.
 */
#define CHERI_C18N_INFO_VERSION		1

struct cheri_c18n_info {
	_Atomic(uint8_t) version;
	size_t stats_size;
	struct rtld_c18n_stats * __kerncap	stats;
};

#ifndef IN_RTLD
#undef _Atomic
#endif

#endif /* __SYS_CHERI_C18N_H__ */
