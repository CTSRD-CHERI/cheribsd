/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 SRI International
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency (DARPA) Contract No. HR001123C0031 ("MTSS").
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

#ifndef __MRS_UTRACE_H__
#define	__MRS_UTRACE_H__

#define	UTRACE_MRS_MALLOC		1
#define	UTRACE_MRS_CALLOC		2
#define	UTRACE_MRS_POSIX_MEMALIGN	3
#define	UTRACE_MRS_ALIGNED_ALLOC	4
#define	UTRACE_MRS_REALLOC		5
#define	UTRACE_MRS_FREE			6
#define	UTRACE_MRS_QUARANTINE_INSERT	7
#define	UTRACE_MRS_MALLOC_REVOKE	8
#define	UTRACE_MRS_QUARANTINE_FLUSH	9
#define	UTRACE_MRS_QUARANTINE_FLUSH_DONE	10
#define	UTRACE_MRS_QUARANTINE_REVOKE	11
#define	UTRACE_MRS_QUARANTINE_REVOKE_DONE	12

#define	MRS_UTRACE_SIG_SZ		4
#define	MRS_UTRACE_SIG			"MRS "

struct utrace_mrs {
	char sig[MRS_UTRACE_SIG_SZ];
	int event;
	size_t s;			/* size input arg */
	void *p;			/* pointer input arg */
	void *r;			/* pointer return value */
	size_t n;			/* alignment/number input arg */
};

#endif /* !__MRS_UTRACE_H__ */
