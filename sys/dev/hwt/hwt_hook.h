/*-
 * Copyright (c) 2023 Ruslan Bukin <br@bsdpad.com>
 *
 * This work was supported by Innovate UK project 105694, "Digital Security
 * by Design (DSbD) Technology Platform Prototype".
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
 *
 * $FreeBSD$
 */

#ifndef _DEV_HWT_HWT_HOOK_H_
#define _DEV_HWT_HWT_HOOK_H_

enum hwt_record_type {
	HWT_RECORD_MMAP,
	HWT_RECORD_MUNMAP,
	HWT_RECORD_EXECUTABLE,
	HWT_RECORD_INTERP,
	HWT_RECORD_THREAD_CREATE,
	HWT_RECORD_THREAD_SET_NAME,
};

struct hwt_record_entry {
	enum hwt_record_type		record_type;
	LIST_ENTRY(hwt_record_entry)	next;
	char				*fullpath;
	struct thread			*td;
	lwpid_t				tid;
	uintptr_t			addr;
	size_t				size;
};

void hwt_switch_in(struct thread *td);
void hwt_switch_out(struct thread *td);
void hwt_record(struct thread *td, enum hwt_record_type record_type,
    struct hwt_record_entry *ent);

#endif /* !_DEV_HWT_HWT_HOOK_H_ */
