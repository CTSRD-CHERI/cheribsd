/*-
 * Copyright (c) 2023 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
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
 */

#ifndef	_HWTVAR_H_
#define	_HWTVAR_H_

struct trace_context {
	struct pmcstat_process *pp;
	struct hwt_record_user_entry *records;
	void *base;
	int bufsize;
	int pid;
	int fd;
	int thr_fd;
	int terminate;
	int thread_id;

	/* Address range filtering. */
	int pause_on_mmap_once;
	char *image_name;
	char *func_name;
};

struct pmcstat_process *hwt_process_alloc(void);
int hwt_process_create(int *sockpair, char **cmd, char **env, int *pid0);
int hwt_process_start(int *sockpair);
int hwt_record_fetch(struct trace_context *tc, int *nrecords);
void hwt_procexit(pid_t pid, int status);
size_t hwt_get_offs(struct trace_context *tc, size_t *offs);
void hwt_sleep(void);
int hwt_elf_count_libs(const char *elf_path, uint32_t *nlibs0);

#endif /* !_HWTVAR_H_ */
