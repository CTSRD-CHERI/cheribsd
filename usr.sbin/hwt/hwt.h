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

#define	TC_MAX_ADDR_RANGES	16

struct trace_context;

struct trace_dev_methods {
	int (*init)(struct trace_context *tc);
	int (*mmap)(struct trace_context *tc);
	int (*process)(struct trace_context *tc);
	int (*set_config)(struct trace_context *tc);
};

struct trace_dev {
	const char *name;
	const char *fullname;
	struct trace_dev_methods *methods;
};

struct trace_context {
	struct trace_dev *trace_dev;
	struct pmcstat_process *pp;
	struct hwt_record_user_entry *records;
	void *base;
	size_t bufsize;
	int attach;
	int pid;
	cpuset_t cpu_map;
	int fd;
	int thr_fd;
	int terminate;
	int kqueue_fd;

	int thread_id;
	int ident;

	/* Address range filtering. */
	int suspend_on_mmap;
	char *image_name;
	char *func_name;
	uintptr_t addr_ranges[TC_MAX_ADDR_RANGES * 2];
	int nranges;

	/* Backend-specific config. */
	void *config;
	int flag_format;

	/* Raw trace. */
	int raw;
	FILE *raw_f;

	/* Trace file. */
	char *filename;

	int mode;
	const char *fs_root;
};

struct pmcstat_process *hwt_process_alloc(void);
int hwt_process_create(int *sockpair, char **cmd, char **env, int *pid0);
int hwt_process_start(int *sockpair);
int hwt_record_fetch(struct trace_context *tc, int *nrecords);
void hwt_procexit(pid_t pid, int status);
int hwt_get_offs(struct trace_context *tc, size_t *offs);
void hwt_sleep(int msec);
int hwt_elf_count_libs(const char *elf_path, uint32_t *nlibs0);
int hwt_find_sym(struct trace_context *tc);
int hwt_start_tracing(struct trace_context *tc);
int hwt_mmap_received(struct trace_context *tc,
    struct hwt_record_user_entry *entry);
int hwt_ncpu(void);

#endif /* !_HWTVAR_H_ */
