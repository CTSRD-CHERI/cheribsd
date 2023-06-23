/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
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
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/errno.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/hwt.h>

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#include "libpmcstat_stubs.h"
#include <libpmcstat.h>

#include "hwtvar.h"
#include "hwt_coresight.h"

#define	PARENTSOCKET		0
#define	CHILDSOCKET		1
#define	NSOCKPAIRFD		2

static struct trace_context tcs;
static int ncpu;

void
hwt_sleep(void)
{
	struct timespec time_to_sleep;

	time_to_sleep.tv_sec = 0;
	time_to_sleep.tv_nsec = 10000000; /* 10 ms */

	nanosleep(&time_to_sleep, &time_to_sleep);
}

void
hwt_procexit(pid_t pid, int exit_status __unused)
{
	struct trace_context *tc;

	tc = &tcs;

	if (tc->pid == pid)
		tc->terminate = 1;
}

static int
hwt_ctx_alloc(int fd)
{
	struct trace_context *tc;
	struct hwt_alloc al;
	int error;

	tc = &tcs;

	al.pid = tc->pid;
	al.bufsize = tc->bufsize;
	al.backend_name = "coresight";

	error = ioctl(fd, HWT_IOC_ALLOC, &al);
	if (error != 0)
		return (error);

	return (0);
}

static int
hwt_map_memory(struct trace_context *tc, int tid)
{
	char filename[32];

	sprintf(filename, "/dev/hwt_%d_%d", tc->pid, tid);

	tc->thr_fd = open(filename, O_RDONLY);
	if (tc->thr_fd < 0) {
		printf("Can't open %s\n", filename);
		return (-1);
	}

	tc->base = mmap(NULL, tc->bufsize, PROT_READ, MAP_SHARED, tc->thr_fd,
	    0);
	if (tc->base == MAP_FAILED) {
		printf("mmap failed: err %d\n", errno);
		return (-1);
	}

	printf("%s: tc->base %#p\n", __func__, tc->base);

	return (0);
}

size_t
hwt_get_offs(struct trace_context *tc, size_t *offs)
{
	struct hwt_bufptr_get bget;
	vm_offset_t curpage_offset;
	int curpage;
	int error;
	int ptr;

	bget.pid = tc->pid;
	bget.ptr = &ptr;
	bget.curpage = &curpage;
	bget.curpage_offset = &curpage_offset;
	error = ioctl(tc->thr_fd, HWT_IOC_BUFPTR_GET, &bget);
	if (error)
		return (error);

	printf("curpage %d curpage_offset %ld\n", curpage, curpage_offset);

	*offs = curpage * PAGE_SIZE + curpage_offset;

	return (0);
}

static int
hwt_get_records(uint32_t *nrec)
{
	struct trace_context *tc;
	int tot_records;
	int nrecords;
	int error;

	tc = &tcs;

	tot_records = 0;

	error = hwt_record_fetch(tc, &nrecords);
	if (error)
		return (error);

	tot_records += nrecords;

	*nrec = tot_records;

	return (0);
}

int
main(int argc __unused, char **argv, char **env)
{
	struct hwt_record_user_entry *entry;
	struct pmcstat_process *pp;
	struct trace_context *tc;
	struct hwt_start s;
	uint32_t tot_rec;
	uint32_t nrec;
	uint32_t nlibs;
	char **cmd;
	int error;
	int fd;
	int sockpair[NSOCKPAIRFD];
	int pid;
	size_t bufsize;

	cmd = argv + 1;

	tc = &tcs;

	error = hwt_elf_count_libs(*cmd, &nlibs);
	if (error != 0) {
		printf("could not count libs\n");
		return (error);
	}

	nlibs += 1; /* add binary itself. */

	ncpu = sysconf(_SC_NPROCESSORS_CONF);

	printf("cmd is %s, nlibs %d\n", *cmd, nlibs);

	fd = open("/dev/hwt", O_RDWR);
	if (fd < 0) {
		printf("Can't open /dev/hwt\n");
		return (-1);
	}

	error = hwt_process_create(sockpair, cmd, env, &pid);
	if (error != 0)
		return (error);

	printf("%s: process pid %d created\n", __func__, pid);

	pp = hwt_process_alloc();
	pp->pp_pid = pid;
	pp->pp_isactive = 1;

	bufsize = 16 * 1024 * 1024;

	tc->pp = pp;
	tc->pid = pid;
	tc->fd = fd;

	tc->bufsize = bufsize;

	error = hwt_ctx_alloc(fd);
	if (error) {
		printf("%s: failed to alloc ctx, pid %d error %d\n", __func__,
		    tc->pid, error);

		while (1);

		return (error);
	}

	error = hwt_get_records(&nrec);
	if (error != 0)
		return (error);

	if (nrec != 1)
		return (error);

	entry = &tc->records[0];

	error = hwt_map_memory(tc, entry->tid);
	if (error != 0) {
		printf("can't map memory");
		return (error);
	}

	printf("starting tracing\n");

	s.pid = tc->pid;
	error = ioctl(fd, HWT_IOC_START, &s);
	if (error) {
		printf("%s: failed to start tracing, error %d\n", __func__,
		    error);
		return (error);
	}

	error = hwt_process_start(sockpair);
	if (error != 0)
		return (error);

	printf("nlibs %d\n", nlibs);

	tot_rec = 0;

	do {
		error = hwt_get_records(&nrec);
		if (error != 0)
			return (error);
		tot_rec += nrec;
	} while (tot_rec < nlibs);

	hwt_coresight_process(tc);

	close(fd);

	return (0);
}
