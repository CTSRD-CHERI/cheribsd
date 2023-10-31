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
#include <sys/cpuset.h>
#include <sys/hwt.h>
#include <sys/stat.h>
#include <sys/user.h>

#include <assert.h>
#include <err.h>
#include <sysexits.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <libutil.h>

#include "libpmcstat_stubs.h"
#include <libpmcstat.h>
#include <libxo/xo.h>

#include "hwt.h"

#if defined(__aarch64__)
#include "hwt_coresight.h"
#endif

#define	HWT_DEBUG
#undef	HWT_DEBUG

#ifdef	HWT_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

#define	PARENTSOCKET		0
#define	CHILDSOCKET		1
#define	NSOCKPAIRFD		2

static struct trace_context tcs;

static struct trace_dev trace_devs[] = {
#if defined(__aarch64__)
	{ "coresight",	"ARM Coresight", &cs_methods },
#endif
	{ NULL, NULL, NULL }
};

void
hwt_sleep(int msec)
{
	struct timespec time_to_sleep;

	time_to_sleep.tv_sec = 0;
	time_to_sleep.tv_nsec = msec * 1000000;

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
hwt_unsuspend_proc(struct trace_context *tc)
{
	struct hwt_wakeup w;
	int error;

	error = ioctl(tc->thr_fd, HWT_IOC_WAKEUP, &w);

	return (error);
}

int
hwt_mmap_received(struct trace_context *tc,
    struct hwt_record_user_entry *entry __unused)
{
	int error;

	assert(tc->mode == HWT_MODE_THREAD);

	if (!tc->suspend_on_mmap)
		return (0);

	if (tc->func_name == NULL)
		return (0);

	error = hwt_find_sym(tc);
	if (error != 0) {
		hwt_unsuspend_proc(tc);
		return (-1);
	}

	tc->suspend_on_mmap = 0;

	error = tc->trace_dev->methods->set_config(tc);
	if (error)
		return (-2);

	error = hwt_start_tracing(tc);
	if (error)
		return (-2);

	printf("%s: tracing started\n", __func__);

	hwt_unsuspend_proc(tc);

	return (0);
}

static int
hwt_ctx_alloc(struct trace_context *tc)
{
	struct hwt_alloc al;
	cpuset_t cpu_map;
	int error;

	CPU_ZERO(&cpu_map);

	memset(&al, 0, sizeof(struct hwt_alloc));

	al.mode = tc->mode;
	if (tc->mode == HWT_MODE_THREAD)
		al.pid = tc->pid;
	else {
		al.cpu_map = &tc->cpu_map;
		al.cpusetsize = sizeof(cpuset_t);
	}

	al.bufsize = tc->bufsize;
	al.backend_name = tc->trace_dev->name;
	al.ident = &tc->ident;

	error = ioctl(tc->fd, HWT_IOC_ALLOC, &al);

	return (error);
}

static int
hwt_map_memory(struct trace_context *tc, int tid)
{
	char filename[32];

	sprintf(filename, "/dev/hwt_%d_%d", tc->ident, tid);

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

	printf("%s: tc->base %p\n", __func__, tc->base);

	return (0);
}

int
hwt_ncpu(void)
{
	int ncpu;

	ncpu = sysconf(_SC_NPROCESSORS_CONF);

	return (ncpu);
}

int
hwt_get_offs(struct trace_context *tc, size_t *offs)
{
	struct hwt_bufptr_get bget;
	vm_offset_t curpage_offset;
	int curpage;
	int error;

	bget.curpage = &curpage;
	bget.curpage_offset = &curpage_offset;

	error = ioctl(tc->thr_fd, HWT_IOC_BUFPTR_GET, &bget);
	if (error)
		return (error);

	dprintf("curpage %d curpage_offset %ld\n", curpage, curpage_offset);

	*offs = curpage * PAGE_SIZE + curpage_offset;

	return (0);
}

static int
hwt_get_records(struct trace_context *tc, uint32_t *nrec)
{
	int nrecords;
	int error;

	error = hwt_record_fetch(tc, &nrecords);
	if (error)
		return (error);

	*nrec = nrecords;

	return (0);
}

int
hwt_find_sym(struct trace_context *tc)
{
	struct pmcstat_symbol *sym;
	uintptr_t addr_start;
	uintptr_t addr_end;

	sym = pmcstat_symbol_search_by_name(tc->pp, tc->image_name,
	    tc->func_name, &addr_start, &addr_end);
	if (sym) {
		printf("sym found, start end %lx %lx\n", (uint64_t)addr_start,
		    (uint64_t)addr_end);
		tc->addr_ranges[tc->nranges] = addr_start;
		tc->addr_ranges[tc->nranges + 1] = addr_end;
		tc->nranges += 1;
		return (0);
	}

	return (ENOENT);
}

int
hwt_start_tracing(struct trace_context *tc)
{
	struct hwt_start s;
	int error;

	error = ioctl(tc->thr_fd, HWT_IOC_START, &s);

	return (error);
}

static void
usage(void)
{

	errx(EX_USAGE,
		"hwt [-s cpu_id] [-c devname] [-b bufsize] [-t id] [-g]"
			" [-r] [-w file] [-i name]"
			" [-f name] [path to executable]\n"
		"\t -s\tcpu_id\t\tCPU (kernel) mode.\n"
		"\t -c\tname\t\tName of tracing device, e.g. 'coresight'.\n"
		"\t -b\tbufsize\t\tSize of trace buffer (per each thread)"
		    " in bytes.\n"
		"\t -t\tid\t\tThread index of application passed to decoder.\n"
		"\t -r\t\t\tRaw flag. Do not decode results.\n"
		"\t -w\tfilename\tStore results into file.\n"
#if defined(__aarch64__)
		"\t -g\t\t\tFormat flag.\n"
#endif
		"\t -i\tname\t\tFilter by dynamic library, executable name,\n"
		"\t\t\t\tkernel module name or 'kernel'.\n"
		"\t -f\tname\t\tFilter by function name."
        );
}

static int
hwt_mode_cpu(struct trace_context *tc)
{
	uint32_t nrec;
	int error;

	if (tc->image_name == NULL || tc->func_name == NULL)
		errx(EX_USAGE, "IP range filtering must be setup for CPU"
		    " tracing");

	error = hwt_ctx_alloc(tc);
	if (error) {
		printf("%s: failed to alloc cpu-mode ctx, error %d errno %d\n",
		    __func__, error, errno);
		if (errno == EPERM)
			printf("Permission denied.");
		printf("\n");
		return (error);
	}

	/*
	 * TODO: It is Coresight-specific to map memory from the first CPU.
	 */
	error = hwt_map_memory(tc, CPU_FFS(&tc->cpu_map) - 1);
	if (error != 0) {
		printf("can't map memory");
		return (error);
	}

	tc->pp->pp_pid = -1;

	error = hwt_get_records(tc, &nrec);
	if (error != 0)
		return (error);

	printf("Received %d kernel mappings\n", nrec);

	error = hwt_find_sym(tc);
	if (error)
		errx(EX_USAGE, "could not find symbol");

	error = tc->trace_dev->methods->set_config(tc);
	if (error != 0)
		errx(EX_DATAERR, "can't set config");

	error = hwt_start_tracing(tc);
	if (error)
		errx(EX_SOFTWARE, "failed to start tracing, error %d\n", error);

	error = tc->trace_dev->methods->process(tc);
	if (error) {
		printf("cant process data, error %d\n", error);
		return (error);
	}

	return (0);
}

static int
hwt_new_proc(struct trace_context *tc, int *sockpair, char **cmd, char **env,
    uint32_t *nlibs0)
{
	struct stat st;
	uint32_t nlibs;
	int error;

	error = stat(*cmd, &st);
	if (error) {
		printf("Could not find target executable"
		    " error %d.\n", error);
		return (error);
	}

	error = hwt_elf_count_libs(*cmd, &nlibs);
	if (error != 0) {
		printf("Could not count libs in the executable provided.\n");
		return (error);
	}

	nlibs += 1; /* add binary itself. */

	dprintf("cmd is %s, nlibs %d\n", *cmd, nlibs);

	error = hwt_process_create(sockpair, cmd, env, &tc->pid);
	if (error != 0)
		return (error);

	printf("%s: process pid %d created\n", __func__, tc->pid);

	*nlibs0 = nlibs;

	return (0);
}

static int
hwt_get_vmmap(struct trace_context *tc)
{
	struct kinfo_vmentry *vmmap, *kve;
	int cnt;
	int i, j;

	pmcstat_interned_string path;
	struct pmcstat_image *image;
	struct pmc_plugins plugins;
	struct pmcstat_args args;
	unsigned long addr;

	memset(&plugins, 0, sizeof(struct pmc_plugins));
	memset(&args, 0, sizeof(struct pmcstat_args));
	args.pa_fsroot = "/";

	vmmap = kinfo_getvmmap(tc->pid, &cnt);
	if (vmmap == NULL)
		return (ENXIO);

	printf("vmmap cnt %d\n", cnt);

	for (i = 0, j = 0; i < cnt; i++) {
		kve = &vmmap[i];
		if ((kve->kve_protection & KVME_PROT_EXEC) == 0)
			continue;
		if (*kve->kve_path == '\0')
			continue;

		path = pmcstat_string_intern(kve->kve_path);
		image = pmcstat_image_from_path(path, 0, &args, &plugins);
		if (image == NULL)
			continue;

		if (image->pi_type == PMCSTAT_IMAGE_UNKNOWN)
			pmcstat_image_determine_type(image, &args);

		addr = (unsigned long)kve->kve_start & ~1;
		addr -= (image->pi_start - image->pi_vaddr);
		pmcstat_image_link(tc->pp, image, addr);

		printf("  lib #%d: path %s addr %lx\n", j++,
		    kve->kve_path, (unsigned long)kve->kve_start);
	}

	return (0);
}

static int
hwt_mode_thread(struct trace_context *tc, char **cmd, char **env)
{
	uint32_t tot_rec;
	uint32_t nrec;
	uint32_t nlibs;
	int sockpair[NSOCKPAIRFD];
	int error;

	nlibs = 0;

	if (tc->attach == 0) {
		error = hwt_new_proc(tc, sockpair, cmd, env, &nlibs);
		if (error)
			return (error);

		if (tc->func_name != NULL)
			tc->suspend_on_mmap = 1;
	}

	tc->pp->pp_pid = tc->pid;

	error = hwt_ctx_alloc(tc);
	if (error) {
		printf("%s: failed to alloc thread-mode ctx "
		    "error %d errno %d\n", __func__, error, errno);
		if (errno == EPERM)
			printf("Permission denied.");
		printf("\n");
		return (error);
	}

	error = hwt_map_memory(tc, 0);
	if (error != 0) {
		printf("can't map memory");
		return (error);
	}

	error = tc->trace_dev->methods->set_config(tc);
	if (error != 0)
		errx(EX_DATAERR, "can't set config");

	if (tc->attach)
		hwt_get_vmmap(tc);

	if (tc->attach || tc->suspend_on_mmap == 0) {
		/* No address range filtering. Start tracing immediately. */
		error = hwt_start_tracing(tc);
		if (error)
			errx(EX_SOFTWARE, "failed to start tracing, error %d\n",
			    error);
	}

	if (tc->attach == 0) {
		error = hwt_process_start(sockpair);
		if (error != 0)
			return (error);
	}

	printf("Expect %d records.\n", nlibs);

	tot_rec = 0;

	/*
	 * Ensure we got expected amount of mmap/interp records so that
	 * mapping tables constructed before we do symbol lookup.
	 */

	do {
		error = hwt_get_records(tc, &nrec);
		if (error != 0)
			return (error);
		tot_rec += nrec;
		hwt_sleep(10);
	} while (tot_rec < nlibs);

	error = tc->trace_dev->methods->process(tc);
	if (error) {
		printf("Can't process data, error %d.\n", error);
		return (error);
	}

	return (0);
}

static int
hwt_get_cpumask(const char *arg, cpuset_t *cpumask)
{
	const char *start;
	int cpu_id;
	char *end;

	CPU_ZERO(cpumask);

	start = arg;

	while (*start) {
		cpu_id = strtol(start, &end, 0);
		if (cpu_id < 0)
			return (-1);

		if (end == start)
			return (-2);

		CPU_SET(cpu_id, cpumask);

		start = end + strspn(end, ", \t");
	};

	return (0);
}

int
main(int argc, char **argv, char **env)
{
	struct trace_context *tc;
	char *trace_dev_name;
	int error;
	int option;
	int found;
	int thread_id_specified;
	int i;

	tc = &tcs;

	memset(tc, 0, sizeof(struct trace_context));

	/* Defaults */
	tc->bufsize = 128 * 1024 * 1024;

	/* First available is default trace device. */
	tc->trace_dev = &trace_devs[0];
	if (tc->trace_dev->name == NULL) {
		printf("No trace devices available\n");
		return (1);
	}

	tc->mode = HWT_MODE_THREAD;
	tc->fs_root = "/";
	tc->thread_id = 0;
	tc->attach = 0;
	thread_id_specified = 0;

	argc = xo_parse_args(argc, argv);
	if (argc < 0)
		exit(EXIT_FAILURE);

	while ((option = getopt(argc, argv, "P:R:gs:hc:b:rw:t:i:f:")) != -1)
		switch (option) {
		case 'P':
			tc->attach = 1;
			tc->pid = atol(optarg);
			break;
		case 's':
			tc->mode = HWT_MODE_CPU;
			hwt_get_cpumask(optarg, &tc->cpu_map);
			break;
		case 'R':
			tc->fs_root = optarg;
			break;
		case 'c':
			trace_dev_name = strdup(optarg);
			found = 0;
			for (i = 0; trace_devs[i].name != NULL; i++) {
				if (strcmp(trace_devs[i].name,
				    trace_dev_name) == 0) {
					tc->trace_dev = &trace_devs[i];
					found = 1;
					break;
				}
			}
			if (!found) {
				printf("Trace device \"%s\" not available.\n",
				    trace_dev_name);
				return (ENOENT);
			}
			break;
		case 'b':
			tc->bufsize = atol(optarg);
			break;
		case 'r':
			/* Do not decode trace. */
			tc->raw = 1;
			break;
		case 'w':
			/* Store trace into a file. */
			tc->filename = strdup(optarg);
			break;
		case 'i':
			/*
			 * Name of dynamic lib or main executable for IP
			 * address range filtering.
			 */
			tc->image_name = strdup(optarg);
			break;
		case 'f':
			/* Name of the func to trace. */
			tc->func_name = strdup(optarg);
			break;
		case 't':
			tc->thread_id = atoi(optarg);
			thread_id_specified = 1;
			break;
		case 'g':
			tc->flag_format = 1;
			break;
		case 'h':
			usage();
			break;
		default:
			break;
		}

	if (tc->mode == HWT_MODE_CPU && thread_id_specified) {
		printf("Thread ID to decode used in THREAD mode only.\n");
		exit(1);
	}

	if (tc->raw != 0 && tc->filename == NULL) {
		printf("Filename must be specified for the raw data.\n");
		exit(1);
	}

	if ((tc->image_name == NULL && tc->func_name != NULL) ||
	    (tc->image_name != NULL && tc->func_name == NULL))
		errx(EX_USAGE, "For address range tracing specify both image "
		    "and func, or none of them.");

	tc->fd = open("/dev/hwt", O_RDWR);
	if (tc->fd < 0) {
		printf("Can't open /dev/hwt\n");
		return (-1);
	}

	tc->pp = hwt_process_alloc();
	tc->pp->pp_isactive = 1;

	argc += optind;
	argv += optind;

	if (tc->mode == HWT_MODE_THREAD) {
		if (*argv == NULL && tc->attach == 0)
			usage();
		error = hwt_mode_thread(tc, argv, env);
	} else {
		if (*argv != NULL)
			usage();
		error = hwt_mode_cpu(tc);
	}

	close(tc->fd);

	return (error);
}
