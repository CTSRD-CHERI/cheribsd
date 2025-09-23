/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Ruslan Bukin <br@bsdpad.com>
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
#include <sys/hwc.h>
#include <sys/stat.h>

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

#include <libgen.h>
#include <libxo/xo.h>

#include "hwc.h"
#include "hwc_process.h"

#if defined(__riscv)
#include "riscv/hwc_pmu.h"
#endif

#define	HWC_DEBUG
#undef	HWC_DEBUG

#ifdef	HWC_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

static struct hwc_context tcs;

static struct hwc_backend backends[] = {
#if defined(__riscv)
	{ "pmu", "RISC-V Performace Monitoring Unit", &pmu_methods },
#endif
	{ NULL, NULL, NULL }
};

void
hwc_procexit(pid_t pid, int exit_status __unused)
{
	struct hwc_context *tc;

	tc = &tcs;

	if (tc->pid == pid)
		tc->terminate = 1;
}

static int
hwc_ctx_alloc(struct hwc_context *tc)
{
	struct hwc_alloc al;
	char filename[32];
	int error = 0;

	if (tc->backend->methods->init != NULL){
		error = tc->backend->methods->init(tc);
		if (error)
			return (error);
	}

	memset(&al, 0, sizeof(struct hwc_alloc));
	al.mode = tc->mode;
	if (tc->mode == HWC_MODE_THREAD)
		al.pid = tc->pid;
	else {
#if 0
		al.cpu_map = &tc->cpu_map;
		al.cpusetsize = sizeof(cpuset_t);
#endif
	}

	al.pid = tc->pid;
	al.backend_name = tc->backend->name;
	al.ident = &tc->ident;

	error = ioctl(tc->fd, HWC_IOC_ALLOC, &al);
	if (error) {
		printf("%s: could not allocate ctx, error %d\n", __func__,
		    error);
		return (error);
	}

	sprintf(filename, "/dev/hwc_%d", tc->ident);

	tc->ctx_fd = open(filename, O_RDWR);
	if (tc->ctx_fd < 0) {
		printf("Can't open %s\n", filename);
		return (-1);
	}

	return (0);
}

int
hwc_start_tracing(struct hwc_context *tc)
{
	struct hwc_start s;
	int error;

	error = ioctl(tc->fd, HWC_IOC_START, &s);

	return (error);
}

int
hwc_stop_tracing(struct hwc_context *tc)
{
	struct hwc_stop s;
	int error;

	error = ioctl(tc->fd, HWC_IOC_STOP, &s);

	return (error);
}

static void
usage(void)
{

	errx(EX_USAGE,
		"hwc [-c devname] [path to executable]\n"
		"\t -c\tname\t\tName of tracing device, e.g. 'coresight'.\n"
		"\t -o\toutput-file\t\tFile name to store results into.\n"
		"\t -h\tHelp."
        );
}

static int
hwc_process_loop(struct hwc_context *tc)
{
	int status;
	int error;

	xo_open_container("trace");
	xo_open_list("entries");

	dprintf("Decoder started. Press ctrl+c to stop.\n");

	while (1) {
		error = waitpid(tc->pid, &status, WNOHANG);
		if (error != 0 && WIFEXITED(status))
			tc->terminate = 1;

		if (!tc->terminate)
			tc->backend->methods->run_once(tc);

		if (errno == EINTR || tc->terminate) {
			dprintf("%s: tracing terminated - exiting\n", __func__);
			/* Fetch any remaining records */
			if (tc->backend->methods->shutdown != NULL)
				tc->backend->methods->shutdown(tc);
			return (0);
		}
	}

	xo_close_list("file");
	xo_close_container("wc");
	if (xo_finish() < 0)
		xo_err(EXIT_FAILURE, "stdout");

	return (0);
}

static int
hwc_new_proc(struct hwc_context *tc, int *sockpair, char **cmd, char **env)
{
	struct stat st;
	int error;

	error = stat(*cmd, &st);
	if (error) {
		printf("Could not find target executable"
		    " error %d.\n", error);
		return (error);
	}

	dprintf("cmd is %s\n", *cmd);

	error = hwc_process_create(sockpair, cmd, env, &tc->pid);
	if (error != 0)
		return (error);

	dprintf("%s: process pid %d created\n", __func__, tc->pid);

	return (0);
}

static int
hwc_mode_thread(struct hwc_context *tc, char **cmd, char **env)
{
	int sockpair[NSOCKPAIRFD];
	int error;

	if (tc->attach == 0) {
		error = hwc_new_proc(tc, sockpair, cmd, env);
		if (error)
			return (error);
	}

	error = hwc_ctx_alloc(tc);
	if (error) {
		printf("%s: failed to alloc thread-mode ctx "
		       "error %d errno %d %s\n",
		    __func__, error, errno, strerror(errno));
		if (errno == EPERM)
			printf("Permission denied");
		else if (errno == EINVAL)
			printf("Invalid argument: buffer size is not a multiple"
			    " of page size, or is too small/large");
		printf("\n");
		return (error);
	}

	if (tc->backend->methods->configure == NULL) {
		printf("configure method is missing\n");
		return (ENXIO);
	}

	error = tc->backend->methods->configure(tc);
	if (error) {
		printf("could not configure backend, error %d\n", error);
		return (error);
	}

	if (tc->attach == 0) {
		error = hwc_process_start(sockpair);
		if (error != 0)
			return (error);
	}

	return (hwc_process_loop(tc));
}

int
main(int argc, char **argv, char **env)
{
	struct hwc_context *tc;
	char *backend_name;
	int error;
	int option;
	int found;
	int i;

	tc = &tcs;

	memset(tc, 0, sizeof(struct hwc_context));

	/* First available is default trace device. */
	tc->backend = &backends[0];
	if (tc->backend->name == NULL) {
		printf("No trace devices available\n");
		return (1);
	}

	argc = xo_parse_args(argc, argv);
	if (argc < 0)
		exit(EXIT_FAILURE);

	while ((option = getopt(argc, argv, "P:R:gs:hc:b:rw:t:i:f:o:")) != -1)
		switch (option) {
		case 'P':
			tc->attach = 1;
			tc->pid = atol(optarg);
			break;
		case 'f':
			tc->config_file = strdup(optarg);
			break;
		case 'o':
			tc->output_file = strdup(optarg);
			break;
		case 'c':
			backend_name = strdup(optarg);
			found = 0;
			for (i = 0; backends[i].name != NULL; i++) {
				if (strcmp(backends[i].name, backend_name) ==
				    0) {
					tc->backend = &backends[i];
					found = 1;
					break;
				}
			}
			if (!found) {
				printf("Backend with name \"%s\" not found.\n",
				    backend_name);
				return (ENOENT);
			}
			break;
		case 'h':
			usage();
			break;
		default:
			break;
		}

	tc->fd = open("/dev/hwc", O_RDWR);
	if (tc->fd < 0) {
		printf("Can't open /dev/hwc\n");
		return (-1);
	}

	argc += optind;
	argv += optind;

	if (*argv == NULL && tc->attach == 0)
		usage();

	tc->mode = HWC_MODE_THREAD;

	error = hwc_mode_thread(tc, argv, env);

	close(tc->fd);

	return (error);
}
