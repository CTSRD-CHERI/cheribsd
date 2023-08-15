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
#include <sys/cpuset.h>
#include <sys/hwt.h>
#include <sys/hwt_record.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <err.h>
#include <string.h>

#include "hwt.h"

#include "libpmcstat_stubs.h"
#include <libpmcstat.h>

#define	HWT_RECORD_DEBUG
#undef	HWT_RECORD_DEBUG

#ifdef	HWT_RECORD_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

int
hwt_record_fetch(struct trace_context *tc, int *nrecords)
{
	struct hwt_record_user_entry *entry;
	pmcstat_interned_string path;
	struct pmcstat_image *image;
	struct pmc_plugins plugins;
	struct pmcstat_args args;
	unsigned long addr;
	struct hwt_record_get record_get;
	char imagepath[PATH_MAX];
	struct stat st;
	int nentries;
	int error;
	int j;

	memset(&plugins, 0, sizeof(struct pmc_plugins));
	memset(&args, 0, sizeof(struct pmcstat_args));
	args.pa_fsroot = "/";
	nentries = 256;

	tc->records = malloc(sizeof(struct hwt_record_user_entry) * nentries);

	record_get.records = tc->records;
	record_get.nentries = &nentries;

	error = ioctl(tc->thr_fd, HWT_IOC_RECORD_GET, &record_get);
	if (error != 0) {
		printf("RECORD_GET error %d entires %d\n",
		    error, nentries);
		return (error);
	}

	dprintf("%s: error %d: nent %d\n", __func__, error, nentries);

	for (j = 0; j < nentries; j++) {
		entry = &tc->records[j];

		switch (entry->record_type) {
		case HWT_RECORD_MMAP:
		case HWT_RECORD_MUNMAP:
		case HWT_RECORD_EXECUTABLE:
		case HWT_RECORD_INTERP:
			printf("  lib #%d: path %s addr %lx\n", j,
			    entry->fullpath,
			    (unsigned long)entry->addr);

			path = pmcstat_string_intern(entry->fullpath);
			image = pmcstat_image_from_path(path, 0, &args,
			    &plugins);
			if (image == NULL)
				return (-1);

			if (image->pi_type == PMCSTAT_IMAGE_UNKNOWN)
				pmcstat_image_determine_type(image, &args);

			addr = (unsigned long)entry->addr & ~1;
			addr -= (image->pi_start - image->pi_vaddr);
			pmcstat_image_link(tc->pp, image, addr);
			dprintf("image pi_vaddr %lx pi_start %lx"
			    " pi_entry %lx\n",
			    (unsigned long)image->pi_vaddr,
			    (unsigned long)image->pi_start,
			    (unsigned long)image->pi_entry);
			hwt_mmap_received(tc, entry);
			break;
		case HWT_RECORD_KERNEL:
			snprintf(imagepath, sizeof(imagepath), "%s/%s",
			    tc->fs_root, entry->fullpath);
			error = stat(imagepath, &st);
			if (error)
				errx(EX_OSERR, "Image \"%s\" not found\n",
				    imagepath);
			printf("  image #%d: path %s addr %lx\n", j,
			    imagepath, (unsigned long)entry->addr);
			path = pmcstat_string_intern(imagepath);
			image = pmcstat_image_from_path(path, 1, &args,
			    &plugins);
			if (image == NULL)
				return (-1);
			if (image->pi_type == PMCSTAT_IMAGE_UNKNOWN)
				pmcstat_image_determine_type(image, &args);
			addr = (unsigned long)entry->addr & ~1;
			pmcstat_image_link(tc->pp, image, addr);
			break;
		case HWT_RECORD_THREAD_CREATE:
		case HWT_RECORD_THREAD_SET_NAME:
			break;
		default:
			break;
		}
	}

	*nrecords = nentries;

	return (0);
}
