/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2015 Neel Natu <neel@freebsd.org>
 * All rights reserved.
 * Copyright (c) 2020 Andrew Turner <andrew@FreeBSD.org>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND
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
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <machine/vmm.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include <vmmapi.h>
#include "bhyverun.h"
#include "bootcode.h"
#include "debug.h"

static int
bootcode_alloc(struct vmctx *ctx, size_t len, char **region_out,
    vm_paddr_t *gpa_out)
{
	vm_paddr_t gpa;

	if (len == 0) {
		warnx("ROM size %zu is invalid", len);
		return (EINVAL);
	}

	gpa = (1ULL << 32);
	len = roundup2(len, PAGE_SIZE);
	*region_out = vm_map_gpa(ctx, gpa, len);
	*gpa_out = gpa;

	return (0);
}

int
bootcode_load(struct vmctx *ctx, const char *romfile, vm_paddr_t *gpa_out)
{
	struct stat sbuf;
	ssize_t rlen;
	char *ptr;
	int fd, i, rv;

	rv = -1;
	fd = open(romfile, O_RDONLY);
	if (fd < 0) {
		EPRINTLN("Error opening bootcode \"%s\": %s",
		    romfile, strerror(errno));
		goto done;
	}

        if (fstat(fd, &sbuf) < 0) {
		EPRINTLN("Could not fstat bootcode file \"%s\": %s",
		    romfile, strerror(errno));
		goto done;
        }

	/* Map the bootcode into the guest address space */
	if (bootcode_alloc(ctx, sbuf.st_size, &ptr, gpa_out) != 0)
		goto done;

	/* Read 'romfile' into the guest address space */
	for (i = 0; i < sbuf.st_size / PAGE_SIZE; i++) {
		rlen = read(fd, ptr + i * PAGE_SIZE, PAGE_SIZE);
		if (rlen != PAGE_SIZE) {
			EPRINTLN("Incomplete read of page %d of bootcode "
			    "file %s: %ld bytes", i, romfile, rlen);
			goto done;
		}
	}
	if ((sbuf.st_size % PAGE_SIZE) != 0) {
		rlen = read(fd, ptr + i * PAGE_SIZE, sbuf.st_size % PAGE_SIZE);
		if (rlen != sbuf.st_size % PAGE_SIZE) {
			EPRINTLN("Incomplete read of page %d of bootcode "
			    "file %s: %ld bytes", i, romfile, rlen);
			goto done;
		}
	}
	rv = 0;
done:
	if (fd >= 0)
		close(fd);
	return (rv);
}
