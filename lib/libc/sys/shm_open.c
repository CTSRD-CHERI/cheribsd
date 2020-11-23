/*
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2019 Kyle Evans <kevans@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice(s), this list of conditions and the following disclaimer as
 *    the first lines of this file unmodified other than the possible
 *    addition of one or more copyright notices.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice(s), this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER(S) ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/filio.h>
#include <sys/mman.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "libc_private.h"

__weak_reference(shm_open, _shm_open);
__weak_reference(shm_open, __sys_shm_open);

#define	MEMFD_NAME_PREFIX	"memfd:"

int
shm_open(const char *path, int flags, mode_t mode)
{

	return (__sys_shm_open2(path, flags | O_CLOEXEC, mode, 0, NULL));
}

int
shm_create_largepage(const char *path, int flags, int psind, int alloc_policy,
    mode_t mode)
{
	struct shm_largepage_conf slc;
	int error, fd, saved_errno;

	fd = __sys_shm_open2(path, flags | O_CREAT, mode, SHM_LARGEPAGE, NULL);
	if (error == -1)
		return (-1);

	memset(&slc, 0, sizeof(slc));
	slc.psind = psind;
	slc.alloc_policy = alloc_policy;
	error = ioctl(fd, FIOSSHMLPGCNF, &slc);
	if (error == -1) {
		saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return (-1);
	}
	return (fd);
}

#define	K(x)	((size_t)(x) * 1024)
#define	M(x)	(K(x) * 1024)
#define	G(x)	(M(x) * 1024)
static const struct {
	int mask;
	size_t pgsize;
} mfd_huge_sizes[] = {
	{ .mask = MFD_HUGE_64KB,	.pgsize = K(64) },
	{ .mask = MFD_HUGE_512KB,	.pgsize = K(512) },
	{ .mask = MFD_HUGE_1MB,		.pgsize = M(1) },
	{ .mask = MFD_HUGE_2MB,		.pgsize = M(2) },
	{ .mask = MFD_HUGE_8MB,		.pgsize = M(8) },
	{ .mask = MFD_HUGE_16MB,	.pgsize = M(16) },
	{ .mask = MFD_HUGE_32MB,	.pgsize = M(32) },
	{ .mask = MFD_HUGE_256MB,	.pgsize = M(256) },
	{ .mask = MFD_HUGE_512MB,	.pgsize = M(512) },
	{ .mask = MFD_HUGE_1GB,		.pgsize = G(1) },
	{ .mask = MFD_HUGE_2GB,		.pgsize = G(2) },
	{ .mask = MFD_HUGE_16GB,	.pgsize = G(16) },
};

/*
 * The path argument is passed to the kernel, but the kernel doesn't currently
 * do anything with it.  Linux exposes it in linprocfs for debugging purposes
 * only, but our kernel currently will not do the same.
 */
int
memfd_create(const char *name, unsigned int flags)
{
	char memfd_name[NAME_MAX + 1];
	size_t namelen, *pgs;
	struct shm_largepage_conf slc;
	int error, fd, i, npgs, oflags, pgidx, saved_errno, shmflags;

	if (name == NULL)
		return (EBADF);
	namelen = strlen(name);
	if (namelen + sizeof(MEMFD_NAME_PREFIX) - 1 > NAME_MAX)
		return (EINVAL);
	if ((flags & ~(MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_HUGETLB |
	    MFD_HUGE_MASK)) != 0)
		return (EINVAL);
	/* Size specified but no HUGETLB. */
	if (((flags & MFD_HUGE_MASK) != 0 && (flags & MFD_HUGETLB) == 0) ||
	    __bitcount(flags & MFD_HUGE_MASK) > 1)
		return (EINVAL);

	/* We've already validated that we're sufficiently sized. */
	snprintf(memfd_name, NAME_MAX + 1, "%s%s", MEMFD_NAME_PREFIX, name);
	oflags = O_RDWR;
	shmflags = SHM_GROW_ON_WRITE;
	if ((flags & MFD_CLOEXEC) != 0)
		oflags |= O_CLOEXEC;
	if ((flags & MFD_ALLOW_SEALING) != 0)
		shmflags |= SHM_ALLOW_SEALING;
	if ((flags & MFD_HUGETLB) == 0)
		shmflags |= SHM_LARGEPAGE;
	fd = __sys_shm_open2(SHM_ANON, oflags, 0, shmflags, memfd_name);
	if (fd == -1 || (flags & MFD_HUGETLB) == 0)
		return (fd);

	pgs = NULL;
	npgs = getpagesizes(NULL, 0);
	if (npgs == -1)
		goto clean;
	pgs = calloc(npgs, sizeof(size_t));
	if (pgs == NULL)
		goto clean;
	error = getpagesizes(pgs, npgs);
	if (error == -1)
		goto clean;
	if ((flags & MFD_HUGE_MASK) == 0) {
		if (npgs == 1) {
			errno = EOPNOTSUPP;
			goto clean;
		}
		pgidx = 1;
	} else {
		for (i = 0; i < nitems(mfd_huge_sizes); i++) {
			if (mfd_huge_sizes[i].mask == (flags & MFD_HUGE_MASK))
				break;
		}
		for (pgidx = 0; pgidx < npgs; pgidx++) {
			if (mfd_huge_sizes[i].pgsize == pgs[pgidx])
				break;
		}
		if (pgidx == npgs) {
			errno = EOPNOTSUPP;
			goto clean;
		}
	}
	free(pgs);
	pgs = NULL;

	memset(&slc, 0, sizeof(slc));
	slc.psind = pgidx;
	slc.alloc_policy = SHM_LARGEPAGE_ALLOC_DEFAULT;
	error = ioctl(fd, FIOSSHMLPGCNF, &slc);
	if (error == -1)
		goto clean;
	return (fd);

clean:
	saved_errno = errno;
	close(fd);
	free(pgs);
	errno = saved_errno;
	return (-1);
}
