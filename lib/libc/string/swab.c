/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2024 rilysh <nightquick@proton.me>
 */

#include <unistd.h>
#include <sys/endian.h>

typedef uint16_t __aligned(1) unaligned16_t;

void
swab(const void * __restrict from, void * __restrict to, ssize_t len)
{
	const unaligned16_t *f = from;
	unaligned16_t *t = to;

	/*
	 * POSIX says overlapping copy behavior is undefined, however many
	 * applications assume the old FreeBSD and current GNU libc behavior
	 * that will swap the bytes correctly when from == to. Reading both bytes
	 * and swapping them before writing them back accomplishes this.
	 */
	while (len > 1) {
		*t++ = bswap16(*f++);
		len -= 2;
	}
}
