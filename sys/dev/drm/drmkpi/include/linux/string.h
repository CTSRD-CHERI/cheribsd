/*-
 * Copyright (c) 2010 Isilon Systems, Inc.
 * Copyright (c) 2010 iX Systems, Inc.
 * Copyright (c) 2010 Panasas, Inc.
 * Copyright (c) 2013-2017 Mellanox Technologies, Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef __DRMCOMPAT_LINUX_STRING_H__
#define	__DRMCOMPAT_LINUX_STRING_H__

#include <sys/ctype.h>

#include <linux/types.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/err.h>

#include <sys/libkern.h>

static inline int
match_string(const char *const *table, int n, const char *key)
{
	int i;

	for (i = 0; i != n && table[i] != NULL; i++) {
		if (strcmp(table[i], key) == 0)
			return (i);
	}
	return (-EINVAL);
}

static inline void *
kmemdup(const void *src, size_t len, gfp_t gfp)
{
	void *dst;

	dst = kmalloc(len, gfp);
	if (dst != NULL)
		memcpy(dst, src, len);
	return (dst);
}

static inline char *
kstrdup(const char *string, gfp_t gfp)
{
	char *retval;
	size_t len;

	if (string == NULL)
		return (NULL);
	len = strlen(string) + 1;
	retval = kmalloc(len, gfp);
	if (retval != NULL)
		memcpy(retval, string, len);
	return (retval);
}

static inline void *
memchr_inv(const void *start, int c, size_t length)
{
	const u8 *ptr;
	const u8 *end;
	u8 ch;

	ch = c;
	ptr = start;
	end = ptr + length;

	while (ptr != end) {
		if (*ptr != ch)
			return (__DECONST(void *, ptr));
		ptr++;
	}
	return (NULL);
}

static inline size_t
str_has_prefix(const char *str, const char *prefix)
{
	size_t len;

	len = strlen(prefix);
	return (strncmp(str, prefix, len) == 0 ? len : 0);
}

static inline ssize_t
strscpy(char* dst, const char* src, size_t len)
{
	size_t i;

	if (len <= INT_MAX) {
		for (i = 0; i < len; i++)
			if ('\0' == (dst[i] = src[i]))
				return ((ssize_t)i);
		if (i != 0)
			dst[--i] = '\0';
	}

	return (-E2BIG);
}

#endif	/* __DRMCOMPAT_LINUX_STRING_H__ */
