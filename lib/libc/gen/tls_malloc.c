/*-
 * Copyright 1996-1998 John D. Polstra.
 * All rights reserved.
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

#include <sys/param.h>
#include <sys/types.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libc_private.h"

void	*__je_bootstrap_malloc(size_t size);
void	*__je_bootstrap_calloc(size_t num, size_t size);
void	__je_bootstrap_free(void *ptr);

void *
tls_malloc(size_t size)
{

	return (__je_bootstrap_malloc(size));
}

void *
tls_calloc(size_t number, size_t size)
{

	return (__je_bootstrap_calloc(number, size));
}

void
tls_free(void *ptr)
{

	__je_bootstrap_free(ptr);
	return;
}

void *
tls_malloc_aligned(size_t size, size_t align)
{
	vaddr_t memshift;
	void *mem, *res;
	if (align < sizeof(void *))
		align = sizeof(void *);

	mem = tls_malloc(size + sizeof(void *) + align - 1);
	memshift = roundup2((vaddr_t)mem + sizeof(void *), align) - (vaddr_t)mem;
	res = (void *)((uintptr_t)mem + memshift);
	*(void **)((uintptr_t)res - sizeof(void *)) = mem;
	return (res);
}

void *
tls_calloc_aligned(size_t number, size_t size, size_t align)
{
	void *buf;

	if (size != 0 && number > SIZE_MAX / size)
		return (NULL);
	buf = tls_malloc_aligned(number * size, align);
	memset(buf, 0, number * size);
	return (buf);
}

void
tls_free_aligned(void *ptr)
{
	void *mem;
	uintptr_t x;

	if (ptr == NULL)
		return;

	x = (uintptr_t)ptr;
	x -= sizeof(void *);
	mem = *(void **)x;
	tls_free(mem);
}
