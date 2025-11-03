/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 John Baldwin
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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
#include <sys/systm.h>

#include <cheri/cheric.h>

void *
memcpy_c(void *dst0, const void *src0, size_t len)
{
	const char *src;
	char *dst;
	ptraddr_t dst_addr, src_addr;
	int tocopy;

	dst = dst0;
	src = src0;
	
	if (len == 0 || dst == src)
		return (dst);

	dst_addr = (ptraddr_t)dst;
	src_addr = (ptraddr_t)src;
	if (dst_addr < src_addr) {
		/* Forwards. */

		/* Do both buffers have the same relative alignment? */
		if ((dst_addr ^ src_addr) % sizeof(uintptr_t) == 0 &&
		    len >= sizeof(uintptr_t)) {
			/* Byte copy to get aligned. */
			tocopy = dst_addr % sizeof(uintptr_t);
			if (tocopy != 0) {
				tocopy = sizeof(uintptr_t) - tocopy;
				KASSERT(tocopy <= len, ("tocopy %d too large", tocopy));
				do {
					*dst++ = *src++;
					len--;
				} while (--tocopy != 0);
			}

			KASSERT((ptraddr_t)dst % sizeof(uintptr_t) == 0,
			    ("dst %p not aligned",
			    (void *)(uintptr_t)dst));
			KASSERT((ptraddr_t)src % sizeof(uintptr_t) == 0,
			    ("src %p not aligned",
			    (void *)(uintptr_t)src));

			/* Copy capabilities. */
			while (len >= sizeof(uintptr_t)) {
				*(uintptr_t *)dst =
				    *(const uintptr_t *)src;
				dst += sizeof(uintptr_t);
				src += sizeof(uintptr_t);
				len -= sizeof(uintptr_t);
			}
		}

		/* Byte copy unaligned buffers and trailers. */
		if (len != 0) {
			do {
				*dst++ = *src++;
			} while (--len != 0);
		}
	} else {
		/* Backwards. */

		src += len;
		dst += len;
		dst_addr = (ptraddr_t)dst;
		src_addr = (ptraddr_t)src;
		
		/* Do both buffers have the same relative alignment? */
		if ((dst_addr ^ src_addr) % sizeof(uintptr_t) == 0 &&
		    len >= sizeof(uintptr_t)) {
			/* Byte copy to get aligned. */
			tocopy = dst_addr % sizeof(uintptr_t);
			if (tocopy != 0) {
				KASSERT(tocopy <= len, ("tocopy %d too large", tocopy));
				do {
					*--dst = *--src;
					len--;
				} while (--tocopy != 0);
			}

			KASSERT((ptraddr_t)dst % sizeof(uintptr_t) == 0,
			    ("dst %p not aligned", (void *)(uintptr_t)dst));
			KASSERT((ptraddr_t)src % sizeof(uintptr_t) == 0,
			    ("src %p not aligned", (void *)(uintptr_t)src));

			/* Copy capabilities. */
			while (len >= sizeof(uintptr_t)) {
				dst -= sizeof(uintptr_t);
				src -= sizeof(uintptr_t);
				*(uintptr_t *)dst =
				    *(const uintptr_t *)src;
				len -= sizeof(uintptr_t);
			}
		}

		/* Byte copy unaligned buffers and trailers. */
		if (len != 0) {
			do {
				*--dst = *--src;
			} while (--len != 0);
		}
	}
	return (dst);
}

__strong_reference(memcpy_c, memmove_c);

void *
memcpynocap_c(void *dst, const void *src,
    size_t len)
{
	return (memcpy_c(dst, cheri_andperm(src, ~CHERI_PERM_LOAD_CAP), len));
}

__strong_reference(memcpynocap_c, memmovenocap_c);
/*
 * CHERI CHANGES START
 * {
 *   "updated": 20230509,
 *   "target_type": "kernel",
 *   "changes": [
 *     "support",
 *     "ctoptr"
 *   ]
 * }
 * CHERI CHANGES END
 */
