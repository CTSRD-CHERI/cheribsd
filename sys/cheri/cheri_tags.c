/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2022 John Baldwin
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency (DARPA) Contract No. HR001122C0110 ("ETC").
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
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/sysctl.h>

#include <cheri/cheri.h>

u_int	cheri_cloadtags_stride;
SYSCTL_UINT(_security_cheri, OID_AUTO, cloadtags_stride, CTLFLAG_RD,
    &cheri_cloadtags_stride, 0,
    "Number of capabilities covered by a single CLoadTags");

void
cheri_read_tags_page(const void *page, void *tagbuf, bool *hastagsp)
{
	const char *src;
	char *dst;
	uint64_t tags;
	u_int len, tagbits;
	bool hastags;

	KASSERT(is_aligned(page, PAGE_SIZE),
	    ("%s: pointer %p is not page-aligned", __func__, page));

	src = page;
	dst = tagbuf;
	len = PAGE_SIZE;
	tags = 0;
	tagbits = 0;
	hastags = false;
	while (len > 0) {
		tags |= cheri_loadtags(src) << tagbits;
		tagbits += cheri_cloadtags_stride;
		if (tags != 0)
			hastags = true;

		while (tagbits >= 8) {
			*dst = tags & 0xff;

			tags >>= 8;
			tagbits -= 8;
			dst++;
		}

		src += cheri_cloadtags_stride * sizeof(uintcap_t);
		len -= cheri_cloadtags_stride * sizeof(uintcap_t);
	}

	KASSERT(tagbits == 0, ("%s: partial tag bits %u at end of page",
	    __func__, tagbits));

	if (hastagsp != NULL)
		*hastagsp = hastags;
}

static void
measure_cloadtags_stride(void *dummy __unused)
{
	void * __capability *buf;
	uint64_t tags;
	u_int i;

	/*
	 * Malloc a buffer as allocating an aligned page on the stack
	 * risks overflowing the stack.
	 *
	 * Note that the buffer must not be simply aligned on a
	 * capability boundary but aligned on a stride of
	 * capabilities.
	 */
	buf = malloc_aligned(sizeof(*buf) * 64, sizeof(*buf) * 64,
	    M_TEMP, M_WAITOK | M_ZERO);

#ifdef INVARIANTS
	tags = cheri_loadtags(buf);

	KASSERT(tags == 0, ("CLoadTags on a zeroed buffer returned %lu", tags));
#endif

	/* CLoadTags can't return more than 64 bits. */
	for (i = 0; i < 64; i++)
		buf[i] = userspace_root_cap;

	tags = cheri_loadtags(buf);

	KASSERT(tags != 0, ("CLoadTags returned 0"));
	KASSERT(powerof2(tags + 1),
	    ("CLoadTags didn't return a valid bit mask"));

	cheri_cloadtags_stride = fls(tags);
	KASSERT(powerof2(cheri_cloadtags_stride),
	    ("CLoadTags isn't a power of 2"));

	zfree(buf, M_TEMP);
}
SYSINIT(cloadtags_stride, SI_SUB_VM_CONF, SI_ORDER_ANY,
    measure_cloadtags_stride, NULL);
