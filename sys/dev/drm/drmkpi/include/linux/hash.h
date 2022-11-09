/*
 * Copyright (c) 2013 François Tigeot
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
 */

#ifndef __DRMCOMPAT_LINUX_HASH_H__
#define __DRMCOMPAT_LINUX_HASH_H__

#include <asm/types.h>
#include <sys/hash.h>
#include <linux/bitops.h>

static inline u64 hash_64(u64 val, unsigned int bits)
{
	u64 ret;

	ret = (uint64_t)hash32_buf(&val, sizeof(val), bits);

	return ret >> (64 - bits);
}

static inline u32 hash_32(u32 val, unsigned int bits)
{
	u32 ret;

	ret = hash32_buf(&val, sizeof(val), bits);

	return ret >> (32 - bits);
}

#if BITS_PER_LONG == 64	/* amd64 */
#define hash_long(val, bits) hash_64(val, bits)
#else	/* i386 */
#define hash_long(val, bits) hash_32(val, bits)
#endif

#endif	/* __DRMCOMPAT_LINUX_HASH_H__ */
