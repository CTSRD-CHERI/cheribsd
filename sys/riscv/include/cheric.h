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

#ifndef _MACHINE_CHERIC_H_
#define	_MACHINE_CHERIC_H_

#if __has_feature(capabilities)
#define	cheri_capmode(cap)	cheri_setflags(cap, CHERI_FLAGS_CAP_MODE)
#endif

#ifdef _KERNEL
/* XXX: Convert faulting CBuildCap into tag-stripping. */
extern void * __capability cheri_buildcap_safe(void * __capability, intcap_t);

#undef cheri_buildcap
#define	cheri_buildcap(x, y)	cheri_buildcap_safe((x), (y))
#endif

#define	cheri_poison_get(x) ({						\
	int is_poison = 0;						\
	asm volatile("cgetpoison %0, %1" : "=r" (is_poison) : "C" (x));	\
	is_poison;							\
})

#define	cheri_poison_set(x)						\
	asm volatile("cpoison %0, 0(%1)" : : "C" (x), "C" (x))

#define	cheri_is_poison(x) ({						\
	int version = 0;						\
	asm volatile("cgetcappoison %0, %1" : "=r" (version) : "C" (x)); \
	version;							\
})

#define	cheri_poison_clear(x)						\
	asm volatile("cclearpoison %0, 0(%1)" : : "C" (x), "C" (x))

#define	cheri_poison_set_version(x, v) ({				\
	void *c;							\
	asm volatile("csetcappver %0, %1, %2" : : "C" (c), "C" (x), "r" (v)); \
	c;								\
})

#define	cheri_poison_get_version(x) ({					\
	int v;								\
	asm volatile("cgetcappver %0, %1" : "=r" (v) : "C" (x));	\
	v;								\
})
#endif /* !_MACHINE_CHERIC_H_ */
