/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2001 Doug Rabson
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

#ifndef _COMPAT_H_
#define	_COMPAT_H_

/*
 * Helper macros for translating objects between different ABIs.
 */

#define	PTRIN(v)	(void *)(uintptr_t)(v)
#define	PTROUT(v)	(uintptr_t)(v)

#define	CP(src, dst, fld) do {			\
	(dst).fld = (src).fld;			\
} while (0)

#define	CP2(src, dst, sfld, dfld) do {		\
	(dst).dfld = (src).sfld;		\
} while (0)

#define	PTRIN_CP(src, dst, fld) do {		\
	(dst).fld = PTRIN((src).fld);		\
} while (0)

#define	PTROUT_CP(src, dst, fld) do {		\
	(dst).fld = PTROUT((src).fld);		\
} while (0)

#define	TV_CP(src, dst, fld) do {		\
	CP((src).fld, (dst).fld, tv_sec);	\
	CP((src).fld, (dst).fld, tv_usec);	\
} while (0)

#define	TS_CP(src, dst, fld) do {		\
	CP((src).fld, (dst).fld, tv_sec);	\
	CP((src).fld, (dst).fld, tv_nsec);	\
} while (0)

#define	ITS_CP(src, dst) do {			\
	TS_CP((src), (dst), it_interval);	\
	TS_CP((src), (dst), it_value);		\
} while (0)

#define	BT_CP(src, dst, fld) do {				\
	CP((src).fld, (dst).fld, sec);				\
	*(uint64_t *)&(dst).fld.frac[0] = (src).fld.frac;	\
} while (0)

/*
 * Macros to create userspace capabilities from virtual addresses.
 * Addresses are assumed to be relative to the current userspace
 * thread's address space and are created from the DDC or PCC of
 * the current PCB.
 */
#if __has_feature(capabilities)
/*
 * Derive out-of-bounds and small values from NULL.  This allows common
 * sentinel values to work.
 */
#define ___USER_CFROMPTR(ptr, cap, is_offset)				\
    ((void *)(uintptr_t)(ptr) == NULL ? NULL :				\
     ((vm_offset_t)(ptr) < 4096 ||					\
      (vm_offset_t)(ptr) > VM_MAXUSER_ADDRESS) ?			\
	(void * __capability)(uintcap_t)(ptraddr_t)(ptr) :		\
	(is_offset) ?							\
	__builtin_cheri_offset_set((cap), (ptraddr_t)(ptr)) :		\
	__builtin_cheri_address_set((cap), (ptraddr_t)(ptr)))

#define	USER_PTR_UNBOUND(ptr)						\
	___USER_CFROMPTR((ptr), __USER_DDC, __USER_DDC_OFFSET_ENABLED)

#define	USER_CODE_PTR(ptr)						\
	___USER_CFROMPTR((ptr), __USER_PCC, __USER_PCC_OFFSET_ENABLED)

#define	USER_PTR(ptr, len)						\
({									\
	void * __capability unbound = USER_PTR_UNBOUND(ptr);		\
	(security_cheri_bound_legacy_capabilities &&			\
	    __builtin_cheri_tag_get(unbound) ?				\
	    __builtin_cheri_bounds_set(unbound, (len)) : unbound);	\
})

#else /* !has_feature(capabilities) */

#define	USER_PTR_UNBOUND(ptr)	((void *)(uintptr_t)(ptr))
#define	USER_CODE_PTR(ptr)	((void *)(uintptr_t)(ptr))
#define	USER_PTR(ptr, len)	((void *)(uintptr_t)(ptr))

#endif /* !has_feature(capabilities) */

#define	USER_PTR_ADDR(ptr)	USER_PTR_UNBOUND(ptr)
#define	USER_PTR_ARRAY(objp, cnt) \
     USER_PTR((objp), sizeof(*(objp)) * (cnt))
#define	USER_PTR_OBJ(objp)	USER_PTR((objp), sizeof(*(objp)))
/*
 * NOTE: we can't place tigher bounds because we don't know what the
 * length is until after we use it.
 */
#define	USER_PTR_STR(strp)	USER_PTR_UNBOUND(strp)
#define	USER_PTR_PATH(path)	USER_PTR((path), MAXPATHLEN)

#endif /* !_COMPAT_H_ */
