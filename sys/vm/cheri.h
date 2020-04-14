/*-
 * Copyright (c) 2018 Alfredo Mazzinghi
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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

/*
 * Capability-specific virtual memory checks.
 * Verify that the kernel VM is handing out
 * capabilities as expected.
 */

#ifndef _VM_CHERI_H_
#define	_VM_CHERI_H_

#ifdef CHERI_PURECAP_KERNEL
#include <sys/systm.h>
#include <cheri/cheric.h>

#include <machine/cherireg.h>

/* Check that a capability is dereferenceable */
#define	CHERI_VM_ASSERT_VALID(ptr)					\
	KASSERT(cheri_gettag((void *)(ptr)),				\
		("VM expect valid capability %s %s:%d", __func__,	\
		 __FILE__, __LINE__))

/* Check that the given pointer can fit a capability
 * This is useful to detect when someone is passing a vm_offset_t* when
 * we want a uintptr_t*
 */
#define	CHERI_VM_ASSERT_FIT_PTR(ptr) do {				\
		CHERI_VM_ASSERT_VALID(ptr);				\
		KASSERT(cheri_getlen((void *)ptr) >= sizeof(void *),	\
			("Cheri can not store a pointer here %p, "	\
			 "not enugh_space(%lu) %s %s:%d", ptr,		\
			 (u_long)cheri_getlen((void *)ptr),		\
			 __func__, __FILE__, __LINE__));		\
	} while (0)

/*
 * Check whether the bounds on a pointer have been set correctly
 * by an allocator
 */
#define	CHERI_VM_ASSERT_BOUNDS(ptr, expect) do {			\
		CHERI_VM_ASSERT_VALID(ptr);				\
		KASSERT(cheri_getlen((void *)ptr) <=			\
			CHERI_REPRESENTABLE_LENGTH(expect),		\
			("Invalid bounds on pointer in %s %s:%d "	\
			 "expected %lx, found %lx",			\
			 __func__, __FILE__, __LINE__,			\
			 (u_long)expect,				\
			 (u_long)cheri_getlen((void *)ptr)));		\
	} while (0)

/*
 * Check that the bounds on a pointers are matching the expected length.
 * This is used to ensure exact bounds.
 */
#define	CHERI_VM_ASSERT_EXACT(ptr, len) do {				\
		KASSERT(cheri_getlen((void *)ptr) == len,		\
			("Inexact bounds on pointer in %s %s:%d "	\
			"expected %lx, found %lx",			\
			__func__, __FILE__, __LINE__,			\
			(u_long)len, cheri_getlen((void *)ptr)));	\
	} while (0)

#else /* ! CHERI_PURECAP_KERNEL */
#define	CHERI_VM_ASSERT_VALID(ptr)
#define	CHERI_VM_ASSERT_FIT_PTR(ptr)
#define	CHERI_VM_ASSERT_BOUNDS(ptr, expect)
#define	CHERI_VM_ASSERT_EXACT(ptr, len)
#endif /* ! CHERI_PURECAP_KERNEL*/

#endif /* _VM_CHERI_H_ */
// CHERI CHANGES START
// {
//   "updated": 20200414,
//   "target_type": "header",
//   "changes_purecap": [
//     "support"
//   ]
// }
// CHERI CHANGES END
