/*-
 * Copyright (c) 2018 Alfredo Mazzinghi
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
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

#ifndef _SYS_PTRBITS_H_
#define _SYS_PTRBITS_H_

/*
 * Macros for explicit low pointer bits manipulations.
 * These operations are meant to make code independant
 * from the pointer representation.
 *
 * Note that atomic operations on low pointer bits should
 * behave in the same way as these macros.
 */

/* Private macros, these should not be used directly */
#ifdef CHERI_PURECAP_KERNEL
/*
 * XXX-AM:
 * Eventually we should move all the cheri-related things into
 * a machine dependant header and include machine/ptrbits.h.
 */
#include <cheri/cheric.h>

/* #define __ptr_set_flag(p, f) cheri_set_low_ptr_bits(p, f) */
/* #define __ptr_get_flag(p, f) cheri_get_low_ptr_bits(p, f) */
/* #define __ptr_clear_flag(p, f) cheri_clear_low_ptr_bits(p, f) */
#define __ptr_set_flag(p, f)						\
  (uintptr_t)(cheri_setoffset((void *)(p), cheri_getoffset((void *)(p)) | (vm_offset_t)(f)))
#define __ptr_get_flag(p, f)			\
  (vm_offset_t)(cheri_getoffset((void *)(p)) & (f))
#define __ptr_clear_flag(p, f)			\
  (uintptr_t)(cheri_setoffset((void *)(p), cheri_getoffset((void *)(p)) & ~(vm_offset_t)(f)))
#else /* ! CHERI_PURECAP_KERNEL */
#define __ptr_set_flag(p, f) ((uintptr_t)(p) | (uintptr_t)(f))
#define __ptr_get_flag(p, f) ((uintptr_t)(p) & (uintptr_t)(f))
#define __ptr_clear_flag(p, f) ((uintptr_t)(p) & ~(uintptr_t)(f))
#endif /* ! CHERI_PURECAP_KERNEL */


/* Public macros */
#define ptr_set_flag(p, f) __ptr_set_flag(p, f)
#define ptr_get_flag(p, f) __ptr_get_flag(p, f)
#define ptr_clear_flag(p, f) __ptr_clear_flag(p, f)

#endif /* _SYS_PTRBITS_H_ */
// CHERI CHANGES START
// {
//   "updated": 20180809,
//   "target_type": "header",
//   "changes_purecap": [
//     "support",
//     "pointer_bit_flags"
//   ]
// }
// CHERI CHANGES END
