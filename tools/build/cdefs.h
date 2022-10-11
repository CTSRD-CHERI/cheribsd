/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2019 Alex Richardson <arichardson@FreeBSD.org>
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
 *
 * $FreeBSD$
 */
#ifndef _LEGACY_SYS_CDEFS_H_
#define	_LEGACY_SYS_CDEFS_H_

#include_next <sys/cdefs.h>

/* Provide stub __kerncap when bootstrapping */
#define __kerncap
#define __CHERI_USER_ABI 0

/* Provide stub sub-object opt-out macros when bootstrapping */
#define __no_subobject_bounds
#define __subobject_use_container_bounds
#define __subobject_variable_length
#define __subobject_variable_length_maxsize(n)
#define __subobject_use_remaining_size
#define __subobject_use_remaining_size_max(n)
#define __subobject_use_full_array_bounds
#define __subobject_cxx_reference_use_full_array_bounds
#define __subobject_member_used_for_c_inheritance
#define __subobject_type_used_for_c_inheritance

#if !__has_builtin(__builtin_no_change_bounds)
#define __builtin_no_change_bounds(expr) (expr)
#endif
#define __unbounded_addressof(obj)	(&__builtin_no_change_bounds(obj))
#define __bounded_addressof(obj, size)	(&(obj))
/* Work around bug in sub-object bounds */
#define __array2d_unbounded_pointer(array, idx1, idx2)	\
    &__builtin_no_change_bounds(__builtin_no_change_bounds(array[idx1])[idx2])

/* TODO: what about __builtin_align* ? */

#endif /* #ifndef _LEGACY_SYS_CDEFS_H_ */
