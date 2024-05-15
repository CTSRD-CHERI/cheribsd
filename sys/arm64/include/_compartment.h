/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Konrad Witaszczyk
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) under Office of
 * Naval Research (ONR) Contract No. N00014-22-1-2463 ("SoftWare Integrated
 * with Secure Hardware (SWISH)").
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

#ifndef _MACHINE__COMPARTMENT_H_
#define	_MACHINE__COMPARTMENT_H_

/*
 * This header file includes compartmentalization-related macros that are common
 * to assembly and C source code files.
 */

/*
 * A compartment identifier for the kernel itself.
 */
#define	COMPARTMENT_KERNEL_ID			1

#define	TRAMPOLINE_TYPE_COMPARTMENT_ENTRY	0
#define	TRAMPOLINE_TYPE_EXECUTIVE_ENTRY	1
#define	TRAMPOLINE_TYPE_MAX			TRAMPOLINE_TYPE_EXECUTIVE_ENTRY

#ifdef CHERI_COMPARTMENTALIZE_KERNEL
#define	COMPARTMENT_ENTRY_NAME(name)	name ## _compartment
#define	EXECUTIVE_ENTRY_NAME(name)	name ## _executive
#else
#define	COMPARTMENT_ENTRY_NAME(name)	name
#define	EXECUTIVE_ENTRY_NAME(name)	name
#endif

#endif	/* !_MACHINE__COMPARTMENT_H_ */
