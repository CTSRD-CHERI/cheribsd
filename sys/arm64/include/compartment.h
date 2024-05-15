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

#ifndef _MACHINE_COMPARTMENT_H_
#define	_MACHINE_COMPARTMENT_H_

#include <machine/_compartment.h>
#include <machine/elf.h>
#include <machine/ifunc.h>

/*
 * This header file includes compartmentalization-related macros for C source
 * code files.
 */

#ifdef CHERI_COMPARTMENTALIZE_KERNEL
#define	COMPARTMENT_ADD_ENTRY(ret_type, name, args)			\
	DEFINE_IFUNC(, ret_type, name, args)				\
	{								\
		uintptr_t func;						\
									\
		ELF_STATIC_RELOC_LABEL(func,				\
		    COMPARTMENT_ENTRY_NAME(name));			\
		return (compartment_entry_for_kernel(func));		\
	}
#define	COMPARTMENT_ENTRY(ret_type, name, args)				\
	static ret_type COMPARTMENT_ENTRY_NAME(name) args;		\
	COMPARTMENT_ADD_ENTRY(ret_type, name, args);			\
	static __attribute__((used)) ret_type				\
	COMPARTMENT_ENTRY_NAME(name) args

#define	SUPERVISOR_ADD_ENTRY(ret_type, name, args)			\
	DEFINE_IFUNC(, ret_type, name, args)				\
	{								\
		uintptr_t func;						\
									\
		ELF_STATIC_RELOC_LABEL(func,				\
		    SUPERVISOR_ENTRY_NAME(name));			\
		return (supervisor_entry_for_kernel(func));		\
	}
#define	SUPERVISOR_EXIT(name, args)					\
	({								\
		KASSERT((cheri_getperm(&name) &				\
		    CHERI_PERM_EXECUTIVE) == 0,				\
		    ("Supervisor's exit %s has invalid permissions",	\
		    #name));						\
		name args;						\
	})
#define	SUPERVISOR_ENTRY(ret_type, name, args)				\
	static ret_type SUPERVISOR_ENTRY_NAME(name) args;		\
	SUPERVISOR_ADD_ENTRY(ret_type, name, args)			\
	static __attribute__((used)) ret_type				\
	SUPERVISOR_ENTRY_NAME(name) args
#define	SUPERVISOR_ASSERT()						\
	KASSERT((cheri_getperm(cheri_getpcc()) &			\
	    CHERI_PERM_EXECUTIVE) != 0,					\
	    ("PCC %#lp has invalid permissions",			\
	    (void *)cheri_getpcc()))
#else
#define	COMPARTMENT_ENTRY(ret_type, name, args)				\
	ret_type							\
	COMPARTMENT_ENTRY_NAME(name) args

#define	SUPERVISOR_ENTRY(ret_type, name, args)				\
	ret_type							\
	SUPERVISOR_ENTRY_NAME(name) args
#endif

#endif	/* !_MACHINE_COMPARTMENT_H_ */
