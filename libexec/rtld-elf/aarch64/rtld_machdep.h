/*-
 * Copyright (c) 1999, 2000 John D. Polstra.
 * Copyright (c) 2014 the FreeBSD Foundation
 * Copyright 2018-2020 Alex Richardson <arichardson@FreeBSD.org>
 * Copyright 2020 Jessica Clarke <jrtc27@FreeBSD.org>
 * Copyright 2020 Brett F. Gutstein
 * All rights reserved.
 *
 * Portions of this software were developed by Andrew Turner
 * under sponsorship from the FreeBSD Foundation.
 *
 * Portions of this software were developed by SRI International and the
 * University of Cambridge Computer Laboratory under DARPA/AFRL contract
 * FA8750-10-C-0237 ("CTSRD"), as part of the DARPA CRASH research programme.
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

#ifndef RTLD_MACHDEP_H
#define	RTLD_MACHDEP_H	1

#include <sys/types.h>
#include <machine/atomic.h>
#include <machine/tls.h>

struct Struct_Obj_Entry;

#define	MD_PLT_ENTRY

#define	MD_OBJ_ENTRY	\
    bool variant_pcs : 1;	/* Object has a variant pcs function */

/* Return the address of the .dynamic section in the dynamic linker. */
#ifdef __CHERI_PURE_CAPABILITY__
#define rtld_dynamic(obj) (&_DYNAMIC)
#else
#define	rtld_dynamic(obj)						\
({									\
	Elf_Addr _dynamic_addr;						\
	asm volatile("adr	%0, _DYNAMIC" : "=&r"(_dynamic_addr));	\
	(const Elf_Dyn *)_dynamic_addr;					\
})
#endif

bool arch_digest_dynamic(struct Struct_Obj_Entry *obj, const Elf_Dyn *dynp);

bool arch_digest_note(struct Struct_Obj_Entry *obj, const Elf_Note *note);

uintptr_t reloc_jmpslot(uintptr_t *where, uintptr_t target,
    const struct Struct_Obj_Entry *defobj, const struct Struct_Obj_Entry *obj,
    const Elf_Rel *rel);

#ifdef __CHERI_PURE_CAPABILITY__

#define make_function_pointer(def, defobj) \
	make_function_cap(def, defobj)

/* ignore _init/_fini */
#define call_initfini_pointer(obj, target) rtld_fatal("%s: _init or _fini used!", obj->path)
#define call_init_pointer(obj, target) rtld_fatal("%s: _init or _fini used!", obj->path)

/* TODO: Per-function captable/PLT/FNDESC support */
#ifdef CHERI_LIB_C18N
#define call_init_array_pointer(_obj, _target)				\
	(C18N_FPTR_ENABLED ? (InitArrFunc)(_target).value :		\
	    (InitArrFunc)tramp_intern(NULL, RTLD_COMPART_ID,		\
	        &(struct tramp_data) {					\
		    .target = (void *)(_target).value,			\
		    .defobj = _obj,					\
		    .sig = (struct func_sig) {				\
			.valid = true,					\
			.reg_args = 3, .mem_args = false,		\
			.ret_args = NONE }				\
	}))(main_argc, main_argv, environ)

#define call_fini_array_pointer(_obj, _target)				\
	(C18N_FPTR_ENABLED ? (InitFunc)(_target).value :		\
	    (InitFunc)tramp_intern(NULL, RTLD_COMPART_ID,		\
	        &(struct tramp_data) {					\
		    .target = (void *)(_target).value,			\
		    .defobj = _obj,					\
		    .sig = (struct func_sig) {				\
			.valid = true,					\
			.reg_args = 0, .mem_args = false,		\
			.ret_args = NONE }				\
	}))()
#else
#define call_init_array_pointer(obj, target)				\
	(((InitArrFunc)(target).value)(main_argc, main_argv, environ))

#define call_fini_array_pointer(obj, target)				\
	(((InitFunc)(target).value)())
#endif

#else /* __CHERI_PURE_CAPABILITY__ */

#define	make_function_pointer(def, defobj) \
	((defobj)->relocbase + (def)->st_value)

#define	call_initfini_pointer(obj, target) \
	(((InitFunc)(target))())

#define	call_init_pointer(obj, target) \
	(((InitArrFunc)(target))(main_argc, main_argv, environ))

#endif /* __CHERI_PURE_CAPABILITY__ */

/*
 * Pass zeros into the ifunc resolver so we can change them later. The first
 * 8 arguments on arm64 are passed in registers so make them known values
 * if we decide to use them later. Because of this ifunc resolvers can assume
 * no arguments are passed in, and if this changes later will be able to
 * compare the argument with 0 to see if it is set.
 */
#define	call_ifunc_resolver(ptr) \
	(((uintptr_t (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, \
	    uint64_t, uint64_t, uint64_t))ptr)(0, 0, 0, 0, 0, 0, 0, 0))

#define	round(size, align)				\
	(((size) + (align) - 1) & ~((align) - 1))
#define	calculate_first_tls_offset(size, align, offset)	\
	round(TLS_TCB_SIZE, align)
#define	calculate_tls_offset(prev_offset, prev_size, size, align, offset) \
	round(prev_offset + prev_size, align)
#define calculate_tls_post_size(align) \
	round(TLS_TCB_SIZE, align) - TLS_TCB_SIZE

typedef struct {
    unsigned long ti_module;
    unsigned long ti_offset;
} tls_index;

extern void *__tls_get_addr(tls_index *ti);

#define md_abi_variant_hook(x)

#endif
