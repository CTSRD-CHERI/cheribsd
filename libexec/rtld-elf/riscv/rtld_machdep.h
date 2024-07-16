/*-
 * Copyright (c) 1999, 2000 John D. Polstra.
 * Copyright (c) 2015 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 * Copyright 2018-2020 Alex Richardson <arichardson@FreeBSD.org>
 * Copyright 2020 Jessica Clarke <jrtc27@FreeBSD.org>
 *
 * Portions of this software were developed by SRI International and the
 * University of Cambridge Computer Laboratory under DARPA/AFRL contract
 * FA8750-10-C-0237 ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Portions of this software were developed by the University of Cambridge
 * Computer Laboratory as part of the CTSRD Project, with support from the
 * UK Higher Education Innovation Fund (HEIF).
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
#define RTLD_MACHDEP_H	1

#include <sys/types.h>
#include <machine/atomic.h>
#include <machine/tls.h>

struct Struct_Obj_Entry;

#define	MD_OBJ_ENTRY

#ifndef __CHERI_PURE_CAPABILITY__
uint64_t set_gp(struct Struct_Obj_Entry *obj);
#endif

/* Return the address of the .dynamic section in the dynamic linker. */
#ifdef __CHERI_PURE_CAPABILITY__
#define rtld_dynamic(obj) (&_DYNAMIC)
#else
#define rtld_dynamic(obj)                                               \
({                                                                      \
	Elf_Addr _dynamic_addr;                                         \
	__asm __volatile("lla       %0, _DYNAMIC" : "=r"(_dynamic_addr));   \
	(const Elf_Dyn *)_dynamic_addr;                                 \
})
#endif

/* No arch-specific dynamic tags */
#define	arch_digest_dynamic(obj, dynp)	false

/* No architecture specific notes */
#define	arch_digest_note(obj, note)	false

uintptr_t reloc_jmpslot(uintptr_t *where, uintptr_t target,
    const struct Struct_Obj_Entry *defobj, const struct Struct_Obj_Entry *obj,
    const Elf_Rel *rel);

#ifdef __CHERI_PURE_CAPABILITY__

#define make_function_pointer(def, defobj) \
	make_function_cap(def, defobj)

/* ignore _init/_fini */
#define call_initfini_pointer(obj, target) rtld_fatal("%s: _init or _fini used!", obj->path)
#define call_init_pointer(obj, target) rtld_fatal("%s: _init or _fini used!", obj->path)

/* TODO: Per-function captable/PLT/FNDESC support (needs CGP) */
#ifdef CHERI_LIB_C18N
#define call_init_array_pointer(_obj, _target)				\
	(((InitArrFunc)tramp_intern(NULL, &(struct tramp_data) {	\
		.target = (void *)(_target).value,			\
		.defobj = _obj,						\
		.sig = (struct func_sig) { .valid = true,		\
		    .reg_args = 3, .mem_args = false, .ret_args = NONE }\
	}))(main_argc, main_argv, environ))

#define call_fini_array_pointer(_obj, _target)				\
	(((InitFunc)tramp_intern(NULL, &(struct tramp_data) {		\
		.target = (void *)(_target).value,			\
		.defobj = _obj,						\
		.sig = (struct func_sig) { .valid = true,		\
		    .reg_args = 0, .mem_args = false, .ret_args = NONE }\
	}))())
#else
#define call_init_array_pointer(obj, target)				\
	(((InitArrFunc)(target).value)(main_argc, main_argv, environ))

#define call_fini_array_pointer(obj, target)				\
	(((InitFunc)(target).value)())
#endif

#else /* __CHERI_PURE_CAPABILITY__ */

#define make_function_pointer(def, defobj) \
	((defobj)->relocbase + (def)->st_value)

#define call_initfini_pointer(obj, target)				\
({									\
	uint64_t old0;							\
	old0 = set_gp(obj);						\
	(((InitFunc)(target))());					\
	__asm __volatile("mv    gp, %0" :: "r"(old0));			\
})

#define call_init_pointer(obj, target)					\
({									\
	uint64_t old1;							\
	old1 = set_gp(obj);						\
	(((InitArrFunc)(target))(main_argc, main_argv, environ));	\
	__asm __volatile("mv    gp, %0" :: "r"(old1));			\
})

#endif /* __CHERI_PURE_CAPABILITY__ */

#define	call_ifunc_resolver(ptr) \
	(((uintptr_t (*)(void))ptr)())

/*
 * TLS
 */

#define round(size, align) \
    (((size) + (align) - 1) & ~((align) - 1))
#define calculate_first_tls_offset(size, align, offset)	\
    TLS_TCB_SIZE
#define calculate_tls_offset(prev_offset, prev_size, size, align, offset) \
    round(prev_offset + prev_size, align)
#define calculate_tls_post_size(align)  0

typedef struct {
	unsigned long ti_module;
	unsigned long ti_offset;
} tls_index;

extern void *__tls_get_addr(tls_index* ti);

#define	md_abi_variant_hook(x)

#endif
