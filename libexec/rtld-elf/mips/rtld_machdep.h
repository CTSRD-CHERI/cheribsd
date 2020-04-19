/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 1999, 2000 John D. Polstra.
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
 *
 * $FreeBSD$
 */

#ifndef RTLD_MACHDEP_H
#define RTLD_MACHDEP_H	1

#ifdef __CHERI_PURE_CAPABILITY__
#error "Should not be included by rtld-cheri-elf"
#endif

#include <sys/types.h>
#include <sys/sysctl.h>
#include <machine/atomic.h>
#include <machine/tls.h>

struct Struct_Obj_Entry;

/* Return the address of the .dynamic section in the dynamic linker. */
#define rtld_dynamic(obj) (&_DYNAMIC)

Elf_Addr reloc_jmpslot(Elf_Addr *where, Elf_Addr target,
    const struct Struct_Obj_Entry *defobj, const struct Struct_Obj_Entry *obj,
    const Elf_Rel *rel);
Elf_Addr _mips_rtld_bind(struct Struct_Obj_Entry *obj, Elf_Size reloff);
void *_mips_get_tls(void);


#define make_function_pointer(def, defobj) \
	((defobj)->relocbase + (def)->st_value)

#define call_initfini_pointer(obj, target) \
	(((InitFunc)(target))())

#define call_init_pointer(obj, target) \
	(((InitArrFunc)(target))(main_argc, main_argv, environ))

#define	call_ifunc_resolver(ptr) \
	(((Elf_Addr (*)(void))ptr)())

typedef struct {
	unsigned long ti_module;
	unsigned long ti_offset;
} tls_index;

#define round(size, align) \
    (((size) + (align) - 1) & ~((align) - 1))
#define calculate_first_tls_offset(size, align, offset)	\
    TLS_TCB_SIZE
#define calculate_tls_offset(prev_offset, prev_size, size, align, offset) \
    round(prev_offset + prev_size, align)
#define calculate_tls_end(off, size)    ((off) + (size))
#define calculate_tls_post_size(align)  0

extern void *__tls_get_addr(tls_index *ti);

#define	RTLD_DEFAULT_STACK_PF_EXEC	PF_X
#define	RTLD_DEFAULT_STACK_EXEC		PROT_EXEC

#define md_abi_variant_hook(x)

// Validating e_flags:
#define rtld_validate_target_eflags(path, hdr, main_path)	\
	_rtld_validate_target_eflags(path, hdr, main_path)
static inline bool
_rtld_validate_target_eflags(const char* path, Elf_Ehdr *hdr, const char* main_path)
{
	static size_t cheri_flag = 0;
	size_t machine = (hdr->e_flags & EF_MIPS_MACH);
	bool is_cheri = machine == EF_MIPS_MACH_CHERI256 || machine == EF_MIPS_MACH_CHERI128;
	/* RTLD is built with the MIPS compiler, so ask the kernel for size */
	if (is_cheri) {
		if (!cheri_flag) {
			uint32_t cap_size;
			size_t len = sizeof(cap_size);
			if (sysctlbyname("security.cheri.capability_size",
			    &cap_size, &len, NULL, 0) == -1) {
				rtld_fatal("Found CHERI DSO but couldn't get "
				    "expected CHERI size from kernel!");
			}
			if (cap_size == 32)
				cheri_flag = EF_MIPS_MACH_CHERI256;
			else if (cap_size == 16)
				cheri_flag = EF_MIPS_MACH_CHERI128;
			else
				rtld_fatal("Invalid cheri size");
		} else if (machine != cheri_flag) {
			_rtld_error("%s: cannot load %s since EF_MIPS_MACH_CHERI"
			    " != 0x%zx (e_flags=0x%zx)", main_path, path,
			    cheri_flag, (size_t)hdr->e_flags);
			return false;
		}
	}
	if ((hdr->e_flags & EF_MIPS_ABI) == EF_MIPS_ABI_CHERIABI) {
		_rtld_error("%s: cannot load %s since it is CheriABI",
		    main_path, path);
		return false;
	}
	return true;
}

#endif
