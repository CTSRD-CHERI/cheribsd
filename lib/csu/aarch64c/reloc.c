/*-
 * Copyright (c) 2019 Leandro Lupori
 * Copyright (c) 2021 The FreeBSD Foundation
 * Copyright (c) 2022 Jessica Clarke
 *
 * Portions of this software were developed by Andrew Turner
 * under sponsorship from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

/*
 * Fragments consist of a 64-bit address followed by a 56-bit length and an
 * 8-bit permission field.
 */
static uintcap_t
init_cap_from_fragment(const Elf_Addr *fragment, void * __capability data_cap,
    const void * __capability text_rodata_cap, Elf_Addr base_addr,
    Elf_Size addend)
{
	uintcap_t cap;
	Elf_Addr address, len;
	uint8_t perms;

	address = fragment[0];
	len = fragment[1] & ((1UL << (8 * sizeof(*fragment) - 8)) - 1);
	perms = fragment[1] >> (8 * sizeof(*fragment) - 8);

	cap = perms == MORELLO_FRAG_EXECUTABLE ?
	    (uintcap_t)text_rodata_cap : (uintcap_t)data_cap;
	cap = cheri_setaddress(cap, base_addr + address);

	if (perms == MORELLO_FRAG_EXECUTABLE || perms == MORELLO_FRAG_RODATA) {
		cap = cheri_clearperm(cap, CHERI_PERM_SEAL |
		    CHERI_PERM_STORE | CHERI_PERM_STORE_CAP |
		    CHERI_PERM_STORE_LOCAL_CAP);
	}
	if (perms == MORELLO_FRAG_RWDATA || perms == MORELLO_FRAG_RODATA) {
		cap = cheri_clearperm(cap, CHERI_PERM_SEAL |
		    CHERI_PERM_EXECUTE);
		cap = cheri_setbounds(cap, len);
	}

	cap += addend;

	if (perms == MORELLO_FRAG_EXECUTABLE) {
		/*
		 * TODO tight bounds: lower bound and len should be set
		 * with LSB == 0 for C64 code.
		 */
		cap = cheri_sealentry(cap);
	}

	return (cap);
}

static void
crt1_handle_rela(const Elf_Rela *r, void *data_cap, const void *code_cap)
{
	typedef uintptr_t (*ifunc_resolver_t)(
	    uint64_t, uint64_t, uint64_t, uint64_t,
	    uint64_t, uint64_t, uint64_t, uint64_t);
	uintptr_t *where, target, ptr;
	Elf_Addr *fragment;

	switch (ELF_R_TYPE(r->r_info)) {
	case R_MORELLO_IRELATIVE:
		where = (uintptr_t *)((uintptr_t)data_cap +
		    (r->r_offset - (ptraddr_t)data_cap));
		fragment = (Elf_Addr *)where;
		/*
		 * XXX: See libexec/rtld-elf/aarch64/reloc.c. Unlike there we
		 * can ignore the ET_DYN case.
		 */
		if ((Elf_Ssize)fragment[0] == r->r_addend)
			ptr = (uintptr_t)code_cap +
			    (r->r_addend - (ptraddr_t)code_cap);
		else
			ptr = init_cap_from_fragment(fragment, data_cap,
			    code_cap, 0, r->r_addend);
		target = ((ifunc_resolver_t)ptr)(0, 0, 0, 0, 0, 0, 0, 0);
		*where = target;
		break;
	}
}
