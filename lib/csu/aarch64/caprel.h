/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 SRI International
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency (DARPA) Contract No. FA8750-24-C-B047 ("DEC").
 */

#ifndef __CAPREL_H__
#define	__CAPREL_H__

#include <sys/types.h>
#include <machine/elf.h>

#include <cheri/cheric.h>

#define	FUNC_PTR_REMOVE_PERMS						\
	(CHERI_PERM_SEAL | CHERI_PERM_STORE | CHERI_PERM_STORE_CAP |	\
	CHERI_PERM_STORE_LOCAL_CAP)

#define	DATA_PTR_REMOVE_PERMS						\
	(CHERI_PERM_SEAL | CHERI_PERM_EXECUTE)

#define	CAP_RELOC_REMOVE_PERMS						\
	(CHERI_PERM_SW_VMEM)

/*
 * Fragments consist of a 64-bit address followed by a 56-bit length and an
 * 8-bit permission field.
 */
static __always_inline uintcap_t
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
	cap = cheri_clearperm(cap, CAP_RELOC_REMOVE_PERMS);

	if (perms == MORELLO_FRAG_EXECUTABLE || perms == MORELLO_FRAG_RODATA) {
		cap = cheri_clearperm(cap, FUNC_PTR_REMOVE_PERMS);
	}
	if (perms == MORELLO_FRAG_RWDATA || perms == MORELLO_FRAG_RODATA) {
		cap = cheri_clearperm(cap, DATA_PTR_REMOVE_PERMS);
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

static __always_inline void
elf_reloc(const Elf_Rela *rela, void * __capability data_cap,
    const void * __capability code_cap, Elf_Addr relocbase)
{
	Elf_Addr addr;
	Elf_Addr *where;

	if (ELF_R_TYPE(rela->r_info) != R_MORELLO_RELATIVE)
		__builtin_trap();

	addr = relocbase + rela->r_offset;
#ifdef __CHERI_PURE_CAPABILITY__
	where = cheri_setaddress(data_cap, addr);
#else
	where = (Elf_Addr *)addr;
#endif
	*(uintcap_t *)(void *)where = init_cap_from_fragment(where, data_cap,
	    code_cap, relocbase, rela->r_addend);
}

#endif /* __CAPREL_H__ */
