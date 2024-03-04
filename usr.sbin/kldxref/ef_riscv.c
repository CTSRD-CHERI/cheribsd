/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2018 John Baldwin <jhb@FreeBSD.org>
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

#include <sys/types.h>
#include <machine/elf.h>
#if __has_feature(capabilities)
#include <cheri/cheric.h>
#endif

#include <err.h>
#include <errno.h>
#include <stdlib.h>

#include "ef.h"

int
ef_reloc(struct elf_file *ef, const void *reldata, int reltype, Elf_Off relbase,
    Elf_Off dataoff, size_t len, void *dest)
{
	Elf_Addr *where;
	const Elf_Rela *rela;
	Elf_Addr addend, addr;
	Elf_Size rtype, symidx;

	switch (reltype) {
	case EF_RELOC_RELA:
		rela = (const Elf_Rela *)reldata;
		where = (Elf_Addr *)((char *)dest + relbase + rela->r_offset -
		    dataoff);
		addend = rela->r_addend;
		rtype = ELF_R_TYPE(rela->r_info);
		symidx = ELF_R_SYM(rela->r_info);
		break;
	default:
		return (EINVAL);
	}

	if ((char *)where < (char *)dest || (char *)where >= (char *)dest + len)
		return (0);

	switch (rtype) {
	case R_RISCV_64:	/* S + A */
		addr = EF_SYMADDR(ef, symidx) + addend;
		*where = addr;
		break;
	case R_RISCV_RELATIVE:	/* B + A */
		addr = addend + relbase;
		*where = addr;
		break;
	case R_RISCV_CHERI_CAPABILITY:
		warnx("unhandled R_RISCV_CHERI_CAPABILITY relocation");
		break;
	default:
		warnx("unhandled relocation type %d", (int)rtype);
	}
	return (0);
}

#if __has_feature(capabilities)
int
ef_capreloc(struct elf_file *ef, const struct capreloc *cr, Elf_Off relbase,
    Elf_Off dataoff, size_t len, void *dest)
{
	void * __capability *where;

	where = (void * __capability *)((char *)dest + relbase +
	    cr->capability_location - dataoff);

	if ((char *)where < (char *)dest || (char *)where >= (char *)dest + len)
		return (0);
	*where = cheri_fromint(relbase + cr->object + cr->offset);
	return (0);
}
#endif
