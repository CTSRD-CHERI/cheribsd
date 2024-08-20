/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2006,2008 Joseph Koshy
 * Copyright (c) 2024 Konrad Witaszczyk
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency (DARPA) Contract No. HR001123C0031 ("MTSS").
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

#include <gelf.h>
#include <libelf.h>
#include <limits.h>
#include <stdint.h>

#include "_libelf.h"

Elf64_Ohdr *
elf64_getohdr(Elf *e)
{
	return (_libelf_getohdr(e, ELFCLASS64));
}

GElf_Ohdr *
gelf_getohdr(Elf *e, int index, GElf_Ohdr *d)
{
	int ec;
	Elf64_Ehdr *eh64;
	Elf64_Ohdr *ep64;
	size_t ohnum;

	if (d == NULL || e == NULL ||
	    ((ec = e->e_class) != ELFCLASS64) ||
	    (e->e_kind != ELF_K_ELF) || index < 0 ||
	    elf_getohdrnum(e, &ohnum) < 0) {
		LIBELF_SET_ERROR(ARGUMENT, 0);
		return (NULL);
	}

	if ((size_t)index >= ohnum) {
		LIBELF_SET_ERROR(ARGUMENT, 0);
		return (NULL);
	}

	if ((eh64 = _libelf_ehdr(e, ELFCLASS64, 0)) == NULL ||
	    (ep64 = _libelf_getohdr(e, ELFCLASS64)) == NULL)
		return (NULL);

	ep64 += index;

	*d = *ep64;

	return (d);
}

Elf64_Ohdr *
elf64_newohdr(Elf *e, size_t count)
{
	return (_libelf_newohdr(e, ELFCLASS64, count));
}

void *
gelf_newohdr(Elf *e, size_t count)
{
	if (e == NULL) {
		LIBELF_SET_ERROR(ARGUMENT, 0);
		return (NULL);
	}
	return (_libelf_newohdr(e, e->e_class, count));
}

int
gelf_update_ohdr(Elf *e, int ndx, GElf_Ohdr *s)
{
	int ec;
	size_t ohnum;
	void *ehdr;
	Elf64_Ohdr *ph64;

	if (s == NULL || e == NULL || e->e_kind != ELF_K_ELF ||
	    ((ec = e->e_class) != ELFCLASS64) ||
	    elf_getohdrnum(e, &ohnum) < 0) {
		LIBELF_SET_ERROR(ARGUMENT, 0);
		return (0);
	}

	if (e->e_cmd == ELF_C_READ) {
		LIBELF_SET_ERROR(MODE, 0);
		return (0);
	}

	if ((ehdr = _libelf_ehdr(e, ec, 0)) == NULL)
		return (0);

	if (ndx < 0 || (size_t)ndx > ohnum) {
		LIBELF_SET_ERROR(ARGUMENT, 0);
		return (0);
	}

	(void) elf_flagelf(e, ELF_C_SET, ELF_F_DIRTY);

	ph64 = e->e_u.e_elf.e_ohdr.e_ohdr64 + ndx;
	*ph64 = *s;
	return (1);
}
