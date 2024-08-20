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

#include <assert.h>
#include <gelf.h>
#include <libelf.h>
#include <stdlib.h>

#include "_libelf.h"

void *
_libelf_getohdr(Elf *e, int ec)
{
	size_t ohnum;
	size_t msz;
	void *ohdr;

	assert(ec == ELFCLASS64);

	if (e == NULL) {
		LIBELF_SET_ERROR(ARGUMENT, 0);
		return (NULL);
	}

	if ((ohdr = ((void *) e->e_u.e_elf.e_ohdr.e_ohdr64)) != NULL)
		return (ohdr);

	ohnum = e->e_u.e_elf.e_nohdr;

	if ((msz = _libelf_msize(ELF_T_OHDR, ec, EV_CURRENT)) == 0)
		return (NULL);

	if ((ohdr = calloc(ohnum, msz)) == NULL) {
		LIBELF_SET_ERROR(RESOURCE, 0);
		return (NULL);
	}

	e->e_u.e_elf.e_ohdr.e_ohdr64 = ohdr;

	return (ohdr);
}


void *
_libelf_newohdr(Elf *e, int ec, size_t count)
{
	void *ehdr, *newohdr, *oldohdr;
	size_t msz;

	if (e == NULL) {
		LIBELF_SET_ERROR(ARGUMENT, 0);
		return (NULL);
	}

	if ((ehdr = _libelf_ehdr(e, ec, 0)) == NULL) {
		LIBELF_SET_ERROR(SEQUENCE, 0);
		return (NULL);
	}

	assert(e->e_class == ec);
	assert(ec == ELFCLASS64);
	assert(e->e_version == EV_CURRENT);

	if ((msz = _libelf_msize(ELF_T_OHDR, ec, e->e_version)) == 0)
		return (NULL);

	newohdr = NULL;
	if (count > 0 && (newohdr = calloc(count, msz)) == NULL) {
		LIBELF_SET_ERROR(RESOURCE, 0);
		return (NULL);
	}

	if ((oldohdr = (void *) e->e_u.e_elf.e_ohdr.e_ohdr64) != NULL)
		free(oldohdr);

	e->e_u.e_elf.e_ohdr.e_ohdr64 = (Elf64_Ohdr *) newohdr;
	e->e_u.e_elf.e_nohdr = count;

	elf_flagelf(e, ELF_C_SET, ELF_F_DIRTY);

	return (newohdr);
}
