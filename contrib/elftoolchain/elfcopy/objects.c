/*- * SPDX-License-Identifier: BSD-2-Clause
 *
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

#include <sys/param.h>
#include <assert.h>
#include <err.h>
#include <stdlib.h>
#include <string.h>

#include "elfcopy.h"

void
create_ohdr(struct elfcopy *ecp)
{
	Elf_Data		 fbuf, mbuf;
	GElf_Ohdr		 oohdr;
	GElf_Shdr		 sh;
	char			*data;
	struct transplant	*obj;
	struct section		*s;
	struct segment		*seg;
	size_t			 datasize, fsz, ndx;
	unsigned int		 align, off;
	int			 ii;

	assert(ecp->oohnum > 1);

	if (gelf_newohdr(ecp->eout, ecp->oohnum) == NULL)
		errx(EXIT_FAILURE, "gelf_newohdr() failed: %s",
		    elf_errmsg(-1));

	fsz = gelf_fsize(ecp->eout, ELF_T_OHDR, 1, EV_CURRENT);
	memset(&mbuf, 0, sizeof(mbuf));
	mbuf.d_type = ELF_T_OHDR;
	mbuf.d_size = sizeof(oohdr);
	mbuf.d_version = EV_CURRENT;
	memset(&fbuf, 0, sizeof(fbuf));
	fbuf.d_type = mbuf.d_type;
	fbuf.d_size = fsz;
	fbuf.d_version = mbuf.d_version;

	datasize = fsz * ecp->oohnum;
	data = calloc(1, datasize);
	if (data == NULL)
		err(EXIT_FAILURE, "calloc() failed");

	ii = 0;
	TAILQ_FOREACH(obj, &ecp->v_transplants, t_list) {
		if (ii >= ecp->oohnum)
			errx(EXIT_FAILURE, "create_ohdr: invalid number of objects");

		if (gelf_getohdr(ecp->eout, ii, &oohdr) != &oohdr)
			errx(EXIT_FAILURE, "gelf_getohdr failed: %s",
			    elf_errmsg(-1));

		oohdr.o_name = obj->name;
		oohdr.o_vaddr = obj->vaddr;
		oohdr.o_memsz = obj->msz;
		oohdr.o_dynamicndx = obj->dynamicndx;
		if (!gelf_update_ohdr(ecp->eout, ii, &oohdr))
			errx(EXIT_FAILURE, "gelf_update_ohdr failed: %s",
			    elf_errmsg(-1));

		mbuf.d_buf = &oohdr;
		fbuf.d_buf = data + ii * fsz;
		if (gelf_xlatetof(ecp->eout, &fbuf, &mbuf, ELFDATANONE) == NULL)
			err(EXIT_FAILURE, "gelf_xlatetof failed");
		ii++;
	}

	align = gelf_falign(ecp->eout, ELF_T_OHDR);
	off = roundup(first_free_offset(ecp), align);
	/*
	 * The object headers are not loadable.
	 */
	s = create_external_section(ecp, ".object", NULL, data, datasize,
	    off, SHT_PROGBITS, ELF_T_BYTE, 0, align, 0, 0);

	/*
	 * Link .object with .shstrtab that stores names of objects.
	 */
	if (gelf_getshdr(s->os, &sh) == NULL)
		errx(EXIT_FAILURE, "gelf_getshdr() failed: %s",
		    elf_errmsg(-1));
	elf_getshdrstrndx(ecp->ein, &ndx);
	sh.sh_link = ndx;
	if (!gelf_update_shdr(s->os, &sh))
		errx(EXIT_FAILURE, "gelf_update_shdr() failed: %s",
		    elf_errmsg(-1));

	if ((seg = calloc(1, sizeof(*seg))) == NULL)
		err(EXIT_FAILURE, "calloc() failed");
	seg->p_type	= PT_OBJECT;
	seg->vaddr	= 0;
	seg->paddr	= 0;
	seg->p_flags	= PF_R;
	seg->p_align	= s->align;
	seg->off	= s->off;
	seg->fsz	= s->sz;
	seg->msz	= seg->fsz;
	seg->type	= seg->p_type;
	STAILQ_INSERT_TAIL(&ecp->v_seg, seg, seg_list);

	ecp->object = s;
	ecp->ophnum++;
}
