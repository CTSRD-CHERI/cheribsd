/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Ruslan Bukin <br@bsdpad.com>
 *
 * This work was supported by Innovate UK project 105694, "Digital Security
 * by Design (DSbD) Technology Platform Prototype".
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
#include <sys/types.h>
#include <sys/cpuset.h>
#include <sys/hwt.h>

#include <assert.h>
#include <fcntl.h>
#include <gelf.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "hwt.h"

int
hwt_elf_count_libs(const char *elf_path, uint32_t *nlibs0)
{
	GElf_Shdr shdr;
	GElf_Phdr ph;
	GElf_Ehdr eh;
	Elf_Scn *scn;
	Elf *elf;
	size_t sh_entsize;
	Elf_Data *data;
	GElf_Dyn dyn;
	int is_dynamic;
	uint32_t nlibs;
	int fd;
	size_t i;

	nlibs = 0;

	assert(elf_version(EV_CURRENT) != EV_NONE);

	fd = open(elf_path, O_RDONLY, 0);

	assert(fd >= 0);

	elf = elf_begin(fd, ELF_C_READ, NULL);

	assert(elf != NULL);
	assert(elf_kind(elf) == ELF_K_ELF);

	if (gelf_getehdr(elf, &eh) != &eh) {
		printf("could not find elf header\n");
		return (-1);
	}

	if (eh.e_type != ET_EXEC && eh.e_type != ET_DYN) {
		printf("unsupported image\n");
		return (-2);
	}

	if (eh.e_ident[EI_CLASS] != ELFCLASS32 &&
	    eh.e_ident[EI_CLASS] != ELFCLASS64)
		return (-3);

	is_dynamic = 0;

	for (i = 0; i < eh.e_phnum; i++) {
		if (gelf_getphdr(elf, i, &ph) != &ph) {
			printf("could not get program header %zu\n", i);
			return (-4);
		}
		switch (ph.p_type) {
		case PT_DYNAMIC:
			is_dynamic = 1;
			break;
		case PT_INTERP:
			nlibs++;
			break;
		}
	}

	if (!is_dynamic)
		goto done;

	scn = NULL;
	data = NULL;

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		assert(gelf_getshdr(scn, &shdr) == &shdr);

		if (shdr.sh_type == SHT_DYNAMIC) {
			data = elf_getdata(scn, data);
			assert(data != NULL);

			sh_entsize = gelf_fsize(elf, ELF_T_DYN, 1, EV_CURRENT);

			for (i = 0; i < shdr.sh_size / sh_entsize; i++) {
				assert(gelf_getdyn(data, i, &dyn) == &dyn);
				if (dyn.d_tag == DT_NEEDED)
					nlibs++;
			}
		}
	}

done:
	assert(elf_end(elf) == 0);
	assert(close(fd) == 0);

	*nlibs0 = nlibs;

	return (0);
}
