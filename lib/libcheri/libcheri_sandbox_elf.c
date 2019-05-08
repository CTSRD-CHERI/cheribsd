/*-
 * Copyright (c) 2014-2015 SRI International
 * Copyright (c) 2015 Robert N. M. Watson
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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

/* Allow building the sandbox loader debug program on the host: */
#ifndef __FreeBSD__
#include "sandbox_loader_host_compat.h"
#endif

#include <sys/types.h>
#include <sys/endian.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/queue.h>

#include <assert.h>
#include <elf.h>
#include <err.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "libcheri_sandbox_elf.h"
#include "libcheri_private.h"
#include "libcheri_sandbox.h"

STAILQ_HEAD(sandbox_map_head, sandbox_map_entry);

struct sandbox_map_entry {
	STAILQ_ENTRY(sandbox_map_entry)	sme_entries;

	size_t	sme_map_offset;		/* Offset to sandbox start */
	size_t	sme_len;		/* Length of mapping */
	int	sme_prot;		/* Page protections */
	int	sme_flags;		/* Mmap flags */
	int	sme_fd;			/* File */
	off_t	sme_file_offset;	/* Offset in file */
	size_t	sme_tailbytes;		/* Bytes to zero on last page */
};

struct sandbox_map {
	struct sandbox_map_head	sm_head;
	size_t			sm_minoffset;
	size_t			sm_maxoffset;
	unsigned		sm_flags;	/* code or data */
#ifdef ELF_LOADER_DEBUG
	const char *		sm_name;	/* File name for debugging */
	const char *		sm_kind;	/* code/data (for debugging) */
#endif
};

static struct sandbox_map_entry *
sandbox_map_entry_new(size_t map_offset, size_t len, int prot, int flags,
    int fd, off_t file_offset, size_t tailbytes)
{
	struct sandbox_map_entry *sme;

	if ((sme = calloc(1, sizeof(*sme))) == NULL) {
		warn("%s: calloc", __func__);
		return (NULL);
	}
	sme->sme_map_offset = map_offset;
	sme->sme_len = roundup2(len, PAGE_SIZE);
	sme->sme_prot = prot;
	sme->sme_flags = flags;
	sme->sme_fd = fd;
	sme->sme_file_offset = file_offset;
	sme->sme_tailbytes = tailbytes;

	return (sme);
}

static void *
sandbox_map_entry_mmap(void *base, struct sandbox_map_entry *sme, int add_prot)
{
	caddr_t taddr;
	void *addr;

	taddr = (caddr_t)base + sme->sme_map_offset;
	if (sme->sme_fd > -1)
		loader_dbg("mapping 0x%zx bytes at %p, file offset 0x%zx\n",
		    sme->sme_len, taddr, (size_t)sme->sme_file_offset);
	else
		loader_dbg("mapping 0x%zx bytes at 0x%p\n", sme->sme_len, taddr);
	if ((addr = mmap(taddr, sme->sme_len, sme->sme_prot | add_prot,
	    sme->sme_flags, sme->sme_fd, sme->sme_file_offset)) ==
	    MAP_FAILED) {
		warn("%s: mmap", __func__);
		return (addr);
	}
	assert((vaddr_t)addr == (vaddr_t)taddr);

	memset((caddr_t)addr + sme->sme_len - sme->sme_tailbytes, 0, sme->sme_tailbytes);

	return (addr);
}

static int
sandbox_map_entry_mprotect(void *base, struct sandbox_map_entry *sme)
{
	caddr_t taddr;

	taddr = (caddr_t)base + sme->sme_map_offset;
	if (mprotect(taddr, sme->sme_len, sme->sme_prot) != 0) {
		warn("%s: mprotect", __func__);
		return (-1);
	}
	return (0);
}

int
sandbox_map_load(void *base, struct sandbox_map *sm)
{
	struct sandbox_map_entry *sme;

	STAILQ_FOREACH(sme, &sm->sm_head, sme_entries) {
		if (sandbox_map_entry_mmap(base, sme, PROT_WRITE) == MAP_FAILED)
			return (-1);
	}
	return (0);
}

int
sandbox_map_protect(void *base, struct sandbox_map *sm)
{
	struct sandbox_map_entry *sme;

	STAILQ_FOREACH(sme, &sm->sm_head, sme_entries) {
		if (sme->sme_prot & PROT_WRITE)
			continue;
		if (sandbox_map_entry_mprotect(base, sme) == -1)
			return (-1);
	}
	return (0);
}

int
sandbox_map_reload(void *base, struct sandbox_map *sm)
{
	struct sandbox_map_entry *sme;

	STAILQ_FOREACH(sme, &sm->sm_head, sme_entries) {
		if (!(sme->sme_prot & PROT_WRITE))
			continue;
		if (sandbox_map_entry_mmap(base, sme, 0) == MAP_FAILED)
			return (-1);
	}
	return (0);
}

void
sandbox_map_free(struct sandbox_map *sm)
{
	struct sandbox_map_entry *sme, *sme_temp;

	if (sm == NULL)
		return;

	STAILQ_FOREACH_SAFE(sme, &sm->sm_head, sme_entries, sme_temp) {
		STAILQ_REMOVE(&sm->sm_head, sme, sandbox_map_entry,
		    sme_entries);
		free(sme);
	}
#ifdef ELF_LOADER_DEBUG
	free(__DECONST(char*, sm->sm_name));
#endif
	free(sm);
}

size_t
sandbox_map_maxoffset(struct sandbox_map *sm)
{

	return(sm->sm_maxoffset);
}

size_t
sandbox_map_minoffset(struct sandbox_map *sm)
{

	return(sm->sm_minoffset);
}

static void
dump_sandbox_map_entry(const struct sandbox_map_entry *sme __unused)
{

#if defined(ELF_LOADER_DEBUG) && ELF_LOADER_DEBUG > 1
	fprintf(stderr, "  sme_map_offset  = 0x%zx\n", sme->sme_map_offset);
	fprintf(stderr, "  sme_len         = 0x%zx\n", sme->sme_len);
	fprintf(stderr, "  sme_prot        = 0x%x\n", (uint)sme->sme_prot);
	fprintf(stderr, "  sme_flags       = 0x%x\n", (uint)sme->sme_flags);
	fprintf(stderr, "  sme_fd          = 0x%d\n", sme->sme_fd);
	fprintf(stderr, "  sme_file_offset = 0x%zx\n",
	    (size_t)sme->sme_file_offset);
	fprintf(stderr, "  sme_tailbytes   = 0x%zx\n\n", sme->sme_tailbytes);
#endif
}

static void
dump_sandbox_map(struct sandbox_map *sm __unused)
{
#if defined(ELF_LOADER_DEBUG) && ELF_LOADER_DEBUG > 1
	struct sandbox_map_entry *sme;

	fprintf(stderr, "sandbox map for %s (%s)\n", sm->sm_name, sm->sm_kind);
	STAILQ_FOREACH(sme, &sm->sm_head, sme_entries) {
		dump_sandbox_map_entry(sme);
	}
#endif
}

static int
sandbox_map_optimize(struct sandbox_map *sm)
{
	size_t delta, entry_end, newlen;
	struct sandbox_map_entry *sme, *next_sme, *tmp_sme;

	/*
	 * Search for any mapping that start below sm->sm_minoffset (the
	 * offset of the first real program data in a section) and shift
	 * them up to match.  This eliminates the problem of the reserved
	 * first 0x8000 bytes being mapped from the ELF file due to linker
	 * script bugs.
	 */
	STAILQ_FOREACH(sme, &sm->sm_head, sme_entries) {
		if (sme->sme_map_offset < sm->sm_minoffset) {
			delta = sm->sm_minoffset - sme->sme_map_offset;
			loader_dbg("shifting map up by 0x%zx from 0x%zx\n",
			    delta, sme->sme_map_offset);
			assert(sme->sme_len > delta);
			sme->sme_map_offset += delta;
			sme->sme_len -= delta;
			sme->sme_file_offset += delta;
		}
	}

	/*
	 * Search for mapping with segments that will be overwritten by
	 * the next mapping and truncate the mappings appropriately.
	 */
	STAILQ_FOREACH_SAFE(sme, &sm->sm_head, sme_entries, tmp_sme) {
		next_sme = STAILQ_NEXT(sme, sme_entries);
		if (next_sme == NULL)
			break;

		/*
		 * Normal elf files have their sections sorted.  We can't
		 * do anything useful if they aren't.  Complain loudly
		 * if this happens so we know we need to handle this case.
		 */
		if (next_sme->sme_map_offset < sme->sme_map_offset) {
			warnx("%s: unsorted mappings, most optimizations are "
			    "disabled!", __func__);
			continue;
		}

		if (sme->sme_map_offset + sme->sme_len <=
		    next_sme->sme_map_offset)
			continue;
		if (sme->sme_map_offset + sme->sme_len >
		    next_sme->sme_map_offset + next_sme->sme_len) {
			/* This should not happen in normal ELF files... */
			warnx("%s: mapping 0x%zx of length 0x%zx surrounds "
			    "next mapping 0x%zx of length 0x%zx!", __func__,
			    sme->sme_map_offset, sme->sme_len,
			    next_sme->sme_map_offset, next_sme->sme_len);
			continue;
		}
		newlen = next_sme->sme_map_offset - sme->sme_map_offset;
		loader_dbg("truncating mapping at 0x%zx from 0x%zx to 0x%zx\n",
		    sme->sme_map_offset, sme->sme_len, newlen);
		sme->sme_len = newlen;
		sme->sme_tailbytes = 0;
		if (sme->sme_len == 0) {
			STAILQ_REMOVE(&sm->sm_head, sme, sandbox_map_entry,
			    sme_entries);
			free(sme);
		}
	}

	/*
	 * Search for mappings containing tailbytes and map the last page to
	 * check if the bytes actually need to be zeroed.
	 */
	STAILQ_FOREACH(sme, &sm->sm_head, sme_entries) {
		char *lastpage;
		if (sme->sme_tailbytes == 0)
			continue;
		loader_dbg("Testing %zu tailbytes for mapping at 0x%zx\n",
		    sme->sme_tailbytes, sme->sme_map_offset);
		if ((lastpage = mmap(0, PAGE_SIZE, PROT_READ, MAP_PRIVATE,
		    sme->sme_fd, sme->sme_file_offset + sme->sme_len -
		    PAGE_SIZE)) == MAP_FAILED) {
			warn("%s: mmap\n", __func__);
			return (-1);
		}
		for (/**/; sme->sme_tailbytes > 0; sme->sme_tailbytes--)
			if (lastpage[PAGE_SIZE - sme->sme_tailbytes] != 0)
				break;
		loader_dbg("%zu actual tailbytes\n", sme->sme_tailbytes);
		if (munmap(lastpage, PAGE_SIZE) == -1) {
			warn("%s: munmap", __func__);
			return (-1);
		}
	}

	loader_dbg("Attempting to merge adjacent mappings in %s (flags %x)\n",
	    sm->sm_name, sm->sm_flags);
	/*
	 * Search for adjacent mappings of the same file with the same
	 * permissions and combine them.
	 */
	STAILQ_FOREACH_SAFE(sme, &sm->sm_head, sme_entries, tmp_sme) {
		dump_sandbox_map_entry(sme);
		next_sme = STAILQ_NEXT(sme, sme_entries);
		if (next_sme == NULL)
			continue;

		/*
		 * Normal elf files have their sections sorted.  We can't
		 * do anything useful if they aren't.
		 */
		if (next_sme->sme_map_offset < sme->sme_map_offset ||
		    next_sme->sme_file_offset < sme->sme_file_offset)
			continue;

		/*
		 * Note: the truncation pass above ensures that eligable
		 * entries run precisely to the page proceeding the next one.
		 */
		entry_end = sme->sme_map_offset + sme->sme_len;
		delta = next_sme->sme_map_offset - sme->sme_map_offset;
		if (sme->sme_tailbytes > 0 ||
		    sme->sme_prot != next_sme->sme_prot ||
		    sme->sme_flags != next_sme->sme_flags ||
		    sme->sme_fd != next_sme->sme_fd ||
		    entry_end != next_sme->sme_map_offset ||
		    (size_t)next_sme->sme_file_offset - sme->sme_file_offset
		    != delta)
			continue;

		loader_dbg("combining mapping at 0x%zx with mapping at 0x%zx\n",
		    sme->sme_map_offset, next_sme->sme_map_offset);

		next_sme->sme_map_offset -= delta;
		next_sme->sme_len += delta;
		next_sme->sme_file_offset -= delta;

		STAILQ_REMOVE(&sm->sm_head, sme, sandbox_map_entry, sme_entries);
		free(sme);
	}

	return (0);
}

/* We support only MIPS big endian */
#define LIBCHERI_EXPECTED_ELF_MACHINE EM_MIPS
#define LIBCHERI_EXPECTED_ELF_ORDER ELFDATA2MSB
/*
 * But for debugging we want to be able to parse the sandbox files on a machine
 * with different endianess. We use a hacky from_elf() macro to access the
 * values since we can't use C++ here.
 */
#if LIBCHERI_EXPECTED_ELF_ORDER == ELFDATA2MSB
#define from_elf64(x) be64toh(x)
#define from_elf32(x) be32toh(x)
#define from_elf16(x) be16toh(x)
#elif LIBCHERI_EXPECTED_ELF_ORDER == ELFDATA2LSB
#define from_elf64(x) le64toh(x)
#define from_elf32(x) le32toh(x)
#define from_elf16(x) le16toh(x)
#endif
/* _Generic doesn't seem to work so use this as a workaround for templates */
#define from_elf(x)	__builtin_choose_expr(					\
	__builtin_types_compatible_p(__typeof__(&(x)), uint64_t*),		\
		from_elf64(x),	__builtin_choose_expr(				\
	__builtin_types_compatible_p(__typeof__(&(x)), uint32_t*),		\
		from_elf32(x),	__builtin_choose_expr(				\
	__builtin_types_compatible_p(__typeof__(&(x)), uint16_t*),		\
		from_elf16(x), (void)0 /*error on assignment*/)))

struct sandbox_map *
sandbox_parse_elf64(int fd, const char* name, unsigned flags)
{
	int i, prot;
	size_t taddr;
	ssize_t rlen;
	size_t maplen, mappedbytes, offset, headbytes, tailbytes;
	size_t min_section_addr = (size_t)-1;
	Elf64_Ehdr raw_ehdr; /* Not endian converted */
	Elf64_Phdr raw_phdr;
	Elf64_Shdr raw_shdr;
	struct sandbox_map *sm;
	struct sandbox_map_entry *sme;

	if ((sm = calloc(1, sizeof(*sm))) == NULL) {
		warn("%s: malloc sandbox_map", __func__);
		return (NULL);
	}
	STAILQ_INIT(&sm->sm_head);
	sm->sm_flags = flags;
#ifdef ELF_LOADER_DEBUG
	if (name)
		sm->sm_name = strdup(name);
#endif

	if ((rlen = pread(fd, &raw_ehdr, sizeof(raw_ehdr), 0)) != sizeof(raw_ehdr)) {
		warn("%s: read ELF header for %s", __func__, name);
		goto error;
	}

	if (flags & SANDBOX_LOADELF_CODE)
		loader_dbg("%s: loading code\n", __func__);
	if (flags & SANDBOX_LOADELF_DATA)
		loader_dbg("%s: loading data\n", __func__);

	/* Check for a valid ELF file  */
	if (memcmp(&raw_ehdr.e_ident, ELFMAG, strlen(ELFMAG)) != 0) {
		warnx("%s: %s is not a valid ELF file:", __func__, name);
		goto error;
	}
	if (raw_ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
		warnx("%s: %s is not a 64-bit ELF file", __func__, name);
		goto error;
	}
	if (raw_ehdr.e_ident[EI_OSABI] != ELFOSABI_FREEBSD) {
		warnx("%s: %s is not a FreeBSD ELF file", __func__, name);
		goto error;
	}
	if (raw_ehdr.e_ident[EI_DATA] != LIBCHERI_EXPECTED_ELF_ORDER) {
		warnx("%s: %s has wrong endianess", __func__, name);
		goto error;
	}

	/*
	 * All the fields may be in the wrong endianess so we use macros
	 * to access them. This should compile to nothing on CheriBSD but is
	 * useful to debug loading of sandbox binaries on the host system.
	 */
#define ehdr_member(name) from_elf(raw_ehdr.name)
#define phdr_member(name) from_elf(raw_phdr.name)
	if (ehdr_member(e_machine) != LIBCHERI_EXPECTED_ELF_MACHINE) {
		warnx("%s: %s has wrong e_machine %d", __func__, name,
		    ehdr_member(e_machine));
		goto error;
	}
	loader_dbg("type %d\n", ehdr_member(e_type));
	loader_dbg("version %d\n", ehdr_member(e_version));
	loader_dbg("machine %d\n", ehdr_member(e_machine));
	loader_dbg("entry %zx\n", (size_t)ehdr_member(e_entry));
	loader_dbg("flags 0x%zx\n", (size_t)ehdr_member(e_flags));
	loader_dbg("elf header size %jd (read %jd)\n",
	    (intmax_t)ehdr_member(e_ehsize), rlen);
	loader_dbg("program header offset %jd\n", (intmax_t)ehdr_member(e_phoff));
	loader_dbg("program header size %jd\n", (intmax_t)ehdr_member(e_phentsize));
	loader_dbg("program header number %jd\n", (intmax_t)ehdr_member(e_phnum));
	loader_dbg("section header offset %jd\n", (intmax_t)ehdr_member(e_shoff));
	loader_dbg("section header size %jd\n", (intmax_t)ehdr_member(e_shentsize));
	loader_dbg("section header number %jd\n", (intmax_t)ehdr_member(e_shnum));
	loader_dbg("section name strings section %jd\n",
	    (intmax_t)ehdr_member(e_shstrndx));

	for (i = 0; i < ehdr_member(e_phnum); i++) {
		Elf64_Addr phdr_offset =
		    ehdr_member(e_phoff) + ehdr_member(e_phentsize) * i;
		if ((rlen = pread(fd, &raw_phdr, sizeof(raw_phdr),
		    phdr_offset)) != sizeof(raw_phdr)) {
			warn("%s: failed to reading program header %d: Read %zd"
			    " instead of %zd bytes", __func__, i+1, rlen,
			    sizeof(raw_phdr));
			goto error;
		}
#if defined(ELF_LOADER_DEBUG) && ELF_LOADER_DEBUG > 1
		loader_dbg("phdr[%d] type        %jx\n", i,
		    (intmax_t)phdr_member(p_type));
		loader_dbg("phdr[%d] flags       %jx (%c%c%c)\n", i,
		    (intmax_t)phdr_member(p_flags),
		    phdr_member(p_flags) & PF_R ? 'r' : '-',
		    phdr_member(p_flags) & PF_W ? 'w' : '-',
		    phdr_member(p_flags) & PF_X ? 'x' : '-');
		loader_dbg("phdr[%d] offset      0x%016jx\n", i,
		    (intmax_t)phdr_member(p_offset));
		loader_dbg("phdr[%d] vaddr       0x%016jx\n", i,
		    (intmax_t)phdr_member(p_vaddr));
		loader_dbg("phdr[%d] file size   0x%016jx\n", i,
		    (intmax_t)phdr_member(p_filesz));
		loader_dbg("phdr[%d] memory size 0x%016jx\n", i,
		    (intmax_t)phdr_member(p_memsz));
#endif
		if (phdr_member(p_type) != PT_LOAD) {
			/* XXXBD: should we handled GNU_STACK? */
			loader_dbg("skipping non-PT_LOAD segment phdr[%d]\n", i);
			continue;
		}

		/*
		 * Consider something 'data' if PF_X is unset; otherwise,
		 * consider it code.  Either way, load it only if requested by
		 * a suitable flag.
		 */
		if (phdr_member(p_flags) & PF_X) {
#ifdef NOTYET
			/*
			 * XXXRW: Our current linker script will sometimes
			 * place data and code in the same page.  For now,
			 * map code into object instances.
			 */
			if (!(flags & SANDBOX_LOADELF_CODE)) {
				loader_dbg("skipping code segment %d\n", i+1);
				continue;
			}
#endif
		} else {
			if (!(flags & SANDBOX_LOADELF_DATA)) {
				loader_dbg("skipping data segment %d\n", i+1);
				continue;
			}
		}

		prot = (
		    (phdr_member(p_flags) & PF_R ? PROT_READ : 0) |
		    (phdr_member(p_flags) & PF_W ? PROT_WRITE : 0) |
		    (phdr_member(p_flags) & PF_X ? PROT_EXEC : 0));
		/* XXXBD: write should not be required for code! */
		/* XXXBD: ideally read would not be required for code. */
		if (flags & SANDBOX_LOADELF_CODE)
			prot &= PROT_READ | PROT_WRITE | PROT_EXEC;
		else if (flags & SANDBOX_LOADELF_DATA)
			prot &= PROT_READ | PROT_WRITE;

		taddr = rounddown2((phdr_member(p_vaddr)), PAGE_SIZE);
		offset = rounddown2(phdr_member(p_offset), PAGE_SIZE);
		headbytes = phdr_member(p_offset) - offset;
		maplen = headbytes + phdr_member(p_filesz);
		/* XXX-BD: rtld handles this, but I don't see why you would. */
		if (phdr_member(p_filesz) != phdr_member(p_memsz) && !(phdr_member(p_flags) & PF_W)) {
			warnx("%s: segment %d expects 0 fill, but is not "
			    "writable, skipping", __func__, i+1);
			continue;
		}

		/* Calculate bytes to be zeroed in last page */
		mappedbytes = roundup2(maplen, PAGE_SIZE);
		tailbytes = mappedbytes - maplen;

		if ((sme = sandbox_map_entry_new(taddr, maplen, prot,
		    MAP_FIXED | MAP_PRIVATE | MAP_PREFAULT_READ,
		    fd, offset, tailbytes)) == NULL)
			goto error;
		STAILQ_INSERT_TAIL(&sm->sm_head, sme, sme_entries);

		sm->sm_maxoffset = MAX(sm->sm_maxoffset, phdr_member(p_vaddr) +
		    phdr_member(p_memsz));

		/*
		 * If we would map everything directly or everything fit
		 * in the mapped range we're done.
		 */
		if (phdr_member(p_filesz) == phdr_member(p_memsz) ||
		    headbytes + phdr_member(p_memsz) <= mappedbytes)
			continue;

		taddr = taddr + mappedbytes;
		maplen = headbytes + phdr_member(p_memsz) - mappedbytes;

		if ((sme = sandbox_map_entry_new(taddr, maplen, prot,
		    MAP_FIXED | MAP_ANON, -1, 0, 0)) == NULL)
			goto error;
		STAILQ_INSERT_TAIL(&sm->sm_head, sme, sme_entries);
	}

	for (i = 1; i < ehdr_member(e_shnum); i++) {	/* Skip section 0 */
		if ((rlen = pread(fd, &raw_shdr, sizeof(raw_shdr),
		    ehdr_member(e_shoff) + ehdr_member(e_shentsize) * i)) !=
		    sizeof(raw_shdr)) {
			warn("%s: reading %d section header", __func__, i+1);
			goto error;
		}

		/*
		 * Find the "real" section with the lowest address.
		 * Exclude everything in the first page as those would
		 * either introduce potential NULL related bugs or
		 * treat various ELF stables as valid.
		 */
		Elf64_Addr sh_addr = from_elf(raw_shdr.sh_addr);
		if (sh_addr >= 0x1000 && min_section_addr > sh_addr)
			min_section_addr = sh_addr;
	}
	loader_dbg("minimum section address 0x%lx\n", min_section_addr);
	sm->sm_minoffset = rounddown2(min_section_addr, PAGE_SIZE);

	sandbox_map_optimize(sm);

	loader_dbg("%s: final layout:\n", __func__);
	dump_sandbox_map(sm);

	return (sm);
error:
	sandbox_map_free(sm);
	return (NULL);
}

#ifdef TEST_LOADELF64

#include <errno.h>

static ssize_t
sandbox_loadelf64(int fd, const char* name, void *base, size_t maxsize __unused,
    unsigned flags)
{
	struct sandbox_map *sm;
	ssize_t maxoffset;

	assert((intptr_t)base % PAGE_SIZE == 0);

	if ((sm = sandbox_parse_elf64(fd, name, flags)) == NULL) {
		warnx("%s: sandbox_parse_elf64", __func__);
		return (-1);
	}
	if (sandbox_map_load(base, sm) == -1) {
		warnx("%s: sandbox_map_load", __func__);
		return (-1);
	}
	maxoffset = sm->sm_maxoffset;
	sandbox_map_free(sm);

	return (maxoffset);
}

int sb_verbose = 1;

int
main(int argc, char **argv)
{
	void *base;
	ssize_t codelen;
	ssize_t datalen;
	size_t maxlen;
	int fd;

	if (argc != 2)
		errx(1, "usage: elf_loader <file>");

	maxlen = 10 * 1024 * 1024;
	long pagesize = sysconf(_SC_PAGE_SIZE);
	fprintf(stderr, "Pagesize = %ld\n", pagesize);
	assert(maxlen % pagesize == 0);
	// Linux needs MAP_PRIVATE or MAP_SHARED set otherwise it returns -EINVAL
	base = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
	if (base == MAP_FAILED)
		err(1, "%s: mmap region", __func__);

	if ((fd = open(argv[1], O_RDONLY)) == -1)
		err(1, "%s: open(%s)", __func__, argv[1]);

	if ((codelen = sandbox_loadelf64(fd, argv[1], base, maxlen,
	    SANDBOX_LOADELF_CODE)) == -1)
		errx(1, "%s: sandbox_loadelf64 (code) failed", __func__);
	printf("mapped %jd code bytes from %s\n", codelen, argv[1]);

	if ((datalen = sandbox_loadelf64(fd, argv[1], base, maxlen,
	    SANDBOX_LOADELF_DATA)) == -1)
		errx(1, "%s: sandbox_loadelf64 (data) failed", __func__);
	printf("mapped %jd datalen bytes from %s\n", datalen, argv[1]);

	return (0);
}
#endif
