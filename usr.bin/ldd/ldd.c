/*-
 * SPDX-License-Identifier: BSD-4-Clause
 *
 * Copyright (c) 1993 Paul Kranenburg
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Paul Kranenburg.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/wait.h>

#include <machine/elf.h>

#include <arpa/inet.h>

#include <assert.h>
#include <dlfcn.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <spawn.h>

#include "extern.h"
#include "paths.h"

/* We don't support a.out executables on arm64 and riscv */
#if !defined(__aarch64__) && !defined(__riscv)
#include <a.out.h>
#define	AOUT_SUPPORTED
#endif

#if defined(__mips)
#define RTLD_DIRECT_EXEC_TRACE_SUPPORTED 1
#else
#define RTLD_DIRECT_EXEC_TRACE_SUPPORTED 0
#endif

/*
 * 32-bit ELF data structures can only be used if the system header[s] declare
 * them.  There is no official macro for determining whether they are declared,
 * so check for the existence of one of the 32-macros defined in elf(5).
 */
#ifdef ELF32_R_TYPE
#define	ELF32_SUPPORTED
#endif

#define	LDD_SETENV(name, value, overwrite) do {		\
	setenv("LD_" name, value, overwrite);		\
	setenv("LD_32_" name, value, overwrite);	\
	setenv("LD_CHERI_" name, value, overwrite);	\
} while (0)

#define	LDD_UNSETENV(name) do {		\
	unsetenv("LD_" name);		\
	unsetenv("LD_32_" name);	\
	unsetenv("LD_CHERI_" name);	\
} while (0)

static int	is_executable(const char *fname, int fd, int *is_shlib,
		    int *type, const char** rtld);
static void	usage(void);

#define	TYPE_UNKNOWN	0
#define	TYPE_AOUT	1
#define	TYPE_ELF	2	/* Architecture default */
#if __ELF_WORD_SIZE > 32 && defined(ELF32_SUPPORTED)
#define	TYPE_ELF32	3	/* Explicit 32 bits on architectures >32 bits */
#endif

extern char **environ;

#if RTLD_DIRECT_EXEC_TRACE_SUPPORTED == 1

static int
trace_rtld_direct_exec(pid_t * child, const char *rtld, const char *file)
{
	char *argv[4];
	int rval;

	argv[0] = strdup(rtld);
	argv[1] = strdup("-t");
	argv[2] = strdup(file);
	argv[3] = NULL;

	rval = posix_spawn(child, rtld, NULL, NULL, argv, environ);
	if (rval != 0) {
		warnc(rval, "posix_spawn(%s, %s)", rtld, file);
		rval = 1;
		assert(*child == -1);
	}
	for (size_t i = 0; i < sizeof(argv) / sizeof(argv[0]); i++)
		free(argv[i]);
	return (rval);

}

#elif __ELF_WORD_SIZE > 32 && defined(ELF32_SUPPORTED)

#define	_PATH_LDD32	"/usr/bin/ldd32"

static int
execldd32(char *file, char *fmt1, char *fmt2, int aflag, int vflag)
{
	char *argv[9];
	int i, rval, status;

	LDD_UNSETENV("TRACE_LOADED_OBJECTS");
	rval = 0;
	i = 0;
	argv[i++] = strdup(_PATH_LDD32);
	if (aflag)
		argv[i++] = strdup("-a");
	if (vflag)
		argv[i++] = strdup("-v");
	if (fmt1 != NULL) {
		argv[i++] = strdup("-f");
		argv[i++] = strdup(fmt1);
	}
	if (fmt2 != NULL) {
		argv[i++] = strdup("-f");
		argv[i++] = strdup(fmt2);
	}
	argv[i++] = strdup(file);
	argv[i++] = NULL;

	switch (fork()) {
	case -1:
		err(1, "fork");
		break;
	case 0:
		execv(_PATH_LDD32, argv);
		warn("%s", _PATH_LDD32);
		_exit(127);
		break;
	default:
		if (wait(&status) < 0)
			rval = 1;
		else if (WIFSIGNALED(status))
			rval = 1;
		else if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
			rval = 1;
		break;
	}
	while (i--)
		free(argv[i]);
	LDD_SETENV("TRACE_LOADED_OBJECTS", "yes", 1);
	return (rval);
}
#endif


int
main(int argc, char *argv[])
{
	char *fmt1, *fmt2;
	int rval, c, aflag, vflag;

	aflag = vflag = 0;
	fmt1 = fmt2 = NULL;

	while ((c = getopt(argc, argv, "af:v")) != -1) {
		switch (c) {
		case 'a':
			aflag++;
			break;
		case 'f':
			if (fmt1 != NULL) {
				if (fmt2 != NULL)
					errx(1, "too many formats");
				fmt2 = optarg;
			} else
				fmt1 = optarg;
			break;
		case 'v':
			vflag++;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (vflag && fmt1 != NULL)
		errx(1, "-v may not be used with -f");

	if (argc <= 0) {
		usage();
		/* NOTREACHED */
	}

#ifdef __i386__
	if (vflag) {
		for (c = 0; c < argc; c++)
			dump_file(argv[c]);
		exit(error_count == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
	}
#endif

	rval = 0;
	for (; argc > 0; argc--, argv++) {
		int fd, status, is_shlib, rv, type;
		const char* rtld = NULL;

		if ((fd = open(*argv, O_RDONLY, 0)) < 0) {
			warn("%s", *argv);
			rval |= 1;
			continue;
		}
		rv = is_executable(*argv, fd, &is_shlib, &type, &rtld);
		close(fd);
		if (rv == 0) {
			rval |= 1;
			continue;
		}

		switch (type) {
		case TYPE_ELF:
		case TYPE_AOUT:
			break;
#if __ELF_WORD_SIZE > 32 && defined(ELF32_SUPPORTED)
		case TYPE_ELF32:
#if RTLD_DIRECT_EXEC_TRACE_SUPPORTED == 1
			break;
#else
			rval |= execldd32(*argv, fmt1, fmt2, aflag, vflag);
			continue;
#endif
#endif
		case TYPE_UNKNOWN:
		default:
			/*
			 * This shouldn't happen unless is_executable()
			 * is broken.
			 */
			errx(EDOOFUS, "unknown executable type");
		}

		/* ld.so magic */
		LDD_SETENV("TRACE_LOADED_OBJECTS", "yes", 1);
		if (fmt1 != NULL)
			LDD_SETENV("TRACE_LOADED_OBJECTS_FMT1", fmt1, 1);
		if (fmt2 != NULL)
			LDD_SETENV("TRACE_LOADED_OBJECTS_FMT2", fmt2, 1);

		LDD_SETENV("TRACE_LOADED_OBJECTS_PROGNAME", *argv, 1);
		if (aflag)
			LDD_SETENV("TRACE_LOADED_OBJECTS_ALL", "1", 1);
		else if (fmt1 == NULL && fmt2 == NULL)
			/* Default formats */
			printf("%s:\n", *argv);
		fflush(stdout);

		pid_t child = -1;
		if (is_shlib == 0) {
			int error = posix_spawn(&child, *argv, NULL, NULL,
			    argv, environ);
			if (error != 0) {
				warnc(error, "is_shlib==0, %s", *argv);
				rval |= 1;
				continue;
			}
		} else {
#if RTLD_DIRECT_EXEC_TRACE_SUPPORTED == 1
			if (trace_rtld_direct_exec(&child, rtld, *argv) == 0) {
				goto wait_for_child;
			}
			warnx("Could not execute %s, will try dlopen()"
				    "instead", *argv);
#endif
			child = fork();
			switch(child) {
			case -1:
				err(1, "fork");
				break;
			case 0:
				dlopen(*argv, RTLD_TRACE);
				warnx("%s: %s", *argv, dlerror());
				_exit(1);
			default:
				break;
			}
		}
#if RTLD_DIRECT_EXEC_TRACE_SUPPORTED == 1
wait_for_child:
#endif
		if (child != -1) {
			if (waitpid(child, &status, 0) < 0) {
				warn("waitpid(%d)", child);
				rval |= 1;
			} else if (WIFSIGNALED(status)) {
				fprintf(stderr, "%s: signal %d\n", *argv,
				    WTERMSIG(status));
				rval |= 1;
			} else if (WIFEXITED(status) &&
			    WEXITSTATUS(status) != 0) {
				fprintf(stderr, "%s: exit status %d\n", *argv,
				    WEXITSTATUS(status));
				rval |= 1;
			}
		}
	}

	return rval;
}

static void
usage(void)
{

	fprintf(stderr, "usage: ldd [-a] [-v] [-f format] program ...\n");
	exit(1);
}

#if !defined(__aarch64__) && !defined(__riscv)
static bool
check_notes(const char *buf, size_t len)
{
	const Elf_Note *note;
	const char *name;
	size_t namesz, descsz;

	for (;;) {
		if (len < sizeof(*note))
			return (false);
		note = (const Elf_Note *)(uintptr_t)buf;
		buf += sizeof(*note);
		len -= sizeof(*note);

		namesz = roundup2(note->n_namesz, 4);
		descsz = roundup2(note->n_descsz, 4);
		if (len < namesz + descsz)
			return (false);

		name = buf;
		if (strncmp(name, "FreeBSD", namesz) == 0 && 
		    note->n_type == NT_FREEBSD_ABI_TAG)
			return (true);

		buf += namesz + descsz;
		len -= namesz + descsz;
	}

	return (false);
}

static bool
is_freebsd_elf(const char *fname, Elf *elf, GElf_Ehdr *ehdr)
{
	GElf_Shdr shdr;
	Elf_Scn *scn;
	Elf_Data *d;

	switch (ehdr->e_ident[EI_OSABI]) {
	case ELFOSABI_FREEBSD:
		return (true);
	case ELFOSABI_NONE:
		break;
	default:
		return (false);
	}

	scn = NULL;
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		if (gelf_getshdr(scn, &shdr) == NULL) {
			warnx("%s: %s", fname, elf_errmsg(0));
			return (false);
		}

		if (shdr.sh_type != SHT_NOTE)
			continue;

		d = elf_getdata(scn, NULL);
		if (d == NULL)
			continue;

		if (check_notes(d->d_buf, d->d_size))
			return (true);
	}

	return (false);
}
#endif

static int
is_executable(const char *fname, int fd, int *is_shlib, int *type,
    const char** rtld)
{
	union {
#ifdef AOUT_SUPPORTED
		struct exec aout;
#endif
		Elf_Ehdr elf;
	} hdr;
	Elf *elf;
	int n;

	*is_shlib = 0;
	*type = TYPE_UNKNOWN;
	*rtld = NULL;

	if ((n = read(fd, &hdr, sizeof(hdr))) == -1) {
		warn("%s: can't read program header", fname);
		return (0);
	}

#ifdef AOUT_SUPPORTED
	if ((size_t)n >= sizeof(hdr.aout) && !N_BADMAG(hdr.aout)) {
		/* a.out file */
		if ((N_GETFLAG(hdr.aout) & EX_DPMASK) != EX_DYNAMIC
#if 1 /* Compatibility */
		    || hdr.aout.a_entry < __LDPGSZ
#endif
			) {
			warnx("%s: not a dynamic executable", fname);
			return (0);
		}
		*type = TYPE_AOUT;
		warnx("%s: aout support is deprecated", fname);
		return (1);
	}
#endif

	if ((size_t)n >= sizeof(hdr.elf) && IS_ELF(hdr.elf)) {
		GElf_Ehdr ehdr;
		GElf_Phdr phdr;
		int i;
		bool dynamic, interp;

		dynamic = false;
		interp = false;

		if (elf_version(EV_CURRENT) == EV_NONE) {
			warnx("unsupported libelf");
			return (0);
		}
		elf = elf_begin(fd, ELF_C_READ, NULL);
		if (elf == NULL) {
			warnx("%s: %s", fname, elf_errmsg(0));
			return (0);
		}
		if (elf_kind(elf) != ELF_K_ELF) {
			elf_end(elf);
			warnx("%s: not a dynamic ELF executable", fname);
			return (0);
		}
		if (gelf_getehdr(elf, &ehdr) == NULL) {
			warnx("%s: %s", fname, elf_errmsg(0));
			elf_end(elf);
			return (0);
		}

		*type = TYPE_ELF;
		*rtld = _DEFAULT_PATH_RTLD;
#if __ELF_WORD_SIZE > 32 && defined(ELF32_SUPPORTED)
		if (gelf_getclass(elf) == ELFCLASS32) {
			*type = TYPE_ELF32;
			*rtld = _COMPAT32_PATH_RTLD;
		}
#endif

		for (i = 0; i < ehdr.e_phnum; i++) {
			if (gelf_getphdr(elf, i, &phdr) == NULL) {
				warnx("%s: %s", fname, elf_errmsg(0));
				elf_end(elf);
				return (0);
			}
			switch (phdr.p_type) {
			case PT_DYNAMIC:
				dynamic = true;
				break;
			case PT_INTERP:
				interp = true;
				break;
			}
		}

		if (!dynamic) {
			elf_end(elf);
			warnx("%s: not a dynamic ELF executable", fname);
			return (0);
		}

		/*
		 * PIE binaries are ET_DYN, so use the presence of
		 * PT_INTERP to differentiate executables from shared
		 * libraries.
		 */
		if (!interp) {
			*is_shlib = 1;

#if !defined(__aarch64__) && !defined(__riscv)
			/*
			 * Shared libraries on AArch64 and RISC-V have
			 * neither a FreeBSD OSABI or a brand note.
			 */
			if (!is_freebsd_elf(fname, elf, &ehdr)) {
				elf_end(elf);
				warnx("%s: not a FreeBSD ELF shared object",
				    fname);
				return (0);
			}
#endif
		}
		elf_end(elf);

#ifndef __CHERI_PURE_CAPABILITY__
#ifdef __mips__
		if ((ehdr.e_flags & EF_MIPS_ABI) == EF_MIPS_ABI_CHERIABI)
			*rtld = _CHERIABI_PATH_RTLD;
#endif
#ifdef __riscv
		if ((ehdr.e_flags & EF_RISCV_CHERIABI) != 0)
			*rtld = _CHERIABI_PATH_RTLD;
#endif
#endif
		return (1);
	}

	warnx("%s: not a dynamic executable", fname);
	return (0);
}
