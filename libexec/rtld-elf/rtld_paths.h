/*-
 * Copyright 1996, 1997, 1998, 1999, 2000 John D. Polstra.
 * Copyright 2003 Alexander Kabaev <kan@FreeBSD.ORG>.
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
 *
 * $FreeBSD$
 */

#ifndef _RTLD_PATHS_H
#define _RTLD_PATHS_H

#undef _PATH_ELF_HINTS

#define	_DEFAULT_BASENAME_RTLD		"ld-elf.so.1"
#ifndef	_CHERIABI_BASENAME_RTLD
#define	_CHERIABI_BASENAME_RTLD		"ld-elf64c.so.1"
#endif
#ifndef	_COMPAT32_BASENAME_RTLD
#define	_COMPAT32_BASENAME_RTLD		"ld-elf32.so.1"
#endif
#ifndef	_COMPAT64_BASENAME_RTLD
#define	_COMPAT64_BASENAME_RTLD		"ld-elf64.so.1"
#endif

#ifdef COMPAT_CHERI
#define	_PATH_ELF_HINTS		"/var/run/ld-elf64c.so.hints"
#define	_PATH_LIBMAP_CONF	"/etc/libmap64c.conf"
#define	_BASENAME_RTLD		_CHERIABI_BASENAME_RTLD
#define	STANDARD_LIBRARY_PATH	"/lib64c:/usr/lib64c"
#define	LD_			"LD_CHERI_"
#endif

#ifndef _PATH_ELF32_HINTS
#define	_PATH_ELF32_HINTS	"/var/run/ld-elf32.so.hints"
#endif

#ifdef COMPAT_32BIT
#define	_PATH_ELF_HINTS		_PATH_ELF32_HINTS
#define	_PATH_LIBMAP_CONF	"/etc/libmap32.conf"
#define	_BASENAME_RTLD		_COMPAT32_BASENAME_RTLD
#define	STANDARD_LIBRARY_PATH	"/lib32:/usr/lib32"
#define	LD_			"LD_32_"
#endif

#ifndef _PATH_ELF64_HINTS
#define	_PATH_ELF64_HINTS	"/var/run/ld-elf64.so.hints"
#endif

#ifdef COMPAT_64BIT
#define	_PATH_ELF_HINTS		_PATH_ELF64_HINTS
#define	_PATH_LIBMAP_CONF	"/etc/libmap64.conf"
#define	_BASENAME_RTLD		_COMPAT64_BASENAME_RTLD
#define	STANDARD_LIBRARY_PATH	"/lib64:/usr/lib64"
#define	LD_			"LD_64_"
#endif

#ifndef _PATH_ELF_HINTS
#define	_PATH_ELF_HINTS		"/var/run/ld-elf.so.hints"
#endif

#ifndef _PATH_LIBMAP_CONF
#define	_PATH_LIBMAP_CONF	"/etc/libmap.conf"
#endif

#ifndef _BASENAME_RTLD
#define	_BASENAME_RTLD		_DEFAULT_BASENAME_RTLD
#endif

#ifndef _PATH_RTLD
#define	_PATH_RTLD		"/libexec/" _BASENAME_RTLD
#endif

/* Provide these constants for /usr/bin/ldd32 */
#ifndef _DEFAULT_PATH_RTLD
#define	_DEFAULT_PATH_RTLD	"/libexec/" _DEFAULT_BASENAME_RTLD
#endif
#ifndef _CHERIABI_PATH_RTLD
#define	_CHERIABI_PATH_RTLD	"/libexec/" _CHERIABI_BASENAME_RTLD
#endif
#ifndef _COMPAT32_PATH_RTLD
#define	_COMPAT32_PATH_RTLD	"/libexec/" _COMPAT32_BASENAME_RTLD
#endif
#ifndef _COMPAT64_PATH_RTLD
#define	_COMPAT64_PATH_RTLD	"/libexec/" _COMPAT64_BASENAME_RTLD
#endif

#ifndef STANDARD_LIBRARY_PATH
#define	STANDARD_LIBRARY_PATH	"/lib/casper:/lib:/usr/lib"
#endif

#ifndef LD_
#define	LD_			"LD_"
#endif

#ifdef IN_RTLD
extern const char *ld_elf_hints_default;
extern const char *ld_path_libmap_conf;
extern const char *ld_path_rtld;
extern const char *ld_standard_library_path;
extern const char *ld_env_prefix;
#endif

#endif /* _RTLD_PATHS_H */
