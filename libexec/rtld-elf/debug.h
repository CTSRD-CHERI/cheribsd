/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright 1996-1998 John D. Polstra.
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

/*
 * Support for printing debugging messages.
 */

#ifndef DEBUG_H
#define DEBUG_H 1

#include <sys/cdefs.h>
/* assert() is always enabled. For expensive checks use dbg_assert() instead. */
#undef NDEBUG
#include <assert.h>
#include <string.h>
#include "rtld_printf.h"

__BEGIN_DECLS
enum RtldDebugCategory {
	RTLD_DBG_NO_CATEGORY = 1 << 0,
	RTLD_DBG_RELOC = 1 << 1,
	RTLD_DBG_RELOC_SELF = 1 << 2,
	RTLD_DBG_PLT = 1 << 3,
	RTLD_DBG_RELOC_STATS = 1 << 4,

	RTLD_DBG_CHERI = 1 << 5,
	RTLD_DBG_CHERI_PLT = 1 << 6,
	RTLD_DBG_CHERI_PLT_VERBOSE = 1 << 7,

	RTLD_DBG_SYMLOOKUP = 1 << 8,

	RTLD_DBG_LAST = RTLD_DBG_SYMLOOKUP,
	RTLD_DBG_ALL = (RTLD_DBG_LAST << 1) - 1
};
void debug_printf(enum RtldDebugCategory cat, const char *, ...) __printflike(2, 3);
extern int debug;
__END_DECLS

#ifndef NO_LD_DEBUG
#define dbg(...)	debug_printf(RTLD_DBG_NO_CATEGORY, __VA_ARGS__)
#define dbg_cat(category, ...)	debug_printf(RTLD_DBG_ ## category, __VA_ARGS__)
#define dbg_assert(cond)	assert(cond)
#else
#define dbg(...)	((void) 0)
#define dbg_cat(category, ...)	((void) 0)
#define dbg_assert(cond)	((void) 0)
#endif
#define dbg_cheri(...)			dbg_cat(CHERI, __VA_ARGS__)
#define dbg_cheri_plt(...)		dbg_cat(CHERI_PLT, __VA_ARGS__)
#define dbg_cheri_plt_verbose(...)	dbg_cat(CHERI_PLT_VERBOSE, __VA_ARGS__)


#ifdef __CHERI_PURE_CAPABILITY__
#define _MYNAME	"ld-cheri-elf.so.1"
#elif !defined(COMPAT_32BIT)
#define _MYNAME	"ld-elf.so.1"
#else
#define _MYNAME	"ld-elf32.so.1"
#endif

/* assert() is always enabled. For expensive checks use dbg_assert() instead. */

#define msg(s)		rtld_write(STDERR_FILENO, s, strlen(s))
#define trace()		msg(_MYNAME ": " __XSTRING(__LINE__) "\n")


#endif /* DEBUG_H */
