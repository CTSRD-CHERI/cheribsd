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

extern void debug_printf(const char *, ...) __printflike(1, 2);
extern int debug;

#ifdef DEBUG
#define dbg(...)	debug_printf(__VA_ARGS__)
#define dbg_assert(cond)	assert(cond)
#else
#define dbg(...)	((void) 0)
#define dbg_assert(cond)	((void) 0)
#endif

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
