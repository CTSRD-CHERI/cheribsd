/*-
 * Copyright 2011 Konstantin Belousov <kib@FreeBSD.org>.
 * Copyright 2018 Alex Richardson <arichardson@FreeBSD.org>
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

#ifndef SIMPLE_PRINTF_H
#define SIMPLE_PRINTF_H 1

#include <sys/cdefs.h>
#include <stdarg.h>
#include <unistd.h>

#ifndef SIMPLE_PRINTF_PREFIX
#error "You must define SIMPLE_PRINTF_PREFIX"
#endif

#define SIMPLE_PRINTF_FN(x)	__CONCAT(__CONCAT(SIMPLE_PRINTF_PREFIX, _), x)

__BEGIN_DECLS

int SIMPLE_PRINTF_FN(snprintf)(char *buf, size_t bufsize, const char *fmt, ...)
    __printflike(3, 4);
int SIMPLE_PRINTF_FN(vsnprintf)(char *buf, size_t bufsize, const char *fmt,
    va_list ap);
int SIMPLE_PRINTF_FN(vfdprintf)(int fd, const char *fmt, va_list ap);
int SIMPLE_PRINTF_FN(vprintf)(const char *fmt, va_list ap);
int SIMPLE_PRINTF_FN(fdprintf)(int fd, const char *fmt, ...)
    __printflike(2, 3);
int SIMPLE_PRINTF_FN(fdprintfx)(int fd, const char *fmt, ...);
int SIMPLE_PRINTF_FN(printf)(const char *fmt, ...) __printflike(1, 2);

void SIMPLE_PRINTF_FN(fdputstr)(int fd, const char *str);
void SIMPLE_PRINTF_FN(putstr)(const char *str);
void SIMPLE_PRINTF_FN(fdputchar)(int fd, int c);
void SIMPLE_PRINTF_FN(putchar)(int c);

ssize_t SIMPLE_PRINTF_FN(write)(int fd, const void *buf, size_t count) __hidden;

__END_DECLS

#endif
