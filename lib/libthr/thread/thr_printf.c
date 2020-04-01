/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2002 Jonathan Mini <mini@freebsd.org>
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
/*
 * CHERI CHANGES START
 * {
 *   "updated": 20181114,
 *   "target_type": "lib",
 *   "changes": [
 *     "support"
 *   ],
 *   "change_comment": "printf"
 * }
 * CHERI CHANGES END
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "libc_private.h"
#include "thr_private.h"

static void	pchar(int fd, char c);
static void	pstr(int fd, const char *s);

/*
 * Write formatted output to stdout, in a thread-safe manner.
 *
 * Recognises the following conversions:
 *	%c	-> char
 *	%d	-> signed int (base 10)
 *	%s	-> string
 *	%u	-> unsigned int (base 10)
 *	%x	-> unsigned int (base 16)
 *	%p	-> unsigned int (base 16)
 */
void
_thread_fdprintf(int fd, const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	_thread_vprintf(fd, fmt, ap);
	va_end(ap);
}

void
_thread_vfdprintf(int fd, const char *fmt, va_list ap)
{
	static const char digits[16] = "0123456789abcdef";
	/* XXX_AR: we should print capabilities not vaddr_t -> increase size */
	char buf[40];
	char *s;
	uint64_t r, u;
	int c;
	int64_t d;
	int islong, isalt;
	int isptr;
	void* pointer;

	while ((c = *fmt++)) {
		isalt = 0;
		islong = 0;
		isptr = 0;
		if (c == '%') {
next:			c = *fmt++;
			if (c == '\0')
				return;
			switch (c) {
			case '#':
				isalt = 1;
				goto next;
			case 'c':
				pchar(fd, va_arg(ap, int));
				continue;
			case 's':
				pstr(fd, va_arg(ap, char *));
				continue;
			case 'l':
				islong = 1;
				goto next;
			case 'p':
				isptr = 1;
				islong = 1;
				/* FALLTHROUGH */
			case 'd':
			case 'u':
			case 'x':
				if ((c == 'x' && isalt) || isptr)
					pstr(fd, "0x");
				r = ((c == 'u') || (c == 'd')) ? 10 : 16;
				if (c == 'd') {
					if (islong)
						d = va_arg(ap, int64_t);
					else
						d = va_arg(ap, int);
					if (d < 0) {
						pchar(fd, '-');
						u = (uint64_t)(d * -1);
					} else
						u = (uint64_t)d;
				} else {
					if (isptr) {
						pointer = va_arg(ap, void*);
						u = (vaddr_t)pointer;
					} else if (islong) {
						u = va_arg(ap, uint64_t);
					} else {
						u = va_arg(ap, unsigned);
					}
				}
				s = buf;
				do {
					*s++ = digits[u % r];
				} while (u /= r);
				while (--s >= buf)
					pchar(fd, *s);
				continue;
			}
		}
		pchar(fd, c);
	}
}

/*
 * Write a single character to stdout, in a thread-safe manner.
 */
static void
pchar(int fd, char c)
{

	__sys_write(fd, &c, 1);
}

/*
 * Write a string to stdout, in a thread-safe manner.
 */
static void
pstr(int fd, const char *s)
{

	__sys_write(fd, s, strlen(s));
}

#error "Should no longer be used"
