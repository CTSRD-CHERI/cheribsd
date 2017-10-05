/*-
 * Copyright (c) 2017 SRI International
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
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

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/syscall.h>

#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include "libc_private.h"

int
syscall(int number, ...)
{
	va_list ap;
	int64_t a0, a1, a2, a3, a4, a5, a6, a7;
	intptr_t p0, p1, p2, p3, p4, p5, p6, p7;

	a0 = a1 = a2 = a3 = a4 = a5 = a6 = a7 = 0;
	p0 = p1 = p2 = p3 = p4 = p5 = p6 = p7 = 0;

	va_start(ap, number);
	switch (number) {
		/* No arguments */
		case SYS_fork:
		case SYS_getpid:
			break;

		/* 1 Pointer */
		case SYS_sigreturn:
			p0 = va_arg(ap, intptr_t);
			break;

		case SYS_write:
			a0 = va_arg(ap, int);
			p0 = va_arg(ap, intptr_t);
			a1 = va_arg(ap, size_t);
			break;

		default:
			return (ENOSYS);
	}

	return (__syscall_by_token(__systokens[number], a0, a1, a2, a3, a4, a5,
	    a6, a7, p0, p1, p2, p3, p4, p5, p6, p7));
}
