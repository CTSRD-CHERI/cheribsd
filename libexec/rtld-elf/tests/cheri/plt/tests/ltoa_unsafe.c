/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2018 Alex Richadson <arichardson@FreeBSD.org>
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
#include <stdbool.h>
#include "plt_test.h"


const char* ltoa_unsafe(long n, int base) {
	if (base < 2 || base > 16) {
		__builtin_trap();
	}
	static const char digits[] = "0123456789abcdef";
	// worst case (binary): 8 chars per byte + null + sign + 2 bytes prefix
	const int BUFFER_SIZE = sizeof(long) * 8 + 1 + 1 + 2;
	static char buf[BUFFER_SIZE];
	char *start = buf + BUFFER_SIZE - 1;
	bool negative = n < 0;
	if (negative)
		n = -n;
	*start = '\0';
	do {
		*--start = (char)(digits[n % base]);
		n /= base;
	} while (n);
	// Add 0x/0o/0b prefix
	if (base == 2) {
		*--start = 'b';
		*--start = '0';
	} else if (base == 8) {
		*--start = 'o';
		*--start = '0';
	} else if (base == 16) {
		*--start = 'x';
		*--start = '0';
	}
	if (negative) {
		*--start = '-';
	}
	return start;
}
