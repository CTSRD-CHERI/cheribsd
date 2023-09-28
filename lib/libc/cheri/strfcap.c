/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2021 SRI International
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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

#include <sys/cdefs.h>
#include <sys/param.h>

#include <cheri/cheric.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static ssize_t
_strfcap(char * __restrict buf, size_t maxsize, const char * __restrict format,
    uintcap_t cap, bool tag)
{
	char tmp[(sizeof(void * __capability) * 2) + 1], fmt[9], *fmtp;
	const char *percent, *opt_start = NULL;
	char number_fmt, *orig_buf;
	size_t size = 0;
	long number;
	int width = 1, precision = 1;
	bool alt = false, right_pad = false;
	bool comma, have_attributes;
#ifdef CHERI_FLAGS_CAP_MODE
	bool capmode = false;
#endif

#define	_OUT(str, len)							\
	do {								\
		if (size < maxsize)					\
			memcpy(buf, (str), MIN((len), maxsize - size));	\
		buf += (len);						\
		size += (len);						\
	} while(0)

#define	FLUSH_OPT()							\
	do {								\
		if (opt_start != NULL) {				\
			_OUT(opt_start, percent - opt_start);		\
			opt_start = NULL;				\
		}							\
	} while (0)

#define OUT(str)							\
	do {								\
		FLUSH_OPT();						\
		_OUT((str), strlen(str));				\
	} while (0)

	orig_buf = buf;
	have_attributes = !tag || cheri_getsealed(cap);
#ifdef CHERI_FLAGS_CAP_MODE
	if ((cheri_getperm(cap) & CHERI_PERM_EXECUTE) != 0 &&
	    cheri_getflags(cap) == CHERI_FLAGS_CAP_MODE) {
		capmode = true;
		have_attributes = true;
	}
#endif

	for (; *format; ++format) {
		if (*format != '%') {
			if (size < maxsize)
				*buf = *format;
			buf++;
			size++;
			continue;
		}

		number_fmt = 'd';
		percent = format;
more_spec:
		switch (*++format) {
		case '\0':
			*orig_buf = '\0';
			return (-1);
			continue;

		case '1': case '2': case '3': case '4': case '5':
		case '6': case '7': case '8': case '9':
			width = *format - '0';
			while (*++format >= '0' && *format <= '9')
				width = (width * 10) + *format - '0';
			--format;
			goto more_spec;

		case '.':
			precision = 0;
			while (*++format >= '0' && *format <= '9')
				precision = (precision * 10) + *format - '0';
			--format;
			goto more_spec;

		case '-':
			right_pad = true;
			goto more_spec;

		case 'a':
			number = cheri_getaddress(cap);
			break;

		case 'A':
			if (have_attributes) {
				OUT("(");
				comma = false;
				if (!tag) {
					OUT("invalid");
					comma = true;
				}
				switch cheri_gettype(cap) {
				case CHERI_OTYPE_UNSEALED:
					break;
				case CHERI_OTYPE_SENTRY:
					if (comma)
						OUT(",");
					OUT("sentry");
					comma = true;
					break;
				default:
					if (comma)
						OUT(",");
					OUT("sealed");
					comma = true;
					break;
				}
#ifdef CHERI_FLAGS_CAP_MODE
				if (capmode) {
					if (comma)
						OUT(",");
					OUT("capmode");
				}
#endif
				OUT(")");
			} else
				opt_start = NULL;
			continue;

		case 'b':
			number = cheri_getbase(cap);
			break;

		case 'B':
			FLUSH_OPT();
			for (char *bytes = (char *)&cap;
			    bytes < (char *)&cap + sizeof(cap); bytes++) {
				snprintf(tmp, sizeof(tmp), "%02hhx", *bytes);
				_OUT(tmp, 2);
			}
			continue;

		case 'C': {
			size_t ret;

			FLUSH_OPT();
			if (cheri_is_null_derived(cap)) {
				alt = true;
				number_fmt = 'x';
				number = cheri_getaddress(cap);
				break;
			}
			ret = _strfcap(buf,
			    maxsize > size ? maxsize - size : 0,
			    "%#xa [%P,%#xb-%#xt]%? %A", cap, tag);
			buf += ret;
			size += ret;
			continue;
		}

		case 'l':
			number = cheri_getlength(cap);
			break;

		case 'o':
			number = cheri_getoffset(cap);
			break;

		case 'p':
			number = cheri_getperm(cap);
			break;

		case 'P':
			if (cheri_getperm(cap) & CHERI_PERM_LOAD)
				OUT("r");
			if (cheri_getperm(cap) & CHERI_PERM_STORE)
				OUT("w");
			if (cheri_getperm(cap) & CHERI_PERM_EXECUTE)
				OUT("x");
			if (cheri_getperm(cap) & CHERI_PERM_LOAD_CAP)
				OUT("R");
			if (cheri_getperm(cap) & CHERI_PERM_STORE_CAP)
				OUT("W");
#ifdef CHERI_PERM_EXECUTIVE
			if (cheri_getperm(cap) & CHERI_PERM_EXECUTIVE)
				OUT("E");
#endif
			continue;

		case 's':
			number = cheri_gettype(cap);
			break;

		case 'S':
			switch cheri_gettype(cap) {
			case CHERI_OTYPE_UNSEALED:
				OUT("<unsealed>");
				continue;
			case CHERI_OTYPE_SENTRY:
				OUT("<sentry>");
				continue;
			}
			number = cheri_gettype(cap);
			break;

		case 't':
			number = cheri_gettop(cap);
			break;

		case 'T':
			tag = true;
			continue;

		case 'v':
			number = cheri_gettag(cap);
			break;

		case 'x':
		case 'X':
			number_fmt = *format;
			goto more_spec;

		case '?':
			opt_start = format + 1;
			while(*(format + 1) != '\0' && *(format + 1) != '%')
				format++;
			if (opt_start == format + 1)
				opt_start = NULL;	/* or error? */
			continue;

		case '%':
			OUT("%");
			continue;

		case '#':
			alt = true;
			goto more_spec;
		}

		/* If we're here, we're rendering a number. */
		fmtp = fmt;
		*fmtp++ = '%';
		if (alt)
			*fmtp++ = '#';
		if (right_pad)
			*fmtp++ = '-';
		*fmtp++ = '*';
		*fmtp++ = '.';
		*fmtp++ = '*';
		*fmtp++ = 'l';
		*fmtp++ = number_fmt;
		*fmtp = '\0';
		snprintf(tmp, sizeof(tmp), fmt, width, precision, number);
		OUT(tmp);
	}

	orig_buf[MIN(size, maxsize - 1)] = '\0';
	return (size);
}

ssize_t
strfcap(char * __restrict buf, size_t maxsize, const char * __restrict format,
    uintcap_t cap)
{
	return (_strfcap(buf, maxsize, format, cap, cheri_gettag(cap)));
}
