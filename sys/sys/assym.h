/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1999 Marcel Moolenaar
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer 
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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

#ifndef _SYS_ASSYM_H_
#define	_SYS_ASSYM_H_

#define	ASSYM_BIAS		0x100	/* avoid zero-length arrays */
#define	ASSYM_ABS(value)	((value) < 0 ? -((value) + 1) + 1ULL : (value))

/*
 * The choice of "y" is to ensure that it sorts after "sign" like the "w"
 * that was once here, when we exported 16 bits at a time, did.  I'm so
 * sorry you're having to think about this.
 */

#define	ASSYM(name, value)                                                        \
char name ## sign[((value) < 0 ? 1 : 0) + ASSYM_BIAS];                            \
char name ## y0[((ASSYM_ABS(value) & 0x00000000000000FFULL)      ) + ASSYM_BIAS]; \
char name ## y1[((ASSYM_ABS(value) & 0x000000000000FF00ULL) >>  8) + ASSYM_BIAS]; \
char name ## y2[((ASSYM_ABS(value) & 0x0000000000FF0000ULL) >> 16) + ASSYM_BIAS]; \
char name ## y3[((ASSYM_ABS(value) & 0x00000000FF000000ULL) >> 24) + ASSYM_BIAS]; \
char name ## y4[((ASSYM_ABS(value) & 0x000000FF00000000ULL) >> 32) + ASSYM_BIAS]; \
char name ## y5[((ASSYM_ABS(value) & 0x0000FF0000000000ULL) >> 40) + ASSYM_BIAS]; \
char name ## y6[((ASSYM_ABS(value) & 0x00FF000000000000ULL) >> 48) + ASSYM_BIAS]; \
char name ## y7[((ASSYM_ABS(value) & 0xFF00000000000000ULL) >> 56) + ASSYM_BIAS]

/* char name ## _datatype_ ## STRINGIFY(typeof(((struct parenttype *)(0x0))-> name)) [1]; */
#ifdef OFFSET_TEST
#define OFFSET_CTASSERT CTASSERT
#else
#define OFFSET_CTASSERT(...)
#endif

#define OFFSYM(name, parenttype, datatype)				\
char __assym_offset__ ## parenttype ## __ ## name ## __ ## datatype [offsetof(struct parenttype, name)]; \
CTASSERT(__builtin_types_compatible_p(__typeof(((struct parenttype *)(0x0))-> name), datatype)); \
OFFSET_CTASSERT(offsetof(struct parenttype, name) == offsetof(struct parenttype ## _lite, name))

#endif /* !_SYS_ASSYM_H_ */
