/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Konrad Witaszczyk
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) under Office of
 * Naval Research (ONR) Contract No. N00014-22-1-2463 ("SoftWare Integrated
 * with Secure Hardware (SWISH)").
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

#ifndef _SYS__PCPU_H_
#define	_SYS__PCPU_H_

#ifdef PCPU_FUNCS
#ifdef __CHERI_PURE_CAPABILITY__
#define	_PCPU_PTR(pcpu, type, _member)					\
	cheri_setboundsexact((type *)(void *)&pcpu->pc ## _member,	\
	    CHERI_REPRESENTABLE_LENGTH(sizeof(pcpu->pc ## _member)))
#else
#define	_PCPU_PTR(pcpu, type, _member)					\
	((type *)(void *)&pcpu->pc ## _member)
#endif

#define	PCPU_DECLARE(type, member)					\
	type *__pcpu_ptr_ ## member(struct pcpu *pcpu);			\
	type *__pcpu_id_ptr_ ## member(int id)

#define	PCPU_DEFINE(type, member)					\
	type *								\
	__pcpu_ptr_ ## member(struct pcpu *pcpu)			\
	{								\
									\
		return (_PCPU_PTR(pcpu, type, _ ## member));		\
	}								\
	type *								\
	__pcpu_id_ptr_ ## member(int id)				\
	{								\
									\
		return (_PCPU_PTR(pcpu_find(id), type, _ ## member));	\
	}
#else
#define	PCPU_DECLARE(type, member)
#define	PCPU_DEFINE(type, member)
#endif

#endif /* !_SYS__PCPU_H_*/
