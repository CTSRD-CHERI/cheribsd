/*-
* SPDX-License-Identifier: BSD-2-Clause
*
* Copyright (c) 2019 (holder)
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

#include <machine/asm.h>

/*
 * This must be stackless, as it is called very early in boot.
 *
 * XREF sys/mips/beri/beri_mp.h beri_get_* functions.
 */
LEAF(platform_processor_id)

	# t1: core index
	mfc0	t0, $15, 6
	andi	t1, t0, 0xFFFF

	# t2: number of threads per core
	srl	t2, t1, 16
	daddiu	t2, t2, 1

	# t3: thread index
	mfc0	t3, $15, 7
	andi	t3, t3, 0xFFFF

	# processor ID is coreix * nthreads + threadix
	mult	t1, t2
	mflo	v0
	jr ra
	daddu	v0, v0, t3

END(platform_processor_id)
