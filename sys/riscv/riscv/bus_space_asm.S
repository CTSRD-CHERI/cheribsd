/*-
 * Copyright (c) 2016-2020 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * Portions of this software were developed by SRI International and the
 * University of Cambridge Computer Laboratory under DARPA/AFRL contract
 * FA8750-10-C-0237 ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Portions of this software were developed by the University of Cambridge
 * Computer Laboratory as part of the CTSRD Project, with support from the
 * UK Higher Education Innovation Fund (HEIF).
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

__FBSDID("$FreeBSD$");

#ifdef __CHERI_PURE_CAPABILITY__
ENTRY(generic_bs_r_1)
	cincoffset ca3, ca1, a2
	clbu	a0, 0(ca3)
	cret
END(generic_bs_r_1)

ENTRY(generic_bs_r_2)
	cincoffset ca3, ca1, a2
	clhu	a0, 0(ca3)
	cret
END(generic_bs_r_2)

ENTRY(generic_bs_r_4)
	cincoffset ca3, ca1, a2
	clw	a0, 0(ca3)
	cret
END(generic_bs_r_4)

ENTRY(generic_bs_r_8)
	cincoffset ca3, ca1, a2
	cld	a0, 0(ca3)
	cret
END(generic_bs_r_8)

ENTRY(generic_bs_w_1)
	cincoffset ca4, ca1, a2
	csb	a3, 0(ca4)
	cret
END(generic_bs_w_1)

ENTRY(generic_bs_w_2)
	cincoffset ca4, ca1, a2
	csh	a3, 0(ca4)
	cret
END(generic_bs_w_2)

ENTRY(generic_bs_w_4)
	cincoffset ca4, ca1, a2
	csw	a3, 0(ca4)
	cret
END(generic_bs_w_4)

ENTRY(generic_bs_w_8)
	cincoffset ca4, ca1, a2
	csd	a3, 0(ca4)
	cret
END(generic_bs_w_8)
#else
ENTRY(generic_bs_r_1)
	add	a3, a1, a2
	lbu	a0, 0(a3)
	ret
END(generic_bs_r_1)

ENTRY(generic_bs_r_2)
	add	a3, a1, a2
	lhu	a0, 0(a3)
	ret
END(generic_bs_r_2)

ENTRY(generic_bs_r_4)
	add	a3, a1, a2
	lw	a0, 0(a3)
	ret
END(generic_bs_r_4)

ENTRY(generic_bs_r_8)
	add	a3, a1, a2
	ld	a0, 0(a3)
	ret
END(generic_bs_r_8)

ENTRY(generic_bs_w_1)
	add	a4, a1, a2
	sb	a3, 0(a4)
	ret
END(generic_bs_w_1)

ENTRY(generic_bs_w_2)
	add	a4, a1, a2
	sh	a3, 0(a4)
	ret
END(generic_bs_w_2)

ENTRY(generic_bs_w_4)
	add	a4, a1, a2
	sw	a3, 0(a4)
	ret
END(generic_bs_w_4)

ENTRY(generic_bs_w_8)
	add	a4, a1, a2
	sd	a3, 0(a4)
	ret
END(generic_bs_w_8)
#endif

/*
 * CHERI CHANGES START
 * {
 *   "updated": 20221205,
 *   "target_type": "kernel",
 *   "changes_purecap": [
 *     "support"
 *   ]
 * }
 * CHERI CHANGES END
 */
