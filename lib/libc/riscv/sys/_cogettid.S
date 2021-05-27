/*
 * Copyright (c) 2020 Peter S. Blandford-Baker
 * All rights reserved.
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
#include <cheri/cherireg.h>
__FBSDID("$FreeBSD$");
#include "SYS.h"

#define CAP_FRAME_SIZE (15 * CHERICAP_SIZE)
#define FP_SIZE (8)

#if defined(__riscv_float_abi_double)
#define FP_FRAME_SIZE (12 * FP_SIZE)
#else
#define FP_FRAME_SIZE (0)
#endif

#define CINVOKE_FRAME_SIZE (FP_FRAME_SIZE + CAP_FRAME_SIZE)

/*
 * lwpid_t 
 * _cogettid(void *switcher_code, void *target_scb)
 */
ENTRY(_cogettid)

	cincoffsetimm	csp, csp, -CAP_FRAME_SIZE
	csc	cs0,	(0 * CHERICAP_SIZE)(csp)
	csc	cs1,	(1 * CHERICAP_SIZE)(csp)
	csc	cs2,	(2 * CHERICAP_SIZE)(csp)
	csc	cs3,	(3 * CHERICAP_SIZE)(csp)
	csc	cs4,	(4 * CHERICAP_SIZE)(csp)
	csc	cs5,	(5 * CHERICAP_SIZE)(csp)
	csc	cs6,	(6 * CHERICAP_SIZE)(csp)
	csc	cs7,	(7 * CHERICAP_SIZE)(csp)
	csc	cs8,	(8 * CHERICAP_SIZE)(csp)
	csc	cs9,	(9 * CHERICAP_SIZE)(csp)
	csc	cs10,	(10 * CHERICAP_SIZE)(csp)
	csc	cs11,	(11 * CHERICAP_SIZE)(csp)
	csc	cra,	(12 * CHERICAP_SIZE)(csp)
	csc	ctp,	(13 * CHERICAP_SIZE)(csp)
	cspecialr ct1, ddc
	csc	ct1,	(14 * CHERICAP_SIZE)(csp)

#if defined(__riscv_float_abi_double)
	cincoffsetimm	csp, csp, -FP_FRAME_SIZE
	/* Save fp regs */
	cfsd	fs0,	(0 * FP_SIZE)(csp)
	cfsd	fs1,	(1 * FP_SIZE)(csp)
	cfsd	fs2,	(2 * FP_SIZE)(csp)
	cfsd	fs3,	(3 * FP_SIZE)(csp)
	cfsd	fs4,	(4 * FP_SIZE)(csp)
	cfsd	fs5,	(5 * FP_SIZE)(csp)
	cfsd	fs6,	(6 * FP_SIZE)(csp)
	cfsd	fs7,	(7 * FP_SIZE)(csp)
	cfsd	fs8,	(8 * FP_SIZE)(csp)
	cfsd	fs9, 	(9 * FP_SIZE)(csp)
	cfsd	fs10,	(10 * FP_SIZE)(csp)
	cfsd	fs11, 	(11 * FP_SIZE)(csp)
#endif
	cllc cra, 1f
	cinvoke ca0, ca1

1:
#if defined(__riscv_float_abi_double)
	/* Restore fp regs */
	cfld	fs0,	(0 * FP_SIZE)(csp)
	cfld	fs1,	(1 * FP_SIZE)(csp)
	cfld	fs2,	(2 * FP_SIZE)(csp)
	cfld	fs3,	(3 * FP_SIZE)(csp)
	cfld	fs4,	(4 * FP_SIZE)(csp)
	cfld	fs5,	(5 * FP_SIZE)(csp)
	cfld	fs6,	(6 * FP_SIZE)(csp)
	cfld	fs7,	(7 * FP_SIZE)(csp)
	cfld	fs8,	(8 * FP_SIZE)(csp)
	cfld	fs9, 	(9 * FP_SIZE)(csp)
	cfld	fs10,	(10 * FP_SIZE)(csp)
	cfld	fs11, 	(11 * FP_SIZE)(csp)
	cincoffsetimm	csp, csp, FP_FRAME_SIZE
#endif
	/* Restore the (saved) general purpose (i.e. capability) registers and ra */
	clc	cs0, 	(0 * CHERICAP_SIZE)(csp)
	clc	cs1, 	(1 * CHERICAP_SIZE)(csp)
	clc	cs2, 	(2 * CHERICAP_SIZE)(csp)
	clc	cs3, 	(3 * CHERICAP_SIZE)(csp)
	clc	cs4, 	(4 * CHERICAP_SIZE)(csp)
	clc	cs5, 	(5 * CHERICAP_SIZE)(csp)
	clc	cs6, 	(6 * CHERICAP_SIZE)(csp)
	clc	cs7, 	(7 * CHERICAP_SIZE)(csp)
	clc	cs8, 	(8 * CHERICAP_SIZE)(csp)
	clc	cs9, 	(9 * CHERICAP_SIZE)(csp)
	clc	cs10, 	(10 * CHERICAP_SIZE)(csp)
	clc	cs11, 	(11 * CHERICAP_SIZE)(csp)
	clc	cra, 	(12 * CHERICAP_SIZE)(csp)
	clc	ctp, 	(13 * CHERICAP_SIZE)(csp)
	clc	ct1, 	(14 * CHERICAP_SIZE)(csp)
	cspecialw ddc, ct1
	cincoffsetimm	csp, csp, CAP_FRAME_SIZE

	bnez	t0, 2f
	cret
2:
	ASM_LOCAL_TAILCALL(t1, cerror)
END(_cogettid)

