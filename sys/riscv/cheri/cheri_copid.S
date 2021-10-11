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

#include <sys/errno.h>
#include <machine/asm.h>
#include <machine/cherireg.h>
#include <machine/switcher.h>

#define	idc ct6
.option capmode

/*
 *
 */
.text
.globl _C_LABEL(switcher_cogetpid)
_C_LABEL(switcher_cogetpid):
    clc ct6, SCB_CALLER_SCB(idc)
	clw a0, SCB_PID(ct6)
	cmove ct6, cnull
	li t0, 0
	cret
.globl _C_LABEL(eswitcher_cogetpid)
_C_LABEL(eswitcher_cogetpid):

/*
 *
 */
.text
.globl _C_LABEL(switcher_cogettid)
_C_LABEL(switcher_cogettid):
    clc ct6, SCB_CALLER_SCB(idc)
	clw a0, SCB_TID(ct6)
	cmove ct6, cnull
	li t0, 0
	cret
.globl _C_LABEL(eswitcher_cogettid)
_C_LABEL(eswitcher_cogettid):

.data
.globl szswitcher_cogetpid
szswitcher_cogetpid:
.long eswitcher_cogetpid-switcher_cogetpid

.global szswitcher_cogettid
szswitcher_cogettid:
.long eswitcher_cogettid-switcher_cogettid