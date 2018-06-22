/*	$NetBSD: ixp425_intr.h,v 1.6 2005/12/24 20:06:52 perry Exp $	*/

/*-
 * SPDX-License-Identifier: BSD-4-Clause
 *
 * Copyright (c) 2001, 2002 Wasabi Systems, Inc.
 * All rights reserved.
 *
 * Written by Jason R. Thorpe for Wasabi Systems, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed for the NetBSD Project by
 *	Wasabi Systems, Inc.
 * 4. The name of Wasabi Systems, Inc. may not be used to endorse
 *    or promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY WASABI SYSTEMS, INC. ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL WASABI SYSTEMS, INC
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 *
 */

#ifndef _IXP425_INTR_H_
#define _IXP425_INTR_H_

#define	ARM_IRQ_HANDLER	_C_LABEL(ixp425_intr_dispatch)

#ifndef _LOCORE

#include <machine/armreg.h>

#include <arm/xscale/ixp425/ixp425reg.h>

#define IXPREG(reg)     *((__volatile u_int32_t*) (reg))

void ixp425_do_pending(void);

extern __volatile uint32_t intr_enabled;
extern uint32_t intr_steer;

static __inline void __attribute__((__unused__))
ixp425_set_intrmask(void)
{
	IXPREG(IXP425_INT_ENABLE) = intr_enabled & IXP425_INT_HWMASK;
}

static __inline void
ixp425_set_intrsteer(void)
{
	IXPREG(IXP425_INT_SELECT) = intr_steer & IXP425_INT_HWMASK;
}

extern __volatile uint32_t intr_enabled2;
extern uint32_t intr_steer2;

static __inline void __attribute__((__unused__))
ixp435_set_intrmask(void)
{
	IXPREG(IXP435_INT_ENABLE2) = intr_enabled2 & IXP435_INT_HWMASK;
}

static __inline void
ixp435_set_intrsteer(void)
{
	IXPREG(IXP435_INT_SELECT2) = intr_steer2 & IXP435_INT_HWMASK;
}

#endif /* _LOCORE */

#endif /* _IXP425_INTR_H_ */
