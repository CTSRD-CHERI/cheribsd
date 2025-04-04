/*	$NetBSD: am7990var.h,v 1.23 2005/12/11 12:21:25 christos Exp $	*/

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 1997, 1998 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Charles M. Hannum and by Jason R. Thorpe of the Numerical Aerospace
 * Simulation Facility, NASA Ames Research Center.
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */


#ifndef _DEV_LE_AM7990VAR_H_
#define	_DEV_LE_AM7990VAR_H_

/*
 * Ethernet software status per device.
 *
 * NOTE: this structure MUST be the first element in machine-dependent
 * le_softc structures!  This is designed SPECIFICALLY to make it possible
 * to simply cast a "void *" to "struct le_softc *" or to
 * "struct am7990_softc *".  Among other things, this saves a lot of hair
 * in the interrupt handlers.
 */
struct am7990_softc {
	struct lance_softc lsc;
} __no_subobject_bounds;

int	am7990_config(struct am7990_softc *, const char*, int);
void	am7990_detach(struct am7990_softc *);
void	am7990_intr(void *);

#endif /* !_DEV_LE_AM7990VAR_H_ */
// CHERI CHANGES START
// {
//   "updated": 20230509,
//   "target_type": "header",
//   "changes_purecap": [
//     "subobject_bounds"
//   ]
// }
// CHERI CHANGES END
