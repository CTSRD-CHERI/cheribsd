/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2018 SRI International
 * Copyright (c) 2020-2022 Microsoft Corp.
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

#ifndef LIBCHERI_CAPREVOKE_H
#define LIBCHERI_CAPREVOKE_H

#include <stddef.h>
#include <cheri/revoke.h>

/*
 * The per-object interface protects against concurrent mutation and both
 * intra- and inter-epoch double-frees.
 */
int caprev_shadow_nomap_set_len(ptraddr_t sbase, uint64_t * __capability sb,
    ptraddr_t ob, size_t len, void * __capability user_obj);

void caprev_shadow_nomap_clear_len(ptraddr_t sbase, uint64_t * __capability sb,
    ptraddr_t ob, size_t len);

int caprev_shadow_nomap_set(ptraddr_t sbase, uint64_t * __capability sb,
    void * __capability priv_obj, void * __capability user_obj);

void caprev_shadow_nomap_clear(ptraddr_t sbase, uint64_t * __capability sb,
    void * __capability obj);

/*
 * For already interlocked allocators where these protections are not
 * necessary, we also export a "raw" interface, which is especially useful
 * when objects can coalesce in quarantine prior to being staged for
 * revocation, as fewer bitmap writes are necessary.
 */

void caprev_shadow_nomap_set_raw(ptraddr_t sbase, uint64_t * __capability sb,
    ptraddr_t heap_start, ptraddr_t heap_end);

void caprev_shadow_nomap_clear_raw(ptraddr_t sbase, uint64_t * __capability sb,
    ptraddr_t heap_start, ptraddr_t heap_end);

/* Utility functions for testing */
void caprev_shadow_nomap_offsets(
    ptraddr_t ob, size_t len, ptrdiff_t *fwo, ptrdiff_t *lwo);

void caprev_shadow_nomap_masks(
    ptraddr_t ob, size_t len, uint64_t *fwm, uint64_t *lwm);

#endif
