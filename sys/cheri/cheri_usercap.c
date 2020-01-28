/*-
 * Copyright (c) 2011-2017 Robert N. M. Watson
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
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

#include <sys/param.h>
#include <sys/systm.h>

#include <cheri/cheric.h>

/* Set to -1 to prevent it from being zeroed with the rest of BSS */
void * __capability userspace_cap = (void * __capability)(intcap_t)-1;

/*
 * Build a new userspace capability derived from userspace_cap.
 * The resulting capability may include both read and execute permissions,
 * but not write.
 */
void * __capability
_cheri_capability_build_user_code(uint32_t perms, vaddr_t basep, size_t length,
    off_t off, const char* func, int line)
{

	KASSERT((perms & ~CHERI_CAP_USER_CODE_PERMS) == 0,
	    ("%s:%d: perms %x has permission not in CHERI_CAP_USER_CODE_PERMS %x",
	    func, line, perms, CHERI_CAP_USER_CODE_PERMS));

	return (_cheri_capability_build_user_rwx(
	    perms & CHERI_CAP_USER_CODE_PERMS, basep, length, off, func, line));
}

/*
 * Build a new userspace capability derived from userspace_cap.
 * The resulting capability may include read and write permissions, but
 * not execute.
 */
void * __capability
_cheri_capability_build_user_data(uint32_t perms, vaddr_t basep, size_t length,
    off_t off, const char* func, int line)
{

	KASSERT((perms & ~CHERI_CAP_USER_DATA_PERMS) == 0,
	    ("%s:%d: perms %x has permission not in CHERI_CAP_USER_DATA_PERMS %x",
	    func, line, perms, CHERI_CAP_USER_DATA_PERMS));

	return (_cheri_capability_build_user_rwx(
	    perms & CHERI_CAP_USER_DATA_PERMS, basep, length, off, func, line));
}

/*
 * Build a new userspace capability derived from userspace_cap.
 * The resulting capability may include read, write, and execute permissions.
 *
 * This function violates W^X and its use is discouraged and the reason for
 * use should be documented in a comment when it is used.
 */
void * __capability
_cheri_capability_build_user_rwx(uint32_t perms, vaddr_t basep, size_t length,
    off_t off, const char* func __unused, int line __unused)
{
	void * __capability tmpcap;

	tmpcap = cheri_setoffset(cheri_andperm(cheri_csetbounds(
	    cheri_setoffset(userspace_cap, basep), length), perms), off);

	KASSERT(cheri_getlen(tmpcap) == length,
	    ("%s:%d: Constructed capability has wrong length 0x%zx != 0x%zx: "
	    _CHERI_PRINTF_CAP_FMT, func, line, cheri_getlen(tmpcap), length,
	    _CHERI_PRINTF_CAP_ARG(tmpcap)));

	return (tmpcap);
}
