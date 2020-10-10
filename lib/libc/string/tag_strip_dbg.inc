/*-
 * Copyright 2019-2020 Alex Richardson <arichardson@FreeBSD.org>
 *
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

/*
 * This file implements a debug check to find memcpy() calls to unaligned
 * destinations that would result in tag stripping even though the user
 * intended to retain tags. It has been extremely useful in the past to detect
 * incorrect casts or missing _Alignas annotations in certain software.
 *
 * However, we can't assume that any tag-stripping memcpy() is always a real
 * bug: It can also happen when copying large stack-allocated unions that were
 * partially initialized or structures with a large NUL-terminated char[].
 *
 * To simplify debugging this warning message can be turned into an abort()
 * by setting the CHERI_ABORT_ON_TAG_STRIPPING_COPY environment variable.
 *
 */

#if __has_feature(capabilities)
extern ssize_t __sys_write(int, const void *, size_t);
#define write_to_stderr(str) __sys_write(2, (str), __builtin_strlen(str))
extern int __sysctlbyname(const char *name, size_t namelen, void *oldp,
    size_t *oldlenp, const void *newp, size_t newlen);
#define ABORT_ON_TAG_LOSS_SYSCTL "debug.cheri.abort_on_memcpy_tag_loss"
#define ABORT_ON_TAG_LOSS_ENVVAR "CHERI_ABORT_ON_TAG_STRIPPING_COPY"

static void
handle_untagged_copy(const void *__capability taggedcap, vaddr_t src_addr,
    vaddr_t dst_addr, size_t offset)
{
	char errmsg_buffer[1024];
	/* XXXAR: These functions do not exist yet... */
	snprintf(errmsg_buffer, sizeof(errmsg_buffer),
	    "%s: Attempting to copy a tagged capability (%#p) from 0x%jx to "
	    "underaligned destination 0x%jx. Use memmove_nocap()/memcpy_nocap()"
	    " if you intended to strip tags.\n", getprogname(),
#ifdef __CHERI_PURE_CAPABILITY__
	    taggedcap,
#else
	    /* Can't use capabilities in fprintf in hybrid mode */
	    (void *)(uintptr_t)(__cheri_addr vaddr_t)(taggedcap),
#endif
	    (uintmax_t)(src_addr + offset), (uintmax_t)(dst_addr + offset));
	write_to_stderr(errmsg_buffer);
	/* TODO: allow overriding the behaviour with a function pointer? */
	static int abort_on_tag_loss = -1;
	if (abort_on_tag_loss == -1) {
		const char *from_env = getenv(ABORT_ON_TAG_LOSS_ENVVAR);
		if (from_env != NULL) {
			/* Enabled unless empty or starts with zero. */
			if (*from_env == '\0' || *from_env == '0')
				abort_on_tag_loss = 0;
			else
				abort_on_tag_loss = 1;
		}
	}
	if (abort_on_tag_loss == -1) {
		/* If the env var is not set fall back to the global sysctl */
		size_t olen = sizeof(abort_on_tag_loss);
		if (__sysctlbyname(ABORT_ON_TAG_LOSS_SYSCTL,
		    __builtin_strlen(ABORT_ON_TAG_LOSS_SYSCTL),
		    &abort_on_tag_loss, &olen, NULL, 0) == -1) {
			write_to_stderr(
			    "ERROR: could not determine whether "
			    "tag stripping memcpy should abort. Assuming it "
			    "shouldn't.\n");
			abort_on_tag_loss = 0;
		}
	}
	if (abort_on_tag_loss) {
		write_to_stderr("Note: accidental tag stripping is fatal, set "
				"the " ABORT_ON_TAG_LOSS_ENVVAR " environment "
				"variable or the " ABORT_ON_TAG_LOSS_SYSCTL
				" sysctl to 0 to disable this behaviour.\n");
		abort();
	}
}

/*
 * Check that we aren't attempting to copy a capabilities to a misaligned
 * destination (which would strip the tag bit instead of raising an exception).
 */
static void
check_no_tagged_capabilities_in_copy(
    const char *__CAP src, const char *__CAP dst, size_t len)
{
	static int error_logged = 0;

	if (len < sizeof(void *__capability)) {
		return; /* Return early if copying less than a capability. */
	}
	if (error_logged) {
		return; /* Only report one error and skip checks afterwards. */
	}
	const vaddr_t src_addr = (__cheri_addr vaddr_t)src;
	const vaddr_t to_first_cap =
	    __builtin_align_up(src_addr, sizeof(void *__capability)) - src_addr;
	const vaddr_t last_clc_offset = len - sizeof(void *__capability);
	for (vaddr_t offset = to_first_cap; offset <= last_clc_offset;
	     offset += sizeof(void *__capability)) {
		const void *__capability const *__CAP aligned_src =
		    (const void *__capability const *__CAP)(src + offset);
		if (__predict_true(!__builtin_cheri_tag_get(*aligned_src))) {
			continue; /* untagged values are fine */
		}

		if (error_logged)
			break;
		error_logged = 1;
		/* Got a tagged value, this is always an error! */
		handle_untagged_copy(
		    *aligned_src, src_addr, (__cheri_addr vaddr_t)dst, offset);
	}
}
#endif
