/*-
 * Copyright (c) 2014-2017 Robert N. M. Watson
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

#include <sys/types.h>
#include <sys/stat.h>

#include <cheri/cheri.h>
#include <cheri/cheric.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "libcheri_ccall.h"
#include "libcheri_class.h"
#define CHERI_FD_INTERNAL
#include "libcheri_fd.h"
#include "libcheri_system.h"
#include "libcheri_sandbox.h"

/*
 * This file implements the CHERI 'file descriptor' (fd) class.  Pretty
 * minimalist.
 *
 * XXXRW: This is a slightly risky business, as we're taking capabilities as
 * arguments and casting them back to global pointers that can be passed to
 * the conventional MIPS system-call ABI.  We need to check that the access we
 * then perform on the pointer is authorised by the capability it was derived
 * from (e.g., length, permissions).
 *
 * XXXRW: Right now, no implementation of permission checking narrowing
 * file-descriptor rights, but we will add that once user permissions are
 * supported.  There's some argument we would like to have a larger permission
 * mask than supported by CHERI -- how should we handle that?
 *
 * XXXRW: This raises lots of questions about reference/memory management.
 * For now, define a 'revoke' interface that clears the fd (-1) to prevent new
 * operations from started.  However, this doesn't block waiting on old ones
 * to complete.  Differentiate 'revoke' from 'destroy', the latter of which is
 * safe only once all references have drained.  We rely on the ambient code
 * knowing when it is safe (or perhaps never calling it).
 *
 * XXXRW: Userspace CCall: break out into two files, one for setup, the other
 * for methods?
 */

CHERI_CLASS_DECL(cheri_fd);

__capability vm_offset_t	*cheri_fd_vtable;

/*
 * Data segment for a cheri_fd.
 */
struct cheri_fd {
	struct sandbox_object	*cf_sbop; /* Corresponding sandbox object. */
	int			 cf_fd;	  /* Underlying file descriptor. */
};

#define	min(x, y)	((x) < (y) ? (x) : (y))

/*
 * XXXRW: CHERI system objects must have a corresponding sandbox_object to use
 * during domain transition.  Define one here.
 */

/*
 * Allocate a new cheri_fd object for an already-open file descriptor.
 *
 * XXXRW: What to return in the userspace CCall world order?  The sandbox..?
 */
int
cheri_fd_new(int fd, struct sandbox_object **sbopp)
{
	__capability void *invoke_pcc;
	struct cheri_fd *cfp;

	cfp = calloc(1, sizeof(*cfp));
	if (cfp == NULL) {
		errno = ENOMEM;
		return (-1);
	}
	cfp->cf_fd = fd;

	/*
	 * Construct a code capability for this class; for system classes,
	 * this is just the ambient $pcc with the offset set to the entry
	 * address.
	 *
	 * XXXRW: Possibly, we should just pass cheri_fd to sandbox creation
	 * rather than embedding this logic in each system class?
	 */
	invoke_pcc = cheri_setoffset(cheri_getpcc(),
	    (register_t)CHERI_CLASS_ENTRY(cheri_fd));

	/*
	 * Set up system-object state for the sandbox.
	 */
	if (sandbox_object_new_system_object(
	    (__cheri_cast void * __capability)(void *)cfp, invoke_pcc,
	    cheri_fd_vtable, &cfp->cf_sbop) != 0) {
		free(cfp);
		return (-1);
	}
	*sbopp = cfp->cf_sbop;
	return (0);
}

/*
 * Revoke further accesses via the object -- although in-flight accesses
 * continue.  Note: does not close the fd or free memory.  The latter must
 */
void
cheri_fd_revoke(struct sandbox_object *sbop)
{
	__capability struct cheri_fd *cfp;

	cfp = sandbox_object_private_get(sbop);
	cfp->cf_fd = -1;
}

/*
 * Actually free a cheri_fd.  This can only be done if there are no
 * outstanding references in any sandboxes (etc).
 */
void
cheri_fd_destroy(struct sandbox_object *sbop)
{
	__capability struct cheri_fd *cfp;

	cfp = sandbox_object_getsandboxdata(sbop);
	sandbox_object_destroy(sbop);
	free((__cheri_cast struct cheri_fd *)cfp);
}

/*
 * Forward fstat() on a cheri_fd to the underlying file descriptor.
 */
struct cheri_fd_ret
cheri_fd_fstat(__capability struct stat *sb_c)
{
	struct cheri_fd_ret ret;
	__capability struct cheri_fd *cfp;
	struct stat *sb;

	/* XXXRW: Object-capability user permission check on idc. */

	/* XXXRW: Change to check permissions directly and throw exception. */
	if (!(cheri_getperm(sb_c) & CHERI_PERM_STORE) ||
	    !(cheri_getlen(sb_c) >= sizeof(*sb))) {
		ret.cfr_retval0 = -1;
		ret.cfr_retval1 = EPROT;
		return (ret);
	}
	sb = cheri_cap_to_typed_ptr(sb_c, struct stat);

	/* Check that the cheri_fd hasn't been revoked. */
	cfp = sandbox_object_private_get_idc();
	if (cfp->cf_fd == -1) {
		ret.cfr_retval0 = -1;
		ret.cfr_retval1 = EBADF;
		return (ret);
	}

	/* Forward to operating system. */
	ret.cfr_retval0 = fstat(cfp->cf_fd, sb);
	ret.cfr_retval1 = (ret.cfr_retval0 < 0 ? errno : 0);
	return (ret);
}

/*
 * Forward lseek() on a cheri_fd to the underlying file descriptor.
 */
struct cheri_fd_ret
cheri_fd_lseek(off_t offset, int whence)
{
	struct cheri_fd_ret ret;
	__capability struct cheri_fd *cfp;

	/* XXXRW: Object-capability user permission check on idc. */

	/* Check that the cheri_fd hasn't been revoked. */
	cfp = sandbox_object_private_get_idc();
	if (cfp->cf_fd == -1) {
		ret.cfr_retval0 = -1;
		ret.cfr_retval1 = EBADF;
		return (ret);
	}

	/* Forward to operating system. */
	ret.cfr_retval0 = lseek(cfp->cf_fd, offset, whence);
	ret.cfr_retval1 = (ret.cfr_retval0 < 0 ? errno : 0);
	return (ret);
}

/*
 * Forward read() on a cheri_fd to the underlying file descriptor.
 */
struct cheri_fd_ret
cheri_fd_read(__capability void *buf_c, size_t nbytes)
{
	struct cheri_fd_ret ret;
	__capability struct cheri_fd *cfp;
	void *buf;

	/* XXXRW: Object-capability user permission check on idc. */

	/* XXXRW: Change to check permissions directly and throw exception. */
	if (!(cheri_getperm(buf_c) & CHERI_PERM_STORE)) {
		ret.cfr_retval0 = -1;
		ret.cfr_retval1 = EPROT;
		return (ret);
	}
	buf = cheri_cap_to_ptr(buf_c, nbytes);

	/* Check that the cheri_fd hasn't been revoked. */
	cfp = sandbox_object_private_get_idc();
	if (cfp->cf_fd == -1) {
		ret.cfr_retval0 = -1;
		ret.cfr_retval1 = EBADF;
		return (ret);
	}

	/* Forward to operating system. */
	ret.cfr_retval0 = read(cfp->cf_fd, buf,
	    min(nbytes, cheri_getlen(buf_c) - cheri_getoffset(buf_c)));
	ret.cfr_retval1 = (ret.cfr_retval0 < 0 ? errno : 0);
	return (ret);
}

/*
 * Forward write_c() on a cheri_fd to the underlying file descriptor.
 */
struct cheri_fd_ret
cheri_fd_write(__capability const void *buf_c, size_t nbytes)
{
	struct cheri_fd_ret ret;
	__capability struct cheri_fd *cfp;
	const void *buf;

	/* XXXRW: Object-capability user permission check on idc. */

	/* XXXRW: Change to check permissions directly and throw exception. */
	if (!(cheri_getperm(buf_c) & CHERI_PERM_LOAD)) {
		ret.cfr_retval0 = -1;
		ret.cfr_retval1 = EPROT;
		return (ret);
	}
	buf = cheri_cap_to_ptr(buf_c, nbytes);

	/* Check that cheri_fd hasn't been revoked. */
	cfp = sandbox_object_private_get_idc();
	if (cfp->cf_fd == -1) {
		ret.cfr_retval0 = -1;
		ret.cfr_retval1 = EBADF;
		return (ret);
	}

	/* Forward to operating system. */
	ret.cfr_retval0 = write(cfp->cf_fd, buf,
	    min(nbytes, cheri_getlen(buf_c) - cheri_getoffset(buf_c)));
	ret.cfr_retval1 = (ret.cfr_retval0 < 0 ? errno : 0);
	return (ret);
}
