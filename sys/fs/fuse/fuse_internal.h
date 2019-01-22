/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2007-2009 Google Inc. and Amit Singh
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following disclaimer
 *   in the documentation and/or other materials provided with the
 *   distribution.
 * * Neither the name of Google Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * Copyright (C) 2005 Csaba Henk.
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef _FUSE_INTERNAL_H_
#define _FUSE_INTERNAL_H_

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/vnode.h>

#include "fuse_ipc.h"
#include "fuse_node.h"

static __inline int
vfs_isrdonly(struct mount *mp)
{
    return ((mp->mnt_flag & MNT_RDONLY) != 0 ? 1 : 0);
}

static __inline struct mount *
vnode_mount(struct vnode *vp)
{
	return (vp->v_mount);
}

static __inline int
vnode_mountedhere(struct vnode *vp)
{
	return (vp->v_mountedhere != NULL ? 1 : 0);
}

static __inline enum vtype
vnode_vtype(struct vnode *vp)
{
    return (vp->v_type);
}

static __inline int
vnode_isvroot(struct vnode *vp)
{
    return ((vp->v_vflag & VV_ROOT) != 0 ? 1 : 0);
}

static __inline int
vnode_isreg(struct vnode *vp)
{
    return (vp->v_type == VREG ? 1 : 0);
}

static __inline int
vnode_isdir(struct vnode *vp)
{
    return (vp->v_type == VDIR ? 1 : 0);
}

static __inline int
vnode_islnk(struct vnode *vp)
{
    return (vp->v_type == VLNK ? 1 : 0);
}

static __inline ssize_t
uio_resid(struct uio *uio)
{
    return (uio->uio_resid);
}

static __inline off_t
uio_offset(struct uio *uio)
{
    return (uio->uio_offset);
}

static __inline void
uio_setoffset(struct uio *uio, off_t offset)
{
    uio->uio_offset = offset;
}

static __inline void
uio_setresid(struct uio *uio, ssize_t resid)
{
    uio->uio_resid = resid;
}

/* miscellaneous */

static __inline__
int
fuse_isdeadfs(struct vnode *vp)
{
    struct fuse_data *data = fuse_get_mpdata(vnode_mount(vp));

    return (data->dataflags & FSESS_DEAD);
}

static __inline__
int
fuse_iosize(struct vnode *vp)
{
    return vp->v_mount->mnt_stat.f_iosize;
}

/* access */

#define FVP_ACCESS_NOOP   0x01

#define FACCESS_VA_VALID   0x01
#define FACCESS_DO_ACCESS  0x02
#define FACCESS_STICKY     0x04
#define FACCESS_CHOWN      0x08
#define FACCESS_NOCHECKSPY 0x10
#define FACCESS_SETGID     0x12

#define FACCESS_XQUERIES FACCESS_STICKY | FACCESS_CHOWN | FACCESS_SETGID

struct fuse_access_param {
    uid_t    xuid;
    gid_t    xgid;
    uint32_t facc_flags;
};

static __inline int
fuse_match_cred(struct ucred *basecred, struct ucred *usercred)
{
	if (basecred->cr_uid == usercred->cr_uid             &&
	    basecred->cr_uid == usercred->cr_ruid            &&
	    basecred->cr_uid == usercred->cr_svuid           &&
	    basecred->cr_groups[0] == usercred->cr_groups[0] &&
	    basecred->cr_groups[0] == usercred->cr_rgid      &&
	    basecred->cr_groups[0] == usercred->cr_svgid)
		return 0;

	return EPERM;
}

int
fuse_internal_access(struct vnode *vp,
                     mode_t mode,
                     struct fuse_access_param *facp,
                     struct thread *td,
                     struct ucred *cred);

/* attributes */

static __inline
void
fuse_internal_attr_fat2vat(struct mount *mp,
                           struct fuse_attr *fat,
                           struct vattr *vap)
{
    DEBUGX(FUSE_DEBUG_INTERNAL,
        "node #%ju, mode 0%o\n", (uintmax_t)fat->ino, fat->mode);

    vattr_null(vap);

    vap->va_fsid = mp->mnt_stat.f_fsid.val[0];
    vap->va_fileid = fat->ino;
    vap->va_mode = fat->mode & ~S_IFMT;
    vap->va_nlink     = fat->nlink;
    vap->va_uid       = fat->uid;
    vap->va_gid       = fat->gid;
    vap->va_rdev      = fat->rdev;
    vap->va_size      = fat->size;
    vap->va_atime.tv_sec  = fat->atime; /* XXX on some platforms cast from 64 bits to 32 */
    vap->va_atime.tv_nsec = fat->atimensec;
    vap->va_mtime.tv_sec  = fat->mtime;
    vap->va_mtime.tv_nsec = fat->mtimensec;
    vap->va_ctime.tv_sec  = fat->ctime;
    vap->va_ctime.tv_nsec = fat->ctimensec;
    vap->va_blocksize = PAGE_SIZE;
    vap->va_type = IFTOVT(fat->mode);

#if (S_BLKSIZE == 512)
    /* Optimize this case */
    vap->va_bytes = fat->blocks << 9;
#else
    vap->va_bytes = fat->blocks * S_BLKSIZE;
#endif

    vap->va_flags = 0;
}


#define	cache_attrs(vp, fuse_out)					\
	fuse_internal_attr_fat2vat(vnode_mount(vp), &(fuse_out)->attr,	\
	    VTOVA(vp));

/* fsync */

int
fuse_internal_fsync(struct vnode           *vp,
                    struct thread          *td,
                    struct ucred           *cred,
                    struct fuse_filehandle *fufh);

int
fuse_internal_fsync_callback(struct fuse_ticket *tick, struct uio *uio);

/* readdir */

struct pseudo_dirent {
    uint32_t d_namlen;
};

int
fuse_internal_readdir(struct vnode           *vp,
                      struct uio             *uio,
                      struct fuse_filehandle *fufh,
                      struct fuse_iov        *cookediov);

int
fuse_internal_readdir_processdata(struct uio *uio,
                                  size_t reqsize,
                                  void *buf,
                                  size_t bufsize,
                                  void *param);

/* remove */

int
fuse_internal_remove(struct vnode *dvp,
                     struct vnode *vp,
                     struct componentname *cnp,
                     enum fuse_opcode op);

/* rename */

int
fuse_internal_rename(struct vnode *fdvp,
                     struct componentname *fcnp,
                     struct vnode *tdvp,
                     struct componentname *tcnp);
/* revoke */

void
fuse_internal_vnode_disappear(struct vnode *vp);

/* strategy */

/* entity creation */

static __inline
int
fuse_internal_checkentry(struct fuse_entry_out *feo, enum vtype vtyp)
{
    DEBUGX(FUSE_DEBUG_INTERNAL,
        "feo=%p, vtype=%d\n", feo, vtyp);

    if (vtyp != IFTOVT(feo->attr.mode)) {
        DEBUGX(FUSE_DEBUG_INTERNAL,
            "EINVAL -- %x != %x\n", vtyp, IFTOVT(feo->attr.mode));
        return EINVAL;
    }

    if (feo->nodeid == FUSE_NULL_ID) {
        DEBUGX(FUSE_DEBUG_INTERNAL,
            "EINVAL -- feo->nodeid is NULL\n");
        return EINVAL;
    }

    if (feo->nodeid == FUSE_ROOT_ID) {
        DEBUGX(FUSE_DEBUG_INTERNAL,
            "EINVAL -- feo->nodeid is FUSE_ROOT_ID\n");
        return EINVAL;
    }

    return 0;
}

int
fuse_internal_newentry(struct vnode *dvp,
                       struct vnode **vpp,
                       struct componentname *cnp,
                       enum fuse_opcode op,
                       void *buf,
                       size_t bufsize,
                       enum vtype vtyp);

void
fuse_internal_newentry_makerequest(struct mount *mp,
                                   uint64_t dnid,
                                   struct componentname *cnp,
                                   enum fuse_opcode op,
                                   void *buf,
                                   size_t bufsize,
                                   struct fuse_dispatcher *fdip);

int
fuse_internal_newentry_core(struct vnode *dvp,
                            struct vnode **vpp,
                            struct componentname   *cnp,
                            enum vtype vtyp,
                            struct fuse_dispatcher *fdip);

/* entity destruction */

int
fuse_internal_forget_callback(struct fuse_ticket *tick, struct uio *uio);

void
fuse_internal_forget_send(struct mount *mp,
                          struct thread *td,
                          struct ucred *cred,
                          uint64_t nodeid,
                          uint64_t nlookup);

/* fuse start/stop */

int fuse_internal_init_callback(struct fuse_ticket *tick, struct uio *uio);
void fuse_internal_send_init(struct fuse_data *data, struct thread *td);

#endif /* _FUSE_INTERNAL_H_ */
