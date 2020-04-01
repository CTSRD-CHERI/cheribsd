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
 * Copyright (c) 2019 The FreeBSD Foundation
 *
 * Portions of this software were developed by BFF Storage Systems, LLC under
 * sponsorship from the FreeBSD Foundation.
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/queue.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/rwlock.h>
#include <sys/sx.h>
#include <sys/proc.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/namei.h>
#include <sys/extattr.h>
#include <sys/stat.h>
#include <sys/unistd.h>
#include <sys/filedesc.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/dirent.h>
#include <sys/bio.h>
#include <sys/buf.h>
#include <sys/sysctl.h>
#include <sys/vmmeter.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/vm_param.h>
#include <vm/vm_object.h>
#include <vm/vm_pager.h>
#include <vm/vnode_pager.h>
#include <vm/vm_object.h>

#include "fuse.h"
#include "fuse_file.h"
#include "fuse_internal.h"
#include "fuse_ipc.h"
#include "fuse_node.h"
#include "fuse_io.h"

#include <sys/priv.h>

/* Maximum number of hardlinks to a single FUSE file */
#define FUSE_LINK_MAX                      UINT32_MAX

SDT_PROVIDER_DECLARE(fusefs);
/* 
 * Fuse trace probe:
 * arg0: verbosity.  Higher numbers give more verbose messages
 * arg1: Textual message
 */
SDT_PROBE_DEFINE2(fusefs, , vnops, trace, "int", "char*");

/* vnode ops */
static vop_access_t fuse_vnop_access;
static vop_advlock_t fuse_vnop_advlock;
static vop_bmap_t fuse_vnop_bmap;
static vop_close_t fuse_fifo_close;
static vop_close_t fuse_vnop_close;
static vop_create_t fuse_vnop_create;
static vop_deleteextattr_t fuse_vnop_deleteextattr;
static vop_fdatasync_t fuse_vnop_fdatasync;
static vop_fsync_t fuse_vnop_fsync;
static vop_getattr_t fuse_vnop_getattr;
static vop_getextattr_t fuse_vnop_getextattr;
static vop_inactive_t fuse_vnop_inactive;
static vop_link_t fuse_vnop_link;
static vop_listextattr_t fuse_vnop_listextattr;
static vop_lookup_t fuse_vnop_lookup;
static vop_mkdir_t fuse_vnop_mkdir;
static vop_mknod_t fuse_vnop_mknod;
static vop_open_t fuse_vnop_open;
static vop_pathconf_t fuse_vnop_pathconf;
static vop_read_t fuse_vnop_read;
static vop_readdir_t fuse_vnop_readdir;
static vop_readlink_t fuse_vnop_readlink;
static vop_reclaim_t fuse_vnop_reclaim;
static vop_remove_t fuse_vnop_remove;
static vop_rename_t fuse_vnop_rename;
static vop_rmdir_t fuse_vnop_rmdir;
static vop_setattr_t fuse_vnop_setattr;
static vop_setextattr_t fuse_vnop_setextattr;
static vop_strategy_t fuse_vnop_strategy;
static vop_symlink_t fuse_vnop_symlink;
static vop_write_t fuse_vnop_write;
static vop_getpages_t fuse_vnop_getpages;
static vop_print_t fuse_vnop_print;
static vop_vptofh_t fuse_vnop_vptofh;

struct vop_vector fuse_fifoops = {
	.vop_default =		&fifo_specops,
	.vop_access =		fuse_vnop_access,
	.vop_close =		fuse_fifo_close,
	.vop_fsync =		fuse_vnop_fsync,
	.vop_getattr =		fuse_vnop_getattr,
	.vop_inactive =		fuse_vnop_inactive,
	.vop_pathconf =		fuse_vnop_pathconf,
	.vop_print =		fuse_vnop_print,
	.vop_read =		VOP_PANIC,
	.vop_reclaim =		fuse_vnop_reclaim,
	.vop_setattr =		fuse_vnop_setattr,
	.vop_write =		VOP_PANIC,
	.vop_vptofh =		fuse_vnop_vptofh,
};
VFS_VOP_VECTOR_REGISTER(fuse_fifoops);

struct vop_vector fuse_vnops = {
	.vop_allocate =	VOP_EINVAL,
	.vop_default = &default_vnodeops,
	.vop_access = fuse_vnop_access,
	.vop_advlock = fuse_vnop_advlock,
	.vop_bmap = fuse_vnop_bmap,
	.vop_close = fuse_vnop_close,
	.vop_create = fuse_vnop_create,
	.vop_deleteextattr = fuse_vnop_deleteextattr,
	.vop_fsync = fuse_vnop_fsync,
	.vop_fdatasync = fuse_vnop_fdatasync,
	.vop_getattr = fuse_vnop_getattr,
	.vop_getextattr = fuse_vnop_getextattr,
	.vop_inactive = fuse_vnop_inactive,
	/*
	 * TODO: implement vop_ioctl after upgrading to protocol 7.16.
	 * FUSE_IOCTL was added in 7.11, but 32-bit compat is broken until
	 * 7.16.
	 */
	.vop_link = fuse_vnop_link,
	.vop_listextattr = fuse_vnop_listextattr,
	.vop_lookup = fuse_vnop_lookup,
	.vop_mkdir = fuse_vnop_mkdir,
	.vop_mknod = fuse_vnop_mknod,
	.vop_open = fuse_vnop_open,
	.vop_pathconf = fuse_vnop_pathconf,
	/*
	 * TODO: implement vop_poll after upgrading to protocol 7.21.
	 * FUSE_POLL was added in protocol 7.11, but it's kind of broken until
	 * 7.21, which adds the ability for the client to choose which poll
	 * events it wants, and for a client to deregister a file handle
	 */
	.vop_read = fuse_vnop_read,
	.vop_readdir = fuse_vnop_readdir,
	.vop_readlink = fuse_vnop_readlink,
	.vop_reclaim = fuse_vnop_reclaim,
	.vop_remove = fuse_vnop_remove,
	.vop_rename = fuse_vnop_rename,
	.vop_rmdir = fuse_vnop_rmdir,
	.vop_setattr = fuse_vnop_setattr,
	.vop_setextattr = fuse_vnop_setextattr,
	.vop_strategy = fuse_vnop_strategy,
	.vop_symlink = fuse_vnop_symlink,
	.vop_write = fuse_vnop_write,
	.vop_getpages = fuse_vnop_getpages,
	.vop_print = fuse_vnop_print,
	.vop_vptofh = fuse_vnop_vptofh,
};
VFS_VOP_VECTOR_REGISTER(fuse_vnops);

uma_zone_t fuse_pbuf_zone;

/* Check permission for extattr operations, much like extattr_check_cred */
static int
fuse_extattr_check_cred(struct vnode *vp, int ns, struct ucred *cred,
	struct thread *td, accmode_t accmode)
{
	struct mount *mp = vnode_mount(vp);
	struct fuse_data *data = fuse_get_mpdata(mp);

	/*
	 * Kernel-invoked always succeeds.
	 */
	if (cred == NOCRED)
		return (0);

	/*
	 * Do not allow privileged processes in jail to directly manipulate
	 * system attributes.
	 */
	switch (ns) {
	case EXTATTR_NAMESPACE_SYSTEM:
		if (data->dataflags & FSESS_DEFAULT_PERMISSIONS) {
			return (priv_check_cred(cred, PRIV_VFS_EXTATTR_SYSTEM));
		}
		/* FALLTHROUGH */
	case EXTATTR_NAMESPACE_USER:
		return (fuse_internal_access(vp, accmode, td, cred));
	default:
		return (EPERM);
	}
}

/* Get a filehandle for a directory */
static int
fuse_filehandle_get_dir(struct vnode *vp, struct fuse_filehandle **fufhp,
	struct ucred *cred, pid_t pid)
{
	if (fuse_filehandle_get(vp, FREAD, fufhp, cred, pid) == 0)
		return 0;
	return fuse_filehandle_get(vp, FEXEC, fufhp, cred, pid);
}

/* Send FUSE_FLUSH for this vnode */
static int
fuse_flush(struct vnode *vp, struct ucred *cred, pid_t pid, int fflag)
{
	struct fuse_flush_in *ffi;
	struct fuse_filehandle *fufh;
	struct fuse_dispatcher fdi;
	struct thread *td = curthread;
	struct mount *mp = vnode_mount(vp);
	int err;

	if (!fsess_isimpl(vnode_mount(vp), FUSE_FLUSH))
		return 0;

	err = fuse_filehandle_getrw(vp, fflag, &fufh, cred, pid);
	if (err)
		return err;

	fdisp_init(&fdi, sizeof(*ffi));
	fdisp_make_vp(&fdi, FUSE_FLUSH, vp, td, cred);
	ffi = fdi.indata;
	ffi->fh = fufh->fh_id;
	/* 
	 * If the file has a POSIX lock then we're supposed to set lock_owner.
	 * If not, then lock_owner is undefined.  So we may as well always set
	 * it.
	 */
	ffi->lock_owner = td->td_proc->p_pid;

	err = fdisp_wait_answ(&fdi);
	if (err == ENOSYS) {
		fsess_set_notimpl(mp, FUSE_FLUSH);
		err = 0;
	}
	fdisp_destroy(&fdi);
	return err;
}

/* Close wrapper for fifos.  */
static int
fuse_fifo_close(struct vop_close_args *ap)
{
	return (fifo_specops.vop_close(ap));
}

/*
    struct vnop_access_args {
	struct vnode *a_vp;
#if VOP_ACCESS_TAKES_ACCMODE_T
	accmode_t a_accmode;
#else
	int a_mode;
#endif
	struct ucred *a_cred;
	struct thread *a_td;
    };
*/
static int
fuse_vnop_access(struct vop_access_args *ap)
{
	struct vnode *vp = ap->a_vp;
	int accmode = ap->a_accmode;
	struct ucred *cred = ap->a_cred;

	struct fuse_data *data = fuse_get_mpdata(vnode_mount(vp));

	int err;

	if (fuse_isdeadfs(vp)) {
		if (vnode_isvroot(vp)) {
			return 0;
		}
		return ENXIO;
	}
	if (!(data->dataflags & FSESS_INITED)) {
		if (vnode_isvroot(vp)) {
			if (priv_check_cred(cred, PRIV_VFS_ADMIN) ||
			    (fuse_match_cred(data->daemoncred, cred) == 0)) {
				return 0;
			}
		}
		return EBADF;
	}
	if (vnode_islnk(vp)) {
		return 0;
	}

	err = fuse_internal_access(vp, accmode, ap->a_td, ap->a_cred);
	return err;
}

/*
 * struct vop_advlock_args {
 *	struct vop_generic_args a_gen;
 *	struct vnode *a_vp;
 *	void *a_id;
 *	int a_op;
 *	struct flock *a_fl;
 *	int a_flags;
 * }
 */
static int
fuse_vnop_advlock(struct vop_advlock_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct flock *fl = ap->a_fl;
	struct thread *td = curthread;
	struct ucred *cred = td->td_ucred;
	pid_t pid = td->td_proc->p_pid;
	struct fuse_filehandle *fufh;
	struct fuse_dispatcher fdi;
	struct fuse_lk_in *fli;
	struct fuse_lk_out *flo;
	enum fuse_opcode op;
	int dataflags, err;
	int flags = ap->a_flags;

	dataflags = fuse_get_mpdata(vnode_mount(vp))->dataflags;

	if (fuse_isdeadfs(vp)) {
		return ENXIO;
	}

	if (!(dataflags & FSESS_POSIX_LOCKS))
		return vop_stdadvlock(ap);
	/* FUSE doesn't properly support flock until protocol 7.17 */
	if (flags & F_FLOCK)
		return vop_stdadvlock(ap);

	err = fuse_filehandle_get_anyflags(vp, &fufh, cred, pid);
	if (err)
		return err;

	fdisp_init(&fdi, sizeof(*fli));

	switch(ap->a_op) {
	case F_GETLK:
		op = FUSE_GETLK;
		break;
	case F_SETLK:
		op = FUSE_SETLK;
		break;
	case F_SETLKW:
		op = FUSE_SETLKW;
		break;
	default:
		return EINVAL;
	}

	fdisp_make_vp(&fdi, op, vp, td, cred);
	fli = fdi.indata;
	fli->fh = fufh->fh_id;
	fli->owner = fl->l_pid;
	fli->lk.start = fl->l_start;
	if (fl->l_len != 0)
		fli->lk.end = fl->l_start + fl->l_len - 1;
	else
		fli->lk.end = INT64_MAX;
	fli->lk.type = fl->l_type;
	fli->lk.pid = fl->l_pid;

	err = fdisp_wait_answ(&fdi);
	fdisp_destroy(&fdi);

	if (err == 0 && op == FUSE_GETLK) {
		flo = fdi.answ;
		fl->l_type = flo->lk.type;
		fl->l_pid = flo->lk.pid;
		if (flo->lk.type != F_UNLCK) {
			fl->l_start = flo->lk.start;
			if (flo->lk.end == INT64_MAX)
				fl->l_len = 0;
			else
				fl->l_len = flo->lk.end - flo->lk.start + 1;
			fl->l_start = flo->lk.start;
		}
	}

	return err;
}

/* {
	struct vnode *a_vp;
	daddr_t a_bn;
	struct bufobj **a_bop;
	daddr_t *a_bnp;
	int *a_runp;
	int *a_runb;
} */
static int
fuse_vnop_bmap(struct vop_bmap_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct bufobj **bo = ap->a_bop;
	struct thread *td = curthread;
	struct mount *mp;
	struct fuse_dispatcher fdi;
	struct fuse_bmap_in *fbi;
	struct fuse_bmap_out *fbo;
	struct fuse_data *data;
	uint64_t biosize;
	off_t filesize;
	daddr_t lbn = ap->a_bn;
	daddr_t *pbn = ap->a_bnp;
	int *runp = ap->a_runp;
	int *runb = ap->a_runb;
	int error = 0;
	int maxrun;

	if (fuse_isdeadfs(vp)) {
		return ENXIO;
	}

	mp = vnode_mount(vp);
	data = fuse_get_mpdata(mp);
	biosize = fuse_iosize(vp);
	maxrun = MIN(vp->v_mount->mnt_iosize_max / biosize - 1,
		data->max_readahead_blocks);

	if (bo != NULL)
		*bo = &vp->v_bufobj;

	/*
	 * The FUSE_BMAP operation does not include the runp and runb
	 * variables, so we must guess.  Report nonzero contiguous runs so
	 * cluster_read will combine adjacent reads.  It's worthwhile to reduce
	 * upcalls even if we don't know the true physical layout of the file.
	 * 
	 * FUSE file systems may opt out of read clustering in two ways:
	 * * mounting with -onoclusterr
	 * * Setting max_readahead <= maxbcachebuf during FUSE_INIT
	 */
	if (runb != NULL)
		*runb = MIN(lbn, maxrun);
	if (runp != NULL) {
		error = fuse_vnode_size(vp, &filesize, td->td_ucred, td);
		if (error == 0)
			*runp = MIN(MAX(0, filesize / (off_t)biosize - lbn - 1),
				    maxrun);
		else
			*runp = 0;
	}

	if (fsess_isimpl(mp, FUSE_BMAP)) {
		fdisp_init(&fdi, sizeof(*fbi));
		fdisp_make_vp(&fdi, FUSE_BMAP, vp, td, td->td_ucred);
		fbi = fdi.indata;
		fbi->block = lbn;
		fbi->blocksize = biosize;
		error = fdisp_wait_answ(&fdi);
		if (error == ENOSYS) {
			fdisp_destroy(&fdi);
			fsess_set_notimpl(mp, FUSE_BMAP);
			error = 0;
		} else {
			fbo = fdi.answ;
			if (error == 0 && pbn != NULL)
				*pbn = fbo->block;
			fdisp_destroy(&fdi);
			return error;
		}
	}

	/* If the daemon doesn't support BMAP, make up a sensible default */
	if (pbn != NULL)
		*pbn = lbn * btodb(biosize);
	return (error);
}

/*
    struct vop_close_args {
	struct vnode *a_vp;
	int  a_fflag;
	struct ucred *a_cred;
	struct thread *a_td;
    };
*/
static int
fuse_vnop_close(struct vop_close_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct ucred *cred = ap->a_cred;
	int fflag = ap->a_fflag;
	struct thread *td = ap->a_td;
	pid_t pid = td->td_proc->p_pid;
	int err = 0;

	if (fuse_isdeadfs(vp))
		return 0;
	if (vnode_isdir(vp))
		return 0;
	if (fflag & IO_NDELAY)
		return 0;

	err = fuse_flush(vp, cred, pid, fflag);
	/* TODO: close the file handle, if we're sure it's no longer used */
	if ((VTOFUD(vp)->flag & FN_SIZECHANGE) != 0) {
		fuse_vnode_savesize(vp, cred, td->td_proc->p_pid);
	}
	return err;
}

static void
fdisp_make_mknod_for_fallback(
	struct fuse_dispatcher *fdip,
	struct componentname *cnp,
	struct vnode *dvp,
	uint64_t parentnid,
	struct thread *td,
	struct ucred *cred,
	mode_t mode,
	enum fuse_opcode *op)
{
	struct fuse_mknod_in *fmni;

	fdisp_init(fdip, sizeof(*fmni) + cnp->cn_namelen + 1);
	*op = FUSE_MKNOD;
	fdisp_make(fdip, *op, vnode_mount(dvp), parentnid, td, cred);
	fmni = fdip->indata;
	fmni->mode = mode;
	fmni->rdev = 0;
	memcpy((char *)fdip->indata + sizeof(*fmni), cnp->cn_nameptr,
	    cnp->cn_namelen);
	((char *)fdip->indata)[sizeof(*fmni) + cnp->cn_namelen] = '\0';
}
/*
    struct vnop_create_args {
	struct vnode *a_dvp;
	struct vnode **a_vpp;
	struct componentname *a_cnp;
	struct vattr *a_vap;
    };
*/
static int
fuse_vnop_create(struct vop_create_args *ap)
{
	struct vnode *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp;
	struct componentname *cnp = ap->a_cnp;
	struct vattr *vap = ap->a_vap;
	struct thread *td = cnp->cn_thread;
	struct ucred *cred = cnp->cn_cred;

	struct fuse_data *data;
	struct fuse_create_in *fci;
	struct fuse_entry_out *feo;
	struct fuse_open_out *foo;
	struct fuse_dispatcher fdi, fdi2;
	struct fuse_dispatcher *fdip = &fdi;
	struct fuse_dispatcher *fdip2 = NULL;

	int err;

	struct mount *mp = vnode_mount(dvp);
	data = fuse_get_mpdata(mp);
	uint64_t parentnid = VTOFUD(dvp)->nid;
	mode_t mode = MAKEIMODE(vap->va_type, vap->va_mode);
	enum fuse_opcode op;
	int flags;

	if (fuse_isdeadfs(dvp))
		return ENXIO;

	/* FUSE expects sockets to be created with FUSE_MKNOD */
	if (vap->va_type == VSOCK)
		return fuse_internal_mknod(dvp, vpp, cnp, vap);

	/* 
	 * VOP_CREATE doesn't tell us the open(2) flags, so we guess.  Only a
	 * writable mode makes sense, and we might as well include readability
	 * too.
	 */
	flags = O_RDWR;

	bzero(&fdi, sizeof(fdi));

	if (vap->va_type != VREG)
		return (EINVAL);

	if (!fsess_isimpl(mp, FUSE_CREATE) || vap->va_type == VSOCK) {
		/* Fallback to FUSE_MKNOD/FUSE_OPEN */
		fdisp_make_mknod_for_fallback(fdip, cnp, dvp, parentnid, td,
			cred, mode, &op);
	} else {
		/* Use FUSE_CREATE */
		size_t insize;

		op = FUSE_CREATE;
		fdisp_init(fdip, sizeof(*fci) + cnp->cn_namelen + 1);
		fdisp_make(fdip, op, vnode_mount(dvp), parentnid, td, cred);
		fci = fdip->indata;
		fci->mode = mode;
		fci->flags = O_CREAT | flags;
		if (fuse_libabi_geq(data, 7, 12)) {
			insize = sizeof(*fci);
			fci->umask = td->td_proc->p_fd->fd_cmask;
		} else {
			insize = sizeof(struct fuse_open_in);
		}

		memcpy((char *)fdip->indata + insize, cnp->cn_nameptr,
		    cnp->cn_namelen);
		((char *)fdip->indata)[insize + cnp->cn_namelen] = '\0';
	}

	err = fdisp_wait_answ(fdip);

	if (err) {
		if (err == ENOSYS && op == FUSE_CREATE) {
			fsess_set_notimpl(mp, FUSE_CREATE);
			fdisp_destroy(fdip);
			fdisp_make_mknod_for_fallback(fdip, cnp, dvp,
				parentnid, td, cred, mode, &op);
			err = fdisp_wait_answ(fdip);
		}
		if (err)
			goto out;
	}

	feo = fdip->answ;

	if ((err = fuse_internal_checkentry(feo, vap->va_type))) {
		goto out;
	}

	if (op == FUSE_CREATE) {
		foo = (struct fuse_open_out*)(feo + 1);
	} else {
		/* Issue a separate FUSE_OPEN */
		struct fuse_open_in *foi;

		fdip2 = &fdi2;
		fdisp_init(fdip2, sizeof(*foi));
		fdisp_make(fdip2, FUSE_OPEN, vnode_mount(dvp), feo->nodeid, td,
			cred);
		foi = fdip2->indata;
		foi->flags = flags;
		err = fdisp_wait_answ(fdip2);
		if (err)
			goto out;
		foo = fdip2->answ;
	}
	err = fuse_vnode_get(mp, feo, feo->nodeid, dvp, vpp, cnp, vap->va_type);
	if (err) {
		struct fuse_release_in *fri;
		uint64_t nodeid = feo->nodeid;
		uint64_t fh_id = foo->fh;

		fdisp_init(fdip, sizeof(*fri));
		fdisp_make(fdip, FUSE_RELEASE, mp, nodeid, td, cred);
		fri = fdip->indata;
		fri->fh = fh_id;
		fri->flags = flags;
		fuse_insert_callback(fdip->tick, fuse_internal_forget_callback);
		fuse_insert_message(fdip->tick, false);
		goto out;
	}
	ASSERT_VOP_ELOCKED(*vpp, "fuse_vnop_create");
	fuse_internal_cache_attrs(*vpp, &feo->attr, feo->attr_valid,
		feo->attr_valid_nsec, NULL);

	fuse_filehandle_init(*vpp, FUFH_RDWR, NULL, td, cred, foo);
	fuse_vnode_open(*vpp, foo->open_flags, td);
	/* 
	 * Purge the parent's attribute cache because the daemon should've
	 * updated its mtime and ctime
	 */
	fuse_vnode_clear_attr_cache(dvp);
	cache_purge_negative(dvp);

out:
	if (fdip2)
		fdisp_destroy(fdip2);
	fdisp_destroy(fdip);
	return err;
}

/*
    struct vnop_fdatasync_args {
	struct vop_generic_args a_gen;
	struct vnode * a_vp;
	struct thread * a_td;
    };
*/
static int
fuse_vnop_fdatasync(struct vop_fdatasync_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct thread *td = ap->a_td;
	int waitfor = MNT_WAIT;

	int err = 0;

	if (fuse_isdeadfs(vp)) {
		return 0;
	}
	if ((err = vop_stdfdatasync_buf(ap)))
		return err;

	return fuse_internal_fsync(vp, td, waitfor, true);
}

/*
    struct vnop_fsync_args {
	struct vop_generic_args a_gen;
	struct vnode * a_vp;
	int  a_waitfor;
	struct thread * a_td;
    };
*/
static int
fuse_vnop_fsync(struct vop_fsync_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct thread *td = ap->a_td;
	int waitfor = ap->a_waitfor;
	int err = 0;

	if (fuse_isdeadfs(vp)) {
		return 0;
	}
	if ((err = vop_stdfsync(ap)))
		return err;

	return fuse_internal_fsync(vp, td, waitfor, false);
}

/*
    struct vnop_getattr_args {
	struct vnode *a_vp;
	struct vattr *a_vap;
	struct ucred *a_cred;
	struct thread *a_td;
    };
*/
static int
fuse_vnop_getattr(struct vop_getattr_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct vattr *vap = ap->a_vap;
	struct ucred *cred = ap->a_cred;
	struct thread *td = curthread;

	int err = 0;
	int dataflags;

	dataflags = fuse_get_mpdata(vnode_mount(vp))->dataflags;

	/* Note that we are not bailing out on a dead file system just yet. */

	if (!(dataflags & FSESS_INITED)) {
		if (!vnode_isvroot(vp)) {
			fdata_set_dead(fuse_get_mpdata(vnode_mount(vp)));
			err = ENOTCONN;
			return err;
		} else {
			goto fake;
		}
	}
	err = fuse_internal_getattr(vp, vap, cred, td);
	if (err == ENOTCONN && vnode_isvroot(vp)) {
		/* see comment in fuse_vfsop_statfs() */
		goto fake;
	} else {
		return err;
	}

fake:
	bzero(vap, sizeof(*vap));
	vap->va_type = vnode_vtype(vp);

	return 0;
}

/*
    struct vnop_inactive_args {
	struct vnode *a_vp;
	struct thread *a_td;
    };
*/
static int
fuse_vnop_inactive(struct vop_inactive_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct thread *td = ap->a_td;

	struct fuse_vnode_data *fvdat = VTOFUD(vp);
	struct fuse_filehandle *fufh, *fufh_tmp;

	int need_flush = 1;

	LIST_FOREACH_SAFE(fufh, &fvdat->handles, next, fufh_tmp) {
		if (need_flush && vp->v_type == VREG) {
			if ((VTOFUD(vp)->flag & FN_SIZECHANGE) != 0) {
				fuse_vnode_savesize(vp, NULL, 0);
			}
			if ((fvdat->flag & FN_REVOKED) != 0)
				fuse_io_invalbuf(vp, td);
			else
				fuse_io_flushbuf(vp, MNT_WAIT, td);
			need_flush = 0;
		}
		fuse_filehandle_close(vp, fufh, td, NULL);
	}

	if ((fvdat->flag & FN_REVOKED) != 0)
		vrecycle(vp);

	return 0;
}

/*
    struct vnop_link_args {
	struct vnode *a_tdvp;
	struct vnode *a_vp;
	struct componentname *a_cnp;
    };
*/
static int
fuse_vnop_link(struct vop_link_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct vnode *tdvp = ap->a_tdvp;
	struct componentname *cnp = ap->a_cnp;

	struct vattr *vap = VTOVA(vp);

	struct fuse_dispatcher fdi;
	struct fuse_entry_out *feo;
	struct fuse_link_in fli;

	int err;

	if (fuse_isdeadfs(vp)) {
		return ENXIO;
	}
	if (vnode_mount(tdvp) != vnode_mount(vp)) {
		return EXDEV;
	}

	/*
	 * This is a seatbelt check to protect naive userspace filesystems from
	 * themselves and the limitations of the FUSE IPC protocol.  If a
	 * filesystem does not allow attribute caching, assume it is capable of
	 * validating that nlink does not overflow.
	 */
	if (vap != NULL && vap->va_nlink >= FUSE_LINK_MAX)
		return EMLINK;
	fli.oldnodeid = VTOI(vp);

	fdisp_init(&fdi, 0);
	fuse_internal_newentry_makerequest(vnode_mount(tdvp), VTOI(tdvp), cnp,
	    FUSE_LINK, &fli, sizeof(fli), &fdi);
	if ((err = fdisp_wait_answ(&fdi))) {
		goto out;
	}
	feo = fdi.answ;

	err = fuse_internal_checkentry(feo, vnode_vtype(vp));
	if (!err) {
		/* 
		 * Purge the parent's attribute cache because the daemon
		 * should've updated its mtime and ctime
		 */
		fuse_vnode_clear_attr_cache(tdvp);
		fuse_internal_cache_attrs(vp, &feo->attr, feo->attr_valid,
			feo->attr_valid_nsec, NULL);
	}
out:
	fdisp_destroy(&fdi);
	return err;
}

struct fuse_lookup_alloc_arg {
	struct fuse_entry_out *feo;
	struct componentname *cnp;
	uint64_t nid;
	enum vtype vtyp;
};

/* Callback for vn_get_ino */
static int
fuse_lookup_alloc(struct mount *mp, void *arg, int lkflags, struct vnode **vpp)
{
	struct fuse_lookup_alloc_arg *flaa = arg;

	return fuse_vnode_get(mp, flaa->feo, flaa->nid, NULL, vpp, flaa->cnp,
		flaa->vtyp);
}

SDT_PROBE_DEFINE3(fusefs, , vnops, cache_lookup,
	"int", "struct timespec*", "struct timespec*");
SDT_PROBE_DEFINE2(fusefs, , vnops, lookup_cache_incoherent,
	"struct vnode*", "struct fuse_entry_out*");
/*
    struct vnop_lookup_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_dvp;
	struct vnode **a_vpp;
	struct componentname *a_cnp;
    };
*/
int
fuse_vnop_lookup(struct vop_lookup_args *ap)
{
	struct vnode *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp;
	struct componentname *cnp = ap->a_cnp;
	struct thread *td = cnp->cn_thread;
	struct ucred *cred = cnp->cn_cred;

	int nameiop = cnp->cn_nameiop;
	int flags = cnp->cn_flags;
	int wantparent = flags & (LOCKPARENT | WANTPARENT);
	int islastcn = flags & ISLASTCN;
	struct mount *mp = vnode_mount(dvp);

	int err = 0;
	int lookup_err = 0;
	struct vnode *vp = NULL;

	struct fuse_dispatcher fdi;
	bool did_lookup = false;
	struct fuse_entry_out *feo = NULL;
	enum vtype vtyp;	/* vnode type of target */
	off_t filesize;		/* filesize of target */

	uint64_t nid;

	if (fuse_isdeadfs(dvp)) {
		*vpp = NULL;
		return ENXIO;
	}
	if (!vnode_isdir(dvp))
		return ENOTDIR;

	if (islastcn && vfs_isrdonly(mp) && (nameiop != LOOKUP))
		return EROFS;

	if ((cnp->cn_flags & NOEXECCHECK) != 0)
		cnp->cn_flags &= ~NOEXECCHECK;
	else if ((err = fuse_internal_access(dvp, VEXEC, td, cred)))
		return err;

	if (flags & ISDOTDOT) {
		KASSERT(VTOFUD(dvp)->flag & FN_PARENT_NID,
			("Looking up .. is TODO"));
		nid = VTOFUD(dvp)->parent_nid;
		if (nid == 0)
			return ENOENT;
		/* .. is obviously a directory */
		vtyp = VDIR;
		filesize = 0;
	} else if (cnp->cn_namelen == 1 && *(cnp->cn_nameptr) == '.') {
		nid = VTOI(dvp);
		/* . is obviously a directory */
		vtyp = VDIR;
		filesize = 0;
	} else {
		struct timespec now, timeout;

		err = cache_lookup(dvp, vpp, cnp, &timeout, NULL);
		getnanouptime(&now);
		SDT_PROBE3(fusefs, , vnops, cache_lookup, err, &timeout, &now);
		switch (err) {
		case -1:		/* positive match */
			if (timespeccmp(&timeout, &now, >)) {
				counter_u64_add(fuse_lookup_cache_hits, 1);
			} else {
				/* Cache timeout */
				counter_u64_add(fuse_lookup_cache_misses, 1);
				bintime_clear(
					&VTOFUD(*vpp)->entry_cache_timeout);
				cache_purge(*vpp);
				if (dvp != *vpp)
					vput(*vpp);
				else 
					vrele(*vpp);
				*vpp = NULL;
				break;
			}
			return 0;

		case 0:		/* no match in cache */
			counter_u64_add(fuse_lookup_cache_misses, 1);
			break;

		case ENOENT:		/* negative match */
			getnanouptime(&now);
			if (timespeccmp(&timeout, &now, <=)) {
				/* Cache timeout */
				cache_purge_negative(dvp);
				break;
			}
			/* fall through */
		default:
			return err;
		}

		nid = VTOI(dvp);
		fdisp_init(&fdi, cnp->cn_namelen + 1);
		fdisp_make(&fdi, FUSE_LOOKUP, mp, nid, td, cred);

		memcpy(fdi.indata, cnp->cn_nameptr, cnp->cn_namelen);
		((char *)fdi.indata)[cnp->cn_namelen] = '\0';
		lookup_err = fdisp_wait_answ(&fdi);
		did_lookup = true;

		if (!lookup_err) {
			/* lookup call succeeded */
			feo = (struct fuse_entry_out *)fdi.answ;
			nid = feo->nodeid;
			if (nid == 0) {
				/* zero nodeid means ENOENT and cache it */
				struct timespec timeout;

				fdi.answ_stat = ENOENT;
				lookup_err = ENOENT;
				if (cnp->cn_flags & MAKEENTRY) {
					fuse_validity_2_timespec(feo, &timeout);
					cache_enter_time(dvp, *vpp, cnp,
						&timeout, NULL);
				}
			} else if (nid == FUSE_ROOT_ID) {
				lookup_err = EINVAL;
			}
			vtyp = IFTOVT(feo->attr.mode);
			filesize = feo->attr.size;
		}
		if (lookup_err && (!fdi.answ_stat || lookup_err != ENOENT)) {
			fdisp_destroy(&fdi);
			return lookup_err;
		}
	}
	/* lookup_err, if non-zero, must be ENOENT at this point */

	if (lookup_err) {
		/* Entry not found */
		if ((nameiop == CREATE || nameiop == RENAME) && islastcn) {
			err = fuse_internal_access(dvp, VWRITE, td, cred);
			if (!err) {
				/*
				 * Set the SAVENAME flag to hold onto the
				 * pathname for use later in VOP_CREATE or
				 * VOP_RENAME.
				 */
				cnp->cn_flags |= SAVENAME;

				err = EJUSTRETURN;
			}
		} else {
			err = ENOENT;
		}
	} else {
		/* Entry was found */
		if (flags & ISDOTDOT) {
			struct fuse_lookup_alloc_arg flaa;

			flaa.nid = nid;
			flaa.feo = feo;
			flaa.cnp = cnp;
			flaa.vtyp = vtyp;
			err = vn_vget_ino_gen(dvp, fuse_lookup_alloc, &flaa, 0,
				&vp);
			*vpp = vp;
		} else if (nid == VTOI(dvp)) {
			vref(dvp);
			*vpp = dvp;
		} else {
			struct fuse_vnode_data *fvdat;
			struct vattr *vap;

			err = fuse_vnode_get(vnode_mount(dvp), feo, nid, dvp,
			    &vp, cnp, vtyp);
			if (err)
				goto out;
			*vpp = vp;

			/*
			 * In the case where we are looking up a FUSE node
			 * represented by an existing cached vnode, and the
			 * true size reported by FUSE_LOOKUP doesn't match
			 * the vnode's cached size, then any cached writes
			 * beyond the file's current size are lost.
			 *
			 * We can get here:
			 * * following attribute cache expiration, or
			 * * due a bug in the daemon, or
			 */
			fvdat = VTOFUD(vp);
			if (vnode_isreg(vp) &&
			    ((filesize != fvdat->cached_attrs.va_size &&
			      fvdat->flag & FN_SIZECHANGE) ||
			     ((vap = VTOVA(vp)) &&
			      filesize != vap->va_size)))
			{
				SDT_PROBE2(fusefs, , vnops, lookup_cache_incoherent, vp, feo);
				fvdat->flag &= ~FN_SIZECHANGE;
				/*
				 * The server changed the file's size even
				 * though we had it cached, or had dirty writes
				 * in the WB cache!
				 */
				printf("%s: cache incoherent on %s!  "
		    		    "Buggy FUSE server detected.  To prevent "
				    "data corruption, disable the data cache "
				    "by mounting with -o direct_io, or as "
				    "directed otherwise by your FUSE server's "
		    		    "documentation\n", __func__,
				    vnode_mount(vp)->mnt_stat.f_mntonname);
				int iosize = fuse_iosize(vp);
				v_inval_buf_range(vp, 0, INT64_MAX, iosize);
			}

			MPASS(feo != NULL);
			fuse_internal_cache_attrs(*vpp, &feo->attr,
				feo->attr_valid, feo->attr_valid_nsec, NULL);
			fuse_validity_2_bintime(feo->entry_valid,
				feo->entry_valid_nsec,
				&fvdat->entry_cache_timeout);

			if ((nameiop == DELETE || nameiop == RENAME) &&
				islastcn)
			{
				struct vattr dvattr;

				err = fuse_internal_access(dvp, VWRITE, td,
					cred);
				if (err != 0)
					goto out;
				/* 
				 * if the parent's sticky bit is set, check
				 * whether we're allowed to remove the file.
				 * Need to figure out the vnode locking to make
				 * this work.
				 */
				fuse_internal_getattr(dvp, &dvattr, cred, td);
				if ((dvattr.va_mode & S_ISTXT) &&
					fuse_internal_access(dvp, VADMIN, td,
						cred) &&
					fuse_internal_access(*vpp, VADMIN, td,
						cred)) {
					err = EPERM;
					goto out;
				}
			}

			if (islastcn && (
				(nameiop == DELETE) ||
				(nameiop == RENAME && wantparent))) {
				cnp->cn_flags |= SAVENAME;
			}

		}
	}
out:
	if (err) {
		if (vp != NULL && dvp != vp)
			vput(vp);
		else if (vp != NULL)
			vrele(vp);
		*vpp = NULL;
	}
	if (did_lookup)
		fdisp_destroy(&fdi);

	return err;
}

/*
    struct vnop_mkdir_args {
	struct vnode *a_dvp;
	struct vnode **a_vpp;
	struct componentname *a_cnp;
	struct vattr *a_vap;
    };
*/
static int
fuse_vnop_mkdir(struct vop_mkdir_args *ap)
{
	struct vnode *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp;
	struct componentname *cnp = ap->a_cnp;
	struct vattr *vap = ap->a_vap;

	struct fuse_mkdir_in fmdi;

	if (fuse_isdeadfs(dvp)) {
		return ENXIO;
	}
	fmdi.mode = MAKEIMODE(vap->va_type, vap->va_mode);
	fmdi.umask = curthread->td_proc->p_fd->fd_cmask;

	return (fuse_internal_newentry(dvp, vpp, cnp, FUSE_MKDIR, &fmdi,
	    sizeof(fmdi), VDIR));
}

/*
    struct vnop_mknod_args {
	struct vnode *a_dvp;
	struct vnode **a_vpp;
	struct componentname *a_cnp;
	struct vattr *a_vap;
    };
*/
static int
fuse_vnop_mknod(struct vop_mknod_args *ap)
{

	struct vnode *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp;
	struct componentname *cnp = ap->a_cnp;
	struct vattr *vap = ap->a_vap;

	if (fuse_isdeadfs(dvp))
		return ENXIO;

	return fuse_internal_mknod(dvp, vpp, cnp, vap);
}

/*
    struct vop_open_args {
	struct vnode *a_vp;
	int  a_mode;
	struct ucred *a_cred;
	struct thread *a_td;
	int a_fdidx; / struct file *a_fp;
    };
*/
static int
fuse_vnop_open(struct vop_open_args *ap)
{
	struct vnode *vp = ap->a_vp;
	int a_mode = ap->a_mode;
	struct thread *td = ap->a_td;
	struct ucred *cred = ap->a_cred;
	pid_t pid = td->td_proc->p_pid;
	struct fuse_vnode_data *fvdat;

	if (fuse_isdeadfs(vp))
		return ENXIO;
	if (vp->v_type == VCHR || vp->v_type == VBLK || vp->v_type == VFIFO)
		return (EOPNOTSUPP);
	if ((a_mode & (FREAD | FWRITE | FEXEC)) == 0)
		return EINVAL;

	fvdat = VTOFUD(vp);

	if (fuse_filehandle_validrw(vp, a_mode, cred, pid)) {
		fuse_vnode_open(vp, 0, td);
		return 0;
	}

	return fuse_filehandle_open(vp, a_mode, NULL, td, cred);
}

static int
fuse_vnop_pathconf(struct vop_pathconf_args *ap)
{

	switch (ap->a_name) {
	case _PC_FILESIZEBITS:
		*ap->a_retval = 64;
		return (0);
	case _PC_NAME_MAX:
		*ap->a_retval = NAME_MAX;
		return (0);
	case _PC_LINK_MAX:
		*ap->a_retval = MIN(LONG_MAX, FUSE_LINK_MAX);
		return (0);
	case _PC_SYMLINK_MAX:
		*ap->a_retval = MAXPATHLEN;
		return (0);
	case _PC_NO_TRUNC:
		*ap->a_retval = 1;
		return (0);
	default:
		return (vop_stdpathconf(ap));
	}
}

/*
    struct vnop_read_args {
	struct vnode *a_vp;
	struct uio *a_uio;
	int  a_ioflag;
	struct ucred *a_cred;
    };
*/
static int
fuse_vnop_read(struct vop_read_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	int ioflag = ap->a_ioflag;
	struct ucred *cred = ap->a_cred;
	pid_t pid = curthread->td_proc->p_pid;

	if (fuse_isdeadfs(vp)) {
		return ENXIO;
	}

	if (VTOFUD(vp)->flag & FN_DIRECTIO) {
		ioflag |= IO_DIRECT;
	}

	return fuse_io_dispatch(vp, uio, ioflag, cred, pid);
}

/*
    struct vnop_readdir_args {
	struct vnode *a_vp;
	struct uio *a_uio;
	struct ucred *a_cred;
	int *a_eofflag;
	int *a_ncookies;
	u_long **a_cookies;
    };
*/
static int
fuse_vnop_readdir(struct vop_readdir_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct ucred *cred = ap->a_cred;
	struct fuse_filehandle *fufh = NULL;
	struct fuse_iov cookediov;
	int err = 0;
	u_long *cookies;
	off_t startoff;
	ssize_t tresid;
	int ncookies;
	bool closefufh = false;
	pid_t pid = curthread->td_proc->p_pid;

	if (ap->a_eofflag)
		*ap->a_eofflag = 0;
	if (fuse_isdeadfs(vp)) {
		return ENXIO;
	}
	if (				/* XXXIP ((uio_iovcnt(uio) > 1)) || */
	    (uio_resid(uio) < sizeof(struct dirent))) {
		return EINVAL;
	}

	tresid = uio->uio_resid;
	startoff = uio->uio_offset;
	err = fuse_filehandle_get_dir(vp, &fufh, cred, pid);
	if (err == EBADF && vnode_mount(vp)->mnt_flag & MNT_EXPORTED) {
		/* 
		 * nfsd will do VOP_READDIR without first doing VOP_OPEN.  We
		 * must implicitly open the directory here
		 */
		err = fuse_filehandle_open(vp, FREAD, &fufh, curthread, cred);
		if (err == 0) {
			/*
			 * When a directory is opened, it must be read from
			 * the beginning.  Hopefully, the "startoff" still
			 * exists as an offset cookie for the directory.
			 * If not, it will read the entire directory without
			 * returning any entries and just return eof.
			 */
			uio->uio_offset = 0;
		}
		closefufh = true;
	}
	if (err)
		return (err);
	if (ap->a_ncookies != NULL) {
		ncookies = uio->uio_resid /
			(offsetof(struct dirent, d_name) + 4) + 1;
		cookies = malloc(ncookies * sizeof(*cookies), M_TEMP, M_WAITOK);
		*ap->a_ncookies = ncookies;
		*ap->a_cookies = cookies;
	} else {
		ncookies = 0;
		cookies = NULL;
	}
#define DIRCOOKEDSIZE FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + MAXNAMLEN + 1)
	fiov_init(&cookediov, DIRCOOKEDSIZE);

	err = fuse_internal_readdir(vp, uio, startoff, fufh, &cookediov,
		&ncookies, cookies);

	fiov_teardown(&cookediov);
	if (closefufh)
		fuse_filehandle_close(vp, fufh, curthread, cred);

	if (ap->a_ncookies != NULL) {
		if (err == 0) {
			*ap->a_ncookies -= ncookies;
		} else {
			free(*ap->a_cookies, M_TEMP);
			*ap->a_ncookies = 0;
			*ap->a_cookies = NULL;
		}
	}
	if (err == 0 && tresid == uio->uio_resid)
		*ap->a_eofflag = 1;

	return err;
}

/*
    struct vnop_readlink_args {
	struct vnode *a_vp;
	struct uio *a_uio;
	struct ucred *a_cred;
    };
*/
static int
fuse_vnop_readlink(struct vop_readlink_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct ucred *cred = ap->a_cred;

	struct fuse_dispatcher fdi;
	int err;

	if (fuse_isdeadfs(vp)) {
		return ENXIO;
	}
	if (!vnode_islnk(vp)) {
		return EINVAL;
	}
	fdisp_init(&fdi, 0);
	err = fdisp_simple_putget_vp(&fdi, FUSE_READLINK, vp, curthread, cred);
	if (err) {
		goto out;
	}
	if (((char *)fdi.answ)[0] == '/' &&
	    fuse_get_mpdata(vnode_mount(vp))->dataflags & FSESS_PUSH_SYMLINKS_IN) {
		char *mpth = vnode_mount(vp)->mnt_stat.f_mntonname;

		err = uiomove(mpth, strlen(mpth), uio);
	}
	if (!err) {
		err = uiomove(fdi.answ, fdi.iosize, uio);
	}
out:
	fdisp_destroy(&fdi);
	return err;
}

/*
    struct vnop_reclaim_args {
	struct vnode *a_vp;
	struct thread *a_td;
    };
*/
static int
fuse_vnop_reclaim(struct vop_reclaim_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct thread *td = ap->a_td;
	struct fuse_vnode_data *fvdat = VTOFUD(vp);
	struct fuse_filehandle *fufh, *fufh_tmp;

	if (!fvdat) {
		panic("FUSE: no vnode data during recycling");
	}
	LIST_FOREACH_SAFE(fufh, &fvdat->handles, next, fufh_tmp) {
		printf("FUSE: vnode being reclaimed with open fufh "
			"(type=%#x)", fufh->fufh_type);
		fuse_filehandle_close(vp, fufh, td, NULL);
	}

	if (!fuse_isdeadfs(vp) && fvdat->nlookup > 0) {
		fuse_internal_forget_send(vnode_mount(vp), td, NULL, VTOI(vp),
		    fvdat->nlookup);
	}
	cache_purge(vp);
	vfs_hash_remove(vp);
	fuse_vnode_destroy(vp);

	return 0;
}

/*
    struct vnop_remove_args {
	struct vnode *a_dvp;
	struct vnode *a_vp;
	struct componentname *a_cnp;
    };
*/
static int
fuse_vnop_remove(struct vop_remove_args *ap)
{
	struct vnode *dvp = ap->a_dvp;
	struct vnode *vp = ap->a_vp;
	struct componentname *cnp = ap->a_cnp;

	int err;

	if (fuse_isdeadfs(vp)) {
		return ENXIO;
	}
	if (vnode_isdir(vp)) {
		return EPERM;
	}

	err = fuse_internal_remove(dvp, vp, cnp, FUSE_UNLINK);

	return err;
}

/*
    struct vnop_rename_args {
	struct vnode *a_fdvp;
	struct vnode *a_fvp;
	struct componentname *a_fcnp;
	struct vnode *a_tdvp;
	struct vnode *a_tvp;
	struct componentname *a_tcnp;
    };
*/
static int
fuse_vnop_rename(struct vop_rename_args *ap)
{
	struct vnode *fdvp = ap->a_fdvp;
	struct vnode *fvp = ap->a_fvp;
	struct componentname *fcnp = ap->a_fcnp;
	struct vnode *tdvp = ap->a_tdvp;
	struct vnode *tvp = ap->a_tvp;
	struct componentname *tcnp = ap->a_tcnp;
	struct fuse_data *data;
	bool newparent = fdvp != tdvp;
	bool isdir = fvp->v_type == VDIR;
	int err = 0;

	if (fuse_isdeadfs(fdvp)) {
		return ENXIO;
	}
	if (fvp->v_mount != tdvp->v_mount ||
	    (tvp && fvp->v_mount != tvp->v_mount)) {
		SDT_PROBE2(fusefs, , vnops, trace, 1, "cross-device rename");
		err = EXDEV;
		goto out;
	}
	cache_purge(fvp);

	/*
	 * FUSE library is expected to check if target directory is not
	 * under the source directory in the file system tree.
	 * Linux performs this check at VFS level.
	 */
	/* 
	 * If source is a directory, and it will get a new parent, user must
	 * have write permission to it, so ".." can be modified.
	 */
	data = fuse_get_mpdata(vnode_mount(tdvp));
	if (data->dataflags & FSESS_DEFAULT_PERMISSIONS && isdir && newparent) {
		err = fuse_internal_access(fvp, VWRITE,
			tcnp->cn_thread, tcnp->cn_cred);
		if (err)
			goto out;
	}
	sx_xlock(&data->rename_lock);
	err = fuse_internal_rename(fdvp, fcnp, tdvp, tcnp);
	if (err == 0) {
		if (tdvp != fdvp)
			fuse_vnode_setparent(fvp, tdvp);
		if (tvp != NULL)
			fuse_vnode_setparent(tvp, NULL);
	}
	sx_unlock(&data->rename_lock);

	if (tvp != NULL && tvp != fvp) {
		cache_purge(tvp);
	}
	if (vnode_isdir(fvp)) {
		if ((tvp != NULL) && vnode_isdir(tvp)) {
			cache_purge(tdvp);
		}
		cache_purge(fdvp);
	}
out:
	if (tdvp == tvp) {
		vrele(tdvp);
	} else {
		vput(tdvp);
	}
	if (tvp != NULL) {
		vput(tvp);
	}
	vrele(fdvp);
	vrele(fvp);

	return err;
}

/*
    struct vnop_rmdir_args {
	    struct vnode *a_dvp;
	    struct vnode *a_vp;
	    struct componentname *a_cnp;
    } *ap;
*/
static int
fuse_vnop_rmdir(struct vop_rmdir_args *ap)
{
	struct vnode *dvp = ap->a_dvp;
	struct vnode *vp = ap->a_vp;

	int err;

	if (fuse_isdeadfs(vp)) {
		return ENXIO;
	}
	if (VTOFUD(vp) == VTOFUD(dvp)) {
		return EINVAL;
	}
	err = fuse_internal_remove(dvp, vp, ap->a_cnp, FUSE_RMDIR);

	return err;
}

/*
    struct vnop_setattr_args {
	struct vnode *a_vp;
	struct vattr *a_vap;
	struct ucred *a_cred;
	struct thread *a_td;
    };
*/
static int
fuse_vnop_setattr(struct vop_setattr_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct vattr *vap = ap->a_vap;
	struct ucred *cred = ap->a_cred;
	struct thread *td = curthread;
	struct mount *mp;
	struct fuse_data *data;
	struct vattr old_va;
	int dataflags;
	int err = 0, err2;
	accmode_t accmode = 0;
	bool checkperm;
	bool drop_suid = false;
	gid_t cr_gid;

	mp = vnode_mount(vp);
	data = fuse_get_mpdata(mp);
	dataflags = data->dataflags;
	checkperm = dataflags & FSESS_DEFAULT_PERMISSIONS;
	if (cred->cr_ngroups > 0)
		cr_gid = cred->cr_groups[0];
	else
		cr_gid = 0;

	if (fuse_isdeadfs(vp)) {
		return ENXIO;
	}

	if (vap->va_uid != (uid_t)VNOVAL) {
		if (checkperm) {
			/* Only root may change a file's owner */
			err = priv_check_cred(cred, PRIV_VFS_CHOWN);
			if (err) {
				/* As a special case, allow the null chown */
				err2 = fuse_internal_getattr(vp, &old_va, cred,
					td);
				if (err2)
					return (err2);
				if (vap->va_uid != old_va.va_uid)
					return err;
				else
					accmode |= VADMIN;
				drop_suid = true;
			} else
				accmode |= VADMIN;
		} else
			accmode |= VADMIN;
	}
	if (vap->va_gid != (gid_t)VNOVAL) {
		if (checkperm && priv_check_cred(cred, PRIV_VFS_CHOWN))
			drop_suid = true;
		if (checkperm && !groupmember(vap->va_gid, cred))
		{
			/*
			 * Non-root users may only chgrp to one of their own
			 * groups 
			 */
			err = priv_check_cred(cred, PRIV_VFS_CHOWN);
			if (err) {
				/* As a special case, allow the null chgrp */
				err2 = fuse_internal_getattr(vp, &old_va, cred,
					td);
				if (err2)
					return (err2);
				if (vap->va_gid != old_va.va_gid)
					return err;
				accmode |= VADMIN;
			} else
				accmode |= VADMIN;
		} else
			accmode |= VADMIN;
	}
	if (vap->va_size != VNOVAL) {
		switch (vp->v_type) {
		case VDIR:
			return (EISDIR);
		case VLNK:
		case VREG:
			if (vfs_isrdonly(mp))
				return (EROFS);
			break;
		default:
			/*
			 * According to POSIX, the result is unspecified
			 * for file types other than regular files,
			 * directories and shared memory objects.  We
			 * don't support shared memory objects in the file
			 * system, and have dubious support for truncating
			 * symlinks.  Just ignore the request in other cases.
			 */
			return (0);
		}
		/* Don't set accmode.  Permission to trunc is checked upstack */
	}
	if (vap->va_atime.tv_sec != VNOVAL || vap->va_mtime.tv_sec != VNOVAL) {
		if (vap->va_vaflags & VA_UTIMES_NULL)
			accmode |= VWRITE;
		else
			accmode |= VADMIN;
	}
	if (drop_suid) {
		if (vap->va_mode != (mode_t)VNOVAL)
			vap->va_mode &= ~(S_ISUID | S_ISGID);
		else {
			err = fuse_internal_getattr(vp, &old_va, cred, td);
			if (err)
				return (err);
			vap->va_mode = old_va.va_mode & ~(S_ISUID | S_ISGID);
		}
	}
	if (vap->va_mode != (mode_t)VNOVAL) {
		/* Only root may set the sticky bit on non-directories */
		if (checkperm && vp->v_type != VDIR && (vap->va_mode & S_ISTXT)
		    && priv_check_cred(cred, PRIV_VFS_STICKYFILE))
			return EFTYPE;
		if (checkperm && (vap->va_mode & S_ISGID)) {
			err = fuse_internal_getattr(vp, &old_va, cred, td);
			if (err)
				return (err);
			if (!groupmember(old_va.va_gid, cred)) {
				err = priv_check_cred(cred, PRIV_VFS_SETGID);
				if (err)
					return (err);
			}
		}
		accmode |= VADMIN;
	}

	if (vfs_isrdonly(mp))
		return EROFS;

	err = fuse_internal_access(vp, accmode, td, cred);
	if (err)
		return err;
	else
		return fuse_internal_setattr(vp, vap, td, cred);
}

/*
    struct vnop_strategy_args {
	struct vnode *a_vp;
	struct buf *a_bp;
    };
*/
static int
fuse_vnop_strategy(struct vop_strategy_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct buf *bp = ap->a_bp;

	if (!vp || fuse_isdeadfs(vp)) {
		bp->b_ioflags |= BIO_ERROR;
		bp->b_error = ENXIO;
		bufdone(bp);
		return 0;
	}

	/*
	 * VOP_STRATEGY always returns zero and signals error via bp->b_ioflags.
	 * fuse_io_strategy sets bp's error fields
	 */
	(void)fuse_io_strategy(vp, bp);

	return 0;
}


/*
    struct vnop_symlink_args {
	struct vnode *a_dvp;
	struct vnode **a_vpp;
	struct componentname *a_cnp;
	struct vattr *a_vap;
	char *a_target;
    };
*/
static int
fuse_vnop_symlink(struct vop_symlink_args *ap)
{
	struct vnode *dvp = ap->a_dvp;
	struct vnode **vpp = ap->a_vpp;
	struct componentname *cnp = ap->a_cnp;
	const char *target = ap->a_target;

	struct fuse_dispatcher fdi;

	int err;
	size_t len;

	if (fuse_isdeadfs(dvp)) {
		return ENXIO;
	}
	/*
	 * Unlike the other creator type calls, here we have to create a message
	 * where the name of the new entry comes first, and the data describing
	 * the entry comes second.
	 * Hence we can't rely on our handy fuse_internal_newentry() routine,
	 * but put together the message manually and just call the core part.
	 */

	len = strlen(target) + 1;
	fdisp_init(&fdi, len + cnp->cn_namelen + 1);
	fdisp_make_vp(&fdi, FUSE_SYMLINK, dvp, curthread, NULL);

	memcpy(fdi.indata, cnp->cn_nameptr, cnp->cn_namelen);
	((char *)fdi.indata)[cnp->cn_namelen] = '\0';
	memcpy((char *)fdi.indata + cnp->cn_namelen + 1, target, len);

	err = fuse_internal_newentry_core(dvp, vpp, cnp, VLNK, &fdi);
	fdisp_destroy(&fdi);
	return err;
}

/*
    struct vnop_write_args {
	struct vnode *a_vp;
	struct uio *a_uio;
	int  a_ioflag;
	struct ucred *a_cred;
    };
*/
static int
fuse_vnop_write(struct vop_write_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	int ioflag = ap->a_ioflag;
	struct ucred *cred = ap->a_cred;
	pid_t pid = curthread->td_proc->p_pid;

	if (fuse_isdeadfs(vp)) {
		return ENXIO;
	}

	if (VTOFUD(vp)->flag & FN_DIRECTIO) {
		ioflag |= IO_DIRECT;
	}

	return fuse_io_dispatch(vp, uio, ioflag, cred, pid);
}

static daddr_t
fuse_gbp_getblkno(struct vnode *vp, vm_ooffset_t off)
{
	const int biosize = fuse_iosize(vp);

	return (off / biosize);
}

static int
fuse_gbp_getblksz(struct vnode *vp, daddr_t lbn)
{
	off_t filesize;
	int blksz, err;
	const int biosize = fuse_iosize(vp);

	err = fuse_vnode_size(vp, &filesize, NULL, NULL);
	KASSERT(err == 0, ("vfs_bio_getpages can't handle errors here"));
	if (err)
		return biosize;

	if ((off_t)lbn * biosize >= filesize) {
		blksz = 0;
	} else if ((off_t)(lbn + 1) * biosize > filesize) {
		blksz = filesize - (off_t)lbn *biosize;
	} else {
		blksz = biosize;
	}
	return (blksz);
}

/*
    struct vnop_getpages_args {
	struct vnode *a_vp;
	vm_page_t *a_m;
	int a_count;
	int a_reqpage;
    };
*/
static int
fuse_vnop_getpages(struct vop_getpages_args *ap)
{
	struct vnode *vp = ap->a_vp;

	if (!fsess_opt_mmap(vnode_mount(vp))) {
		SDT_PROBE2(fusefs, , vnops, trace, 1,
			"called on non-cacheable vnode??\n");
		return (VM_PAGER_ERROR);
	}

	return (vfs_bio_getpages(vp, ap->a_m, ap->a_count, ap->a_rbehind,
	    ap->a_rahead, fuse_gbp_getblkno, fuse_gbp_getblksz));
}

static const char extattr_namespace_separator = '.';

/*
    struct vop_getextattr_args {
	struct vop_generic_args a_gen;
	struct vnode *a_vp;
	int a_attrnamespace;
	const char *a_name;
	struct uio *a_uio;
	size_t *a_size;
	struct ucred *a_cred;
	struct thread *a_td;
    };
*/
static int
fuse_vnop_getextattr(struct vop_getextattr_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct fuse_dispatcher fdi;
	struct fuse_getxattr_in *get_xattr_in;
	struct fuse_getxattr_out *get_xattr_out;
	struct mount *mp = vnode_mount(vp);
	struct thread *td = ap->a_td;
	struct ucred *cred = ap->a_cred;
	char *prefix;
	char *attr_str;
	size_t len;
	int err;

	if (fuse_isdeadfs(vp))
		return (ENXIO);

	if (!fsess_isimpl(mp, FUSE_GETXATTR))
		return EOPNOTSUPP;

	err = fuse_extattr_check_cred(vp, ap->a_attrnamespace, cred, td, VREAD);
	if (err)
		return err;

	/* Default to looking for user attributes. */
	if (ap->a_attrnamespace == EXTATTR_NAMESPACE_SYSTEM)
		prefix = EXTATTR_NAMESPACE_SYSTEM_STRING;
	else
		prefix = EXTATTR_NAMESPACE_USER_STRING;

	len = strlen(prefix) + sizeof(extattr_namespace_separator) +
	    strlen(ap->a_name) + 1;

	fdisp_init(&fdi, len + sizeof(*get_xattr_in));
	fdisp_make_vp(&fdi, FUSE_GETXATTR, vp, td, cred);

	get_xattr_in = fdi.indata;
	/*
	 * Check to see whether we're querying the available size or
	 * issuing the actual request.  If we pass in 0, we get back struct
	 * fuse_getxattr_out.  If we pass in a non-zero size, we get back
	 * that much data, without the struct fuse_getxattr_out header.
	 */
	if (uio == NULL)
		get_xattr_in->size = 0;
	else
		get_xattr_in->size = uio->uio_resid;

	attr_str = (char *)fdi.indata + sizeof(*get_xattr_in);
	snprintf(attr_str, len, "%s%c%s", prefix, extattr_namespace_separator,
	    ap->a_name);

	err = fdisp_wait_answ(&fdi);
	if (err != 0) {
		if (err == ENOSYS) {
			fsess_set_notimpl(mp, FUSE_GETXATTR);
			err = EOPNOTSUPP;
		}
		goto out;
	}

	get_xattr_out = fdi.answ;

	if (ap->a_size != NULL)
		*ap->a_size = get_xattr_out->size;

	if (uio != NULL)
		err = uiomove(fdi.answ, fdi.iosize, uio);

out:
	fdisp_destroy(&fdi);
	return (err);
}

/*
    struct vop_setextattr_args {
	struct vop_generic_args a_gen;
	struct vnode *a_vp;
	int a_attrnamespace;
	const char *a_name;
	struct uio *a_uio;
	struct ucred *a_cred;
	struct thread *a_td;
    };
*/
static int
fuse_vnop_setextattr(struct vop_setextattr_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct fuse_dispatcher fdi;
	struct fuse_setxattr_in *set_xattr_in;
	struct mount *mp = vnode_mount(vp);
	struct thread *td = ap->a_td;
	struct ucred *cred = ap->a_cred;
	char *prefix;
	size_t len;
	char *attr_str;
	int err;
	
	if (fuse_isdeadfs(vp))
		return (ENXIO);

	if (!fsess_isimpl(mp, FUSE_SETXATTR))
		return EOPNOTSUPP;

	if (vfs_isrdonly(mp))
		return EROFS;

	/* Deleting xattrs must use VOP_DELETEEXTATTR instead */
	if (ap->a_uio == NULL) {
		/*
		 * If we got here as fallback from VOP_DELETEEXTATTR, then
		 * return EOPNOTSUPP.
		 */
		if (!fsess_isimpl(mp, FUSE_REMOVEXATTR))
			return (EOPNOTSUPP);
		else
			return (EINVAL);
	}

	err = fuse_extattr_check_cred(vp, ap->a_attrnamespace, cred, td,
		VWRITE);
	if (err)
		return err;

	/* Default to looking for user attributes. */
	if (ap->a_attrnamespace == EXTATTR_NAMESPACE_SYSTEM)
		prefix = EXTATTR_NAMESPACE_SYSTEM_STRING;
	else
		prefix = EXTATTR_NAMESPACE_USER_STRING;

	len = strlen(prefix) + sizeof(extattr_namespace_separator) +
	    strlen(ap->a_name) + 1;

	fdisp_init(&fdi, len + sizeof(*set_xattr_in) + uio->uio_resid);
	fdisp_make_vp(&fdi, FUSE_SETXATTR, vp, td, cred);

	set_xattr_in = fdi.indata;
	set_xattr_in->size = uio->uio_resid;

	attr_str = (char *)fdi.indata + sizeof(*set_xattr_in);
	snprintf(attr_str, len, "%s%c%s", prefix, extattr_namespace_separator,
	    ap->a_name);

	err = uiomove((char *)fdi.indata + sizeof(*set_xattr_in) + len,
	    uio->uio_resid, uio);
	if (err != 0) {
		goto out;
	}

	err = fdisp_wait_answ(&fdi);

	if (err == ENOSYS) {
		fsess_set_notimpl(mp, FUSE_SETXATTR);
		err = EOPNOTSUPP;
	}
	if (err == ERESTART) {
		/* Can't restart after calling uiomove */
		err = EINTR;
	}

out:
	fdisp_destroy(&fdi);
	return (err);
}

/*
 * The Linux / FUSE extended attribute list is simply a collection of
 * NUL-terminated strings.  The FreeBSD extended attribute list is a single
 * byte length followed by a non-NUL terminated string.  So, this allows
 * conversion of the Linux / FUSE format to the FreeBSD format in place.
 * Linux attribute names are reported with the namespace as a prefix (e.g.
 * "user.attribute_name"), but in FreeBSD they are reported without the
 * namespace prefix (e.g. "attribute_name").  So, we're going from:
 *
 * user.attr_name1\0user.attr_name2\0
 *
 * to:
 *
 * <num>attr_name1<num>attr_name2
 *
 * Where "<num>" is a single byte number of characters in the attribute name.
 * 
 * Args:
 * prefix - exattr namespace prefix string
 * list, list_len - input list with namespace prefixes
 * bsd_list, bsd_list_len - output list compatible with bsd vfs
 */
static int
fuse_xattrlist_convert(char *prefix, const char *list, int list_len,
    char *bsd_list, int *bsd_list_len)
{
	int len, pos, dist_to_next, prefix_len;

	pos = 0;
	*bsd_list_len = 0;
	prefix_len = strlen(prefix);

	while (pos < list_len && list[pos] != '\0') {
		dist_to_next = strlen(&list[pos]) + 1;
		if (bcmp(&list[pos], prefix, prefix_len) == 0 &&
		    list[pos + prefix_len] == extattr_namespace_separator) {
			len = dist_to_next -
			    (prefix_len + sizeof(extattr_namespace_separator)) - 1;
			if (len >= EXTATTR_MAXNAMELEN)
				return (ENAMETOOLONG);

			bsd_list[*bsd_list_len] = len;
			memcpy(&bsd_list[*bsd_list_len + 1],
			    &list[pos + prefix_len +
			    sizeof(extattr_namespace_separator)], len);

			*bsd_list_len += len + 1;
		}

		pos += dist_to_next;
	}

	return (0);
}

/*
 * List extended attributes
 *
 * The FUSE_LISTXATTR operation is based on Linux's listxattr(2) syscall, which
 * has a number of differences compared to its FreeBSD equivalent,
 * extattr_list_file:
 *
 * - FUSE_LISTXATTR returns all extended attributes across all namespaces,
 *   whereas listxattr(2) only returns attributes for a single namespace
 * - FUSE_LISTXATTR prepends each attribute name with "namespace."
 * - If the provided buffer is not large enough to hold the result,
 *   FUSE_LISTXATTR should return ERANGE, whereas listxattr is expected to
 *   return as many results as will fit.
 */
/*
    struct vop_listextattr_args {
	struct vop_generic_args a_gen;
	struct vnode *a_vp;
	int a_attrnamespace;
	struct uio *a_uio;
	size_t *a_size;
	struct ucred *a_cred;
	struct thread *a_td;
    };
*/
static int
fuse_vnop_listextattr(struct vop_listextattr_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct fuse_dispatcher fdi;
	struct fuse_listxattr_in *list_xattr_in;
	struct fuse_listxattr_out *list_xattr_out;
	struct mount *mp = vnode_mount(vp);
	struct thread *td = ap->a_td;
	struct ucred *cred = ap->a_cred;
	char *prefix;
	char *bsd_list = NULL;
	char *linux_list;
	int bsd_list_len;
	int linux_list_len;
	int err;

	if (fuse_isdeadfs(vp))
		return (ENXIO);

	if (!fsess_isimpl(mp, FUSE_LISTXATTR))
		return EOPNOTSUPP;

	err = fuse_extattr_check_cred(vp, ap->a_attrnamespace, cred, td, VREAD);
	if (err)
		return err;

	/*
	 * Add space for a NUL and the period separator if enabled.
	 * Default to looking for user attributes.
	 */
	if (ap->a_attrnamespace == EXTATTR_NAMESPACE_SYSTEM)
		prefix = EXTATTR_NAMESPACE_SYSTEM_STRING;
	else
		prefix = EXTATTR_NAMESPACE_USER_STRING;

	fdisp_init(&fdi, sizeof(*list_xattr_in));
	fdisp_make_vp(&fdi, FUSE_LISTXATTR, vp, td, cred);

	/*
	 * Retrieve Linux / FUSE compatible list size.
	 */
	list_xattr_in = fdi.indata;
	list_xattr_in->size = 0;

	err = fdisp_wait_answ(&fdi);
	if (err != 0) {
		if (err == ENOSYS) {
			fsess_set_notimpl(mp, FUSE_LISTXATTR);
			err = EOPNOTSUPP;
		}
		goto out;
	}

	list_xattr_out = fdi.answ;
	linux_list_len = list_xattr_out->size;
	if (linux_list_len == 0) {
		if (ap->a_size != NULL)
			*ap->a_size = linux_list_len;
		goto out;
	}

	/*
	 * Retrieve Linux / FUSE compatible list values.
	 */
	fdisp_refresh_vp(&fdi, FUSE_LISTXATTR, vp, td, cred);
	list_xattr_in = fdi.indata;
	list_xattr_in->size = linux_list_len;

	err = fdisp_wait_answ(&fdi);
	if (err == ERANGE) {
		/* 
		 * Race detected.  The attribute list must've grown since the
		 * first FUSE_LISTXATTR call.  Start over.  Go all the way back
		 * to userland so we can process signals, if necessary, before
		 * restarting.
		 */
		err = ERESTART;
		goto out;
	} else if (err != 0)
		goto out;

	linux_list = fdi.answ;
	/* FUSE doesn't allow the server to return more data than requested */
	if (fdi.iosize > linux_list_len) {
		printf("WARNING: FUSE protocol violation.  Server returned "
			"more extended attribute data than requested; "
			"should've returned ERANGE instead");
	} else {
		/* But returning less data is fine */
		linux_list_len = fdi.iosize;
	}

	/*
	 * Retrieve the BSD compatible list values.
	 * The Linux / FUSE attribute list format isn't the same
	 * as FreeBSD's format. So we need to transform it into
	 * FreeBSD's format before giving it to the user.
	 */
	bsd_list = malloc(linux_list_len, M_TEMP, M_WAITOK);
	err = fuse_xattrlist_convert(prefix, linux_list, linux_list_len,
	    bsd_list, &bsd_list_len);
	if (err != 0)
		goto out;

	if (ap->a_size != NULL)
		*ap->a_size = bsd_list_len;

	if (uio != NULL)
		err = uiomove(bsd_list, bsd_list_len, uio);

out:
	free(bsd_list, M_TEMP);
	fdisp_destroy(&fdi);
	return (err);
}

/*
    struct vop_deleteextattr_args {
	struct vop_generic_args a_gen;
	struct vnode *a_vp;
	int a_attrnamespace;
	const char *a_name;
	struct ucred *a_cred;
	struct thread *a_td;
    };
*/
static int
fuse_vnop_deleteextattr(struct vop_deleteextattr_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct fuse_dispatcher fdi;
	struct mount *mp = vnode_mount(vp);
	struct thread *td = ap->a_td;
	struct ucred *cred = ap->a_cred;
	char *prefix;
	size_t len;
	char *attr_str;
	int err;

	if (fuse_isdeadfs(vp))
		return (ENXIO);

	if (!fsess_isimpl(mp, FUSE_REMOVEXATTR))
		return EOPNOTSUPP;

	if (vfs_isrdonly(mp))
		return EROFS;

	err = fuse_extattr_check_cred(vp, ap->a_attrnamespace, cred, td,
		VWRITE);
	if (err)
		return err;

	/* Default to looking for user attributes. */
	if (ap->a_attrnamespace == EXTATTR_NAMESPACE_SYSTEM)
		prefix = EXTATTR_NAMESPACE_SYSTEM_STRING;
	else
		prefix = EXTATTR_NAMESPACE_USER_STRING;

	len = strlen(prefix) + sizeof(extattr_namespace_separator) +
	    strlen(ap->a_name) + 1;

	fdisp_init(&fdi, len);
	fdisp_make_vp(&fdi, FUSE_REMOVEXATTR, vp, td, cred);

	attr_str = fdi.indata;
	snprintf(attr_str, len, "%s%c%s", prefix, extattr_namespace_separator,
	    ap->a_name);

	err = fdisp_wait_answ(&fdi);
	if (err == ENOSYS) {
		fsess_set_notimpl(mp, FUSE_REMOVEXATTR);
		err = EOPNOTSUPP;
	}

	fdisp_destroy(&fdi);
	return (err);
}

/*
    struct vnop_print_args {
	struct vnode *a_vp;
    };
*/
static int
fuse_vnop_print(struct vop_print_args *ap)
{
	struct fuse_vnode_data *fvdat = VTOFUD(ap->a_vp);

	printf("nodeid: %ju, parent nodeid: %ju, nlookup: %ju, flag: %#x\n",
	    (uintmax_t)VTOILLU(ap->a_vp), (uintmax_t)fvdat->parent_nid,
	    (uintmax_t)fvdat->nlookup,
	    fvdat->flag);

	return 0;
}
	
/*
 * Get an NFS filehandle for a FUSE file.
 *
 * This will only work for FUSE file systems that guarantee the uniqueness of
 * nodeid:generation, which most don't.
 */
/*
vop_vptofh {
	IN struct vnode *a_vp;
	IN struct fid *a_fhp;
};
*/
static int
fuse_vnop_vptofh(struct vop_vptofh_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct fuse_vnode_data *fvdat = VTOFUD(vp);
	struct fuse_fid *fhp = (struct fuse_fid *)(ap->a_fhp);
	_Static_assert(sizeof(struct fuse_fid) <= sizeof(struct fid),
		"FUSE fid type is too big");
	struct mount *mp = vnode_mount(vp);
	struct fuse_data *data = fuse_get_mpdata(mp);
	struct vattr va;
	int err;

	if (!(data->dataflags & FSESS_EXPORT_SUPPORT))
		return EOPNOTSUPP;

	err = fuse_internal_getattr(vp, &va, curthread->td_ucred, curthread);
	if (err)
		return err;

	/*ip = VTOI(ap->a_vp);*/
	/*ufhp = (struct ufid *)ap->a_fhp;*/
	fhp->len = sizeof(struct fuse_fid);
	fhp->nid = fvdat->nid;
	if (fvdat->generation <= UINT32_MAX)
		fhp->gen = fvdat->generation;
	else
		return EOVERFLOW;
	return (0);
}


