/*-
 * Copyright (c) 2025 Edward Tomasz Napierala <trasz@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This software was developed by SRI International, the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology), and Capabilities Limited under Defense Advanced Research
 * Projects Agency (DARPA) Contract No. FA8750-24-C-B047 ("DEC").
 */

#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/dirent.h>
#include <sys/fcntl.h>
#include <sys/lockmgr.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/vnode.h>

#undef b_error

#include <linux/types.h>
#include <linux/kobject.h>
#include <linux/completion.h>
#include <linux/atomic.h>
#include <linux/fs.h>

#undef brelse

MALLOC_DEFINE(M_LKPIVFS, "lkpivfs", "Linux VFS compat");

static struct file_system_type *global_fst = NULL; // XXX
struct mnt_idmap	nop_mnt_idmap; // XXX
struct user_namespace	init_user_ns;

#define VFSTOSB(mp)    ((struct super_block *)((mp)->mnt_data))

struct buffer_head *
sb_bread(struct super_block *sb, sector_t lbn)
{
	struct vnode *devvp;
	struct buf *bp = NULL;
	size_t size = 512;
	int error;

	devvp = sb->s_devvp;
	MPASS(devvp->v_state = VSTATE_CONSTRUCTED);

	// XXX why
	lbn *= 8;

	if (sb->s_blocksize != 0)
		size = sb->s_blocksize;

	error = bread(devvp, lbn, size, NOCRED, &bp);
	if (error != 0) {
		printf("%s: bread %zd from %lu returned %d\n", __func__, size, lbn, error);
		brelse(bp);
		return (NULL);
	}

	return ((struct buffer_head *)bp);
}

/*
 * This is what gets called when Linux code calls brelse()
 */
void
lkpi_brelse(struct buffer_head *bh)
{
	//printf("%s: bp %p\n", __func__, bh);
	brelse((struct buf *)bh);
}

static int
lkpi_access(struct vop_access_args *ap)
{
	struct vnode *vp = ap->a_vp;
	accmode_t accmode = ap->a_accmode;
	int error;

	/*
	 * Disallow write attempts on read-only filesystems;
	 * unless the file is a socket, fifo, or a block or
	 * character device resident on the filesystem.
	 */
	if (accmode & VMODIFY_PERMS) {
		switch (vp->v_type) {
		case VDIR:
		case VLNK:
		case VREG:
			if (vp->v_mount->mnt_flag & MNT_RDONLY)
				return (EROFS);
			break;
		default:
			break;
		}
	}

	error = vaccess(vp->v_type, vp->i_mode, vp->i_uid, vp->i_gid,
	    accmode, ap->a_cred);

	return (error);
}

static int
lkpi_lookup(struct vop_lookup_args *ap)
{
	struct vnode *dvp, *vp, **vpp;
	struct dentry child_dentry, *dentry;
	struct componentname *cnp;
	int error;

	dvp = ap->a_dvp;
	vpp = ap->a_vpp;
	cnp = ap->a_cnp;

	MPASS(dvp->v_type != VNON);

	if (cnp->cn_flags & ISDOTDOT) {
		/*
		 * Note that in this case, dvp is the child vnode, and we
		 * are looking up the parent vnode - exactly reverse from
		 * normal operation.  Unlocking dvp requires some rather
		 * tricky unlock/relock dance to prevent mp from being freed;
		 * use vn_vget_ino() which takes care of all that.
		 */
		error = vn_vget_ino(dvp, dvp->i_ino, cnp->cn_lkflags, vpp);
		if (error != 0) {
			printf("%s: vn_vget_ino() returned %d\n", __func__, error);
			return (error);
		}
		return (error);
	}

	if (cnp->cn_namelen == 1 && cnp->cn_nameptr[0] == '.') {
		vref(dvp);
		*vpp = dvp;
		return (0);
	}

	memset(&child_dentry, 0, sizeof(child_dentry));
	// XXX: free
	child_dentry.d_name.name = strndup(cnp->cn_nameptr, cnp->cn_namelen, M_LKPIVFS);
	child_dentry.d_name.len = cnp->cn_namelen;

	dentry = dvp->i_op->lookup(dvp, &child_dentry, 0 /* flags */);
	if (IS_ERR(dentry)) {
		printf("%s: ->lookup returned %ld (%p)\n", __func__, PTR_ERR(dentry), dentry);
		return (-PTR_ERR(dentry));
	}
	if (child_dentry.d_inode == NULL) {
		if ((cnp->cn_flags & ISLASTCN) && cnp->cn_nameiop == CREATE)
			return (EJUSTRETURN);
		return (ENOENT);
	}

	vp = child_dentry.d_inode;
	MPASS(vp->v_type != VNON);

	error = vn_lock(vp, cnp->cn_lkflags | LK_RETRY);
	*vpp = vp;

	return (error);
}

static int
lkpi_create(struct vop_create_args *ap)
{
	struct dentry child_dentry;
	struct vattr *vap;
	struct vnode *dvp;
	struct componentname *cnp;
	char *name;
	mode_t mode;
	int failed;

	dvp = ap->a_dvp;
	vap = ap->a_vap;
	cnp = ap->a_cnp;

	// XXX free
	name = strndup(cnp->cn_nameptr, cnp->cn_namelen, M_LKPIVFS);
	mode = vap->va_mode;
	if (vap->va_type == VREG)
		mode |= S_IFREG;

	memset(&child_dentry, 0, sizeof(child_dentry));
	child_dentry.d_name.name = name;
	child_dentry.d_name.len = cnp->cn_namelen;

	failed = dvp->i_op->create(NULL, dvp, &child_dentry, mode, 42 /* XXX */);
	if (failed) {
		printf("%s: ->create returned %d\n", __func__, failed);
		return (EIO);
	}

	*ap->a_vpp = child_dentry.d_inode;

	return (0);
}

static int
lkpi_getattr(struct vop_getattr_args *ap)
{
	struct vnode *vp;
	struct super_block *sb;
	struct mount *mp;
	struct vattr *vap;

	vp = ap->a_vp;
	mp = vp->v_mount;
	sb = VFSTOSB(mp);
	vap = ap->a_vap;

	vap->va_type = vp->v_type;
	vap->va_mode = vp->i_mode;
	vap->va_uid = vp->i_uid;
	vap->va_gid = vp->i_gid;
	vap->va_nlink = vp->i_nlink;
	vap->va_fsid = mp->mnt_stat.f_fsid.val[0];
	vap->va_fileid = vp->i_ino;
	vap->va_size = vp->i_size;
	vap->va_blocksize = sb->s_blocksize;
	vap->va_mtime = vp->i_mtime;
	vap->va_atime = vp->i_atime;
	vap->va_ctime = vp->i_ctime;
	vap->va_birthtime = vp->i_ctime; // XXX
	vap->va_gen = 0;
	vap->va_flags = vp->i_flags;
	vap->va_rdev = NODEV;
	vap->va_bytes = vp->i_size;
	vap->va_filerev = 0;
	vap->va_vaflags = 0;
	vap->va_spare = 0;

	return (0);
}

static int
lkpi_link(struct vop_link_args *ap)
{
	struct dentry target, new_dentry;
	struct vnode *tdvp, *vp;
	struct componentname *cnp;
	char *name;
	int error;

	tdvp = ap->a_tdvp;
	vp = ap->a_vp;
	cnp = ap->a_cnp;

	// XXX free
	name = strndup(cnp->cn_nameptr, cnp->cn_namelen, M_LKPIVFS);

	memset(&target, 0, sizeof(target));
	target.d_inode = vp;

	memset(&new_dentry, 0, sizeof(new_dentry));
	new_dentry.d_name.name = name;
	new_dentry.d_name.len = cnp->cn_namelen;

	error = -tdvp->i_op->link(&target, tdvp, &new_dentry);
	if (error != 0)
		printf("%s: ->link returned -%d\n", __func__, error);

	return (error);
}

static int
lkpi_mkdir(struct vop_mkdir_args *ap)
{
	struct dentry child_dentry;
	struct vattr *vap;
	struct vnode *dvp;
	struct componentname *cnp;
	char *name;
	mode_t mode;
	int failed;

	dvp = ap->a_dvp;
	vap = ap->a_vap;
	cnp = ap->a_cnp;

	// XXX free
	name = strndup(cnp->cn_nameptr, cnp->cn_namelen, M_LKPIVFS);
	mode = vap->va_mode;

	memset(&child_dentry, 0, sizeof(child_dentry));
	child_dentry.d_name.name = name;
	child_dentry.d_name.len = cnp->cn_namelen;

	failed = dvp->i_op->mkdir(NULL, dvp, &child_dentry, mode);
	if (failed) {
		printf("%s: ->mkdir returned %d\n", __func__, failed);
		return (EIO);
	}

	*ap->a_vpp = child_dentry.d_inode;

	return (0);
}

static int
lkpi_read(struct vop_read_args *ap)
{
	struct vnode *vp;
	struct uio *uio;
	struct iovec *iov;
	void * __capability base;
	size_t len, off;
	int nbytes;
	struct file file; // XXX: we shouldn't need this

	vp = ap->a_vp;
	uio = ap->a_uio;

	KASSERT(vp->v_type == VREG, ("!VREG"));

	off = uio->uio_offset;
	if (uio->uio_offset < 0)
		return (EINVAL);

	// XXX: not this
	iov = uio->uio_iov;
	base = iov[0].iov_base;
	len = iov[0].iov_len;
	off = uio->uio_offset;

	memset(&file, 0, sizeof(file));
	file.f_inode = vp;
	nbytes = vp->i_fop->read(&file, (__cheri_fromcap char *)base, len, &off);
	if (nbytes < 0) {
		printf("%s: ->read failed with error %d\n", __func__, nbytes);
		// XXX now what
		return (-nbytes);
	}

	uio->uio_resid -= nbytes;
	uio->uio_offset += nbytes;
	return (0);
}

static int
lkpi_readdir(struct vop_readdir_args *ap)
{
	struct vnode *vp;
	struct dir_context ctx;
	struct file file; // XXX: we shouldn't need this
	struct uio *uio;
	ssize_t off;
	int error;

	vp = ap->a_vp;
	uio = ap->a_uio;

	KASSERT(vp->v_type == VDIR, ("!VDIR"));

	off = uio->uio_offset;
	if (off < 0)
		return (EINVAL);

	// XXX: make it less ugly
	if (off > 0)
		goto eof;

	if (ap->a_eofflag != NULL)
		*ap->a_eofflag = FALSE;

	memset(&ctx, 0, sizeof(ctx));
	ctx.uio = uio;
	ctx.dot = 42; // XXX
	ctx.dotdot = 43; // XXX
	memset(&file, 0, sizeof(file));
	file.f_inode = vp;

	error = -vp->i_fop->iterate_shared(&file, &ctx);
	if (error != 0) {
		printf("%s: ->iterate_shared returned -%d\n", __func__, error);
		return (error);
	}

eof:
	if (ap->a_eofflag != NULL)
		*ap->a_eofflag = TRUE;
	return (0);
}

static int
lkpi_readlink(struct vop_readlink_args *ap)
{
	struct vnode *vp;
	struct uio *uio;
	int error;
	const char *target;

	uio = ap->a_uio;
	vp = ap->a_vp;

	MPASS(uio->uio_offset == 0);
	MPASS(vp->v_type == VLNK);

	target = vp->i_op->get_link((void *)42 /* XXX */, vp, NULL /* XXX */);
	if (IS_ERR(target)) {
		printf("%s: ->get_link returned %ld (%p)\n",
		    __func__, PTR_ERR(target), target);
		return (-PTR_ERR(target));
	}

	error = uiomove((void *)(uintptr_t)target,
	    MIN(strlen(target), uio->uio_resid), uio);
	return (error);
}

static int
lkpi_remove(struct vop_remove_args *ap)
{
	struct dentry child_dentry;
	struct vnode *dvp, *vp;
	struct componentname *cnp;
	char *name;
	int error;

	dvp = ap->a_dvp;
	vp = ap->a_vp;
	cnp = ap->a_cnp;

	// XXX free
	name = strndup(cnp->cn_nameptr, cnp->cn_namelen, M_LKPIVFS);

	memset(&child_dentry, 0, sizeof(child_dentry));
	child_dentry.d_inode = vp;
	child_dentry.d_name.name = name;
	child_dentry.d_name.len = cnp->cn_namelen;

	error = -dvp->i_op->unlink(dvp, &child_dentry);
	if (error != 0)
		printf("%s: ->unlink returned -%d\n", __func__, error);

	return (error);
}

static int
lkpi_rename(struct vop_rename_args *ap)
{
	printf("%s: EDOOFUS\n", __func__);

	return (EDOOFUS);
}

static int
lkpi_rmdir(struct vop_rmdir_args *ap)
{
	struct dentry child_dentry;
	struct vnode *dvp, *vp;
	struct componentname *cnp;
	char *name;
	int error;

	dvp = ap->a_dvp;
	vp = ap->a_vp;
	cnp = ap->a_cnp;

	// XXX free
	name = strndup(cnp->cn_nameptr, cnp->cn_namelen, M_LKPIVFS);

	memset(&child_dentry, 0, sizeof(child_dentry));
	child_dentry.d_inode = vp;
	child_dentry.d_name.name = name;
	child_dentry.d_name.len = cnp->cn_namelen;

	error = -dvp->i_op->rmdir(dvp, &child_dentry);
	if (error != 0)
		printf("%s: ->rmdir returned -%d\n", __func__, error);

	// XXX: According to VOP_RMDIR(9) man page this shouldn't be neededed?
	if (error == 0)
		VOP_UNLOCK(vp);

	return (error);
}

static int
lkpi_setattr(struct vop_setattr_args *ap)
{
	struct dentry dentry;
	struct vnode *vp;
	struct vattr *vap;
	struct iattr ia;
	int error;

	vp = ap->a_vp;
	vap = ap->a_vap;

	memset(&ia, 0, sizeof(ia));

	if (vap->va_type != VNON ||
	    vap->va_nlink != VNOVAL ||
	    vap->va_fsid != VNOVAL ||
	    vap->va_fileid != VNOVAL ||
	    vap->va_blocksize != VNOVAL ||
	    vap->va_rdev != VNOVAL ||
	    vap->va_bytes != VNOVAL ||
	    vap->va_flags != VNOVAL ||
	    vap->va_uid != VNOVAL ||
	    vap->va_gid != VNOVAL ||
	    vap->va_atime.tv_sec != VNOVAL ||
	    vap->va_mtime.tv_sec != VNOVAL ||
	    vap->va_ctime.tv_sec != VNOVAL ||
	    vap->va_gen != VNOVAL) {
		printf("%s: nope\n", __func__);
		return (EINVAL);
	}
	if (vap->va_mode != (mode_t)VNOVAL) {
		ia.ia_mode = vap->va_mode;
	}
	if (vap->va_size != VNOVAL) {
		ia.ia_valid |= ATTR_SIZE;
		ia.ia_size = vap->va_size;
	}

	memset(&dentry, 0, sizeof(dentry));
	dentry.d_inode = vp;
	error = -vp->i_op->setattr(NULL, &dentry, &ia);
	if (error != 0)
		printf("%s: ->setattr returned -%d\n", __func__, error);

	return (error);
}

static int
lkpi_symlink(struct vop_symlink_args *ap)
{
	struct dentry child_dentry;
	struct vnode *dvp;
	struct componentname *cnp;
	char *name;
	const char *target;
	int error;

	dvp = ap->a_dvp;
	cnp = ap->a_cnp;
	target = ap->a_target;

	// XXX free
	name = strndup(cnp->cn_nameptr, cnp->cn_namelen, M_LKPIVFS);

	memset(&child_dentry, 0, sizeof(child_dentry));
	child_dentry.d_name.name = name;
	child_dentry.d_name.len = cnp->cn_namelen;

	error = -dvp->i_op->symlink(NULL, dvp, &child_dentry, target);
	if (error != 0)
		printf("%s: ->symlink returned -%d\n", __func__, error);

	*ap->a_vpp = child_dentry.d_inode;

	return (error);
}

static int
lkpi_write(struct vop_write_args *ap)
{
	struct vnode *vp;
	struct uio *uio;
	struct iovec *iov;
	void * __capability base;
	size_t len, off;
	int nbytes;
	struct file file; // XXX: we shouldn't need this

	vp = ap->a_vp;
	uio = ap->a_uio;

	KASSERT(vp->v_type == VREG, ("!VREG"));

	off = uio->uio_offset;
	if (uio->uio_offset < 0)
		return (EINVAL);

	// XXX: not this
	iov = uio->uio_iov;
	base = iov[0].iov_base;
	len = iov[0].iov_len;
	off = uio->uio_offset;

	memset(&file, 0, sizeof(file));
	file.f_inode = vp;

#if 1
	if (vp->i_fop == NULL) {
		printf("%s: huh\n", __func__);
		return (EDOOFUS);
	}
#endif
	nbytes = vp->i_fop->write(&file, (__cheri_fromcap char *)base, len, &off);
	if (nbytes < 0) {
		printf("%s: ->write failed with error %d\n", __func__, nbytes);
		// XXX now what
		return (-nbytes);
	}

	uio->uio_resid -= nbytes;
	uio->uio_offset += nbytes;

	// XXX: Is this the right way?
	vp->i_size = uio->uio_offset + uio->uio_resid;

	return (0);
}

static int
lkpi_reclaim(struct vop_reclaim_args *ap)
{
	struct vnode *vp;

	vp = ap->a_vp;

	printf("%s: %p\n", __func__, ap);

	vfs_hash_remove(vp);

	// XXX
	vp->v_data = NULL;

	return (0);
}

struct vop_vector lkpi_vnodeops = {
	.vop_default =		&default_vnodeops,

	.vop_access =		lkpi_access,
	.vop_lookup =		lkpi_lookup,
	.vop_create =		lkpi_create,
	.vop_getattr =		lkpi_getattr,
	.vop_link =		lkpi_link,
	.vop_mkdir =		lkpi_mkdir,
	.vop_mknod =		VOP_EOPNOTSUPP,
	.vop_read =		lkpi_read,
	.vop_readdir =		lkpi_readdir,
	.vop_readlink =		lkpi_readlink,
	.vop_remove =		lkpi_remove,
	.vop_rename =		lkpi_rename,
	.vop_rmdir =		lkpi_rmdir,
	.vop_setattr =		lkpi_setattr,
	.vop_symlink =		lkpi_symlink,
	.vop_write =		lkpi_write,
	.vop_reclaim =		lkpi_reclaim,
};
VFS_VOP_VECTOR_REGISTER(lkpi_vnodeops);

struct lkpi_node {
};

struct vnode *
new_inode(struct super_block *sb)
{
	int error;
	struct lkpi_node *lp;
	struct vnode *vp = NULL; // XXX

	error = getnewvnode("lkpi", sb->s_mnt, &lkpi_vnodeops, &vp);
	if (error != 0) {
		printf("%s: getnewvnode returned %d, vp %p\n", __func__, error, vp);
		return (NULL);
	}

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);

	lp = malloc(sizeof(*lp), M_LKPIVFS, M_WAITOK | M_ZERO);
	vp->v_data = lp;

	error = insmntque1(vp, sb->s_mnt);
	if (error != 0) {
		VOP_UNLOCK(vp);
		printf("%s: insmntque returned %d\n", __func__, error);
		return (NULL);
	}

	vp->i_sb = sb;
	vp->i_flags |= I_NEW;

	vn_set_state(vp, VSTATE_CONSTRUCTED);

	return (vp);
}

struct dentry *
d_make_root(struct vnode *vp)
{
	struct super_block *sb;
	struct dentry *d;

	sb = VFSTOSB(vp->v_mount);

	d = malloc(sizeof(*d), M_LKPIVFS, M_WAITOK | M_ZERO);
	d->d_inode = vp;
	d->d_sb = sb;
	vp->v_vflag |= VV_ROOT;

	return (d);
}

struct g_consumer;
int g_vfs_open(struct vnode *vp, struct g_consumer **cpp, const char *fsname, int wr);
void g_vfs_close(struct g_consumer *cp);
void _g_topology_lock(void);
void _g_topology_unlock(void);

struct dentry *
mount_bdev(struct file_system_type *fs_type, int flags, const char *dev_name,
    void *data, int (*fill_super)(struct super_block *, void *, int))
{
	struct mount *mp;
	struct thread *td;
	struct vfsoptlist *opts;
	struct nameidata nd, *ndp = &nd;
	struct vnode *devvp;
	struct g_consumer *cp;
	struct super_block *sb;
	char * __capability fspec;
	int error, len;

	mp = (struct mount *)data;
	td = curthread;
	opts = mp->mnt_optnew;

	if (mp->mnt_flag & MNT_UPDATE) {
		// XXX
		return (0);
	}

	sb = malloc(sizeof(*sb), M_LKPIVFS, M_WAITOK | M_ZERO);
	sb->s_mnt = data;
	mp->mnt_data = sb;

	if (mp->mnt_flag & MNT_ROOTFS) {
		error = ENOTSUP;
		goto fail;
	}

	fspec = NULL;
	error = vfs_getopt(opts, "from", (void **)&fspec, &len);
	if (!error && fspec[len - 1] != '\0') {
		error = EINVAL;
		goto fail;
	}

	/* Check that the mount device exists */
	if (fspec == NULL) {
		error = EINVAL;
		goto fail;
	}
	NDINIT(ndp, LOOKUP, FOLLOW | LOCKLEAF, UIO_SYSSPACE, fspec);
	error = namei(ndp);
	if (error != 0)
		goto fail;
	NDFREE_PNBUF(ndp);
	devvp = ndp->ni_vp;
	vref(devvp); // XXX needed?
	sb->s_devvp = devvp;

	if (!vn_isdisk_error(devvp, &error))
		goto fail2;

	/* Check the access rights on the mount device */
	error = VOP_ACCESS(devvp, VREAD | VWRITE, td->td_ucred, td);
	if (error != 0)
		error = priv_check(td, PRIV_VFS_MOUNT_PERM);
	if (error != 0)
		goto fail2;

	_g_topology_lock();
	error = g_vfs_open(devvp, &cp, fs_type->name,
	    (mp->mnt_flag & MNT_RDONLY) != 0 ? 0 : 1);
	_g_topology_unlock();
	VOP_UNLOCK(devvp);
	if (error != 0) {
		printf("%s: g_vfs_open returned %d\n", __func__, error);
		goto fail2;
	}

	sb->s_bdev = cp;
	error = -fill_super(sb, data, 0);
	if (error != 0) {
		printf("%s: ->fill_super returned -%d\n", __func__, error);
		goto fail3;
	}

	return (0);

fail3:
	_g_topology_lock();
	g_vfs_close(cp);
	_g_topology_unlock();
fail2:
	vrele(devvp);
fail:
	/*
	 * We don't need to return the actual dentry here;
	 * FreeBSD's upper layer code doesn't need it.
	 */
	return (ERR_PTR(-error));
}

static int
lkpi_mount(struct mount *mp)
{
	char *from, *fspath;
	struct file_system_type *fst;
	int flags;

	if (vfs_getopt(mp->mnt_optnew, "from", (void **)&from, NULL))
		return (EINVAL);

	if (vfs_getopt(mp->mnt_optnew, "fspath", (void **)&fspath, NULL))
		return (EINVAL);

	vfs_getnewfsid(mp);

	flags = 0;
	fst = global_fst;
	/*
	 * XXX: We're reusing the last argument to ->mount() to pass mp
	 */
	struct dentry *dentry = fst->mount(fst, flags, from, (void *)mp);
	if (IS_ERR(dentry)) {
		printf("%s: ->mount returned %ld (%p)\n", __func__, PTR_ERR(dentry), dentry);
		return (-PTR_ERR(dentry));
	}

	vfs_mountedfrom(mp, from);
	return (0);
}

static int
lkpi_unmount(struct mount *mp, int mntflags)
{
	struct super_block *sb;
	int error, flags;

	sb = VFSTOSB(mp);

	flags = 0;
	if (mntflags & MNT_FORCE)
		flags |= FORCECLOSE;
	error = vflush(mp, 1, flags, curthread);
	if (error != 0) {
		printf("%s: vflush failed with error %d\n", __func__, error);
		return (error);
	}

	error = -sb->s_op->sync_fs(sb, 1);
	if (error != 0) {
		printf("%s: ->sync_fs returned %d\n", __func__, error);
		return (error);
	}

	_g_topology_lock();
	g_vfs_close(sb->s_bdev);
	_g_topology_unlock();
	vrele(sb->s_devvp);

	free(sb, M_LKPIVFS);
	mp->mnt_data = NULL;

	return (0);
}

static int
lkpi_root(struct mount *mp, int flags, struct vnode **vpp)
{
	struct super_block *sb;
	struct vnode *vp;

	sb = VFSTOSB(mp);

	vp = sb->s_root->d_inode;
	vref(vp);
	if (VOP_ISLOCKED(vp)) {
		// XXX: this is normal?
		//printf("%s: already locked?\n", __func__);
	} else {
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	}

	*vpp = vp;
	return (0);
}

static int
lkpi_statfs(struct mount *mp, struct statfs *sbp)
{
	struct super_block *sb;
	struct kstatfs kstat;
	int error;

	sb = VFSTOSB(mp);

	error = -sb->s_op->statfs(sb->s_root, &kstat);
	if (error != 0) {
		printf("%s: ->statfs returned -%d\n", __func__, error);
		return (error);
	}

	// XXX: alias kstatfs to statfs?
	sbp->f_bsize = kstat.f_bsize;
	sbp->f_iosize = 0; // XXX
	sbp->f_blocks = kstat.f_blocks;
	sbp->f_bfree = kstat.f_bfree;
	sbp->f_bavail = kstat.f_bavail;
	sbp->f_files = kstat.f_files;
	sbp->f_ffree = kstat.f_ffree;

	return (0);
}

static int
lkpi_vget(struct mount *mp, ino_t ino, int lkflags, struct vnode **vpp)
{
	struct vnode *vp, *oldvp;
	struct super_block *sb;
	int error;

	sb = VFSTOSB(mp);

	error = vfs_hash_get(mp, ino, lkflags, curthread, &vp, NULL, NULL);
	if (error != 0 || vp == NULL) {
		vp = new_inode(sb);
		error = vfs_hash_insert(vp, ino, lkflags, curthread,
		    &oldvp, NULL, NULL);
		if (error != 0 || oldvp != NULL) {
			printf("%s: vfs_hash_insert returned %d\n",
			    __func__, error);
			// XXX and?
		}

		ASSERT_VOP_LOCKED(vp, __func__);

		if (vp->i_ino == 0)
			vp->i_ino = ino;
	} else {
		//printf("%s: xoxo, vfs_hash_get found %p for inode %lu\n", __func__, vp, ino);
		ASSERT_VOP_LOCKED(vp, __func__);
	}

	MPASS(vp->i_ino != 0);
	MPASS(vp->i_ino == ino);

	*vpp = vp;
	return (error);
}

/*
 * In FreeBSD this would typically be done with VFS_SET() macro,
 * which calls vfs_modevent()
 */
int
register_filesystem(struct file_system_type *fst)
{
	struct vfsconf *vfc;
	struct vfsops *vfso;
	int error;

	vfso = malloc(sizeof(*vfso), M_LKPIVFS, M_ZERO | M_WAITOK);
	vfso->vfs_mount = lkpi_mount;
	vfso->vfs_unmount = lkpi_unmount;
	vfso->vfs_root = lkpi_root;
	vfso->vfs_statfs = lkpi_statfs;
	vfso->vfs_vget = lkpi_vget;

	vfc = malloc(sizeof(*vfc), M_LKPIVFS, M_ZERO | M_WAITOK);
	vfc->vfc_version = VFS_VERSION;
	strlcpy(vfc->vfc_name, fst->name, sizeof(vfc->vfc_name));
	vfc->vfc_vfsops = vfso;
	vfc->vfc_typenum = -1;
	//vfc->vfc_flags = VFCF_READONLY; // XXX
	vfc->vfc_flags = 0;

	// XXX: stash fst somewhere in vfc somehow
	global_fst = fst;
	error = vfs_modevent(NULL, MOD_LOAD, vfc);
	if (error != 0) {
		printf("%s: vfs_modevent returned %d\n", __func__, error);
		return (error);
	}

	return (error);
}

void
setattr_copy(struct mnt_idmap *idmap, struct vnode *vp, const struct iattr *ia)
{
	if (ia->ia_mode != 0) {
		vp->i_mode = ia->ia_mode;
	}
}

off_t
i_size_read(const struct vnode *vp)
{
	return (vp->i_size);
}

void
set_delayed_call(struct delayed_call *call, void (*fn)(void *cb), void *arg)
{
	static int done = 0;

	if (!done++)
		printf("%s: %p\n", __func__, call);
}

void
mark_buffer_dirty(struct buffer_head *bh)
{
#if 0
	printf("%s: dirtying %p\n", __func__, bh);
#endif
	bdirty((struct buf *)bh);
}

void
inode_init_owner(struct mnt_idmap *idmap, struct vnode *vp, const struct vnode *dir, umode_t mode)
{
	vp->i_mode = mode;
	vp->i_nlink = 1; // XXX: Set it somewhere else?

	if (S_ISREG(vp->i_mode))
		vp->v_type = VREG;
	else if (S_ISDIR(vp->i_mode))
		vp->v_type = VDIR;
	else if (S_ISLNK(vp->i_mode))
		vp->v_type = VLNK;
	else {
		//printf("%s: wrong i_mode %x, should be %x\n", __func__, vp->i_mode, S_IFREG);
		vp->i_mode |= S_IFREG;
		vp->v_type = VREG;
	}

	// XXX: Pass the ucred somehow instead?
	vp->i_uid = curthread->td_ucred->cr_uid;
	vp->i_gid = curthread->td_ucred->cr_gid;
}

void
inode_set_ctime_to_ts(struct vnode *vp, struct timespec64 ts)
{
	MPASS(ts.tv_sec != 0);

	vp->i_ctime = ts;
}

void
inode_set_atime_to_ts(struct vnode *vp, struct timespec64 ts)
{
	MPASS(ts.tv_sec != 0);

	vp->i_atime = ts;
}

void
inode_set_mtime_to_ts(struct vnode *vp, struct timespec64 ts)
{
	MPASS(ts.tv_sec != 0);

	vp->i_mtime = ts;
}

kuid_t
make_kuid(struct user_namespace *from, uid_t uid)
{
	return (uid);
}

kuid_t
make_kgid(struct user_namespace *from, uid_t gid)
{
	return (gid);
}

void
set_nlink(struct vnode *vp, unsigned int nlink)
{
	vp->i_nlink = nlink;
}

void
inc_nlink(struct vnode *vp)
{
	vp->i_nlink++;
}

void
inode_dec_link_count(struct vnode *vp)
{
	// XXX: Make it proper refcount
	vp->i_nlink--;
	if (vp->i_nlink == 0) {
		//printf("%s: recycling vp %p, ino %lu\n", __func__, vp, vp->i_ino);
		vrecycle(vp);
	}
}

void
inode_nohighmem(struct vnode *vp __unused)
{
}

struct vnode *
iget_locked(struct super_block *sb, unsigned long ino)
{
	struct mount *mp;
	struct vnode *vp;
	int error, lkflags;

	lkflags = LK_EXCLUSIVE | LK_RETRY | LK_CANRECURSE;
	mp = sb->s_mnt;

	error = VFS_VGET(mp, ino, lkflags, &vp);
	if (error != 0)
		panic("%s: callers can't handle NULL return; error %d\n", __func__, error);

	if ((vp->i_flags & I_NEW) == 0) {
		/*
		 * Despite the name, iget_locked() returns a locked vnode only
		 * if it was newly created. If it already existed, it's returned
		 * unlocked.
		 */
		VOP_UNLOCK(vp);
	}

	MPASS(ino != 0);
	MPASS(vp->i_ino == ino);

	return (vp);
}

void
__destroy_inode(struct vnode *vp)
{
	printf("%s: %p\n", __func__, vp);
}

void
unlock_new_inode(struct vnode *vp)
{
	MPASS(vp->v_type != VNON);

	vp->i_flags &= ~I_NEW;
	VOP_UNLOCK(vp);
}

void
mark_inode_dirty(struct vnode *vp)
{
	int error;

	error = vinvalbuf(vp, V_SAVE, 0, 0);
	if (error != 0)
		printf("%s: vinvalbuf returned %d for vp %p\n", __func__, error, vp);
}

bool
dir_emit(struct dir_context *ctx, const char *name, int namelen, u64 fileno, unsigned type)
{
	struct dirent dirent;
	struct uio *uio;
	size_t reclen;
	int error;

	uio = ctx->uio;

	reclen = _GENERIC_DIRLEN(namelen);

	if (uio->uio_resid < reclen) {
		printf("%s: foo\n", __func__);
		return (false);
	}

	dirent.d_fileno = fileno;
	dirent.d_off = uio->uio_offset + reclen;
	dirent.d_reclen = reclen;
	dirent.d_type = type;
	dirent.d_namlen = namelen;
	memcpy(dirent.d_name, name, namelen);
	dirent_terminate(&dirent);
	error = uiomove(&dirent, reclen, uio);
	if (error != 0) {
		printf("%s: uiomove returned %d\n", __func__, error);
		return (false);
	}

	// is this valid unix
	ctx->pos++;
	uio->uio_offset += reclen;

	return (true);
}

bool
dir_emit_dots(struct file *file __unused, struct dir_context *ctx)
{
	bool ok;

	ok = dir_emit(ctx, ".", 1, ctx->dot, VDIR);
	if (!ok)
		return (false);
	ok = dir_emit(ctx, "..", 2, ctx->dotdot, VDIR);
	if (!ok)
		return (false);

	return (true);
}

int
unregister_filesystem(struct file_system_type *fst)
{
	printf("%s: no.\n", __func__);
	return (-1);
}

void
//truncate_inode_pages_final(struct address_space *as)
truncate_inode_pages_final(void *as)
{
	printf("%s: %p\n", __func__, as);
}

void
kill_block_super(struct super_block *sb)
{
	printf("%s: %p\n", __func__, sb);
}

void
d_add(struct dentry *dentry, struct vnode *vp)
{
	if (vp == NULL) {
		// XXX: Hm.
		//printf("%s: NULL vp?\n", __func__);
		return;
	}
	if (dentry->d_inode != NULL)
		printf("%s: d_inode was %p, now %p\n", __func__, dentry->d_inode, vp);
	dentry->d_inode = vp;
}

time64_t
inode_get_atime_sec(const struct vnode *vp)
{
	MPASS(vp->i_atime.tv_sec != 0);

	return (vp->i_atime.tv_sec);
}

time64_t
inode_get_mtime_sec(const struct vnode *vp)
{
	MPASS(vp->i_mtime.tv_sec != 0);

	return (vp->i_mtime.tv_sec);
}

time64_t
inode_get_ctime_sec(const struct vnode *vp)
{
	MPASS(vp->i_ctime.tv_sec != 0);

	return (vp->i_ctime.tv_sec);
}

gid_t
from_kgid(struct user_namespace *to, kgid_t gid)
{
	return (gid);
}

gid_t
from_kuid(struct user_namespace *to, kuid_t uid)
{
	return (uid);
}

struct timespec64
simple_inode_init_ts(struct vnode *vp)
{
	struct timespec64 ts;

	vfs_timestamp(&ts);

	vp->i_atime = ts;
	vp->i_mtime = ts;
	vp->i_ctime = ts;

	return (ts);
}

void
insert_inode_hash(struct vnode *vp)
{
	struct vnode *ovp;
	int error;

	error = vfs_hash_insert(vp, vp->i_ino, LK_EXCLUSIVE | LK_RETRY,
	    curthread, &ovp, NULL, NULL);
	if (error != 0 || ovp != NULL)
		panic("%s: vfs_hash_insert failed with error %d, ovp %p\n",
		    __func__, error, ovp);
}

void
d_instantiate(struct dentry *dentry, struct vnode *vp)
{
	MPASS(dentry->d_inode == NULL);

	//printf("%s: instantiating vp %p ino %lu i_nlink %u\n", __func__, vp, vp->i_ino, vp->i_nlink);

	dentry->d_inode = vp;
}

void
ihold(struct vnode *vp)
{
	printf("%s: %p\n", __func__, vp);
}

int
setattr_prepare(struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *ia)
{
	//printf("%s: %p\n", __func__, idmap);
	return (0);
}

int
inode_newsize_ok(const struct vnode *vp, loff_t offset)
{
	//printf("%s: sure!\n", __func__);
	return (0);
}

int
truncate_setsize(struct vnode *vp, loff_t size)
{
	// XXX needed?
	//vnode_pager_setsize(vp, size);
	vp->i_size = size;
	return (0);
}

void
clear_inode(struct vnode *vp)
{
	printf("%s: %p\n", __func__, vp);
}

void
invalidate_inode_buffers(struct vnode *vp)
{
	int error;
	printf("%s: XXX untested, invalidating %p\n", __func__, vp);

	error = vinvalbuf(vp, 0, 0, 0);
	printf("%s: vinvalbuf returned %d for vp %p\n", __func__, error, vp);
}

int
sb_set_blocksize(struct super_block *sb, int size)
{
	sb->s_blocksize = size;
	return (0);
}
