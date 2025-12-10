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
#include <sys/dirent.h>
#include <sys/fcntl.h>
#include <sys/mount.h>
#include <sys/namei.h>

#include <linux/types.h>
#include <linux/kobject.h>
#include <linux/completion.h>
#include <linux/atomic.h>
#include <linux/fs.h>

static struct file_system_type *global_fst = NULL; // XXX
struct mnt_idmap	nop_mnt_idmap; // XXX
struct user_namespace	init_user_ns;

#define VFSTOSB(mp)    ((struct super_block *)((mp)->mnt_data))

// XXX: all this circus is here because we can't include buf.h
extern int breadn_flags(struct vnode *, daddr_t, daddr_t, int, daddr_t *, int *, 
	    int, struct ucred *, int, void (*)(struct buf *), struct buf **);
#define bread(vp, blkno, size, cred, bpp) \
	    breadn_flags(vp, blkno, blkno, size, NULL, NULL, 0, cred, 0, \
		NULL, bpp)

struct buffer_head *
sb_bread(struct super_block *sb, sector_t lbn)
{
	struct buf *bp = NULL;
	size_t size = 512;
	int error;

	// XXX why
	lbn *= 8;

	if (sb->s_blocksize != 0)
		size = sb->s_blocksize;

	error = bread(sb->s_devvp, lbn, size, NOCRED, &bp);
	if (error != 0) {
		printf("%s: bread %zd from %lu returned %d\n", __func__, size, lbn, error);
		brelse((struct buffer_head *)bp);
		return (NULL);
	}

	return ((struct buffer_head *)bp);
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
#if 0
		KASSERT(anp->an_parent != NULL, ("NULL parent"));
		/*
		 * Note that in this case, dvp is the child vnode, and we
		 * are looking up the parent vnode - exactly reverse from
		 * normal operation.  Unlocking dvp requires some rather
		 * tricky unlock/relock dance to prevent mp from being freed;
		 * use vn_vget_ino_gen() which takes care of all that.
		 */
		error = vn_vget_ino_gen(dvp, lkpi_vget_callback,
		    anp->an_parent, cnp->cn_lkflags, vpp);
		if (error != 0) {
			AUTOFS_WARN("vn_vget_ino_gen() failed with error %d",
			    error);
			return (error);
		}
#else
		//printf("%s: ISDOTDOT\n", __func__);
		error = EDOOFUS;
#endif
		return (error);
	}

	if (cnp->cn_namelen == 1 && cnp->cn_nameptr[0] == '.') {
		vref(dvp);
		*vpp = dvp;

		return (0);
	}

	memset(&child_dentry, 0, sizeof(child_dentry));
	// XXX: free
	child_dentry.d_name.name = strndup(cnp->cn_nameptr, cnp->cn_namelen, M_TEMP);
	dentry = dvp->i_op->lookup(dvp, &child_dentry, 0 /* flags */);
	if (IS_ERR(dentry)) {
		printf("%s: lookup returned %ld (%p)\n", __func__, PTR_ERR(dentry), dentry);
		return (-PTR_ERR(dentry));
	}
	if (child_dentry.d_inode == NULL) {
		if ((cnp->cn_flags & ISLASTCN) && cnp->cn_nameiop == CREATE) {
			printf("%s: enoent, but create\n", __func__);
			return (EJUSTRETURN);
		}
		return (ENOENT);
	}

	vp = child_dentry.d_inode;
	MPASS(vp->v_type != VNON);

	if (!VOP_ISLOCKED(vp)) {
		printf("%s: locking %p\n", __func__, vp);
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	} else {
		//printf("%s: %p already locked\n", __func__, vp);
	}
	vref(vp);
	*vpp = vp;

	return (0);
}

static int
lkpi_create(struct vop_create_args *ap)
{
	printf("%s: EDOOFUS\n", __func__);
	return (EDOOFUS);
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
	if (vp->v_type != VREG &&
	    vp->v_type != VDIR &&
	    vp->v_type != VLNK) {
		panic("%s: wrong type %d, should be %d\n", __func__, vp->v_type, VDIR);
	}

	vap->va_mode = vp->i_mode;
	//vap->va_bsdflags = 0;
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
	vap->va_flags = 0;
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
	printf("%s: EDOOFUS\n", __func__);

	return (EDOOFUS);
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

	uio = ap->a_uio;
	vp = ap->a_vp;

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

#if 0
	printf("%s: vp %p, base %p, len %zd, off %zd, iovcnt %d\n",
	    __func__, vp, base, len, off, uio->uio_iovcnt);
#endif
	memset(&file, 0, sizeof(file));
	file.f_inode = vp;
	nbytes = vp->i_fop->read(&file, (__cheri_fromcap char *)base, len, &off);
	if (nbytes < 0) {
		printf("%s: read failed with error %d\n", __func__, nbytes);
		// XXX now what
		return (-nbytes);
	}

	//printf("%s: read %d bytes, old uio_resid %zd\n", __func__, nbytes, uio->uio_resid);
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

	error = vp->i_fop->iterate_shared(&file, &ctx);
	if (error != 0) {
		printf("%s: iterate_shared returned %d\n", __func__, error);
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
		printf("%s: get_link returned %ld (%p)\n",
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
	printf("%s: EDOOFUS\n", __func__);

	return (EDOOFUS);
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
	printf("%s: EDOOFUS\n", __func__);

	return (EDOOFUS);
}

static int
lkpi_setattr(struct vop_setattr_args *ap)
{
	printf("%s: EDOOFUS\n", __func__);

	return (EDOOFUS);
}

static int
lkpi_symlink(struct vop_symlink_args *ap)
{
	printf("%s: EDOOFUS\n", __func__);

	return (EDOOFUS);
}

static int
lkpi_write(struct vop_write_args *ap)
{
	printf("%s: EDOOFUS\n", __func__);

	return (EDOOFUS);
}

static int
lkpi_reclaim(struct vop_reclaim_args *ap)
{
	struct vnode *vp;

	vp = ap->a_vp;

	printf("%s: %p\n", __func__, ap);

	// XXX panics and then backtrace in kgdb is broken
	//vfs_hash_remove(vp);

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

struct inode *
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

	lp = malloc(sizeof(*lp), M_TEMP, M_WAITOK | M_ZERO);
	vp->v_data = lp;

	error = insmntque(vp, sb->s_mnt);
	if (error != 0) {
		VOP_UNLOCK(vp);
		printf("%s: insmntque returned %d\n", __func__, error);
		return (NULL);
	}

	// XXX
	MNT_ILOCK(sb->s_mnt);
	MNT_REL(sb->s_mnt);
	MNT_IUNLOCK(sb->s_mnt);

	vp->i_sb = sb;
	vp->i_flags |= I_NEW;

	vn_set_state(vp, VSTATE_CONSTRUCTED);
	VOP_UNLOCK(vp);

	return (vp);
}

struct dentry *
d_make_root(struct inode *vp)
{
	struct super_block *sb;
	struct dentry *d;

	sb = VFSTOSB(vp->v_mount);

	d = malloc(sizeof(*d), M_TEMP, M_WAITOK | M_ZERO);
	d->d_inode = vp;
	d->d_sb = sb;
	vp->v_vflag |= VV_ROOT;

	return (d);
}

struct g_consumer;
int g_vfs_open(struct vnode *vp, struct g_consumer **cpp, const char *fsname, int wr);
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

	sb = malloc(sizeof(*sb), M_TEMP, M_WAITOK | M_ZERO);
	sb->s_mnt = data;
	mp->mnt_data = sb;

	MNT_ILOCK(mp);
	mp->mnt_flag |= MNT_RDONLY;
	MNT_IUNLOCK(mp);

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
	if ((error = namei(ndp)))
		goto fail;
	NDFREE_PNBUF(ndp);
	devvp = ndp->ni_vp;
	sb->s_devvp = devvp;

	if (!vn_isdisk_error(devvp, &error)) {
		vrele(devvp);
		goto fail;
	}

	/* Check the access rights on the mount device */
	error = VOP_ACCESS(devvp, VREAD, td->td_ucred, td);
	if (error)
		error = priv_check(td, PRIV_VFS_MOUNT_PERM);
	if (error) {
		vrele(devvp);
		goto fail;
	}

	_g_topology_lock();
	error = g_vfs_open(devvp, &cp, fs_type->name, 0);
	_g_topology_unlock();
	VOP_UNLOCK(devvp);
	if (error) {
		vrele(devvp);
		goto fail;
	}

	sb->s_bdev = cp;
	error = -fill_super(sb, data, 0);
	if (error == 0) {
		vrele(devvp);
	} else {
		printf("%s: fill_super returned %d\n", __func__, error);
	}
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

#if 0
	if (vfs_filteropt(mp->mnt_optnew, lkpi_opts))
		return (EINVAL);

	if (mp->mnt_flag & MNT_UPDATE) {
		lkpi_flush(VFSTOSB(mp));
		return (0);
	}
#endif

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
		printf("%s: mount returned %ld (%p)\n", __func__, PTR_ERR(dentry), dentry);
		return (-PTR_ERR(dentry));
	}

	vfs_mountedfrom(mp, from);
	return (0);
}

static int
lkpi_unmount(struct mount *mp, int mntflags)
{
	int error, flags;

	flags = 0;
	if (mntflags & MNT_FORCE)
		flags |= FORCECLOSE;
	error = vflush(mp, 0, flags, curthread);
	if (error != 0) {
		printf("%s: vflush failed with error %d", __func__, error);
		return (error);
	}

	mp->mnt_data = NULL;

	printf("%s: done\n", __func__);

	return (0);
}

static int
lkpi_root(struct mount *mp, int flags, struct vnode **vpp)
{
	int error;
	struct super_block *sb;
	struct vnode *vp;

	sb = VFSTOSB(mp);

	vp = sb->s_root->d_inode;
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	vhold(vp);
	vref(vp);

	*vpp = vp;
	error = 0;

	return (error);
}

static int
lkpi_statfs(struct mount *mp, struct statfs *sbp)
{
	struct super_block *sb;
	struct kstatfs kstat;
	int error;

	sb = VFSTOSB(mp);

	error = sb->s_op->statfs(sb->s_root, &kstat);

	// XXX: alias kstatfs to statfs?
	sbp->f_bsize = kstat.f_bsize;
	sbp->f_iosize = 0; // XXX
	sbp->f_blocks = kstat.f_blocks;
	sbp->f_bfree = kstat.f_bfree;
	sbp->f_bavail = kstat.f_bavail;
	sbp->f_files = kstat.f_files;
	sbp->f_ffree = kstat.f_ffree;

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

	vfso = malloc(sizeof(*vfso), M_TEMP, M_ZERO | M_WAITOK);
	vfso->vfs_mount = lkpi_mount;
	vfso->vfs_unmount = lkpi_unmount;
	vfso->vfs_root = lkpi_root;
	vfso->vfs_statfs = lkpi_statfs;

	vfc = malloc(sizeof(*vfc), M_TEMP, M_ZERO | M_WAITOK);
	vfc->vfc_version = VFS_VERSION;
	strlcpy(vfc->vfc_name, fst->name, sizeof(vfc->vfc_name));
	vfc->vfc_vfsops = vfso;
	vfc->vfc_typenum = -1;
	vfc->vfc_flags = VFCF_READONLY; // XXX

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
setattr_copy(struct mnt_idmap *idmap, struct inode *inode, const struct iattr *attr)
{
	printf("%s: %p\n", __func__, idmap);
}

off_t
i_size_read(const struct inode *inode)
{
	printf("%s: %p\n", __func__, inode);
	return (-1);
}

void
set_delayed_call(struct delayed_call *call, void (*fn)(void *cb), void *arg)
{
	printf("%s: %p\n", __func__, call);
}

void
mark_buffer_dirty(struct buffer_head *bh __unused)
{
	printf("%s: %p\n", __func__, bh);
}

void
inode_init_owner(struct mnt_idmap *idmap, struct inode *inode, const struct inode *dir, umode_t mode)
{
	inode->i_mode = mode;

	if (S_ISREG(inode->i_mode))
		inode->v_type = VREG;
	else if (S_ISDIR(inode->i_mode))
		inode->v_type = VDIR;
	else if (S_ISLNK(inode->i_mode))
		inode->v_type = VLNK;
	else
		panic("%s: wrong i_mode %o", __func__, inode->i_mode);
}

void
inode_set_ctime_to_ts(struct inode *inode, struct timespec64 ts)
{
	inode->i_ctime = ts;
}

void
inode_set_atime_to_ts(struct inode *inode, struct timespec64 ts)
{
	inode->i_atime = ts;
}

void
inode_set_mtime_to_ts(struct inode *inode, struct timespec64 ts)
{
	inode->i_mtime = ts;
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
set_nlink(struct inode *inode, unsigned int nlink)
{
	inode->i_nlink = nlink;
}

void
inode_nohighmem(struct inode *inode)
{
	//printf("%s: %p\n", __func__, inode);
}

struct inode *
iget_locked(struct super_block *sb, unsigned long ino)
{
	struct mount *mp;
	struct inode *inode, *oldinode;
	int error, lkflags;

	// XXX: should be in VFS_VGET() maybe

	mp = sb->s_mnt;
	lkflags = LK_SHARED | LK_RETRY;

	error = vfs_hash_get(mp, ino, lkflags, curthread, &inode, NULL, NULL);
	if (error != 0 || inode == NULL) {
		inode = new_inode(sb);
		//printf("%s: vfs_hash_get returned %d; inserting %p for inode %lu\n", __func__, error, inode, ino);
		error = vfs_hash_insert(inode, ino, lkflags, curthread, &oldinode, NULL, NULL);
		if (error != 0 || oldinode != NULL) {
			printf("%s: vfs_hash_insert returned %d\n", __func__, error);
			// XXX and?
		}

		if (inode->i_ino == 0)
			inode->i_ino = ino;
		return (inode);
	} else {
		//printf("%s: xoxo, vfs_hash_get found %p for inode %lu\n", __func__, inode, ino);
	}

	MPASS(inode->i_ino != 0);
	MPASS(inode->i_ino == ino);

	// NB: callers don't expect NULL, will panic
	return (inode);
}

void
__destroy_inode(struct inode *inode)
{
	printf("%s: %p\n", __func__, inode);
}

void
unlock_new_inode(struct inode *inode)
{

	MPASS(inode->v_type != VNON);

	inode->i_flags &= ~I_NEW;

	if (VOP_ISLOCKED(inode)) {
		printf("%s: unlocking %p\n", __func__, inode);
		VOP_UNLOCK(inode);
	} else {
		printf("%s: not unlocking %p\n", __func__, inode);
	}
}

void
mark_inode_dirty(struct inode *inode)
{
	printf("%s: %p\n", __func__, inode);
}

bool
dir_emit(struct dir_context *ctx, const char *name, int namelen, u64 fileno, unsigned type)
{
	struct dirent dirent;
	struct uio *uio;
	size_t reclen;
	int error;

	uio = ctx->uio;

#if 0
	printf("%s: pos %ld, name %s, namelen %d, ino %lu, type %d\n",
	    __func__, ctx->pos, name, namelen, fileno, type);
#endif

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
d_add(struct dentry *d, struct inode *inode)
{
	//printf("%s: inode %p\n", __func__, inode);
	d->d_inode = inode;
}

time64_t
inode_get_atime_sec(const struct inode *inode)
{
	printf("%s: %p\n", __func__, inode);
	return (-1);
}

time64_t
inode_get_mtime_sec(const struct inode *inode)
{
	printf("%s: %p\n", __func__, inode);
	return (-1);
}

time64_t
inode_get_ctime_sec(const struct inode *inode)
{
	printf("%s: %p\n", __func__, inode);
	return (-1);
}

gid_t
from_kgid(struct user_namespace *to, kgid_t gid)
{
	printf("%s: %d\n", __func__, gid);

	return (gid);
}

gid_t
from_kuid(struct user_namespace *to, kuid_t uid)
{
	printf("%s: %d\n", __func__, uid);

	return (uid);
}

struct timespec64
simple_inode_init_ts(struct inode *inode)
{
	struct timespec64 ts = { 0, 0 };

	printf("%s: %p\n", __func__, inode);
	return (ts);
}

void
insert_inode_hash(struct inode *inode)
{
	//printf("%s: %p\n", __func__, inode);
}

void
inode_dec_link_count(struct inode *inode)
{
	printf("%s: %p\n", __func__, inode);
}

void
inc_nlink(struct inode *inode)
{
	printf("%s: %p\n", __func__, inode);
}

void
d_instantiate(struct dentry *dentry, struct inode *inode)
{
	printf("%s: %p\n", __func__, inode);
}

void
ihold(struct inode *inode)
{
	printf("%s: %p\n", __func__, inode);
}

int
setattr_prepare(struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *ia)
{
	printf("%s: %p\n", __func__, idmap);
	return (-1);
}

int
inode_newsize_ok(const struct inode *inode, loff_t offset)
{
	printf("%s: %p\n", __func__, inode);
	return (-1);
}

int
truncate_setsize(struct inode *inode, loff_t offset)
{
	printf("%s: %p\n", __func__, inode);
	return (-1);
}

void
clear_inode(struct inode *inode)
{
	printf("%s: %p\n", __func__, inode);
}

void
invalidate_inode_buffers(struct inode *inode)
{
	printf("%s: %p\n", __func__, inode);
}

int
sb_set_blocksize(struct super_block *sb, int size)
{
	sb->s_blocksize = size;

	return (0);
}
