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

#include <sys/fcntl.h>
#include <sys/mount.h>
#include <sys/namei.h>

#include <linux/types.h>
#include <linux/kobject.h>
#include <linux/completion.h>
#include <linux/atomic.h>
#include <linux/fs.h>

extern struct file_system_type *global_fst; // XXX

#define VFSTOSB(mp)    ((struct super_block *)((mp)->mnt_data))

// XXX: all this circus is here because we can't include buf.h
extern int breadn_flags(struct vnode *, daddr_t, daddr_t, int, daddr_t *, int *, 
	    int, struct ucred *, int, void (*)(struct buf *), struct buf **);

struct buffer_head *
sb_bread(struct super_block *sb, sector_t bn)
{
	struct buf *bp = NULL;
	int error;

	printf("%s: %p, mnt %p, vnode %p\n", __func__, sb, sb->s_mnt, sb->s_devvp);

	/*
	 * XXX: Our native API's for this is so sad...
	 */
	error = breadn_flags(sb->s_devvp, (daddr_t)bn, (daddr_t)bn,
	    4096 /* PACMANFS_BLOCKSIZE */, NULL, NULL, 0, NOCRED /* curthread->td_ucred */, 0, NULL, &bp);
	printf("%s: bread returned %d\n", __func__, error);
	if (error != 0) {
		return (NULL);
	}

	return ((struct buffer_head *)bp);
}

static int
lkpi_access(struct vop_access_args *ap)
{

	printf("%s: %p\n", __func__, ap);

	return (0);
}

static int
lkpi_lookup(struct vop_lookup_args *ap)
{
	struct vnode *dvp, **vpp;
	struct dentry child_dentry, *dentry;
	struct componentname *cnp;
	int error;

	printf("%s: %p\n", __func__, ap);

	dvp = ap->a_dvp;
	vpp = ap->a_vpp;
	cnp = ap->a_cnp;

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
	//printf("%s: looking up '%s'\n", __func__, child_dentry.d_name.name);
	dentry = dvp->i_op->lookup(dvp, &child_dentry, 0 /* flags */);
	printf("%s: dentry %p\n", __func__, dentry);
	error = EDOOFUS;

	return (error);
}

static int
lkpi_getattr(struct vop_getattr_args *ap)
{
	struct vnode *vp;
	struct mount *mp;
	struct vattr *vap;
	//int error;

	vp = ap->a_vp;
	//anp = vp->v_data;
	mp = vp->v_mount;
	vap = ap->a_vap;

	// XXX pacmanfs doesn't have specialised getattr
	printf("%s: %p\n", __func__, ap);

	KASSERT(ap->a_vp->v_type == VDIR, ("!VDIR"));

	vap->va_type = VDIR;
	vap->va_mode = vp->i_mode;
	vap->va_nlink = vp->i_nlink;
	vap->va_uid = vp->i_uid;
	vap->va_gid = vp->i_gid;
	vap->va_rdev = NODEV;
	vap->va_fsid = mp->mnt_stat.f_fsid.val[0];
	//vap->va_fileid = anp->an_fileno;
	vap->va_size = vp->i_size;
	vap->va_blocksize = S_BLKSIZE;
	//vap->va_mtime = anp->an_ctime;
	//vap->va_atime = anp->an_ctime;
	//vap->va_ctime = anp->an_ctime;
	//vap->va_birthtime = anp->an_ctime;
	vap->va_gen = 0;
	vap->va_flags = 0;
	vap->va_rdev = 0;
	vap->va_bytes = S_BLKSIZE;
	vap->va_filerev = 0;
	vap->va_spare = 0;

	return (0);
}

static int
lkpi_readdir(struct vop_readdir_args *ap)
{
	struct vnode *vp;
	struct dir_context ctx;
	struct file file; // XXX: we shouldn't need this
	struct uio *uio;
	size_t reclen;
	ssize_t initial_resid;
	int error;

	vp = ap->a_vp;
	uio = ap->a_uio;
	initial_resid = ap->a_uio->uio_resid;

	KASSERT(vp->v_type == VDIR, ("!VDIR"));

	if (uio->uio_offset < 0)
		return (EINVAL);

	if (ap->a_eofflag != NULL)
		*ap->a_eofflag = FALSE;

	memset(&ctx, 0, sizeof(ctx));
	memset(&file, 0, sizeof(file));
	file.f_inode = vp;

	error = vp->i_fop->iterate_shared(&file, &ctx);

	if (ap->a_eofflag != NULL)
		*ap->a_eofflag = TRUE;

	return (0);

//out:
	/*
	 * Return error if the initial buffer was too small to do anything.
	 */
	if (uio->uio_resid == initial_resid)
		return (error);

	/*
	 * Don't return an error if we managed to copy out some entries.
	 */
	if (uio->uio_resid < reclen)
		return (0);

	return (error);
}

static int
lkpi_reclaim(struct vop_reclaim_args *ap)
{
	struct vnode *vp;

	vp = ap->a_vp;

	printf("%s: %p\n", __func__, ap);

	// XXX
	vp->v_data = NULL;

	return (0);
}

struct vop_vector lkpi_vnodeops = {
	.vop_default =		&default_vnodeops,

	.vop_access =		lkpi_access,
	.vop_lookup =		lkpi_lookup,
	.vop_create =		VOP_EOPNOTSUPP,
	.vop_getattr =		lkpi_getattr,
	.vop_link =		VOP_EOPNOTSUPP,
	.vop_mknod =		VOP_EOPNOTSUPP,
	.vop_read =		VOP_EOPNOTSUPP,
	.vop_readdir =		lkpi_readdir,
	.vop_remove =		VOP_EOPNOTSUPP,
	.vop_rename =		VOP_EOPNOTSUPP,
	.vop_rmdir =		VOP_EOPNOTSUPP,
	.vop_setattr =		VOP_EOPNOTSUPP,
	.vop_symlink =		VOP_EOPNOTSUPP,
	.vop_write =		VOP_EOPNOTSUPP,
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
	vp->v_type = VDIR;

	error = insmntque(vp, sb->s_mnt);
	if (error != 0) {
		VOP_UNLOCK(vp);
		printf("%s: insmntque returned %d, vp %p\n", __func__, error, vp);
		return (NULL);
	}

	// XXX
	MNT_ILOCK(sb->s_mnt);
	MNT_REL(sb->s_mnt);
	MNT_IUNLOCK(sb->s_mnt);

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
	//vn_set_state(vp, VSTATE_CONSTRUCTED);

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
	//printf("%s: returning -%d\n", __func__, error);
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
	printf("%s: %p\n", __func__, idmap);
}

void
inode_set_ctime_to_ts(struct inode *inode, struct timespec64 ts)
{
	printf("%s: %p\n", __func__, inode);
}

void
inode_set_atime_to_ts(struct inode *inode, struct timespec64 ts)
{
	printf("%s: %p\n", __func__, inode);
}

void
inode_set_mtime_to_ts(struct inode *inode, struct timespec64 ts)
{
	printf("%s: %p\n", __func__, inode);
}

kuid_t
make_kuid(struct user_namespace *from, uid_t uid)
{
	printf("%s: %p\n", __func__, from);
	return (0);
}

kuid_t
make_kgid(struct user_namespace *from, uid_t uid)
{
	printf("%s: %p\n", __func__, from);
	return (0);
}

void
set_nlink(struct inode *inode, unsigned int nlink)
{
	printf("%s: %p\n", __func__, inode);
}

void
inode_nohighmem(struct inode *inode)
{
	printf("%s: %p\n", __func__, inode);
}

struct inode *
iget_locked(struct super_block *sb, unsigned long num)
{
	printf("%s: %p\n", __func__, sb);
	return (NULL);
}

void
__destroy_inode(struct inode *inode)
{
	printf("%s: %p\n", __func__, inode);
}

void
unlock_new_inode(struct inode *inode)
{
	printf("%s: %p\n", __func__, inode);
}

void
mark_inode_dirty(struct inode *inode)
{
	printf("%s: %p\n", __func__, inode);
}

bool
dir_emit(struct dir_context *ctx, const char *name, int namelen, u64 ino, unsigned type)
{
	printf("%s: %p\n", __func__, ctx);
	return (false);
}

bool
dir_emit_dots(struct file *file, struct dir_context *ctx)
{
	printf("%s: %p\n", __func__, file);
	return (false);
}

int
unregister_filesystem(struct file_system_type *fst)
{
	printf("%s: %p\n", __func__, fst);
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
d_add(struct dentry *d, struct inode *add)
{
	printf("%s: %p\n", __func__, d);
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
	printf("%s: %p\n", __func__, to);
	return (-1);
}

gid_t
from_kuid(struct user_namespace *to, kuid_t uid)
{
	printf("%s: %p\n", __func__, to);
	return (-1);
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
	printf("%s: %p\n", __func__, inode);
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
