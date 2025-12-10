/*-
 * Copyright (c) 2010 Isilon Systems, Inc.
 * Copyright (c) 2010 iX Systems, Inc.
 * Copyright (c) 2010 Panasas, Inc.
 * Copyright (c) 2013-2018 Mellanox Technologies, Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef	_LINUXKPI_LINUX_FS_H_
#define	_LINUXKPI_LINUX_FS_H_

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/semaphore.h>
#include <linux/spinlock.h>
#include <linux/dcache.h>
#include <linux/capability.h>
#include <linux/wait_bit.h>
#include <linux/kernel.h>
#include <linux/mutex.h>

struct module;
struct kiocb;
struct dentry;
struct page;
struct file_lock;
struct pipe_inode_info;
struct vm_area_struct;
struct poll_table_struct;
struct files_struct;
struct pfs_node;
struct linux_cdev;
struct dir_context;
struct uio;

#define	inode	vnode
#define	i_cdev	v_rdev
#define	i_private v_data

#define	S_IRUGO	(S_IRUSR | S_IRGRP | S_IROTH)
#define	S_IWUGO	(S_IWUSR | S_IWGRP | S_IWOTH)

typedef struct files_struct *fl_owner_t;

struct file_operations;
struct kstat;
struct fileattr;

#define	kuid_t uid_t
#define	kgid_t gid_t
#define	uuid_t void * // wtf
#define	sector_t uint64_t
#define	i_data v_data
#define	I_NEW	0x01
#define	FS_REQUIRES_DEV	0x01
#define	S_IRWXUGO ACCESSPERMS
#define	MODULE_ALIAS_FS(X) // XXX
#define	block_device g_consumer
#define	umin MIN
#ifndef DT_UNKNOWN
#define	DT_UNKNOWN	0x0
#endif
#define	kfree_link NULL // XXX
#define	ATTR_SIZE	0x01

struct super_block {
	void                    *s_fs_info;     /* Filesystem private info */
	struct block_device     *s_bdev;
	unsigned long           s_blocksize;
	long			s_magic; // XXX
	long			s_time_gran; // XXX
	long			s_maxbytes; // XXX
	const struct super_operations	*s_op;
	struct dentry           *s_root;
	struct mount		*s_mnt;
	struct vnode		*s_devvp;
};

// XXX: This often gets cast to 'struct buf'.
struct buffer_head {
	struct bufobj	*b_bufobj;
	long		b_bcount;
	void		*b_caller1;
	caddr_t		b_data;
	int		b_error;
	uint16_t	b_iocmd;	/* BIO_* bio_cmd from bio.h */
	uint16_t	b_ioflags;	/* BIO_* bio_flags from bio.h */
	off_t		b_iooffset;
	long		b_resid;
};

struct writeback_control {
};

struct mnt_idmap {
};

struct delayed_call {
};

extern struct mnt_idmap nop_mnt_idmap; // XXX

struct user_namespace {
};

extern struct user_namespace init_user_ns;

struct dir_context {
	off_t		pos;
	struct uio	*uio;
	int		dot;
	int		dotdot;
};

struct address_space {
};

struct path {
};

struct file_system_type {
	void	*owner;
	char	*name;
	int	fs_flags;
	struct dentry *	(*mount)(struct file_system_type *, int, const char *, void *);
	void	(*kill_sb)(struct super_block *);
};

struct __kernel_fsid_s {
	int	val[2];
};

typedef struct __kernel_fsid_s __kernel_fsid_t;

struct kstatfs {
	long f_type;
	__kernel_fsid_t f_fsid;
	long f_blocks;
	long f_namelen;
	long f_ffree;
	long f_files;
	long f_bfree;
	long f_bavail;
	long f_bsize;
};

struct iattr {
	unsigned int	ia_valid;
	mode_t		ia_mode;
	off_t		ia_size;
};

struct super_operations {
	int	(*write_inode)(struct inode *, struct writeback_control *wbc);
	int	(*sync_fs)(struct super_block *sb, int wait);
	void	(*destroy_inode)(struct inode *);
	void	(*put_super)(struct super_block *);
	void	(*umount_begin)(struct super_block *);
	void	(*evict_inode)(struct inode *);
	int	(*statfs)(struct dentry *, struct kstatfs *);
};

struct inode_operations {
	struct dentry *	(*lookup)(struct inode *,struct dentry *, unsigned int);
	int	(*create)(struct mnt_idmap *, struct inode *,struct dentry *,
			umode_t, bool);
	int	(*mkdir)(struct mnt_idmap *, struct inode *,struct dentry *,
			umode_t);
	int	(*rmdir)(struct inode *,struct dentry *);
	int	(*unlink)(struct inode *,struct dentry *);
	int	(*symlink)(struct mnt_idmap *, struct inode *,struct dentry *,
			const char *);
	int	(*link)(struct dentry *,struct inode *,struct dentry *);
	int	(*rename)(struct mnt_idmap *, struct inode *, struct dentry *,
			struct inode *, struct dentry *, unsigned int);
	int	(*setattr)(struct mnt_idmap *, struct dentry *, struct iattr *);
	const char *	(*get_link)(struct dentry *, struct inode *,
			struct delayed_call *);
};

struct linux_file_wait_queue {
	struct wait_queue wq;
	struct wait_queue_head *wqh;
	atomic_t state;
#define	LINUX_FWQ_STATE_INIT 0
#define	LINUX_FWQ_STATE_NOT_READY 1
#define	LINUX_FWQ_STATE_QUEUED 2
#define	LINUX_FWQ_STATE_READY 3
#define	LINUX_FWQ_STATE_MAX 4
};

struct linux_file {
	struct file	*_file;
	const struct file_operations	*f_op;
	void		*private_data;
	int		f_flags;
	int		f_mode;	/* Just starting mode. */
	struct dentry	*f_dentry;
	struct dentry	f_dentry_store;
	struct selinfo	f_selinfo;
	struct sigio	*f_sigio;
	struct vnode	*f_vnode;
#define	f_inode	f_vnode
	volatile u_int	f_count;

	/* anonymous shmem object */
	vm_object_t	f_shmem;

	/* kqfilter support */
	int		f_kqflags;
#define	LINUX_KQ_FLAG_HAS_READ (1 << 0)
#define	LINUX_KQ_FLAG_HAS_WRITE (1 << 1)
#define	LINUX_KQ_FLAG_NEED_READ (1 << 2)
#define	LINUX_KQ_FLAG_NEED_WRITE (1 << 3)
	/* protects f_selinfo.si_note */
	spinlock_t	f_kqlock;
	struct linux_file_wait_queue f_wait_queue;

	/* pointer to associated character device, if any */
	struct linux_cdev *f_cdev;

	struct rcu_head	rcu;
};

#define	file		linux_file
#define	fasync_struct	sigio *

#define	fasync_helper(fd, filp, on, queue)				\
({									\
	if ((on))							\
		*(queue) = &(filp)->f_sigio;				\
	else								\
		*(queue) = NULL;					\
	0;								\
})

#define	kill_fasync(queue, sig, pollstat)				\
do {									\
	if (*(queue) != NULL)						\
		pgsigio(*(queue), (sig), 0);				\
} while (0)

typedef int (*filldir_t)(void *, const char *, int, off_t, u64, unsigned);

struct file_operations {
	struct module *owner;
	ssize_t (*read)(struct linux_file *, char __user *, size_t, off_t *);
	ssize_t (*write)(struct linux_file *, const char __user *, size_t, off_t *);
	unsigned int (*poll) (struct linux_file *, struct poll_table_struct *);
	long (*unlocked_ioctl)(struct linux_file *, unsigned int, uintcap_t);
	long (*compat_ioctl)(struct linux_file *, unsigned int, uintcap_t);
	int (*mmap)(struct linux_file *, struct vm_area_struct *);
	int (*open)(struct inode *, struct file *);
	int (*release)(struct inode *, struct linux_file *);
	int (*fasync)(int, struct linux_file *, int);

/* Although not supported in FreeBSD, to align with Linux code
 * we are adding llseek() only when it is mapped to no_llseek which returns
 * an illegal seek error
 */
	off_t (*llseek)(struct linux_file *, off_t, int);
#if 0
	/* We do not support these methods.  Don't permit them to compile. */
	loff_t (*llseek)(struct file *, loff_t, int);
	ssize_t (*aio_read)(struct kiocb *, const struct iovec *,
	    unsigned long, loff_t);
	ssize_t (*aio_write)(struct kiocb *, const struct iovec *,
	    unsigned long, loff_t);
	int (*readdir)(struct file *, void *, filldir_t);
	int (*ioctl)(struct inode *, struct file *, unsigned int,
	    unsigned long);
	int (*flush)(struct file *, fl_owner_t id);
	int (*fsync)(struct file *, struct dentry *, int datasync);
	int (*aio_fsync)(struct kiocb *, int datasync);
	int (*lock)(struct file *, int, struct file_lock *);
	ssize_t (*sendpage)(struct file *, struct page *, int, size_t,
	    loff_t *, int);
	unsigned long (*get_unmapped_area)(struct file *, unsigned long,
	    unsigned long, unsigned long, unsigned long);
	int (*check_flags)(int);
	int (*flock)(struct file *, int, struct file_lock *);
	ssize_t (*splice_write)(struct pipe_inode_info *, struct file *,
	    loff_t *, size_t, unsigned int);
	ssize_t (*splice_read)(struct file *, loff_t *,
	    struct pipe_inode_info *, size_t, unsigned int);
	int (*setlease)(struct file *, long, struct file_lock **);
#endif
	int (*iterate_shared) (struct file *, struct dir_context *);
};
#define	fops_get(fops)		(fops)
#define	replace_fops(f, fops)	((f)->f_op = (fops))

#define	FMODE_READ	FREAD
#define	FMODE_WRITE	FWRITE
#define	FMODE_EXEC	FEXEC
#define	FMODE_UNSIGNED_OFFSET	0x2000
int __register_chrdev(unsigned int major, unsigned int baseminor,
    unsigned int count, const char *name,
    const struct file_operations *fops);
int __register_chrdev_p(unsigned int major, unsigned int baseminor,
    unsigned int count, const char *name,
    const struct file_operations *fops, uid_t uid,
    gid_t gid, int mode);
void __unregister_chrdev(unsigned int major, unsigned int baseminor,
    unsigned int count, const char *name);

static inline void
unregister_chrdev(unsigned int major, const char *name)
{

	__unregister_chrdev(major, 0, 256, name);
}

static inline int
register_chrdev(unsigned int major, const char *name,
    const struct file_operations *fops)
{

	return (__register_chrdev(major, 0, 256, name, fops));
}

static inline int
register_chrdev_p(unsigned int major, const char *name,
    const struct file_operations *fops, uid_t uid, gid_t gid, int mode)
{

	return (__register_chrdev_p(major, 0, 256, name, fops, uid, gid, mode));
}

static inline int
register_chrdev_region(dev_t dev, unsigned range, const char *name)
{

	return 0;
}

static inline void
unregister_chrdev_region(dev_t dev, unsigned range)
{

	return;
}

static inline int
alloc_chrdev_region(dev_t *dev, unsigned baseminor, unsigned count,
			const char *name)
{

	return 0;
}

/* No current support for seek op in FreeBSD */
static inline int
nonseekable_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static inline int
simple_open(struct inode *inode, struct file *filp)
{
	filp->private_data = inode->i_private;
	return 0;
}

extern unsigned int linux_iminor(struct inode *);
#define	iminor(...) linux_iminor(__VA_ARGS__)

static inline struct linux_file *
get_file(struct linux_file *f)
{

	refcount_acquire(f->_file == NULL ? &f->f_count : &f->_file->f_count);
	return (f);
}

static inline bool
get_file_rcu(struct linux_file *f)
{
	return (refcount_acquire_if_not_zero(
	    f->_file == NULL ? &f->f_count : &f->_file->f_count));
}

static inline struct inode *
igrab(struct inode *inode)
{
	int error;

	error = vget(inode, 0);
	if (error)
		return (NULL);

	return (inode);
}

static inline void
iput(struct inode *inode)
{

	vrele(inode);
}

static inline loff_t
no_llseek(struct file *file, loff_t offset, int whence)
{

	return (-ESPIPE);
}

static inline loff_t
default_llseek(struct file *file, loff_t offset, int whence)
{
	return (no_llseek(file, offset, whence));
}

static inline loff_t
generic_file_llseek(struct file *file, loff_t offset, int whence)
{
	return (no_llseek(file, offset, whence));
}

static inline loff_t
noop_llseek(struct linux_file *file, loff_t offset, int whence)
{

	return (file->_file->f_offset);
}

static inline struct vnode *
file_inode(const struct linux_file *file)
{

	return (file->f_vnode);
}

static inline int
call_mmap(struct linux_file *file, struct vm_area_struct *vma)
{

	return (file->f_op->mmap(file, vma));
}

static inline void
i_size_write(struct inode *inode, loff_t i_size)
{
}

/*
 * simple_read_from_buffer: copy data from kernel-space origin
 * buffer into user-space destination buffer
 *
 * @dest: destination buffer
 * @read_size: number of bytes to be transferred
 * @ppos: starting transfer position pointer
 * @orig: origin buffer
 * @buf_size: size of destination and origin buffers
 *
 * Return value:
 * On success, total bytes copied with *ppos incremented accordingly.
 * On failure, negative value.
 */
static inline ssize_t
simple_read_from_buffer(void __user *dest, size_t read_size, loff_t *ppos,
    void *orig, size_t buf_size)
{
	void *p, *read_pos = ((char *) orig) + *ppos;
	size_t buf_remain = buf_size - *ppos;

	if (buf_remain < 0 || buf_remain > buf_size)
		return -EINVAL;

	if (read_size > buf_remain)
		read_size = buf_remain;

	/*
	 * XXX At time of commit only debugfs consumers could be
	 * identified.  If others will use this function we may
	 * have to revise this: normally we would call copy_to_user()
	 * here but lindebugfs will return the result and the
	 * copyout is done elsewhere for us.
	 */
	p = memcpy(dest, read_pos, read_size);
	if (p != NULL)
		*ppos += read_size;

	return (read_size);
}

MALLOC_DECLARE(M_LSATTR);

#define	__DEFINE_SIMPLE_ATTRIBUTE(__fops, __get, __set, __fmt, __wrfunc)\
static inline int							\
__fops ## _open(struct inode *inode, struct file *filp)			\
{									\
	return (simple_attr_open(inode, filp, __get, __set, __fmt));	\
}									\
static const struct file_operations __fops = {				\
	.owner	 = THIS_MODULE,						\
	.open	 = __fops ## _open,					\
	.release = simple_attr_release,					\
	.read	 = simple_attr_read,					\
	.write	 = __wrfunc,						\
	.llseek	 = no_llseek						\
}

#define	DEFINE_SIMPLE_ATTRIBUTE(fops, get, set, fmt)			\
	__DEFINE_SIMPLE_ATTRIBUTE(fops, get, set, fmt, simple_attr_write)
#define	DEFINE_SIMPLE_ATTRIBUTE_SIGNED(fops, get, set, fmt)		\
	__DEFINE_SIMPLE_ATTRIBUTE(fops, get, set, fmt, simple_attr_write_signed)

int simple_attr_open(struct inode *inode, struct file *filp,
    int (*get)(void *, uint64_t *), int (*set)(void *, uint64_t),
    const char *fmt);

int simple_attr_release(struct inode *inode, struct file *filp);

ssize_t simple_attr_read(struct file *filp, char *buf, size_t read_size, loff_t *ppos);

ssize_t simple_attr_write(struct file *filp, const char *buf, size_t write_size, loff_t *ppos);

ssize_t simple_attr_write_signed(struct file *filp, const char *buf,
	    size_t write_size, loff_t *ppos);

void	setattr_copy(struct mnt_idmap *idmap, struct inode *inode, const struct iattr *attr);
off_t	i_size_read(const struct inode *inode);
void	set_delayed_call(struct delayed_call *call, void (*fn)(void *cb), void *arg);
void	mark_buffer_dirty(struct buffer_head *bh);
struct buffer_head	*sb_bread(struct super_block *sb, sector_t bn);
void	inode_init_owner(struct mnt_idmap *idmap, struct inode *inode, const struct inode *dir, umode_t mode);
void	inode_set_ctime_to_ts(struct inode *inode, struct timespec64 ts);
void	inode_set_atime_to_ts(struct inode *inode, struct timespec64 ts);
void	inode_set_mtime_to_ts(struct inode *inode, struct timespec64 ts);
kuid_t	make_kuid(struct user_namespace *from, uid_t uid);
kuid_t	make_kgid(struct user_namespace *from, uid_t uid);
void	set_nlink(struct inode *inode, unsigned int nlink);
void	inode_nohighmem(struct inode *inode);
struct inode	*iget_locked(struct super_block *sb, unsigned long num);
void	__destroy_inode(struct inode *inode);
void	unlock_new_inode(struct inode *inode);
void	mark_inode_dirty(struct inode *inode);
bool	dir_emit(struct dir_context *ctx, const char *name, int namelen, u64 ino, unsigned type);
bool	dir_emit_dots(struct file *file, struct dir_context *ctx);
int	unregister_filesystem(struct file_system_type *fst);
void	truncate_inode_pages_final(void *as);
void	kill_block_super(struct super_block *sb);
void	d_add(struct dentry *d, struct inode *add);
struct inode	*new_inode(struct super_block *sb);
time64_t	inode_get_atime_sec(const struct inode *inode);
time64_t	inode_get_mtime_sec(const struct inode *inode);
time64_t	inode_get_ctime_sec(const struct inode *inode);
gid_t	from_kgid(struct user_namespace *to, kgid_t gid);
gid_t	from_kuid(struct user_namespace *to, kuid_t uid);
struct timespec64	simple_inode_init_ts(struct inode *inode);
void	insert_inode_hash(struct inode *inode);
void	inode_dec_link_count(struct inode *inode);
void	inc_nlink(struct inode *inode);
void	d_instantiate(struct dentry *dentry, struct inode *inode);
void	ihold(struct inode *inode);
int	setattr_prepare(struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *ia);
int	inode_newsize_ok(const struct inode *inode, loff_t offset);
int	truncate_setsize(struct inode *inode, loff_t offset);
void	clear_inode(struct inode *inode);
void	invalidate_inode_buffers(struct inode *inode);
int	sb_set_blocksize(struct super_block *sb, int size);
struct dentry	*d_make_root(struct inode *vp);
struct dentry	*mount_bdev(struct file_system_type *fs_type, int flags,
	    const char *dev_name, void *data,
	    int (*fill_super)(struct super_block *, void *, int));
int	register_filesystem(struct file_system_type *fst);
void	brelse(struct buffer_head *bh);
size_t	bdev_nr_sectors(struct block_device *);

#endif /* _LINUXKPI_LINUX_FS_H_ */
