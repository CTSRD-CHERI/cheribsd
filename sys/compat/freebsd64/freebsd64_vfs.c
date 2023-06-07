/*-
 * Copyright (c) 2015-2019 SRI International
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of
 * the DARPA SSITH research programme.
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/syscallsubr.h>

#include <compat/freebsd64/freebsd64_proto.h>

#if defined(COMPAT_FREEBSD11)
struct freebsd11_statfs64 {
	uint32_t f_version;		/* structure version number */
	uint32_t f_type;		/* type of filesystem */
	uint64_t f_flags;		/* copy of mount exported flags */
	uint64_t f_bsize;		/* filesystem fragment size */
	uint64_t f_iosize;		/* optimal transfer block size */
	uint64_t f_blocks;		/* total data blocks in filesystem */
	uint64_t f_bfree;		/* free blocks in filesystem */
	int64_t	 f_bavail;		/* free blocks avail to non-superuser */
	uint64_t f_files;		/* total file nodes in filesystem */
	int64_t	 f_ffree;		/* free nodes avail to non-superuser */
	uint64_t f_syncwrites;		/* count of sync writes since mount */
	uint64_t f_asyncwrites;		/* count of async writes since mount */
	uint64_t f_syncreads;		/* count of sync reads since mount */
	uint64_t f_asyncreads;		/* count of async reads since mount */
	uint64_t f_spare[10];		/* unused spare */
	uint32_t f_namemax;		/* maximum filename length */
	uid_t	  f_owner;		/* user that mounted the filesystem */
	fsid_t	  f_fsid;		/* filesystem id */
	char	  f_charspare[80];	/* spare string space */
	char	  f_fstypename[16];	/* filesystem type name */
	char	  f_mntfromname[88];	/* mounted filesystem */
	char	  f_mntonname[88];	/* directory on which mounted */
};

struct freebsd11_stat64 {
	__uint32_t st_dev;		/* inode's device */
	__uint32_t st_ino;		/* inode's number */
	mode_t	  st_mode;		/* inode protection mode */
	__uint16_t st_nlink;		/* number of hard links */
	uid_t	  st_uid;		/* user ID of the file's owner */
	gid_t	  st_gid;		/* group ID of the file's group */
	__uint32_t st_rdev;		/* device type */
	struct	timespec st_atim;	/* time of last access */
	struct	timespec st_mtim;	/* time of last data modification */
	struct	timespec st_ctim;	/* time of last file status change */
	off_t	  st_size;		/* file size, in bytes */
	blkcnt_t st_blocks;		/* blocks allocated for file */
	blksize_t st_blksize;		/* optimal blocksize for I/O */
	fflags_t  st_flags;		/* user defined flags for file */
	__uint32_t st_gen;		/* file generation number */
	__int32_t st_lspare;
	struct timespec st_birthtim;	/* time of file creation */
	/*
	 * Explicitly pad st_birthtim to 16 bytes so that the size of
	 * struct stat is backwards compatible.  We use bitfields instead
	 * of an array of chars so that this doesn't require a C99 compiler
	 * to compile if the size of the padding is 0.  We use 2 bitfields
	 * to cover up to 64 bits on 32-bit machines.  We assume that
	 * CHAR_BIT is 8...
	 */
	unsigned int :(8 / 2) * (16 - (int)sizeof(struct timespec));
	unsigned int :(8 / 2) * (16 - (int)sizeof(struct timespec));
};

struct nstat64 {
	__uint32_t st_dev;		/* inode's device */
	__uint32_t st_ino;		/* inode's number */
	__uint32_t st_mode;		/* inode protection mode */
	__uint32_t st_nlink;		/* number of hard links */
	uid_t	  st_uid;		/* user ID of the file's owner */
	gid_t	  st_gid;		/* group ID of the file's group */
	__uint32_t st_rdev;		/* device type */
	struct	timespec st_atim;	/* time of last access */
	struct	timespec st_mtim;	/* time of last data modification */
	struct	timespec st_ctim;	/* time of last file status change */
	off_t	  st_size;		/* file size, in bytes */
	blkcnt_t st_blocks;		/* blocks allocated for file */
	blksize_t st_blksize;		/* optimal blocksize for I/O */
	fflags_t  st_flags;		/* user defined flags for file */
	__uint32_t st_gen;		/* file generation number */
	struct timespec st_birthtim;	/* time of file creation */
	/*
	 * See comment in the definition of struct freebsd11_stat
	 * above about the following padding.
	 */
	unsigned int :(8 / 2) * (16 - (int)sizeof(struct timespec));
	unsigned int :(8 / 2) * (16 - (int)sizeof(struct timespec));
};

static void freebsd11_freebsd64_cvtnstat(struct stat *sb, struct nstat64 *nsb);
#endif

/*
 * kern_descrip.h
 */

#if defined(COMPAT_43) || defined(COMPAT_FREEBSD11)
extern int ino64_trunc_error;

static int
freebsd11_freebsd64_cvtstat(struct stat *st, struct freebsd11_stat64 *ost)
{
	ost->st_dev = st->st_dev;
	if (ost->st_dev != st->st_dev) {
		switch (ino64_trunc_error) {
		default:
			/*
			 * Since dev_t is almost raw, don't clamp to the
			 * maximum for case 2, but ignore the error.
			 */
			break;
		case 1:
			return (EOVERFLOW);
		}
	}
	ost->st_ino = st->st_ino;
	if (ost->st_ino != st->st_ino) {
		switch (ino64_trunc_error) {
		default:
		case 0:
			break;
		case 1:
			return (EOVERFLOW);
		case 2:
			ost->st_ino = UINT32_MAX;
			break;
		}
	}
	ost->st_mode = st->st_mode;
	ost->st_nlink = st->st_nlink;
	if (ost->st_nlink != st->st_nlink) {
		switch (ino64_trunc_error) {
		default:
		case 0:
			break;
		case 1:
			return (EOVERFLOW);
		case 2:
			ost->st_nlink = UINT16_MAX;
			break;
		}
	}
	ost->st_uid = st->st_uid;
	ost->st_gid = st->st_gid;
	ost->st_rdev = st->st_rdev;
	if (ost->st_rdev != st->st_rdev) {
		switch (ino64_trunc_error) {
		default:
			break;
		case 1:
			return (EOVERFLOW);
		}
	}
	ost->st_atim = st->st_atim;
	ost->st_mtim = st->st_mtim;
	ost->st_ctim = st->st_ctim;
	ost->st_size = st->st_size;
	ost->st_blocks = st->st_blocks;
	ost->st_blksize = st->st_blksize;
	ost->st_flags = st->st_flags;
	ost->st_gen = st->st_gen;
	ost->st_lspare = 0;
	ost->st_birthtim = st->st_birthtim;
	bzero((char *)&ost->st_birthtim + sizeof(ost->st_birthtim),
	    sizeof(*ost) - offsetof(struct freebsd11_stat,
	    st_birthtim) - sizeof(ost->st_birthtim));
	return (0);
}

int
freebsd11_freebsd64_stat(struct thread *td,
    struct freebsd11_freebsd64_stat_args* uap)
{
	struct stat sb;
	struct freebsd11_stat64 osb;
	int error;

	error = kern_statat(td, 0, AT_FDCWD, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, &sb, NULL);
	if (error != 0)
		return (error);
	error = freebsd11_freebsd64_cvtstat(&sb, &osb);
	if (error == 0)
		error = copyout(&osb, __USER_CAP_OBJ(uap->ub), sizeof(osb));
	return (error);
}

/*
 * Return status information about a file descriptor.
 */
int
freebsd11_freebsd64_nfstat(struct thread *td,
    struct freebsd11_freebsd64_nfstat_args *uap)
{
	struct nstat64 nub;
	struct stat ub;
	int error;

	error = kern_fstat(td, uap->fd, &ub);
	if (error == 0) {
		freebsd11_freebsd64_cvtnstat(&ub, &nub);
		error = copyout(&nub, __USER_CAP_OBJ(uap->sb), sizeof(nub));
	}
	return (error);
}
#endif /* COMPAT_FREEBSD11 */

/*
 * vfs_acl.c
 */
int
freebsd64___acl_get_file(struct thread *td,
    struct freebsd64___acl_get_file_args *uap)
{
	return (kern___acl_get_path(td, __USER_CAP_STR(uap->path), uap->type,
	    __USER_CAP_OBJ(uap->aclp), FOLLOW));
}

int
freebsd64___acl_get_link(struct thread *td,
    struct freebsd64___acl_get_link_args *uap)
{
	return (kern___acl_get_path(td, __USER_CAP_STR(uap->path), uap->type,
	    __USER_CAP_OBJ(uap->aclp), NOFOLLOW));
}

int
freebsd64___acl_set_file(struct thread *td,
    struct freebsd64___acl_set_file_args *uap)
{
	return(kern___acl_set_path(td, __USER_CAP_STR(uap->path), uap->type,
	    __USER_CAP_OBJ(uap->aclp), FOLLOW));
}

int
freebsd64___acl_set_link(struct thread *td,
    struct freebsd64___acl_set_link_args *uap)
{
	return(kern___acl_set_path(td, __USER_CAP_STR(uap->path), uap->type,
	    __USER_CAP_OBJ(uap->aclp), NOFOLLOW));
}

int
freebsd64___acl_get_fd(struct thread *td,
    struct freebsd64___acl_get_fd_args *uap)
{
	return (kern___acl_get_fd(td, uap->filedes, uap->type,
	    __USER_CAP_OBJ(uap->aclp)));
}

int
freebsd64___acl_set_fd(struct thread *td,
    struct freebsd64___acl_set_fd_args *uap)
{
	return (kern___acl_set_fd(td, uap->filedes, uap->type,
	    __USER_CAP_OBJ(uap->aclp)));
}

int
freebsd64___acl_delete_file(struct thread *td,
    struct freebsd64___acl_delete_file_args *uap)
{
	return (kern___acl_delete_path(td, __USER_CAP_STR(uap->path),
	    uap->type, FOLLOW));
}

int
freebsd64___acl_delete_link(struct thread *td,
    struct freebsd64___acl_delete_link_args *uap)
{
	return (kern___acl_delete_path(td, __USER_CAP_STR(uap->path),
	    uap->type, NOFOLLOW));
}

int
freebsd64___acl_aclcheck_file(struct thread *td,
    struct freebsd64___acl_aclcheck_file_args *uap)
{
	return (kern___acl_aclcheck_path(td, __USER_CAP_STR(uap->path),
	    uap->type, __USER_CAP_OBJ(uap->aclp), FOLLOW));
}

int
freebsd64___acl_aclcheck_link(struct thread *td,
    struct freebsd64___acl_aclcheck_link_args *uap)
{
	return (kern___acl_aclcheck_path(td, __USER_CAP_STR(uap->path),
	    uap->type, __USER_CAP_OBJ(uap->aclp), NOFOLLOW));
}

int
freebsd64___acl_aclcheck_fd(struct thread *td,
    struct freebsd64___acl_aclcheck_fd_args *uap)
{
	return (kern___acl_aclcheck_fd(td, uap->filedes, uap->type,
	    __USER_CAP_OBJ(uap->aclp)));
}

/*
 * vfs_cache.c
 */
int
freebsd64___getcwd(struct thread *td, struct freebsd64___getcwd_args *uap)
{
	return (kern___getcwd(td, __USER_CAP(uap->buf, uap->buflen),
	    uap->buflen));
}

int
freebsd64___realpathat(struct thread *td,
    struct freebsd64___realpathat_args *uap)
{
	return (kern___realpathat(td, uap->fd, __USER_CAP_STR(uap->path),
	    __USER_CAP(uap->buf, uap->size), uap->size, uap->flags,
	    UIO_USERSPACE));
}

/*
 * vfs_extattr.c
 */
int
freebsd64_extattrctl(struct thread *td, struct freebsd64_extattrctl_args *uap)
{
	return (kern_extattrctl(td, __USER_CAP_STR(uap->path), uap->cmd,
	    __USER_CAP_STR(uap->filename), uap->attrnamespace,
	    __USER_CAP_STR(uap->attrname)));
}

int
freebsd64_extattr_set_fd(struct thread *td,
    struct freebsd64_extattr_set_fd_args *uap)
{
	return (kern_extattr_set_fd(td, uap->fd, uap->attrnamespace,
	    __USER_CAP_STR(uap->attrname), __USER_CAP(uap->data, uap->nbytes),
	    uap->nbytes));
}

int
freebsd64_extattr_set_file(struct thread *td,
    struct freebsd64_extattr_set_file_args *uap)
{
	return (kern_extattr_set_path(td, __USER_CAP_STR(uap->path),
	    uap->attrnamespace, __USER_CAP_STR(uap->attrname),
	    __USER_CAP(uap->data, uap->nbytes), uap->nbytes, FOLLOW));
}

int
freebsd64_extattr_set_link(struct thread *td,
    struct freebsd64_extattr_set_link_args *uap)
{
	return (kern_extattr_set_path(td, __USER_CAP_STR(uap->path),
	    uap->attrnamespace, __USER_CAP_STR(uap->attrname),
	    __USER_CAP(uap->data, uap->nbytes), uap->nbytes, NOFOLLOW));
}

int
freebsd64_extattr_get_fd(struct thread *td,
    struct freebsd64_extattr_get_fd_args *uap)
{
	return (kern_extattr_get_fd(td, uap->fd, uap->attrnamespace,
	    __USER_CAP_STR(uap->attrname),
	    __USER_CAP(uap->data, uap->nbytes), uap->nbytes));
}

int
freebsd64_extattr_get_file(struct thread *td,
    struct freebsd64_extattr_get_file_args *uap)
{
	return (kern_extattr_get_path(td, __USER_CAP_STR(uap->path),
	    uap->attrnamespace, __USER_CAP_STR(uap->attrname),
	    __USER_CAP(uap->data, uap->nbytes), uap->nbytes, FOLLOW));
}

int
freebsd64_extattr_get_link(struct thread *td,
    struct freebsd64_extattr_get_link_args *uap)
{
	return (kern_extattr_get_path(td, __USER_CAP_STR(uap->path),
	    uap->attrnamespace, __USER_CAP_STR(uap->attrname),
	    __USER_CAP(uap->data, uap->nbytes), uap->nbytes, NOFOLLOW));
}

int
freebsd64_extattr_delete_fd(struct thread *td,
    struct freebsd64_extattr_delete_fd_args *uap)
{
	return (kern_extattr_delete_fd(td, uap->fd, uap->attrnamespace,
	    __USER_CAP_STR(uap->attrname)));
}

int
freebsd64_extattr_delete_file(struct thread *td,
    struct freebsd64_extattr_delete_file_args *uap)
{
	return (kern_extattr_delete_path(td, __USER_CAP_STR(uap->path),
	    uap->attrnamespace, __USER_CAP_STR(uap->attrname), FOLLOW));
}

int
freebsd64_extattr_delete_link(struct thread *td,
    struct freebsd64_extattr_delete_link_args *uap)
{
	return (kern_extattr_delete_path(td, __USER_CAP_STR(uap->path),
	    uap->attrnamespace, __USER_CAP_STR(uap->attrname), NOFOLLOW));
}

int
freebsd64_extattr_list_fd(struct thread *td,
    struct freebsd64_extattr_list_fd_args *uap)
{
	return (kern_extattr_list_fd(td, uap->fd, uap->attrnamespace,
	    __USER_CAP(uap->data, uap->nbytes), uap->nbytes));
}

int
freebsd64_extattr_list_file(struct thread *td,
    struct freebsd64_extattr_list_file_args *uap)
{
	return (kern_extattr_list_path(td, __USER_CAP_STR(uap->path),
	    uap->attrnamespace, __USER_CAP(uap->data, uap->nbytes),
	    uap->nbytes, FOLLOW));
}

int
freebsd64_extattr_list_link(struct thread *td,
    struct freebsd64_extattr_list_link_args *uap)
{
	return (kern_extattr_list_path(td, __USER_CAP_STR(uap->path),
	    uap->attrnamespace, __USER_CAP(uap->data, uap->nbytes),
	    uap->nbytes, NOFOLLOW));
}

/*
 * vfs_syscalls.c
 */

#ifdef COMPAT_FREEBSD11
int
freebsd11_freebsd64_lstat(struct thread *td,
    struct freebsd11_freebsd64_lstat_args* uap)
{
	struct stat sb;
	struct freebsd11_stat64 osb;
	int error;

	error = kern_statat(td, AT_SYMLINK_NOFOLLOW, AT_FDCWD,
	    __USER_CAP_STR(uap->path), UIO_USERSPACE, &sb, NULL);
	if (error != 0)
		return (error);
	error = freebsd11_freebsd64_cvtstat(&sb, &osb);
	if (error == 0)
		error = copyout(&osb, __USER_CAP_OBJ(uap->ub), sizeof(osb));
	return (error);
}

int
freebsd11_freebsd64_fhstat(struct thread *td,
    struct freebsd11_freebsd64_fhstat_args* uap)
{
	struct fhandle fh;
	struct stat sb;
	struct freebsd11_stat64 osb;
	int error;

	error = copyin(__USER_CAP_OBJ(uap->u_fhp), &fh, sizeof(fhandle_t));
	if (error != 0)
		return (error);
	error = kern_fhstat(td, fh, &sb);
	if (error != 0)
		return (error);
	error = freebsd11_freebsd64_cvtstat(&sb, &osb);
	if (error == 0)
		error = copyout(&osb, __USER_CAP_OBJ(uap->sb), sizeof(osb));
	return (error);
}

int
freebsd11_freebsd64_fstatat(struct thread *td,
    struct freebsd11_freebsd64_fstatat_args* uap)
{
	struct stat sb;
	struct freebsd11_stat64 osb;
	int error;

	error = kern_statat(td, uap->flag, uap->fd, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, &sb, NULL);
	if (error != 0)
		return (error);
	error = freebsd11_freebsd64_cvtstat(&sb, &osb);
	if (error == 0)
		error = copyout(&osb, __USER_CAP_OBJ(uap->buf), sizeof(osb));
	return (error);
}

int
freebsd11_freebsd64_fstat(struct thread *td,
    struct freebsd11_freebsd64_fstat_args *uap)
{
	struct stat sb;
	struct freebsd11_stat64 osb;
	int error;

	error = kern_fstat(td, uap->fd, &sb);
	if (error != 0)
		return (error);
	error = freebsd11_freebsd64_cvtstat(&sb, &osb);
	if (error == 0)
		error = copyout(&osb, __USER_CAP_OBJ(uap->sb), sizeof(osb));
	return (error);
}

/*
 * Implementation of the NetBSD [l]stat() functions.
 */
static void
freebsd11_freebsd64_cvtnstat(struct stat *sb, struct nstat64 *nsb)
{
	bzero(nsb, sizeof(*nsb));
	nsb->st_dev = sb->st_dev;
	nsb->st_ino = sb->st_ino;
	nsb->st_mode = sb->st_mode;
	nsb->st_nlink = sb->st_nlink;
	nsb->st_uid = sb->st_uid;
	nsb->st_gid = sb->st_gid;
	nsb->st_rdev = sb->st_rdev;
	nsb->st_atim = sb->st_atim;
	nsb->st_mtim = sb->st_mtim;
	nsb->st_ctim = sb->st_ctim;
	nsb->st_size = sb->st_size;
	nsb->st_blocks = sb->st_blocks;
	nsb->st_blksize = sb->st_blksize;
	nsb->st_flags = sb->st_flags;
	nsb->st_gen = sb->st_gen;
	nsb->st_birthtim = sb->st_birthtim;
}

int
freebsd11_freebsd64_nstat(struct thread *td,
    struct freebsd11_freebsd64_nstat_args *uap)
{
	struct stat sb;
	struct nstat64 nsb;
	int error;

	error = kern_statat(td, 0, AT_FDCWD, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, &sb, NULL);
	if (error != 0)
		return (error);
	freebsd11_freebsd64_cvtnstat(&sb, &nsb);
	return (copyout(&nsb, __USER_CAP_OBJ(uap->ub), sizeof (nsb)));
}

/*
 * NetBSD lstat.  Get file status; this version does not follow links.
 */
int
freebsd11_freebsd64_nlstat(struct thread *td,
    struct freebsd11_freebsd64_nlstat_args *uap)
{
	struct stat sb;
	struct nstat64 nsb;
	int error;

	error = kern_statat(td, AT_SYMLINK_NOFOLLOW, AT_FDCWD,
	    __USER_CAP_STR(uap->path), UIO_USERSPACE, &sb, NULL);
	if (error != 0)
		return (error);
	freebsd11_freebsd64_cvtnstat(&sb, &nsb);
	return (copyout(&nsb, __USER_CAP_OBJ(uap->ub), sizeof (nsb)));
}

int
freebsd11_freebsd64_getdirentries(struct thread *td,
    struct freebsd11_freebsd64_getdirentries_args *uap)
{
	long base;
	int error;

	error = freebsd11_kern_getdirentries(td, uap->fd,
	    __USER_CAP(uap->buf, uap->count), uap->count, &base, NULL);

	if (error == 0 && uap->basep != NULL)
		error = copyout(&base, __USER_CAP(uap->basep, sizeof(long)),
		    sizeof(long));
	return (error);
}

int
freebsd11_freebsd64_getdents(struct thread *td,
    struct freebsd11_freebsd64_getdents_args *uap)
{
	struct freebsd11_freebsd64_getdirentries_args ap;

	ap.fd = uap->fd;
	ap.buf = uap->buf;
	ap.count = uap->count;
	ap.basep = NULL;
	return (freebsd11_freebsd64_getdirentries(td, &ap));
}
#endif /* COMPAT_FREEBSD11 */

int
freebsd64_quotactl(struct thread *td, struct freebsd64_quotactl_args *uap)
{
	return (kern_quotactl(td, __USER_CAP_STR(uap->path),
	    uap->cmd, uap->uid, __USER_CAP_UNBOUND(uap->arg)));
}

int
freebsd64_statfs(struct thread *td, struct freebsd64_statfs_args *uap)
{
	return (user_statfs(td, __USER_CAP_STR(uap->path),
	    __USER_CAP_OBJ(uap->buf)));
}

int
freebsd64_fstatfs(struct thread *td, struct freebsd64_fstatfs_args *uap)
{
	return (user_fstatfs(td, uap->fd, __USER_CAP_OBJ(uap->buf)));
}

int
freebsd64_getfsstat(struct thread *td, struct freebsd64_getfsstat_args *uap)
{
	return (user_getfsstat(td, __USER_CAP(uap->buf, uap->bufsize),
	    uap->bufsize, uap->mode));
}

#if defined(COMPAT_FREEBSD11)
/*
 * Get old format filesystem statistics.
 */
static void freebsd11_freebsd64_cvtstatfs(struct statfs *,
    struct freebsd11_statfs64 *);

int
freebsd11_freebsd64_statfs(struct thread *td,
    struct freebsd11_freebsd64_statfs_args *uap)
{
	struct freebsd11_statfs64 osb;
	struct statfs *sfp;
	int error;

	sfp = malloc(sizeof(struct statfs), M_STATFS, M_WAITOK);
	error = kern_statfs(td, __USER_CAP_STR(uap->path), UIO_USERSPACE, sfp);
	if (error == 0) {
		freebsd11_freebsd64_cvtstatfs(sfp, &osb);
		error = copyout(&osb, __USER_CAP_OBJ(uap->buf), sizeof(osb));
	}
	free(sfp, M_STATFS);
	return (error);
}

/*
 * Get filesystem statistics.
 */
int
freebsd11_freebsd64_fstatfs(struct thread *td,
    struct freebsd11_freebsd64_fstatfs_args *uap)
{
	struct freebsd11_statfs64 osb;
	struct statfs *sfp;
	int error;

	sfp = malloc(sizeof(struct statfs), M_STATFS, M_WAITOK);
	error = kern_fstatfs(td, uap->fd, sfp);
	if (error == 0) {
		freebsd11_freebsd64_cvtstatfs(sfp, &osb);
		error = copyout(&osb, __USER_CAP_OBJ(uap->buf), sizeof(osb));
	}
	free(sfp, M_STATFS);
	return (error);
}

/*
 * Get statistics on all filesystems.
 */
int
freebsd11_freebsd64_getfsstat(struct thread *td,
    struct freebsd11_freebsd64_getfsstat_args *uap)
{
	struct freebsd11_statfs64 osb;
	struct statfs * __capability buf;
	struct statfs *sp;
	size_t count, size;
	int error;

	count = uap->bufsize / sizeof(struct ostatfs);
	size = count * sizeof(struct statfs);
	error = kern_getfsstat(td, &buf, size, &count, UIO_SYSSPACE,
	    uap->mode);
	if (error == 0)
		td->td_retval[0] = count;
	if (size > 0) {
		sp = (__cheri_fromcap struct statfs *)buf;
		while (count > 0 && error == 0) {
			freebsd11_freebsd64_cvtstatfs(sp, &osb);
			error = copyout(&osb, __USER_CAP_OBJ(uap->buf),
			    sizeof(osb));
			sp++;
			uap->buf++;
			count--;
		}
		free_c(buf, M_STATFS);
	}
	return (error);
}

/*
 * Implement fstatfs() for (NFS) file handles.
 */
int
freebsd11_freebsd64_fhstatfs(struct thread *td,
    struct freebsd11_freebsd64_fhstatfs_args *uap)
{
	struct freebsd11_statfs64 osb;
	struct statfs *sfp;
	fhandle_t fh;
	int error;

	error = copyin(__USER_CAP_OBJ(uap->u_fhp), &fh, sizeof(fhandle_t));
	if (error)
		return (error);
	sfp = malloc(sizeof(struct statfs), M_STATFS, M_WAITOK);
	error = kern_fhstatfs(td, fh, sfp);
	if (error == 0) {
		freebsd11_freebsd64_cvtstatfs(sfp, &osb);
		error = copyout(&osb, __USER_CAP_OBJ(uap->buf), sizeof(osb));
	}
	free(sfp, M_STATFS);
	return (error);
}

/*
 * Convert a new format statfs structure to an old format statfs structure.
 */
static void
freebsd11_freebsd64_cvtstatfs(struct statfs *nsp,
    struct freebsd11_statfs64 *osp)
{

	bzero(osp, sizeof(*osp));
	osp->f_version = FREEBSD11_STATFS_VERSION;
	osp->f_type = nsp->f_type;
	osp->f_flags = nsp->f_flags;
	osp->f_bsize = nsp->f_bsize;
	osp->f_iosize = nsp->f_iosize;
	osp->f_blocks = nsp->f_blocks;
	osp->f_bfree = nsp->f_bfree;
	osp->f_bavail = nsp->f_bavail;
	osp->f_files = nsp->f_files;
	osp->f_ffree = nsp->f_ffree;
	osp->f_syncwrites = nsp->f_syncwrites;
	osp->f_asyncwrites = nsp->f_asyncwrites;
	osp->f_syncreads = nsp->f_syncreads;
	osp->f_asyncreads = nsp->f_asyncreads;
	osp->f_namemax = nsp->f_namemax;
	osp->f_owner = nsp->f_owner;
	osp->f_fsid = nsp->f_fsid;
	strlcpy(osp->f_fstypename, nsp->f_fstypename,
	    MIN(MFSNAMELEN, sizeof(osp->f_fstypename)));
	strlcpy(osp->f_mntonname, nsp->f_mntonname,
	    MIN(MNAMELEN, sizeof(osp->f_mntonname)));
	strlcpy(osp->f_mntfromname, nsp->f_mntfromname,
	    MIN(MNAMELEN, sizeof(osp->f_mntfromname)));
}
#endif /* COMPAT_FREEBSD11 */

int
freebsd64_chdir(struct thread *td, struct freebsd64_chdir_args *uap)
{
	return (kern_chdir(td, __USER_CAP_STR(uap->path), UIO_USERSPACE));
}

int
freebsd64_chroot(struct thread *td, struct freebsd64_chroot_args *uap)
{
	return (kern_chroot(td, __USER_CAP_STR(uap->path)));
}

int
freebsd64_open(struct thread *td, struct freebsd64_open_args *uap)
{
	return (kern_openat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->flags, uap->mode));
}

int
freebsd64_openat(struct thread *td, struct freebsd64_openat_args *uap)
{
	return (kern_openat(td, uap->fd, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->flag, uap->mode));
}


int
freebsd64_mknodat(struct thread *td, struct freebsd64_mknodat_args *uap)
{
	return (kern_mknodat(td, uap->fd, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->mode, uap->dev));
}

#if defined(COMPAT_FREEBSD11)
int
freebsd11_freebsd64_mknod(struct thread *td,
    struct freebsd11_freebsd64_mknod_args *uap)
{
	return (kern_mknodat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->mode, uap->dev));
}

int
freebsd11_freebsd64_mknodat(struct thread *td,
    struct freebsd11_freebsd64_mknodat_args *uap)
{
	return (kern_mknodat(td, uap->fd, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->mode, uap->dev));
}
#endif /* COMPAT_FREEBSD11 */

int
freebsd64_mkfifo(struct thread *td, struct freebsd64_mkfifo_args *uap)
{
	return (kern_mkfifoat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->mode));
}

int
freebsd64_mkfifoat(struct thread *td, struct freebsd64_mkfifoat_args *uap)
{
	return (kern_mkfifoat(td, uap->fd, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->mode));
}

int
freebsd64_link(struct thread *td, struct freebsd64_link_args *uap)
{
	return (kern_linkat(td, AT_FDCWD, AT_FDCWD, __USER_CAP_STR(uap->path),
	    __USER_CAP_STR(uap->to), UIO_USERSPACE, AT_SYMLINK_FOLLOW));
}

int
freebsd64_linkat(struct thread *td, struct freebsd64_linkat_args *uap)
{
	return (kern_linkat(td, uap->fd1, uap->fd2, __USER_CAP_STR(uap->path1),
	    __USER_CAP_STR(uap->path2), UIO_USERSPACE, uap->flag));
}

int
freebsd64_symlink(struct thread *td, struct freebsd64_symlink_args *uap)
{
	return (kern_symlinkat(td, __USER_CAP_STR(uap->path), AT_FDCWD,
	    __USER_CAP_STR(uap->link), UIO_USERSPACE));
}

int
freebsd64_symlinkat(struct thread *td, struct freebsd64_symlinkat_args *uap)
{
	return (kern_symlinkat(td, __USER_CAP_STR(uap->path1), uap->fd,
	    __USER_CAP_STR(uap->path2), UIO_USERSPACE));
}

int
freebsd64_undelete(struct thread *td, struct freebsd64_undelete_args *uap)
{
	return (kern_undelete(td, __USER_CAP_STR(uap->path), UIO_USERSPACE));
}

int
freebsd64_unlink(struct thread *td, struct freebsd64_unlink_args *uap)
{
	return (kern_funlinkat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    FD_NONE, UIO_USERSPACE, 0, 0));
}

int
freebsd64_unlinkat(struct thread *td, struct freebsd64_unlinkat_args *uap)
{
	return (kern_funlinkat_ex(td, uap->fd, __USER_CAP_STR(uap->path),
	    FD_NONE, uap->flag, UIO_USERSPACE, 0));
}

int
freebsd64_funlinkat(struct thread *td, struct freebsd64_funlinkat_args *uap)
{
	return (kern_funlinkat_ex(td, uap->dfd, __USER_CAP_STR(uap->path),
	    uap->fd, uap->flag, UIO_USERSPACE, 0));
}

int
freebsd64_access(struct thread *td, struct freebsd64_access_args *uap)
{
	return (kern_accessat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, 0, uap->amode));
}

int
freebsd64_faccessat(struct thread *td, struct freebsd64_faccessat_args *uap)
{
	return (kern_accessat(td, uap->fd, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->flag, uap->amode));
}

int
freebsd64_eaccess(struct thread *td, struct freebsd64_eaccess_args *uap)
{
	return (kern_accessat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, AT_EACCESS, uap->amode));
}

int
freebsd64_fstatat(struct thread *td, struct freebsd64_fstatat_args *uap)
{
	return (user_fstatat(td, uap->fd, __USER_CAP_STR(uap->path),
	    __USER_CAP_OBJ(uap->buf), uap->flag));
}

int
freebsd64_pathconf(struct thread *td, struct freebsd64_pathconf_args *uap)
{
	long value;
	int error;

	error = kern_pathconf(td, __USER_CAP_STR(uap->path), UIO_USERSPACE,
	    uap->name, FOLLOW, &value);
	if (error == 0)
		td->td_retval[0] = value;
	return (error);
}

int
freebsd64_lpathconf(struct thread *td, struct freebsd64_lpathconf_args *uap)
{
	long value;
	int error;

	error = kern_pathconf(td, __USER_CAP_STR(uap->path), UIO_USERSPACE,
	    uap->name, NOFOLLOW, &value);
	if (error == 0)
		td->td_retval[0] = value;
	return (error);
}

int
freebsd64_readlink(struct thread *td, struct freebsd64_readlink_args *uap)
{
	return (kern_readlinkat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, __USER_CAP(uap->buf, uap->count), UIO_USERSPACE,
	    uap->count));
}

int
freebsd64_readlinkat(struct thread *td, struct freebsd64_readlinkat_args *uap)
{
	return (kern_readlinkat(td, uap->fd, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, __USER_CAP(uap->buf, uap->bufsize), UIO_USERSPACE,
	    uap->bufsize));
}

int
freebsd64_chflags(struct thread *td, struct freebsd64_chflags_args *uap)
{
	return (kern_chflagsat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->flags, 0));
}

int
freebsd64_chflagsat(struct thread *td, struct freebsd64_chflagsat_args *uap)
{
	return (kern_chflagsat(td, uap->fd, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->flags, uap->atflag));
}

int
freebsd64_lchflags(struct thread *td, struct freebsd64_lchflags_args *uap)
{
	return (kern_chflagsat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->flags, AT_SYMLINK_NOFOLLOW));
}

int
freebsd64_chmod(struct thread *td, struct freebsd64_chmod_args *uap)
{
	return (kern_fchmodat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->mode, 0));
}

int
freebsd64_fchmodat(struct thread *td, struct freebsd64_fchmodat_args *uap)
{
	return (kern_fchmodat(td, uap->fd, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->mode, uap->flag));
}

int
freebsd64_lchmod(struct thread *td, struct freebsd64_lchmod_args *uap)
{
	return (kern_fchmodat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->mode, AT_SYMLINK_NOFOLLOW));
}

int
freebsd64_chown(struct thread *td, struct freebsd64_chown_args *uap)
{
	return (kern_fchownat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->uid, uap->gid, 0));
}

int
freebsd64_fchownat(struct thread *td, struct freebsd64_fchownat_args *uap)
{
	return (kern_fchownat(td, uap->fd, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->uid, uap->gid, uap->flag));
}

int
freebsd64_lchown(struct thread *td, struct freebsd64_lchown_args *uap)
{
	return (kern_fchownat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->uid, uap->gid, AT_SYMLINK_NOFOLLOW));
}

int
freebsd64_utimes(struct thread *td, struct freebsd64_utimes_args *uap)
{
	return (kern_utimesat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, __USER_CAP_OBJ(uap->tptr), UIO_USERSPACE));
}

int
freebsd64_futimesat(struct thread *td, struct freebsd64_futimesat_args *uap)
{
	return (kern_utimesat(td, uap->fd, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, __USER_CAP_OBJ(uap->times), UIO_USERSPACE));
}

int
freebsd64_futimes(struct thread *td, struct freebsd64_futimes_args *uap)
{
	return (kern_futimes(td, uap->fd, __USER_CAP_OBJ(uap->tptr),
	    UIO_USERSPACE));
}


int
freebsd64_lutimes(struct thread *td, struct freebsd64_lutimes_args *uap)
{
	return (kern_lutimes(td, __USER_CAP_OBJ(uap->path), UIO_USERSPACE,
	    __USER_CAP_OBJ(uap->tptr), UIO_USERSPACE));
}

int
freebsd64_futimens(struct thread *td, struct freebsd64_futimens_args *uap)
{
	return (kern_futimens(td, uap->fd, __USER_CAP_OBJ(uap->times),
	    UIO_USERSPACE));
}

int
freebsd64_utimensat(struct thread *td, struct freebsd64_utimensat_args *uap)
{
	return (kern_utimensat(td, uap->fd, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, __USER_CAP_OBJ(uap->times), UIO_USERSPACE,
	    uap->flag));
}

int
freebsd64_truncate(struct thread *td, struct freebsd64_truncate_args *uap)
{
	return (kern_truncate(td, __USER_CAP_STR(uap->path), UIO_USERSPACE,
	    uap->length));
}

#if defined(COMPAT_FREEBSD6)
/* Versions with the pad argument */
int
freebsd6_truncate(struct thread *td, struct freebsd6_truncate_args *uap)
{
	return (kern_truncate(td, __USER_CAP_STR(uap->path), UIO_USERSPACE,
	    uap->length));
}
#endif

int
freebsd64_rename(struct thread *td, struct freebsd64_rename_args *uap)
{
	return (kern_renameat(td, AT_FDCWD, __USER_CAP_STR(uap->from),
	    AT_FDCWD, __USER_CAP_STR(uap->to), UIO_USERSPACE));
}

int
freebsd64_renameat(struct thread *td, struct freebsd64_renameat_args *uap)
{
	return (kern_renameat(td, uap->oldfd, __USER_CAP_STR(uap->old),
	    uap->newfd, __USER_CAP_STR(uap->new), UIO_USERSPACE));
}

int
freebsd64_mkdir(struct thread *td, struct freebsd64_mkdir_args *uap)
{
	return (kern_mkdirat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->mode));
}

int
freebsd64_mkdirat(struct thread *td, struct freebsd64_mkdirat_args *uap)
{
	return (kern_mkdirat(td, uap->fd, __USER_CAP_STR(uap->path),
	    UIO_USERSPACE, uap->mode));
}

int
freebsd64_rmdir(struct thread *td, struct freebsd64_rmdir_args *uap)
{
	return (kern_frmdirat(td, AT_FDCWD, __USER_CAP_STR(uap->path),
	    FD_NONE, UIO_USERSPACE, 0));
}

int
freebsd64_getdirentries(struct thread *td,
    struct freebsd64_getdirentries_args *uap)
{
	return (user_getdirentries(td, uap->fd,
	    __USER_CAP(uap->buf, uap->count), uap->count,
	    __USER_CAP_OBJ(uap->basep)));
}

int
freebsd64_unmount(struct thread *td, struct freebsd64_unmount_args *uap)
{
	return (kern_unmount(td, __USER_CAP_STR(uap->path), uap->flags));
}

int
freebsd64_revoke(struct thread *td, struct freebsd64_revoke_args *uap)
{
	return (kern_revoke(td, __USER_CAP_STR(uap->path), UIO_USERSPACE));
}

int
freebsd64_lgetfh(struct thread *td, struct freebsd64_lgetfh_args *uap)
{
	return (kern_getfhat(td, AT_SYMLINK_NOFOLLOW, AT_FDCWD,
	    __USER_CAP_STR(uap->fname), UIO_USERSPACE,
	    __USER_CAP_OBJ(uap->fhp), UIO_USERSPACE));
}

int
freebsd64_getfh(struct thread *td, struct freebsd64_getfh_args *uap)
{
	return (kern_getfhat(td, AT_SYMLINK_NOFOLLOW, AT_FDCWD,
	    __USER_CAP_STR(uap->fname), UIO_USERSPACE,
	    __USER_CAP_OBJ(uap->fhp), UIO_USERSPACE));
}

int
freebsd64_getfhat(struct thread *td, struct freebsd64_getfhat_args *uap)
{
	return (kern_getfhat(td, uap->flags, uap->fd,
	    __USER_CAP_STR(uap->path), UIO_SYSSPACE,
	    __USER_CAP_OBJ(uap->fhp), UIO_USERSPACE));
}

int
freebsd64_fhlink(struct thread *td, struct freebsd64_fhlink_args *uap)
{
	return (kern_fhlinkat(td, AT_FDCWD, __USER_CAP_STR(uap->to),
	    UIO_USERSPACE, __USER_CAP_OBJ(uap->fhp)));
}

int
freebsd64_fhlinkat(struct thread *td, struct freebsd64_fhlinkat_args *uap)
{
	return (kern_fhlinkat(td, uap->tofd, __USER_CAP_STR(uap->to),
	    UIO_USERSPACE, __USER_CAP_OBJ(uap->fhp)));
}

int
freebsd64_fhreadlink(struct thread *td, struct freebsd64_fhreadlink_args *uap)
{
	return (kern_fhreadlink(td, __USER_CAP_OBJ(uap->fhp),
	    __USER_CAP(uap->buf, uap->bufsize), uap->bufsize));
}

int
freebsd64_fhopen(struct thread *td, struct freebsd64_fhopen_args *uap)
{
	return (kern_fhopen(td, __USER_CAP_OBJ(uap->u_fhp), uap->flags));
}

int
freebsd64_fhstat(struct thread *td, struct freebsd64_fhstat_args *uap)
{
	return (user_fhstat(td, __USER_CAP_OBJ(uap->u_fhp),
	    __USER_CAP_OBJ(uap->sb)));
}

int
freebsd64_fhstatfs(struct thread *td, struct freebsd64_fhstatfs_args *uap)
{
	return (user_fhstatfs(td, __USER_CAP_OBJ(uap->u_fhp),
	    __USER_CAP_OBJ(uap->buf)));
}

int
freebsd64_copy_file_range(struct thread *td,
    struct freebsd64_copy_file_range_args *uap)
{
	return (user_copy_file_range(td, uap->infd,
	    __USER_CAP_OBJ(uap->inoffp), uap->outfd,
	    __USER_CAP_OBJ(uap->outoffp), uap->len, uap->flags));
}
