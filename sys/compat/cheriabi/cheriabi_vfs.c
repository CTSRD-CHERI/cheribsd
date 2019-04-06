/*-
 * Copyright (c) 2015-2018 SRI International
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/signal.h>
#include <sys/syscallsubr.h>

#include <compat/cheriabi/cheriabi_proto.h>

/*
 * vfs_acl.c
 */
int
cheriabi___acl_get_file(struct thread *td,
    struct cheriabi___acl_get_file_args *uap)
{

	return (kern___acl_get_path(td, uap->path, uap->type, uap->aclp,
	    FOLLOW));
}

int
cheriabi___acl_get_link(struct thread *td,
    struct cheriabi___acl_get_link_args *uap)
{

	return (kern___acl_get_path(td, uap->path, uap->type, uap->aclp,
	    NOFOLLOW));
}

int
cheriabi___acl_set_file(struct thread *td,
    struct cheriabi___acl_set_file_args *uap)
{

	return(kern___acl_set_path(td, uap->path, uap->type, uap->aclp,
	    FOLLOW));
}

int
cheriabi___acl_set_link(struct thread *td,
    struct cheriabi___acl_set_link_args *uap)
{

	return(kern___acl_set_path(td, uap->path, uap->type, uap->aclp,
	    NOFOLLOW));
}

int
cheriabi___acl_get_fd(struct thread *td,
    struct cheriabi___acl_get_fd_args *uap)
{

	return (kern___acl_get_fd(td, uap->filedes, uap->type, uap->aclp));
}

int
cheriabi___acl_set_fd(struct thread *td,
    struct cheriabi___acl_set_fd_args *uap)
{

	return (kern___acl_set_fd(td, uap->filedes, uap->type, uap->aclp));
}

int
cheriabi___acl_delete_file(struct thread *td,
    struct cheriabi___acl_delete_file_args *uap)
{

	return (kern___acl_delete_path(td, uap->path, uap->type, FOLLOW));
}

int
cheriabi___acl_delete_link(struct thread *td,
    struct cheriabi___acl_delete_link_args *uap)
{

	return (kern___acl_delete_path(td, uap->path, uap->type, NOFOLLOW));
}

int
cheriabi___acl_aclcheck_file(struct thread *td,
    struct cheriabi___acl_aclcheck_file_args *uap)
{

	return (kern___acl_aclcheck_path(td, uap->path, uap->type, uap->aclp,
	    FOLLOW));
}

int
cheriabi___acl_aclcheck_link(struct thread *td,
    struct cheriabi___acl_aclcheck_link_args *uap)
{

	return (kern___acl_aclcheck_path(td, uap->path, uap->type, uap->aclp,
	    NOFOLLOW));
}

int
cheriabi___acl_aclcheck_fd(struct thread *td,
    struct cheriabi___acl_aclcheck_fd_args *uap)
{

	return (kern___acl_aclcheck_fd(td, uap->filedes, uap->type,
	    uap->aclp));
}

/*
 * vfs_cache.c
 */
int
cheriabi___getcwd(struct thread *td, struct cheriabi___getcwd_args *uap)
{

	return (kern___getcwd(td, uap->buf, UIO_USERSPACE, uap->buflen,
	    MAXPATHLEN));
}

/*
 * vfs_extattr.c
 */
int
cheriabi_extattrctl(struct thread *td, struct cheriabi_extattrctl_args *uap)
{

	return (kern_extattrctl(td, uap->path, uap->cmd, uap->filename,
	    uap->attrnamespace, uap->attrname));
}

int
cheriabi_extattr_set_fd(struct thread *td,
    struct cheriabi_extattr_set_fd_args *uap)
{

	return (kern_extattr_set_fd(td, uap->fd, uap->attrnamespace,
	    uap->attrname, uap->data, uap->nbytes));
}

int
cheriabi_extattr_set_file(struct thread *td,
    struct cheriabi_extattr_set_file_args *uap)
{

	return (kern_extattr_set_path(td, uap->path, uap->attrnamespace,
	    uap->attrname, uap->data, uap->nbytes, FOLLOW));
}

int
cheriabi_extattr_set_link(struct thread *td,
    struct cheriabi_extattr_set_link_args *uap)
{

	return (kern_extattr_set_path(td, uap->path, uap->attrnamespace,
	    uap->attrname, uap->data, uap->nbytes, NOFOLLOW));
}

int
cheriabi_extattr_get_fd(struct thread *td,
    struct cheriabi_extattr_get_fd_args *uap)
{

	return (kern_extattr_get_fd(td, uap->fd, uap->attrnamespace,
	    uap->attrname, uap->data, uap->nbytes));
}

int
cheriabi_extattr_get_file(struct thread *td,
    struct cheriabi_extattr_get_file_args *uap)
{

	return (kern_extattr_get_path(td, uap->path, uap->attrnamespace,
	    uap->attrname, uap->data, uap->nbytes, FOLLOW));
}

int
cheriabi_extattr_get_link(struct thread *td,
    struct cheriabi_extattr_get_link_args *uap)
{

	return (kern_extattr_get_path(td, uap->path, uap->attrnamespace,
	    uap->attrname, uap->data, uap->nbytes, NOFOLLOW));
}

int
cheriabi_extattr_delete_fd(struct thread *td,
    struct cheriabi_extattr_delete_fd_args *uap)
{

	return (kern_extattr_delete_fd(td, uap->fd, uap->attrnamespace,
	    uap->attrname));
}

int
cheriabi_extattr_delete_file(struct thread *td,
    struct cheriabi_extattr_delete_file_args *uap)
{

	return (kern_extattr_delete_path(td, uap->path, uap->attrnamespace,
	    uap->attrname, FOLLOW));
}

int
cheriabi_extattr_delete_link(struct thread *td,
    struct cheriabi_extattr_delete_link_args *uap)
{

	return (kern_extattr_delete_path(td, uap->path, uap->attrnamespace,
	    uap->attrname, NOFOLLOW));
}

int
cheriabi_extattr_list_fd(struct thread *td,
    struct cheriabi_extattr_list_fd_args *uap)
{

	return (kern_extattr_list_fd(td, uap->fd, uap->attrnamespace,
	    uap->data, uap->nbytes));
}

int
cheriabi_extattr_list_file(struct thread *td,
    struct cheriabi_extattr_list_file_args *uap)
{

	return (kern_extattr_list_path(td, uap->path, uap->attrnamespace,
	    uap->data, uap->nbytes, FOLLOW));
}

int
cheriabi_extattr_list_link(struct thread *td,
    struct cheriabi_extattr_list_link_args *uap)
{

	return (kern_extattr_list_path(td, uap->path, uap->attrnamespace,
	    uap->data, uap->nbytes, NOFOLLOW));
}

/*
 * vfs_syscalls.c
 */
int
cheriabi_quotactl(struct thread *td, struct cheriabi_quotactl_args *uap)
{

	return (kern_quotactl(td, uap->path, uap->cmd, uap->uid, uap->arg));
}

int
cheriabi_statfs(struct thread *td, struct cheriabi_statfs_args *uap)
{

	return (user_statfs(td, uap->path, uap->buf));
}

int
cheriabi_fstatfs(struct thread *td, struct cheriabi_fstatfs_args *uap)
{

	return (user_fstatfs(td, uap->fd, uap->buf));
}

int
cheriabi_getfsstat(struct thread *td, struct cheriabi_getfsstat_args *uap)
{

	return (user_getfsstat(td, uap->buf, uap->bufsize, uap->mode));
}

int
cheriabi_chdir(struct thread *td, struct cheriabi_chdir_args *uap)
{

	return (kern_chdir(td, uap->path, UIO_USERSPACE));
}

int
cheriabi_chroot(struct thread *td, struct cheriabi_chroot_args *uap)
{

	return (kern_chroot(td, uap->path));
}

int
cheriabi_open(struct thread *td, struct cheriabi_open_args *uap)
{

	return (kern_openat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->flags, uap->mode));
}

int
cheriabi_openat(struct thread *td, struct cheriabi_openat_args *uap)
{

	return (kern_openat(td, uap->fd, uap->path, UIO_USERSPACE, uap->flag,
	    uap->mode));
}


int
cheriabi_mknodat(struct thread *td, struct cheriabi_mknodat_args *uap)
{

	return (kern_mknodat(td, uap->fd, uap->path, UIO_USERSPACE, uap->mode,
	    uap->dev));
}

int
cheriabi_mkfifo(struct thread *td, struct cheriabi_mkfifo_args *uap)
{

	return (kern_mkfifoat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->mode));
}

int
cheriabi_mkfifoat(struct thread *td, struct cheriabi_mkfifoat_args *uap)
{

	return (kern_mkfifoat(td, uap->fd, uap->path, UIO_USERSPACE,
	    uap->mode));
}

int
cheriabi_link(struct thread *td, struct cheriabi_link_args *uap)
{

	return (kern_linkat(td, AT_FDCWD, AT_FDCWD, uap->path, uap->to,
	    UIO_USERSPACE, FOLLOW));
}

int
cheriabi_linkat(struct thread *td, struct cheriabi_linkat_args *uap)
{
	int flag;

	flag = uap->flag;
	if (flag & ~AT_SYMLINK_FOLLOW)
		return (EINVAL);

	return (kern_linkat(td, uap->fd1, uap->fd2, uap->path1, uap->path2,
	    UIO_USERSPACE, (flag & AT_SYMLINK_FOLLOW) ? FOLLOW : NOFOLLOW));
}

int
cheriabi_symlink(struct thread *td, struct cheriabi_symlink_args *uap)
{

	return (kern_symlinkat(td, uap->path, AT_FDCWD, uap->link,
	    UIO_USERSPACE));
}

int
cheriabi_symlinkat(struct thread *td, struct cheriabi_symlinkat_args *uap)
{

	return (kern_symlinkat(td, uap->path1, uap->fd, uap->path2,
	    UIO_USERSPACE));
}

int
cheriabi_undelete(struct thread *td, struct cheriabi_undelete_args *uap)
{

	return (kern_undelete(td, uap->path, UIO_USERSPACE));
}

int
cheriabi_unlink(struct thread *td, struct cheriabi_unlink_args *uap)
{

	return (kern_funlinkat(td, AT_FDCWD, uap->path, FD_NONE,
	    UIO_USERSPACE, 0, 0));
}

int
cheriabi_unlinkat(struct thread *td, struct cheriabi_unlinkat_args *uap)
{

	return (kern_funlinkat_ex(td, uap->fd, uap->path, FD_NONE,
	    uap->flag, UIO_USERSPACE, 0));
}

int
cheriabi_funlinkat(struct thread *td, struct cheriabi_funlinkat_args *uap)
{

	return (kern_funlinkat_ex(td, uap->dfd, uap->path, uap->fd, uap->flag,
	    UIO_USERSPACE, 0));
}

int
cheriabi_access(struct thread *td, struct cheriabi_access_args *uap)
{

	return (kern_accessat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    0, uap->amode));
}

int
cheriabi_faccessat(struct thread *td, struct cheriabi_faccessat_args *uap)
{

	return (kern_accessat(td, uap->fd, uap->path, UIO_USERSPACE,
	    uap->flag, uap->amode));
}

int
cheriabi_eaccess(struct thread *td, struct cheriabi_eaccess_args *uap)
{

	return (kern_accessat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    AT_EACCESS, uap->amode));
}

int
cheriabi_fstatat(struct thread *td, struct cheriabi_fstatat_args *uap)
{

	return (user_fstatat(td, uap->fd, uap->path, uap->buf, uap->flag));
}

int
cheriabi_pathconf(struct thread *td, struct cheriabi_pathconf_args *uap)
{
	long value;
	int error;

	error = kern_pathconf(td, uap->path, UIO_USERSPACE, uap->name,
	    FOLLOW, &value);
	if (error == 0)
		td->td_retval[0] = value;
	return (error);
}

int
cheriabi_lpathconf(struct thread *td, struct cheriabi_lpathconf_args *uap)
{
	long value;
	int error;

	error = kern_pathconf(td, uap->path, UIO_USERSPACE, uap->name,
	    NOFOLLOW, &value);
	if (error == 0)
		td->td_retval[0] = value;
	return (error);
}

int
cheriabi_readlink(struct thread *td, struct cheriabi_readlink_args *uap)
{

	return (kern_readlinkat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->buf, UIO_USERSPACE, uap->count));
}

int
cheriabi_readlinkat(struct thread *td, struct cheriabi_readlinkat_args *uap)
{

	return (kern_readlinkat(td, uap->fd, uap->path, UIO_USERSPACE,
	    uap->buf, UIO_USERSPACE, uap->bufsize));
}

int
cheriabi_chflags(struct thread *td, struct cheriabi_chflags_args *uap)
{

	return (kern_chflagsat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->flags, 0));
}

int
cheriabi_chflagsat(struct thread *td, struct cheriabi_chflagsat_args *uap)
{

	if (uap->atflag & ~AT_SYMLINK_NOFOLLOW)
		return (EINVAL);

	return (kern_chflagsat(td, uap->fd, uap->path, UIO_USERSPACE,
	    uap->flags, uap->atflag));
}

int
cheriabi_lchflags(struct thread *td, struct cheriabi_lchflags_args *uap)
{

	return (kern_chflagsat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->flags, AT_SYMLINK_NOFOLLOW));
}

int
cheriabi_chmod(struct thread *td, struct cheriabi_chmod_args *uap)
{

	return (kern_fchmodat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->mode, 0));
}

int
cheriabi_fchmodat(struct thread *td, struct cheriabi_fchmodat_args *uap)
{

	if (uap->flag & ~AT_SYMLINK_NOFOLLOW)
		return (EINVAL);

	return (kern_fchmodat(td, uap->fd, uap->path, UIO_USERSPACE,
	    uap->mode, uap->flag));
}

int
cheriabi_lchmod(struct thread *td, struct cheriabi_lchmod_args *uap)
{

	return (kern_fchmodat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->mode, AT_SYMLINK_NOFOLLOW));
}

int
cheriabi_chown(struct thread *td, struct cheriabi_chown_args *uap)
{

	return (kern_fchownat(td, AT_FDCWD, uap->path, UIO_USERSPACE, uap->uid,
	    uap->gid, 0));
}

int
cheriabi_fchownat(struct thread *td, struct cheriabi_fchownat_args *uap)
{

	return (kern_fchownat(td, uap->fd, uap->path, UIO_USERSPACE,
	    uap->uid, uap->gid, uap->flag));
}

int
cheriabi_lchown(struct thread *td, struct cheriabi_lchown_args *uap)
{

	return (kern_fchownat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->uid, uap->gid, AT_SYMLINK_NOFOLLOW));
}

int
cheriabi_utimes(struct thread *td, struct cheriabi_utimes_args *uap)
{

	return (kern_utimesat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->tptr, UIO_USERSPACE));
}

int
cheriabi_futimesat(struct thread *td, struct cheriabi_futimesat_args *uap)
{

	return (kern_utimesat(td, uap->fd, uap->path, UIO_USERSPACE,
	    uap->times, UIO_USERSPACE));
}

int
cheriabi_futimes(struct thread *td, struct cheriabi_futimes_args *uap)
{

	return (kern_futimes(td, uap->fd, uap->tptr, UIO_USERSPACE));
}


int
cheriabi_lutimes(struct thread *td, struct cheriabi_lutimes_args *uap)
{
	return (kern_lutimes(td, uap->path, UIO_USERSPACE, uap->tptr,
	    UIO_USERSPACE));
}

int
cheriabi_futimens(struct thread *td, struct cheriabi_futimens_args *uap)
{
	return (kern_futimens(td, uap->fd, uap->times, UIO_USERSPACE));
}

int
cheriabi_utimensat(struct thread *td, struct cheriabi_utimensat_args *uap)
{

	return (kern_utimensat(td, uap->fd, uap->path, UIO_USERSPACE,
	    uap->times, UIO_USERSPACE, uap->flag));
}

int
cheriabi_truncate(struct thread *td, struct cheriabi_truncate_args *uap)
{

	return (kern_truncate(td, uap->path, UIO_USERSPACE, uap->length));
}

int
cheriabi_rename(struct thread *td, struct cheriabi_rename_args *uap)
{

	return (kern_renameat(td, AT_FDCWD, uap->from, AT_FDCWD,
	    uap->to, UIO_USERSPACE));
}

int
cheriabi_renameat(struct thread *td, struct cheriabi_renameat_args *uap)
{

	return (kern_renameat(td, uap->oldfd, uap->old, uap->newfd,
	    uap->new, UIO_USERSPACE));
}

int
cheriabi_mkdir(struct thread *td, struct cheriabi_mkdir_args *uap)
{

	return (kern_mkdirat(td, AT_FDCWD, uap->path, UIO_USERSPACE,
	    uap->mode));
}

int
cheriabi_mkdirat(struct thread *td, struct cheriabi_mkdirat_args *uap)
{

	return (kern_mkdirat(td, uap->fd, uap->path, UIO_USERSPACE, uap->mode));
}

int
cheriabi_rmdir(struct thread *td, struct cheriabi_rmdir_args *uap)
{

	return (kern_frmdirat(td, AT_FDCWD, uap->path, FD_NONE,
	    UIO_USERSPACE, 0));
}

int
cheriabi_getdirentries(struct thread *td,
    struct cheriabi_getdirentries_args *uap)
{

	return (user_getdirentries(td, uap->fd, uap->buf, uap->count,
	    uap->basep));
}

int
cheriabi_unmount(struct thread *td, struct cheriabi_unmount_args *uap)
{

	return (kern_unmount(td, uap->path, uap->flags));
}

int
cheriabi_revoke(struct thread *td, struct cheriabi_revoke_args *uap)
{

	return (kern_revoke(td, uap->path, UIO_USERSPACE));
}

int
cheriabi_lgetfh(struct thread *td, struct cheriabi_lgetfh_args *uap)
{

	return (kern_getfhat(td, AT_SYMLINK_NOFOLLOW, AT_FDCWD, uap->fname,
	    UIO_USERSPACE, uap->fhp));
}

int
cheriabi_getfh(struct thread *td, struct cheriabi_getfh_args *uap)
{

	return (kern_getfhat(td, AT_SYMLINK_NOFOLLOW, AT_FDCWD, uap->fname,
	    UIO_USERSPACE, uap->fhp));
}

int
cheriabi_getfhat(struct thread *td, struct cheriabi_getfhat_args *uap)
{

	if ((uap->flags & ~(AT_SYMLINK_NOFOLLOW | AT_BENEATH)) != 0)
		return (EINVAL);
	return (kern_getfhat(td, uap->flags, uap->fd, uap->path,
	    UIO_SYSSPACE, uap->fhp));
}

int
cheriabi_fhlink(struct thread *td, struct cheriabi_fhlink_args *uap)
{

	return (kern_fhlinkat(td, AT_FDCWD, uap->to, UIO_USERSPACE,
	    uap->fhp));
}

int
cheriabi_fhlinkat(struct thread *td, struct cheriabi_fhlinkat_args *uap)
{

	return (kern_fhlinkat(td, uap->tofd, uap->to, UIO_USERSPACE,
	    uap->fhp));
}

int
cheriabi_fhreadlink(struct thread *td, struct cheriabi_fhreadlink_args *uap)
{

	return (kern_fhreadlink(td, uap->fhp, uap->buf, uap->bufsize));
}

int
cheriabi_fhopen(struct thread *td, struct cheriabi_fhopen_args *uap)
{

	return (kern_fhopen(td, uap->u_fhp, uap->flags));
}

int
cheriabi_fhstat(struct thread *td, struct cheriabi_fhstat_args *uap)
{

	return (user_fhstat(td, uap->u_fhp, uap->sb));
}

int
cheriabi_fhstatfs(struct thread *td, struct cheriabi_fhstatfs_args *uap)
{

	return (user_fhstatfs(td, uap->u_fhp, uap->buf));
}
